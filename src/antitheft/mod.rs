use anyhow::Result;
use regex::Regex;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use parking_lot::Mutex;
use tracing::{info, warn};

/// Anti-Stealer Detection Module — detects and blocks credential harvesting,
/// data exfiltration, and stealer-like behavior patterns.
///
/// This module addresses vulnerabilities found in ZeroClaw's Python tools
/// (unrestricted file I/O, shell=True, no SSRF protection) and OpenClaw's
/// plugin loader (no cryptographic verification).
///
/// Detection layers:
/// 1. Sensitive path access monitoring
/// 2. Credential harvesting pattern detection
/// 3. Multi-step exfiltration correlation (read → encode → send)
/// 4. Anomaly-based access sequence detection
/// 5. Real-time blocking with audit logging
pub struct AntiStealer {
    /// Compiled patterns for sensitive file paths
    sensitive_paths: Vec<SensitivePathRule>,
    /// Compiled patterns for credential content
    credential_patterns: Vec<CredentialPattern>,
    /// Access tracking for multi-step correlation
    access_tracker: Mutex<AccessTracker>,
    /// Whether to enforce blocking (vs. warn-only mode)
    enforce: bool,
}

#[derive(Debug, Clone)]
pub struct SensitivePathRule {
    pub pattern: Regex,
    pub category: SensitiveCategory,
    pub severity: Severity,
    pub description: String,
}

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
pub struct CredentialPattern {
    pub pattern: Regex,
    pub credential_type: String,
    pub severity: Severity,
}

#[derive(Debug)]
struct AccessTracker {
    /// Recent file accesses (path → timestamp)
    file_accesses: HashMap<String, Vec<Instant>>,
    /// Recent network requests (domain → timestamp)
    network_requests: HashMap<String, Vec<Instant>>,
    /// Sensitive data reads in the current window
    sensitive_reads: Vec<SensitiveAccess>,
    /// Number of blocked operations
    blocked_count: u64,
    /// Correlation window (detect read→send within this period)
    correlation_window: Duration,
}

#[derive(Debug, Clone)]
struct SensitiveAccess {
    path: String,
    category: SensitiveCategory,
    timestamp: Instant,
    session_id: String,
}

/// Result of a stealer detection check.
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
                file_accesses: HashMap::new(),
                network_requests: HashMap::new(),
                sensitive_reads: Vec::new(),
                blocked_count: 0,
                correlation_window: Duration::from_secs(300), // 5 minute window
            }),
            enforce,
        })
    }

    /// Check if a file path access should be blocked (stealer detection).
    pub fn check_file_access(&self, path: &str, session_id: &str) -> DetectionResult {
        let mut findings = Vec::new();
        let normalized = Self::normalize_path(path);

        // Check against sensitive path rules
        for rule in &self.sensitive_paths {
            if rule.pattern.is_match(&normalized) {
                findings.push(Finding {
                    rule: format!("sensitive-path:{:?}", rule.category),
                    severity: rule.severity.clone(),
                    description: format!(
                        "Access to sensitive path detected: {} ({})",
                        path, rule.description
                    ),
                    category: format!("{:?}", rule.category),
                });

                // Track the sensitive access for correlation
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
            let mut tracker = self.access_tracker.lock();
            tracker.blocked_count += 1;
            warn!(
                path = %path,
                findings = findings.len(),
                "Anti-Stealer: Blocked access to sensitive file"
            );
        }

        DetectionResult { blocked, findings }
    }

    /// Check if content contains credential-like data (for DLP integration).
    pub fn scan_content(&self, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        for pattern in &self.credential_patterns {
            if pattern.pattern.is_match(content) {
                findings.push(Finding {
                    rule: format!("credential-content:{}", pattern.credential_type),
                    severity: pattern.severity.clone(),
                    description: format!(
                        "Credential-like content detected: {}",
                        pattern.credential_type
                    ),
                    category: "credential_content".to_string(),
                });
            }
        }

        findings
    }

    /// Check for multi-step exfiltration patterns (read sensitive → send network).
    pub fn check_exfiltration_correlation(
        &self,
        network_domain: &str,
        session_id: &str,
    ) -> DetectionResult {
        let mut findings = Vec::new();
        let tracker = self.access_tracker.lock();
        let now = Instant::now();

        // Look for recent sensitive reads in the same session
        let recent_sensitive: Vec<&SensitiveAccess> = tracker
            .sensitive_reads
            .iter()
            .filter(|access| {
                access.session_id == session_id
                    && now.duration_since(access.timestamp) < tracker.correlation_window
            })
            .collect();

        if !recent_sensitive.is_empty() {
            let categories: Vec<String> = recent_sensitive
                .iter()
                .map(|a| format!("{:?}", a.category))
                .collect();

            findings.push(Finding {
                rule: "exfiltration-correlation".to_string(),
                severity: Severity::Critical,
                description: format!(
                    "Network request to {} after reading sensitive files ({}) — possible data exfiltration",
                    network_domain,
                    categories.join(", ")
                ),
                category: "exfiltration".to_string(),
            });
        }

        let blocked = self.enforce && !findings.is_empty();

        DetectionResult { blocked, findings }
    }

    /// Check a shell command for stealer-like patterns.
    pub fn check_command(&self, command: &str) -> DetectionResult {
        let mut findings = Vec::new();
        let cmd_lower = command.to_lowercase();

        // Pattern: reading sensitive files and piping/encoding
        let stealer_patterns = [
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

        for (pattern, description, severity) in &stealer_patterns {
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

        // Multi-command exfiltration pattern: read | encode | send
        if (cmd_lower.contains("cat ") || cmd_lower.contains("read"))
            && (cmd_lower.contains("base64") || cmd_lower.contains("xxd") || cmd_lower.contains("od "))
            && (cmd_lower.contains("curl") || cmd_lower.contains("wget") || cmd_lower.contains("nc "))
        {
            findings.push(Finding {
                rule: "multi-step-exfiltration".to_string(),
                severity: Severity::Critical,
                description: "Multi-step exfiltration pattern detected: read → encode → send"
                    .to_string(),
                category: "exfiltration".to_string(),
            });
        }

        let blocked = self.enforce
            && findings
                .iter()
                .any(|f| matches!(f.severity, Severity::Critical | Severity::High));

        DetectionResult { blocked, findings }
    }

    /// Get the count of blocked operations.
    pub fn blocked_count(&self) -> u64 {
        self.access_tracker.lock().blocked_count
    }

    /// Clean up expired entries from the access tracker.
    pub fn cleanup_expired(&self) {
        let mut tracker = self.access_tracker.lock();
        let now = Instant::now();
        let window = tracker.correlation_window;

        tracker
            .sensitive_reads
            .retain(|access| now.duration_since(access.timestamp) < window);

        tracker
            .file_accesses
            .retain(|_, timestamps| {
                timestamps.retain(|t| now.duration_since(*t) < window);
                !timestamps.is_empty()
            });
    }

    fn normalize_path(path: &str) -> String {
        // Expand ~ to home directory
        let expanded = if path.starts_with("~/") {
            if let Ok(home) = std::env::var("HOME") {
                path.replacen("~", &home, 1)
            } else {
                path.to_string()
            }
        } else {
            path.to_string()
        };

        // Normalize .. and .
        expanded.replace("/./", "/").to_lowercase()
    }

    fn build_sensitive_path_rules() -> Result<Vec<SensitivePathRule>> {
        let rules = vec![
            // SSH Keys
            (r"(?i)(^|/)\.ssh/(id_rsa|id_ed25519|id_ecdsa|id_dsa|authorized_keys|known_hosts|config)$",
             SensitiveCategory::SshKeys, Severity::Critical,
             "SSH private key or configuration"),
            (r"(?i)(^|/)\.ssh/",
             SensitiveCategory::SshKeys, Severity::High,
             "SSH directory access"),

            // Cloud Credentials
            (r"(?i)(^|/)\.aws/(credentials|config)$",
             SensitiveCategory::CloudCredentials, Severity::Critical,
             "AWS credentials file"),
            (r"(?i)(^|/)\.azure/(accessTokens|azureProfile)\.json$",
             SensitiveCategory::CloudCredentials, Severity::Critical,
             "Azure credentials file"),
            (r"(?i)(^|/)\.config/gcloud/(credentials\.db|application_default_credentials\.json)$",
             SensitiveCategory::CloudCredentials, Severity::Critical,
             "GCP credentials file"),
            (r"(?i)(^|/)\.kube/config$",
             SensitiveCategory::CloudCredentials, Severity::Critical,
             "Kubernetes config with cluster credentials"),
            (r"(?i)(^|/)\.docker/config\.json$",
             SensitiveCategory::CloudCredentials, Severity::High,
             "Docker registry credentials"),

            // Crypto Wallets
            (r"(?i)(^|/)(\.bitcoin|\.ethereum|\.solana|\.monero)/",
             SensitiveCategory::CryptoWallets, Severity::Critical,
             "Cryptocurrency wallet directory"),
            (r"(?i)(^|/)wallet\.(dat|json|key)$",
             SensitiveCategory::CryptoWallets, Severity::Critical,
             "Cryptocurrency wallet file"),
            (r"(?i)(^|/)\.electrum/",
             SensitiveCategory::CryptoWallets, Severity::Critical,
             "Electrum wallet directory"),
            (r"(?i)(^|/)\.metamask/",
             SensitiveCategory::CryptoWallets, Severity::Critical,
             "MetaMask wallet data"),

            // Browser Profiles
            (r"(?i)(^|/)(\.mozilla|\.config/google-chrome|\.config/chromium|Library/Application Support/(Google/Chrome|Firefox))/",
             SensitiveCategory::BrowserProfiles, Severity::Critical,
             "Browser profile directory (cookies, saved passwords, history)"),
            (r"(?i)(cookies|login\s*data|web\s*data)\.sqlite$",
             SensitiveCategory::BrowserProfiles, Severity::Critical,
             "Browser credential database"),

            // Password Stores
            (r"(?i)(^|/)\.password-store/",
             SensitiveCategory::PasswordStores, Severity::Critical,
             "pass password store"),
            (r"(?i)(^|/)\.local/share/keyrings/",
             SensitiveCategory::PasswordStores, Severity::Critical,
             "GNOME Keyring store"),
            (r"(?i)(^|/)Library/Keychains/",
             SensitiveCategory::PasswordStores, Severity::Critical,
             "macOS Keychain"),
            (r"(?i)(^|/)(\.keepass|\.kdbx?|\.1password)$",
             SensitiveCategory::PasswordStores, Severity::Critical,
             "Password manager database"),

            // Certificates and Keys
            (r"(?i)\.(pem|p12|pfx|jks|keystore|key|crt|cer)$",
             SensitiveCategory::CertificatesKeys, Severity::High,
             "Certificate or private key file"),
            (r"(?i)(^|/)\.gnupg/(private-keys|secring|trustdb)",
             SensitiveCategory::CertificatesKeys, Severity::Critical,
             "GPG private key"),

            // Environment Files
            (r"(?i)(^|/)\.env(\.[a-z]+)?$",
             SensitiveCategory::EnvironmentFiles, Severity::High,
             "Environment file with potential secrets"),
            (r"(?i)(^|/)\.netrc$",
             SensitiveCategory::EnvironmentFiles, Severity::High,
             "Netrc credentials file"),

            // System Credentials
            (r"(?i)^/etc/(shadow|gshadow|master\.passwd)$",
             SensitiveCategory::SystemCredentials, Severity::Critical,
             "System password database"),
            (r"(?i)^/etc/(sudoers|pam\.d/)",
             SensitiveCategory::SystemCredentials, Severity::High,
             "System authentication config"),

            // Database Credentials
            (r"(?i)(^|/)\.(pgpass|my\.cnf|mongorc\.js|dbshell)$",
             SensitiveCategory::DatabaseCredentials, Severity::High,
             "Database credential file"),
            (r"(?i)(^|/)\.config/redis",
             SensitiveCategory::DatabaseCredentials, Severity::High,
             "Redis configuration with credentials"),

            // API Tokens
            (r"(?i)(^|/)\.(npmrc|pypirc|gem/credentials|cargo/credentials)$",
             SensitiveCategory::ApiTokens, Severity::High,
             "Package registry credentials"),
            (r"(?i)(^|/)\.github/token$",
             SensitiveCategory::ApiTokens, Severity::High,
             "GitHub token file"),
            (r"(?i)(^|/)\.heroku/credentials$",
             SensitiveCategory::ApiTokens, Severity::High,
             "Heroku API credentials"),
        ];

        rules
            .into_iter()
            .map(|(pattern, category, severity, description)| {
                Ok(SensitivePathRule {
                    pattern: Regex::new(pattern)?,
                    category,
                    severity,
                    description: description.to_string(),
                })
            })
            .collect()
    }

    fn build_credential_patterns() -> Result<Vec<CredentialPattern>> {
        let patterns = vec![
            // AWS
            (r"(?i)AKIA[0-9A-Z]{16}", "AWS Access Key ID", Severity::Critical),
            (r"(?i)aws_secret_access_key\s*=\s*\S{40}", "AWS Secret Access Key", Severity::Critical),

            // GCP
            (r#"(?i)"type"\s*:\s*"service_account""#, "GCP Service Account JSON", Severity::Critical),
            (r"(?i)AIza[0-9A-Za-z\-_]{35}", "Google API Key", Severity::High),

            // Azure
            (r"(?i)AccountKey=[A-Za-z0-9+/=]{86}==", "Azure Storage Account Key", Severity::Critical),

            // Private Keys
            (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", "Private Key (PEM)", Severity::Critical),
            (r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "PGP Private Key", Severity::Critical),

            // JWT Tokens
            (r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "JWT Token", Severity::High),

            // GitHub
            (r"(?i)(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}", "GitHub Token", Severity::Critical),
            (r"github_pat_[A-Za-z0-9_]{82}", "GitHub PAT (fine-grained)", Severity::Critical),

            // Slack
            (r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*", "Slack Token", Severity::High),

            // Stripe
            (r"(?i)(sk|pk)_(test|live)_[0-9a-zA-Z]{24,}", "Stripe API Key", Severity::Critical),

            // Database URIs with password
            (r"(?i)(mysql|postgres|mongodb|redis)://[^:]+:[^@]+@", "Database Connection URI with Password", Severity::Critical),

            // Generic high-entropy secrets
            (r#"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*['"][A-Za-z0-9+/=_-]{20,}['"]"#,
             "Generic API Key/Secret", Severity::High),

            // SSH private key content
            (r"(?i)openssh-key-v1\x00", "OpenSSH Private Key (binary)", Severity::Critical),

            // Telegram Bot Token
            (r"\d{8,10}:[A-Za-z0-9_-]{35}", "Telegram Bot Token", Severity::High),

            // Discord Bot Token
            (r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}", "Discord Bot Token", Severity::High),
        ];

        patterns
            .into_iter()
            .map(|(pattern, credential_type, severity)| {
                Ok(CredentialPattern {
                    pattern: Regex::new(pattern)?,
                    credential_type: credential_type.to_string(),
                    severity,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_stealer() -> AntiStealer {
        AntiStealer::new(true).unwrap()
    }

    #[test]
    fn test_blocks_ssh_key_access() {
        let stealer = test_stealer();
        let result = stealer.check_file_access("/home/user/.ssh/id_rsa", "test-session");
        assert!(result.blocked);
        assert!(result.findings.iter().any(|f| f.category == "SshKeys"));
    }

    #[test]
    fn test_blocks_aws_credentials() {
        let stealer = test_stealer();
        let result = stealer.check_file_access("/home/user/.aws/credentials", "test-session");
        assert!(result.blocked);
        assert!(result.findings.iter().any(|f| f.category == "CloudCredentials"));
    }

    #[test]
    fn test_blocks_crypto_wallet() {
        let stealer = test_stealer();
        let result = stealer.check_file_access("/home/user/.bitcoin/wallet.dat", "test-session");
        assert!(result.blocked);
        assert!(result.findings.iter().any(|f| f.category == "CryptoWallets"));
    }

    #[test]
    fn test_blocks_browser_profile() {
        let stealer = test_stealer();
        let result = stealer.check_file_access(
            "/home/user/.config/google-chrome/Default/Login Data",
            "test-session",
        );
        assert!(result.blocked);
        assert!(result.findings.iter().any(|f| f.category == "BrowserProfiles"));
    }

    #[test]
    fn test_blocks_keychain() {
        let stealer = test_stealer();
        let result = stealer.check_file_access(
            "/Users/user/Library/Keychains/login.keychain-db",
            "test-session",
        );
        assert!(result.blocked);
    }

    #[test]
    fn test_allows_normal_file() {
        let stealer = test_stealer();
        let result = stealer.check_file_access("/home/user/project/src/main.rs", "test-session");
        assert!(!result.blocked);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_detects_aws_key_in_content() {
        let stealer = test_stealer();
        let content = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE";
        let findings = stealer.scan_content(content);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.description.contains("AWS")));
    }

    #[test]
    fn test_detects_private_key_in_content() {
        let stealer = test_stealer();
        let content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...";
        let findings = stealer.scan_content(content);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.description.contains("Private Key")));
    }

    #[test]
    fn test_detects_github_token() {
        let stealer = test_stealer();
        let content = "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
        let findings = stealer.scan_content(content);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.description.contains("GitHub")));
    }

    #[test]
    fn test_detects_database_uri() {
        let stealer = test_stealer();
        let content = "DATABASE_URL=postgres://admin:s3cr3t@db.example.com:5432/mydb";
        let findings = stealer.scan_content(content);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.description.contains("Database")));
    }

    #[test]
    fn test_no_false_positive_on_normal_content() {
        let stealer = test_stealer();
        let content = "This is a normal log message. User accessed /home/user/project/README.md";
        let findings = stealer.scan_content(content);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_stealer_command_detection() {
        let stealer = test_stealer();

        // Base64 encoding of sensitive file
        let result = stealer.check_command("base64 ~/.ssh/id_rsa.pem");
        assert!(result.blocked);

        // Searching for credential files
        let result = stealer.check_command("find / -name '*.pem'");
        assert!(result.blocked);

        // Recursive grep for secrets
        let result = stealer.check_command("grep -r password /etc/");
        assert!(result.blocked);

        // Normal command should pass
        let result = stealer.check_command("ls -la");
        assert!(!result.blocked);
    }

    #[test]
    fn test_exfiltration_correlation() {
        let stealer = test_stealer();
        let session = "test-session-123";

        // First, access a sensitive file
        stealer.check_file_access("/home/user/.aws/credentials", session);

        // Then check if network request is correlated
        let result = stealer.check_exfiltration_correlation("evil.com", session);
        assert!(result.blocked);
        assert!(result.findings.iter().any(|f| f.rule == "exfiltration-correlation"));
    }

    #[test]
    fn test_no_correlation_different_session() {
        let stealer = test_stealer();

        // Access sensitive file in session A
        stealer.check_file_access("/home/user/.aws/credentials", "session-a");

        // Network request in session B should NOT correlate
        let result = stealer.check_exfiltration_correlation("evil.com", "session-b");
        assert!(!result.blocked);
    }

    #[test]
    fn test_env_file_detection() {
        let stealer = test_stealer();
        let result = stealer.check_file_access("/home/user/project/.env", "test-session");
        assert!(result.blocked);
        assert!(result.findings.iter().any(|f| f.category == "EnvironmentFiles"));
    }

    #[test]
    fn test_env_variants() {
        let stealer = test_stealer();

        let result = stealer.check_file_access("/app/.env.production", "test");
        assert!(result.blocked);

        let result = stealer.check_file_access("/app/.env.local", "test");
        assert!(result.blocked);
    }

    #[test]
    fn test_jwt_detection() {
        let stealer = test_stealer();
        let content = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let findings = stealer.scan_content(content);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.description.contains("JWT")));
    }

    #[test]
    fn test_stripe_key_detection() {
        let stealer = test_stealer();
        let content = "STRIPE_KEY=sk_live_FAKEFAKEFAKEFAKE";
        let findings = stealer.scan_content(content);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.description.contains("Stripe")));
    }
}
