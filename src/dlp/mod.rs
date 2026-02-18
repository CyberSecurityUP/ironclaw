use anyhow::Result;
use regex::Regex;
use tracing::{info, warn};

/// Data Loss Prevention (DLP) Module — scans tool outputs for sensitive data
/// before they reach the LLM or user.
///
/// This module prevents credential leakage even when tools are tricked into
/// reading sensitive files. It acts as a last line of defense after the
/// Anti-Stealer module (which prevents access) and the sandbox (which isolates).
///
/// Actions:
/// - Block: Prevent the output from being sent (replace with error)
/// - Redact: Replace sensitive values with [REDACTED] markers
/// - Warn: Log a warning but allow the output through
///
/// Coverage:
/// - AWS, GCP, Azure credentials
/// - Private keys (RSA, EC, Ed25519, PGP)
/// - Database connection strings with passwords
/// - JWT tokens
/// - API keys from major providers
/// - SSH private keys
/// - Generic high-entropy secrets
pub struct DlpEngine {
    /// Detection rules for sensitive data patterns
    rules: Vec<DlpRule>,
    /// Default action when sensitive data is detected
    default_action: DlpAction,
    /// Whether the engine is enabled
    enabled: bool,
}

#[derive(Debug, Clone)]
pub struct DlpRule {
    pub id: String,
    pub pattern: Regex,
    pub data_type: DataType,
    pub action: DlpAction,
    pub description: String,
    /// Replacement text when redacting
    pub redaction: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DlpAction {
    /// Block the entire output
    Block,
    /// Redact the matched content
    Redact,
    /// Log a warning but allow
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

/// Result of DLP scanning.
#[derive(Debug, Clone)]
pub struct DlpResult {
    /// The processed output (may be redacted or blocked)
    pub output: String,
    /// Whether the output was blocked entirely
    pub blocked: bool,
    /// Findings from the scan
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

impl DlpEngine {
    pub fn new(enabled: bool, default_action: DlpAction) -> Result<Self> {
        let rules = Self::build_rules(default_action.clone())?;
        info!(
            rules = rules.len(),
            enabled = enabled,
            action = ?default_action,
            "DLP engine initialized"
        );
        Ok(Self {
            rules,
            default_action,
            enabled,
        })
    }

    /// Scan output text for sensitive data and apply DLP actions.
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
                let matched_count = rule.pattern.find_iter(&result).count();

                findings.push(DlpFinding {
                    rule_id: rule.id.clone(),
                    data_type: rule.data_type.clone(),
                    action_taken: rule.action.clone(),
                    description: format!("{} ({} occurrence(s))", rule.description, matched_count),
                    matched_length: rule
                        .pattern
                        .find(&result)
                        .map(|m| m.len())
                        .unwrap_or(0),
                });

                match &rule.action {
                    DlpAction::Block => {
                        should_block = true;
                        warn!(
                            rule = %rule.id,
                            data_type = ?rule.data_type,
                            "DLP: Blocked output containing sensitive data"
                        );
                    }
                    DlpAction::Redact => {
                        result = rule
                            .pattern
                            .replace_all(&result, rule.redaction.as_str())
                            .to_string();
                        warn!(
                            rule = %rule.id,
                            data_type = ?rule.data_type,
                            "DLP: Redacted sensitive data from output"
                        );
                    }
                    DlpAction::Warn => {
                        warn!(
                            rule = %rule.id,
                            data_type = ?rule.data_type,
                            "DLP: Warning — sensitive data detected in output"
                        );
                    }
                }
            }
        }

        if should_block {
            DlpResult {
                output: "[DLP BLOCKED] Output contained sensitive data that cannot be safely transmitted. Check audit log for details.".to_string(),
                blocked: true,
                findings,
            }
        } else {
            DlpResult {
                output: result,
                blocked: false,
                findings,
            }
        }
    }

    /// Get the number of DLP rules loaded.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    fn build_rules(default_action: DlpAction) -> Result<Vec<DlpRule>> {
        let rules = vec![
            // === Private Keys (always block) ===
            DlpRule {
                id: "private-key-rsa".to_string(),
                pattern: Regex::new(r"-----BEGIN (RSA )?PRIVATE KEY-----[\s\S]*?-----END (RSA )?PRIVATE KEY-----")?,
                data_type: DataType::PrivateKey,
                action: DlpAction::Block,
                description: "RSA private key detected".to_string(),
                redaction: "[PRIVATE KEY REDACTED]".to_string(),
            },
            DlpRule {
                id: "private-key-ec".to_string(),
                pattern: Regex::new(r"-----BEGIN EC PRIVATE KEY-----[\s\S]*?-----END EC PRIVATE KEY-----")?,
                data_type: DataType::PrivateKey,
                action: DlpAction::Block,
                description: "EC private key detected".to_string(),
                redaction: "[PRIVATE KEY REDACTED]".to_string(),
            },
            DlpRule {
                id: "private-key-openssh".to_string(),
                pattern: Regex::new(r"-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----")?,
                data_type: DataType::SshKey,
                action: DlpAction::Block,
                description: "OpenSSH private key detected".to_string(),
                redaction: "[SSH KEY REDACTED]".to_string(),
            },
            DlpRule {
                id: "private-key-pgp".to_string(),
                pattern: Regex::new(r"-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?-----END PGP PRIVATE KEY BLOCK-----")?,
                data_type: DataType::PrivateKey,
                action: DlpAction::Block,
                description: "PGP private key detected".to_string(),
                redaction: "[PGP KEY REDACTED]".to_string(),
            },

            // === AWS Credentials ===
            DlpRule {
                id: "aws-access-key".to_string(),
                pattern: Regex::new(r"(?i)(AKIA[0-9A-Z]{16})")?,
                data_type: DataType::AwsCredential,
                action: default_action.clone(),
                description: "AWS Access Key ID detected".to_string(),
                redaction: "[AWS_KEY_REDACTED]".to_string(),
            },
            DlpRule {
                id: "aws-secret-key".to_string(),
                pattern: Regex::new(r"(?i)aws_secret_access_key\s*=\s*([A-Za-z0-9/+=]{40})")?,
                data_type: DataType::AwsCredential,
                action: DlpAction::Block,
                description: "AWS Secret Access Key detected".to_string(),
                redaction: "aws_secret_access_key = [REDACTED]".to_string(),
            },

            // === GCP Credentials ===
            DlpRule {
                id: "gcp-service-account".to_string(),
                pattern: Regex::new(r#"(?i)"type"\s*:\s*"service_account"[\s\S]*?"private_key"\s*:"#)?,
                data_type: DataType::GcpCredential,
                action: DlpAction::Block,
                description: "GCP service account JSON with private key detected".to_string(),
                redaction: "[GCP_SERVICE_ACCOUNT_REDACTED]".to_string(),
            },
            DlpRule {
                id: "gcp-api-key".to_string(),
                pattern: Regex::new(r"AIza[0-9A-Za-z\-_]{35}")?,
                data_type: DataType::GcpCredential,
                action: default_action.clone(),
                description: "Google API key detected".to_string(),
                redaction: "[GOOGLE_API_KEY_REDACTED]".to_string(),
            },

            // === Azure Credentials ===
            DlpRule {
                id: "azure-storage-key".to_string(),
                pattern: Regex::new(r"AccountKey=[A-Za-z0-9+/=]{86}==")?,
                data_type: DataType::AzureCredential,
                action: DlpAction::Block,
                description: "Azure Storage Account Key detected".to_string(),
                redaction: "AccountKey=[REDACTED]".to_string(),
            },

            // === Database URIs ===
            DlpRule {
                id: "database-uri".to_string(),
                pattern: Regex::new(r"(?i)(mysql|postgres|postgresql|mongodb|redis|amqp)://[^:]+:[^@\s]+@[^\s]+")?,
                data_type: DataType::DatabaseUri,
                action: default_action.clone(),
                description: "Database connection URI with embedded password detected".to_string(),
                redaction: "[DATABASE_URI_REDACTED]".to_string(),
            },

            // === JWT Tokens ===
            DlpRule {
                id: "jwt-token".to_string(),
                pattern: Regex::new(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")?,
                data_type: DataType::JwtToken,
                action: default_action.clone(),
                description: "JWT token detected".to_string(),
                redaction: "[JWT_REDACTED]".to_string(),
            },

            // === API Keys ===
            DlpRule {
                id: "github-token".to_string(),
                pattern: Regex::new(r"(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}")?,
                data_type: DataType::ApiKey,
                action: default_action.clone(),
                description: "GitHub token detected".to_string(),
                redaction: "[GITHUB_TOKEN_REDACTED]".to_string(),
            },
            DlpRule {
                id: "github-pat-fine".to_string(),
                pattern: Regex::new(r"github_pat_[A-Za-z0-9_]{82}")?,
                data_type: DataType::ApiKey,
                action: default_action.clone(),
                description: "GitHub fine-grained PAT detected".to_string(),
                redaction: "[GITHUB_PAT_REDACTED]".to_string(),
            },
            DlpRule {
                id: "slack-token".to_string(),
                pattern: Regex::new(r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*")?,
                data_type: DataType::ApiKey,
                action: default_action.clone(),
                description: "Slack token detected".to_string(),
                redaction: "[SLACK_TOKEN_REDACTED]".to_string(),
            },
            DlpRule {
                id: "stripe-key".to_string(),
                pattern: Regex::new(r"(sk|pk)_(test|live)_[0-9a-zA-Z]{24,}")?,
                data_type: DataType::ApiKey,
                action: default_action.clone(),
                description: "Stripe API key detected".to_string(),
                redaction: "[STRIPE_KEY_REDACTED]".to_string(),
            },
            DlpRule {
                id: "anthropic-key".to_string(),
                pattern: Regex::new(r"sk-ant-[A-Za-z0-9_-]{40,}")?,
                data_type: DataType::ApiKey,
                action: DlpAction::Block,
                description: "Anthropic API key detected".to_string(),
                redaction: "[ANTHROPIC_KEY_REDACTED]".to_string(),
            },
            DlpRule {
                id: "openai-key".to_string(),
                pattern: Regex::new(r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}")?,
                data_type: DataType::ApiKey,
                action: DlpAction::Block,
                description: "OpenAI API key detected".to_string(),
                redaction: "[OPENAI_KEY_REDACTED]".to_string(),
            },
            DlpRule {
                id: "telegram-token".to_string(),
                pattern: Regex::new(r"\d{8,10}:[A-Za-z0-9_-]{35}")?,
                data_type: DataType::ApiKey,
                action: default_action.clone(),
                description: "Telegram bot token detected".to_string(),
                redaction: "[TELEGRAM_TOKEN_REDACTED]".to_string(),
            },

            // === Generic Secrets ===
            DlpRule {
                id: "generic-password-assignment".to_string(),
                pattern: Regex::new(r#"(?i)(password|passwd|pwd)\s*[:=]\s*["'][^"']{8,}["']"#)?,
                data_type: DataType::GenericSecret,
                action: default_action.clone(),
                description: "Password assignment detected".to_string(),
                redaction: "[PASSWORD_REDACTED]".to_string(),
            },
            DlpRule {
                id: "generic-secret-assignment".to_string(),
                pattern: Regex::new(r#"(?i)(secret|secret_key|api_secret)\s*[:=]\s*["'][^"']{16,}["']"#)?,
                data_type: DataType::GenericSecret,
                action: default_action.clone(),
                description: "Secret value assignment detected".to_string(),
                redaction: "[SECRET_REDACTED]".to_string(),
            },

            // === /etc/shadow content ===
            DlpRule {
                id: "shadow-file-content".to_string(),
                pattern: Regex::new(r"(?m)^[a-z_][a-z0-9_-]*:\$[0-9a-z]+\$[^\n:]+:[0-9]*:")?,
                data_type: DataType::GenericSecret,
                action: DlpAction::Block,
                description: "Password hash from /etc/shadow detected".to_string(),
                redaction: "[SHADOW_CONTENT_REDACTED]".to_string(),
            },
        ];

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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_engine() -> DlpEngine {
        DlpEngine::new(true, DlpAction::Redact).unwrap()
    }

    #[test]
    fn test_blocks_rsa_private_key() {
        let engine = test_engine();
        let content = r#"Here is the key:
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2Z3qX2BTLS4e...
-----END RSA PRIVATE KEY-----
"#;
        let result = engine.scan_output(content);
        assert!(result.blocked);
        assert!(result.findings.iter().any(|f| f.data_type == DataType::PrivateKey));
    }

    #[test]
    fn test_blocks_openssh_key() {
        let engine = test_engine();
        let content = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAA...
-----END OPENSSH PRIVATE KEY-----"#;
        let result = engine.scan_output(content);
        assert!(result.blocked);
        assert!(result.findings.iter().any(|f| f.data_type == DataType::SshKey));
    }

    #[test]
    fn test_redacts_aws_access_key() {
        let engine = test_engine();
        let content = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE";
        let result = engine.scan_output(content);
        assert!(!result.blocked);
        assert!(result.output.contains("[AWS_KEY_REDACTED]"));
        assert!(!result.output.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn test_blocks_aws_secret_key() {
        let engine = test_engine();
        let content = "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let result = engine.scan_output(content);
        assert!(result.blocked);
    }

    #[test]
    fn test_redacts_github_token() {
        let engine = test_engine();
        let content = "GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
        let result = engine.scan_output(content);
        assert!(result.output.contains("[GITHUB_TOKEN_REDACTED]"));
        assert!(!result.output.contains("ghp_ABCDEF"));
    }

    #[test]
    fn test_redacts_database_uri() {
        let engine = test_engine();
        let content = "DATABASE_URL=postgres://admin:super_secret_pwd@db.example.com:5432/mydb";
        let result = engine.scan_output(content);
        assert!(result.output.contains("[DATABASE_URI_REDACTED]"));
        assert!(!result.output.contains("super_secret_pwd"));
    }

    #[test]
    fn test_redacts_jwt() {
        let engine = test_engine();
        let content = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let result = engine.scan_output(content);
        assert!(result.output.contains("[JWT_REDACTED]"));
    }

    #[test]
    fn test_redacts_slack_token() {
        let engine = test_engine();
        let content = "SLACK_TOKEN=xoxb-1234567890123-1234567890123-AbCdEfGhIjKl";
        let result = engine.scan_output(content);
        assert!(result.output.contains("[SLACK_TOKEN_REDACTED]"));
    }

    #[test]
    fn test_redacts_stripe_key() {
        let engine = test_engine();
        let content = "STRIPE_SECRET=sk_live_FAKEFAKEFAKEFAKE";
        let result = engine.scan_output(content);
        assert!(result.output.contains("[STRIPE_KEY_REDACTED]"));
    }

    #[test]
    fn test_blocks_shadow_content() {
        let engine = test_engine();
        let content = "root:$6$xyz$longhashhere:19000:0:99999:7:::";
        let result = engine.scan_output(content);
        assert!(result.blocked);
    }

    #[test]
    fn test_allows_normal_output() {
        let engine = test_engine();
        let content = "Build successful. 42 tests passed. No errors found.";
        let result = engine.scan_output(content);
        assert!(!result.blocked);
        assert!(result.findings.is_empty());
        assert_eq!(result.output, content);
    }

    #[test]
    fn test_disabled_engine_passes_everything() {
        let engine = DlpEngine::new(false, DlpAction::Block).unwrap();
        let content = "AKIAIOSFODNN7EXAMPLE";
        let result = engine.scan_output(content);
        assert!(!result.blocked);
        assert_eq!(result.output, content);
    }

    #[test]
    fn test_blocks_anthropic_key() {
        let engine = test_engine();
        let content = "key: sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop";
        let result = engine.scan_output(content);
        assert!(result.blocked);
        assert!(result.findings.iter().any(|f| f.rule_id == "anthropic-key"));
    }

    #[test]
    fn test_redacts_password_assignment() {
        let engine = test_engine();
        let content = r#"config = { password: "my_super_secret_password_123" }"#;
        let result = engine.scan_output(content);
        assert!(result.output.contains("[PASSWORD_REDACTED]"));
        assert!(!result.output.contains("my_super_secret_password_123"));
    }

    #[test]
    fn test_blocks_pgp_private_key() {
        let engine = test_engine();
        let content = r#"-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG v2
lQHYBF...
-----END PGP PRIVATE KEY BLOCK-----"#;
        let result = engine.scan_output(content);
        assert!(result.blocked);
    }

    #[test]
    fn test_blocks_azure_storage_key() {
        let engine = test_engine();
        // 86 chars of base64 + ==
        let key = "A".repeat(86) + "==";
        let content = format!("AccountKey={}", key);
        let result = engine.scan_output(&content);
        assert!(result.blocked);
    }

    #[test]
    fn test_multiple_findings() {
        let engine = test_engine();
        let content = r#"
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij
DATABASE=postgres://admin:pass@db.local:5432/app
"#;
        let result = engine.scan_output(content);
        assert!(result.findings.len() >= 3);
    }

    #[test]
    fn test_gcp_api_key() {
        let engine = test_engine();
        let content = "GOOGLE_API_KEY=AIzaSyA-1234567890abcdefghijklmnopqrstuv";
        let result = engine.scan_output(content);
        assert!(result.findings.iter().any(|f| f.data_type == DataType::GcpCredential));
    }
}
