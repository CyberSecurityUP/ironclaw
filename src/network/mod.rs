use anyhow::Result;
use regex::Regex;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tracing::{info, warn};

/// SSRF Protection Module — prevents Server-Side Request Forgery attacks.
///
/// Addresses the vulnerability found in ZeroClaw's Python web tool
/// (unrestricted HTTP requests with no SSRF protection).
///
/// Protection layers:
/// 1. URL scheme validation (only http/https allowed)
/// 2. Private/reserved IP range blocking
/// 3. Cloud metadata endpoint blocking
/// 4. DNS rebinding prevention
/// 5. Localhost/loopback blocking
/// 6. IPv6 mapped IPv4 detection
pub struct SsrfGuard {
    /// Cloud metadata endpoints to block
    metadata_endpoints: Vec<MetadataEndpoint>,
    /// Whether to block private/internal IPs
    block_private: bool,
    /// Additional blocked domains
    blocked_domains: Vec<String>,
    /// Allowed domains (if non-empty, only these are permitted)
    allowed_domains: Vec<String>,
}

#[derive(Debug, Clone)]
struct MetadataEndpoint {
    host: String,
    description: String,
    cloud_provider: String,
}

/// Result of SSRF validation.
#[derive(Debug, Clone)]
pub struct SsrfCheckResult {
    pub allowed: bool,
    pub reason: Option<String>,
}

impl SsrfGuard {
    pub fn new(
        block_private: bool,
        blocked_domains: Vec<String>,
        allowed_domains: Vec<String>,
    ) -> Self {
        let metadata_endpoints = vec![
            MetadataEndpoint {
                host: "169.254.169.254".to_string(),
                description: "AWS/GCP Instance Metadata Service".to_string(),
                cloud_provider: "AWS/GCP".to_string(),
            },
            MetadataEndpoint {
                host: "metadata.google.internal".to_string(),
                description: "GCP Metadata Service (DNS)".to_string(),
                cloud_provider: "GCP".to_string(),
            },
            MetadataEndpoint {
                host: "metadata.azure.com".to_string(),
                description: "Azure Instance Metadata Service".to_string(),
                cloud_provider: "Azure".to_string(),
            },
            MetadataEndpoint {
                host: "169.254.170.2".to_string(),
                description: "AWS ECS Task Metadata".to_string(),
                cloud_provider: "AWS".to_string(),
            },
            MetadataEndpoint {
                host: "100.100.100.200".to_string(),
                description: "Alibaba Cloud Metadata".to_string(),
                cloud_provider: "Alibaba".to_string(),
            },
            MetadataEndpoint {
                host: "169.254.169.123".to_string(),
                description: "AWS Time Sync / NTP (link-local)".to_string(),
                cloud_provider: "AWS".to_string(),
            },
            MetadataEndpoint {
                host: "fd00:ec2::254".to_string(),
                description: "AWS IMDSv2 IPv6".to_string(),
                cloud_provider: "AWS".to_string(),
            },
        ];

        info!(
            metadata_endpoints = metadata_endpoints.len(),
            block_private = block_private,
            blocked_domains = blocked_domains.len(),
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
        // Step 1: Validate URL scheme
        if let Err(reason) = self.validate_scheme(url) {
            return SsrfCheckResult {
                allowed: false,
                reason: Some(reason),
            };
        }

        // Step 2: Extract host from URL
        let host = match self.extract_host(url) {
            Some(h) => h,
            None => {
                return SsrfCheckResult {
                    allowed: false,
                    reason: Some("Cannot extract host from URL".to_string()),
                };
            }
        };

        // Step 3: Check against cloud metadata endpoints
        if let Some(endpoint) = self.is_metadata_endpoint(&host) {
            return SsrfCheckResult {
                allowed: false,
                reason: Some(format!(
                    "Blocked cloud metadata endpoint: {} ({})",
                    endpoint.description, endpoint.cloud_provider
                )),
            };
        }

        // Step 4: Check blocked domains
        if self.is_blocked_domain(&host) {
            return SsrfCheckResult {
                allowed: false,
                reason: Some(format!("Domain '{}' is in the block list", host)),
            };
        }

        // Step 5: If allowlist is configured, check it
        if !self.allowed_domains.is_empty() && !self.is_allowed_domain(&host) {
            return SsrfCheckResult {
                allowed: false,
                reason: Some(format!(
                    "Domain '{}' is not in the allow list",
                    host
                )),
            };
        }

        // Step 6: Parse as IP and check for private/reserved ranges
        if let Ok(ip) = host.parse::<IpAddr>() {
            if let Err(reason) = self.check_ip(ip) {
                return SsrfCheckResult {
                    allowed: false,
                    reason: Some(reason),
                };
            }
        }

        // Step 7: Check for numeric IP obfuscation techniques
        if let Err(reason) = self.check_ip_obfuscation(&host) {
            return SsrfCheckResult {
                allowed: false,
                reason: Some(reason),
            };
        }

        SsrfCheckResult {
            allowed: true,
            reason: None,
        }
    }

    /// Validate an IP address after DNS resolution (DNS rebinding prevention).
    pub fn check_resolved_ip(&self, ip: IpAddr) -> SsrfCheckResult {
        match self.check_ip(ip) {
            Ok(()) => SsrfCheckResult {
                allowed: true,
                reason: None,
            },
            Err(reason) => SsrfCheckResult {
                allowed: false,
                reason: Some(format!("DNS resolution returned blocked IP: {}", reason)),
            },
        }
    }

    fn validate_scheme(&self, url: &str) -> Result<(), String> {
        let lower = url.to_lowercase();
        if lower.starts_with("https://") || lower.starts_with("http://") {
            Ok(())
        } else if lower.starts_with("file://") {
            Err("file:// scheme blocked — potential local file read".to_string())
        } else if lower.starts_with("gopher://") {
            Err("gopher:// scheme blocked — known SSRF attack vector".to_string())
        } else if lower.starts_with("dict://") {
            Err("dict:// scheme blocked — known SSRF attack vector".to_string())
        } else if lower.starts_with("ftp://") {
            Err("ftp:// scheme blocked — unencrypted protocol".to_string())
        } else if lower.starts_with("data:") {
            Err("data: URI blocked — potential injection vector".to_string())
        } else {
            Err(format!(
                "Unknown URL scheme — only http:// and https:// are allowed"
            ))
        }
    }

    fn extract_host(&self, url: &str) -> Option<String> {
        // Simple URL host extraction
        let without_scheme = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .unwrap_or(url);

        // Handle userinfo@ prefix (can be used for confusion attacks)
        let after_userinfo = if let Some(at_pos) = without_scheme.find('@') {
            // Check if @ appears before the first /
            let slash_pos = without_scheme.find('/').unwrap_or(without_scheme.len());
            if at_pos < slash_pos {
                &without_scheme[at_pos + 1..]
            } else {
                without_scheme
            }
        } else {
            without_scheme
        };

        // Extract host (before port, path, or query)
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

        // Remove port number
        let host = if host.starts_with('[') {
            // IPv6 address in brackets
            host.split(']').next().map(|h| format!("{}]", h))
        } else {
            Some(host.rsplit(':').last().unwrap_or(host).to_string())
        };

        host.map(|h| h.trim_matches(|c| c == '[' || c == ']').to_string())
    }

    fn is_metadata_endpoint(&self, host: &str) -> Option<&MetadataEndpoint> {
        let host_lower = host.to_lowercase();
        self.metadata_endpoints
            .iter()
            .find(|ep| host_lower == ep.host.to_lowercase())
    }

    fn is_blocked_domain(&self, host: &str) -> bool {
        let host_lower = host.to_lowercase();
        self.blocked_domains.iter().any(|d| {
            let d_lower = d.to_lowercase();
            if d_lower.starts_with("*.") {
                host_lower.ends_with(&d_lower[1..])
            } else {
                host_lower == d_lower
            }
        })
    }

    fn is_allowed_domain(&self, host: &str) -> bool {
        let host_lower = host.to_lowercase();
        self.allowed_domains.iter().any(|d| {
            let d_lower = d.to_lowercase();
            if d_lower.starts_with("*.") {
                host_lower.ends_with(&d_lower[1..])
            } else {
                host_lower == d_lower
            }
        })
    }

    fn check_ip(&self, ip: IpAddr) -> Result<(), String> {
        if !self.block_private {
            return Ok(());
        }

        match ip {
            IpAddr::V4(ipv4) => self.check_ipv4(ipv4),
            IpAddr::V6(ipv6) => self.check_ipv6(ipv6),
        }
    }

    fn check_ipv4(&self, ip: Ipv4Addr) -> Result<(), String> {
        let octets = ip.octets();

        // Loopback (127.0.0.0/8)
        if octets[0] == 127 {
            return Err(format!("Loopback address blocked: {}", ip));
        }

        // Link-local (169.254.0.0/16)
        if octets[0] == 169 && octets[1] == 254 {
            return Err(format!("Link-local address blocked: {}", ip));
        }

        // Private ranges (RFC 1918)
        // 10.0.0.0/8
        if octets[0] == 10 {
            return Err(format!("Private network (10.0.0.0/8) blocked: {}", ip));
        }

        // 172.16.0.0/12
        if octets[0] == 172 && (octets[1] >= 16 && octets[1] <= 31) {
            return Err(format!("Private network (172.16.0.0/12) blocked: {}", ip));
        }

        // 192.168.0.0/16
        if octets[0] == 192 && octets[1] == 168 {
            return Err(format!("Private network (192.168.0.0/16) blocked: {}", ip));
        }

        // CGNAT (100.64.0.0/10) — RFC 6598
        if octets[0] == 100 && (octets[1] >= 64 && octets[1] <= 127) {
            return Err(format!("CGNAT (100.64.0.0/10) blocked: {}", ip));
        }

        // Broadcast
        if octets == [255, 255, 255, 255] {
            return Err("Broadcast address blocked".to_string());
        }

        // Unspecified
        if octets == [0, 0, 0, 0] {
            return Err("Unspecified address (0.0.0.0) blocked".to_string());
        }

        // Documentation ranges (RFC 5737)
        // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
        if (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
            || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
            || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
        {
            return Err(format!("Documentation range address blocked: {}", ip));
        }

        Ok(())
    }

    fn check_ipv6(&self, ip: Ipv6Addr) -> Result<(), String> {
        // Loopback (::1)
        if ip == Ipv6Addr::LOCALHOST {
            return Err("IPv6 loopback (::1) blocked".to_string());
        }

        // Unspecified (::)
        if ip == Ipv6Addr::UNSPECIFIED {
            return Err("IPv6 unspecified (::) blocked".to_string());
        }

        // Link-local (fe80::/10)
        let segments = ip.segments();
        if (segments[0] & 0xffc0) == 0xfe80 {
            return Err(format!("IPv6 link-local address blocked: {}", ip));
        }

        // Unique local (fc00::/7) — IPv6 equivalent of RFC 1918
        if (segments[0] & 0xfe00) == 0xfc00 {
            return Err(format!("IPv6 unique local address blocked: {}", ip));
        }

        // IPv4-mapped IPv6 (::ffff:0:0/96) — could be used to bypass IPv4 checks
        if segments[0..5] == [0, 0, 0, 0, 0] && segments[5] == 0xffff {
            let ipv4 = Ipv4Addr::new(
                (segments[6] >> 8) as u8,
                (segments[6] & 0xff) as u8,
                (segments[7] >> 8) as u8,
                (segments[7] & 0xff) as u8,
            );
            return self
                .check_ipv4(ipv4)
                .map_err(|e| format!("IPv4-mapped IPv6 address: {}", e));
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

        // Octal IP (e.g., 0177.0.0.1 = 127.0.0.1)
        if host.contains('.') && host.starts_with('0') && !host.starts_with("0.") {
            return Err(format!(
                "Possible octal IP obfuscation detected: {}",
                host
            ));
        }

        // Hex IP (e.g., 0x7f000001 = 127.0.0.1)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_guard() -> SsrfGuard {
        SsrfGuard::new(true, vec![], vec![])
    }

    #[test]
    fn test_blocks_metadata_aws() {
        let guard = test_guard();
        let result = guard.check_url("http://169.254.169.254/latest/meta-data/");
        assert!(!result.allowed);
        assert!(result.reason.unwrap().contains("metadata"));
    }

    #[test]
    fn test_blocks_metadata_gcp() {
        let guard = test_guard();
        let result = guard.check_url("http://metadata.google.internal/computeMetadata/v1/");
        assert!(!result.allowed);
    }

    #[test]
    fn test_blocks_metadata_azure() {
        let guard = test_guard();
        let result = guard.check_url("http://metadata.azure.com/metadata/instance");
        assert!(!result.allowed);
    }

    #[test]
    fn test_blocks_localhost() {
        let guard = test_guard();
        let result = guard.check_url("http://127.0.0.1/admin");
        assert!(!result.allowed);
        assert!(result.reason.unwrap().contains("Loopback"));
    }

    #[test]
    fn test_blocks_private_10() {
        let guard = test_guard();
        let result = guard.check_url("http://10.0.0.1/internal");
        assert!(!result.allowed);
        assert!(result.reason.unwrap().contains("Private"));
    }

    #[test]
    fn test_blocks_private_172() {
        let guard = test_guard();
        let result = guard.check_url("http://172.16.0.1/internal");
        assert!(!result.allowed);
    }

    #[test]
    fn test_blocks_private_192() {
        let guard = test_guard();
        let result = guard.check_url("http://192.168.1.1/admin");
        assert!(!result.allowed);
    }

    #[test]
    fn test_blocks_file_scheme() {
        let guard = test_guard();
        let result = guard.check_url("file:///etc/passwd");
        assert!(!result.allowed);
        assert!(result.reason.unwrap().contains("file://"));
    }

    #[test]
    fn test_blocks_gopher_scheme() {
        let guard = test_guard();
        let result = guard.check_url("gopher://evil.com:25/");
        assert!(!result.allowed);
    }

    #[test]
    fn test_allows_public_url() {
        let guard = test_guard();
        let result = guard.check_url("https://api.example.com/v1/data");
        assert!(result.allowed);
    }

    #[test]
    fn test_blocks_ipv6_loopback() {
        let guard = test_guard();
        let result = guard.check_url("http://[::1]/admin");
        assert!(!result.allowed);
    }

    #[test]
    fn test_blocks_decimal_ip_obfuscation() {
        let guard = test_guard();
        // 2130706433 = 127.0.0.1
        let result = guard.check_url("http://2130706433/admin");
        assert!(!result.allowed);
        assert!(result.reason.unwrap().contains("obfuscation"));
    }

    #[test]
    fn test_blocks_hex_ip_obfuscation() {
        let guard = test_guard();
        // 0x7f000001 = 127.0.0.1
        let result = guard.check_url("http://0x7f000001/admin");
        assert!(!result.allowed);
        assert!(result.reason.unwrap().contains("Hex IP"));
    }

    #[test]
    fn test_blocks_cgnat() {
        let guard = test_guard();
        let result = guard.check_url("http://100.64.0.1/internal");
        assert!(!result.allowed);
        assert!(result.reason.unwrap().contains("CGNAT"));
    }

    #[test]
    fn test_domain_allowlist() {
        let guard = SsrfGuard::new(
            true,
            vec![],
            vec!["api.example.com".to_string(), "*.github.com".to_string()],
        );

        let result = guard.check_url("https://api.example.com/data");
        assert!(result.allowed);

        let result = guard.check_url("https://raw.github.com/file");
        assert!(result.allowed);

        let result = guard.check_url("https://evil.com/steal");
        assert!(!result.allowed);
    }

    #[test]
    fn test_domain_blocklist() {
        let guard = SsrfGuard::new(
            true,
            vec!["evil.com".to_string(), "*.malware.org".to_string()],
            vec![],
        );

        let result = guard.check_url("https://evil.com/steal");
        assert!(!result.allowed);

        let result = guard.check_url("https://payload.malware.org/c2");
        assert!(!result.allowed);

        let result = guard.check_url("https://safe.example.com/api");
        assert!(result.allowed);
    }

    #[test]
    fn test_userinfo_bypass_attempt() {
        let guard = test_guard();
        // Attacker tries http://safe.com@169.254.169.254/
        let result = guard.check_url("http://safe.com@169.254.169.254/latest/meta-data/");
        assert!(!result.allowed);
    }

    #[test]
    fn test_resolved_ip_check() {
        let guard = test_guard();

        // After DNS resolves to a private IP (DNS rebinding attack)
        let result = guard.check_resolved_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!result.allowed);

        let result = guard.check_resolved_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(result.allowed);
    }

    #[test]
    fn test_blocks_data_uri() {
        let guard = test_guard();
        let result = guard.check_url("data:text/html,<script>alert(1)</script>");
        assert!(!result.allowed);
    }

    #[test]
    fn test_ipv4_mapped_ipv6() {
        let guard = test_guard();
        // ::ffff:127.0.0.1 — IPv4-mapped IPv6 bypass attempt
        let ip = "::ffff:127.0.0.1".parse::<IpAddr>().unwrap();
        let result = guard.check_resolved_ip(ip);
        assert!(!result.allowed);
    }
}
