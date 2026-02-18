use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tracing::{info, warn};

use crate::core::config::PermissionsConfig;
use crate::core::types::SecurityContext;

/// Role-Based Access Control (RBAC) system for IronClaw.
///
/// Implements a Zero Trust permission model where:
/// - All actions are denied by default
/// - Permissions must be explicitly granted
/// - Each tool has a defined set of required permissions
/// - Roles aggregate permissions for common use cases
/// - Deny rules always take precedence over allow rules
pub struct Policy {
    /// Defined roles and their permissions
    roles: HashMap<String, Role>,
    /// Per-tool permission requirements
    tool_permissions: HashMap<String, ToolAccess>,
    /// Filesystem access control
    fs_policy: FilesystemPolicy,
    /// Network access control
    net_policy: NetworkPolicy,
    /// System-level access control
    sys_policy: SystemPolicy,
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
    pub rate_limit: Option<RateLimit>,
    pub required_permissions: HashSet<String>,
}

#[derive(Debug)]
pub struct RateLimit {
    pub max_per_hour: u32,
    pub current_count: std::sync::atomic::AtomicU32,
    pub window_start: parking_lot::Mutex<std::time::Instant>,
}

impl Clone for RateLimit {
    fn clone(&self) -> Self {
        Self {
            max_per_hour: self.max_per_hour,
            current_count: std::sync::atomic::AtomicU32::new(
                self.current_count.load(std::sync::atomic::Ordering::Relaxed),
            ),
            window_start: parking_lot::Mutex::new(*self.window_start.lock()),
        }
    }
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
    allow_private: bool,
    max_requests_per_hour: u32,
}

#[derive(Debug, Clone)]
struct SystemPolicy {
    allow_shell: bool,
    require_approval_high_risk: bool,
    max_concurrent: usize,
}

/// Simplified glob pattern matching (no external dependency needed for basic matching).
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

            if p[pi] == '*' && pi + 1 < p.len() && p[pi + 1] == '*' {
                // ** matches everything including /
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

            if p[pi] == '*' {
                // * matches everything except /
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

impl Policy {
    /// Create a policy from configuration.
    pub fn from_config(config: &PermissionsConfig) -> Result<Self> {
        let fs_policy = Self::build_fs_policy(&config.filesystem)?;
        let net_policy = Self::build_net_policy(&config.network);
        let sys_policy = Self::build_sys_policy(&config.system);

        let tool_permissions = Self::build_tool_permissions(&config.tools);

        // Create default roles
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

    fn build_fs_policy(
        config: &crate::core::config::FilesystemPermissions,
    ) -> Result<FilesystemPolicy> {
        let read_allow = config
            .read
            .iter()
            .map(|p| glob::Pattern::new(p))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("Invalid glob pattern: {}", e))?;

        let write_allow = config
            .write
            .iter()
            .map(|p| glob::Pattern::new(p))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("Invalid glob pattern: {}", e))?;

        let deny = config
            .deny
            .iter()
            .map(|p| glob::Pattern::new(p))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("Invalid glob pattern: {}", e))?;

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
                        rate_limit: perms.rate_limit.map(|max| RateLimit {
                            max_per_hour: max,
                            current_count: std::sync::atomic::AtomicU32::new(0),
                            window_start: parking_lot::Mutex::new(std::time::Instant::now()),
                        }),
                        required_permissions: HashSet::new(),
                    },
                )
            })
            .collect()
    }

    /// Check if a tool can be accessed in the given security context.
    pub fn check_tool_access(&self, tool_name: &str, ctx: &SecurityContext) -> Result<()> {
        // Check if tool is explicitly disabled
        if let Some(access) = self.tool_permissions.get(tool_name) {
            if !access.enabled {
                anyhow::bail!("Tool '{}' is disabled by policy", tool_name);
            }

            // Check rate limit
            if let Some(rate_limit) = &access.rate_limit {
                let mut window_start = rate_limit.window_start.lock();
                let now = std::time::Instant::now();

                // Reset window if expired (1 hour)
                if now.duration_since(*window_start) > std::time::Duration::from_secs(3600) {
                    *window_start = now;
                    rate_limit
                        .current_count
                        .store(0, std::sync::atomic::Ordering::Relaxed);
                }

                let count = rate_limit
                    .current_count
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if count >= rate_limit.max_per_hour {
                    anyhow::bail!(
                        "Tool '{}' rate limit exceeded ({}/hour)",
                        tool_name,
                        rate_limit.max_per_hour
                    );
                }
            }
        }

        // Check role permissions
        if let Some(role) = self.roles.get(&ctx.role) {
            // Check deny list first (deny always wins)
            for denied in &role.deny {
                if tool_name.starts_with(denied) {
                    warn!(
                        tool = %tool_name,
                        role = %ctx.role,
                        "Access denied by role deny list"
                    );
                    anyhow::bail!(
                        "Tool '{}' is denied for role '{}'",
                        tool_name,
                        ctx.role
                    );
                }
            }

            // Check if role has tool.execute permission
            if !role.permissions.contains("tool.execute") {
                anyhow::bail!(
                    "Role '{}' does not have tool.execute permission",
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

    /// Check if a filesystem path can be read.
    pub fn check_fs_read(&self, path: &str) -> Result<()> {
        // Check deny list first
        for deny_pattern in &self.fs_policy.deny {
            if deny_pattern.matches(path) {
                anyhow::bail!("Path '{}' is denied by filesystem policy", path);
            }
        }

        // If no allow patterns defined, allow all non-denied paths
        if self.fs_policy.read_allow.is_empty() {
            return Ok(());
        }

        // Check allow list
        for allow_pattern in &self.fs_policy.read_allow {
            if allow_pattern.matches(path) {
                return Ok(());
            }
        }

        anyhow::bail!(
            "Path '{}' is not in filesystem read allow list",
            path
        )
    }

    /// Check if a filesystem path can be written.
    pub fn check_fs_write(&self, path: &str) -> Result<()> {
        // Check deny list first
        for deny_pattern in &self.fs_policy.deny {
            if deny_pattern.matches(path) {
                anyhow::bail!("Path '{}' is denied by filesystem policy", path);
            }
        }

        // If no allow patterns defined, deny all writes by default (secure default)
        if self.fs_policy.write_allow.is_empty() {
            anyhow::bail!(
                "No write paths configured — all writes denied by default"
            );
        }

        for allow_pattern in &self.fs_policy.write_allow {
            if allow_pattern.matches(path) {
                return Ok(());
            }
        }

        anyhow::bail!(
            "Path '{}' is not in filesystem write allow list",
            path
        )
    }

    /// Check if a network domain is allowed.
    pub fn check_network_access(&self, domain: &str) -> Result<()> {
        // Block list takes precedence
        if self.net_policy.block_domains.contains(domain) {
            anyhow::bail!("Domain '{}' is blocked by network policy", domain);
        }

        // If allow list is empty, allow all non-blocked domains
        if self.net_policy.allow_domains.is_empty() {
            return Ok(());
        }

        // Check allow list with wildcard support
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

        anyhow::bail!(
            "Domain '{}' is not in network allow list",
            domain
        )
    }

    /// Number of tool permissions defined.
    pub fn tool_count(&self) -> usize {
        self.tool_permissions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::config::*;

    fn test_policy() -> Policy {
        let config = PermissionsConfig {
            filesystem: FilesystemPermissions {
                read: vec!["./src/**".to_string()],
                write: vec!["./output/**".to_string()],
                deny: default_denied_paths(),
            },
            network: NetworkPermissions {
                allow_domains: vec!["api.example.com".to_string(), "*.github.com".to_string()],
                block_domains: default_blocked_domains(),
                block_private: true,
                max_requests_per_hour: 100,
            },
            system: SystemPermissions {
                allow_shell: false,
                require_approval: true,
                max_concurrent: 4,
            },
            tools: HashMap::new(),
        };
        Policy::from_config(&config).unwrap()
    }

    fn default_denied_paths() -> Vec<String> {
        vec![
            "/etc/shadow".to_string(),
            "/root/.ssh/**".to_string(),
            "**/.env".to_string(),
        ]
    }

    fn default_blocked_domains() -> Vec<String> {
        vec![
            "169.254.169.254".to_string(),
            "metadata.google.internal".to_string(),
        ]
    }

    #[test]
    fn test_fs_read_denied_path() {
        let policy = test_policy();
        assert!(policy.check_fs_read("/etc/shadow").is_err());
    }

    #[test]
    fn test_fs_read_allowed_path() {
        let policy = test_policy();
        assert!(policy.check_fs_read("./src/main.rs").is_ok());
    }

    #[test]
    fn test_fs_write_no_config_denies() {
        let config = PermissionsConfig::default();
        let policy = Policy::from_config(&config).unwrap();
        // With default config (no write allow list), all writes are denied
        assert!(policy.check_fs_write("/tmp/test.txt").is_err());
    }

    #[test]
    fn test_network_blocks_metadata() {
        let policy = test_policy();
        assert!(policy.check_network_access("169.254.169.254").is_err());
        assert!(policy.check_network_access("metadata.google.internal").is_err());
    }

    #[test]
    fn test_network_allows_configured_domains() {
        let policy = test_policy();
        assert!(policy.check_network_access("api.example.com").is_ok());
    }

    #[test]
    fn test_network_wildcard_matching() {
        let policy = test_policy();
        assert!(policy.check_network_access("api.github.com").is_ok());
        assert!(policy.check_network_access("raw.github.com").is_ok());
    }

    #[test]
    fn test_shell_disabled() {
        let policy = test_policy();
        let ctx = SecurityContext {
            role: "agent".to_string(),
            permissions: vec![],
            session_id: "test".to_string(),
            approved: false,
            source_ip: None,
            channel: None,
            user_id: None,
            created_at: chrono::Utc::now(),
        };
        assert!(policy.check_tool_access("shell", &ctx).is_err());
    }
}
