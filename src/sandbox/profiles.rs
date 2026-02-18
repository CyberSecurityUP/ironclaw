//! Multi-Level Sandbox Profiles for IronClaw.
//!
//! Provides named isolation levels (Minimal, Standard, Elevated, Unrestricted,
//! Custom) that map to concrete sandbox configurations. Skills and tasks can
//! request a profile by name, and the resolver merges the profile defaults
//! with any per-skill overrides from the config file.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, warn};

use crate::core::config::SandboxConfig;

// ---------------------------------------------------------------------------
// Sandbox Level
// ---------------------------------------------------------------------------

/// Named isolation levels with increasing privilege.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SandboxLevel {
    /// Minimal isolation: read-only FS, no network, tight resource limits.
    Minimal,
    /// Standard isolation: read-only FS, no network, moderate limits.
    Standard,
    /// Elevated: writable tmpfs, limited network, higher limits.
    Elevated,
    /// Unrestricted: full FS access, full network, relaxed limits.
    /// Use only for trusted internal tools.
    Unrestricted,
    /// Custom: user-defined profile (must be in config).
    Custom,
}

impl Default for SandboxLevel {
    fn default() -> Self {
        Self::Standard
    }
}

impl std::fmt::Display for SandboxLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Minimal => write!(f, "minimal"),
            Self::Standard => write!(f, "standard"),
            Self::Elevated => write!(f, "elevated"),
            Self::Unrestricted => write!(f, "unrestricted"),
            Self::Custom => write!(f, "custom"),
        }
    }
}

impl SandboxLevel {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "minimal" => Self::Minimal,
            "standard" => Self::Standard,
            "elevated" => Self::Elevated,
            "unrestricted" => Self::Unrestricted,
            _ => Self::Custom,
        }
    }
}

// ---------------------------------------------------------------------------
// Sandbox Profile
// ---------------------------------------------------------------------------

/// Concrete sandbox configuration derived from a level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxProfile {
    pub level: SandboxLevel,
    pub name: String,
    pub filesystem: FilesystemAccess,
    pub network: NetworkAccess,
    pub resources: ResourceLimits,
    pub env_policy: EnvPolicy,
}

/// Filesystem access policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemAccess {
    /// Read-only root filesystem.
    pub read_only: bool,
    /// Writable paths (bind-mounted).
    pub writable_paths: Vec<String>,
    /// Tmpfs size in MB (0 = no tmpfs).
    pub tmpfs_size_mb: u64,
    /// Block device access.
    pub allow_devices: bool,
}

impl Default for FilesystemAccess {
    fn default() -> Self {
        Self {
            read_only: true,
            writable_paths: Vec::new(),
            tmpfs_size_mb: 64,
            allow_devices: false,
        }
    }
}

/// Network access policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAccess {
    /// Allow outbound network access.
    pub enabled: bool,
    /// Allowed domains (empty = allow all when enabled=true).
    pub allowed_domains: Vec<String>,
    /// Block private/RFC-1918 ranges.
    pub block_private: bool,
    /// Block cloud metadata endpoints.
    pub block_metadata: bool,
}

impl Default for NetworkAccess {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_domains: Vec::new(),
            block_private: true,
            block_metadata: true,
        }
    }
}

/// Resource limits for sandboxed execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Memory limit in MB.
    pub memory_mb: u64,
    /// CPU cores (fractional).
    pub cpu_cores: f64,
    /// Maximum PIDs.
    pub max_pids: u32,
    /// Wall-clock timeout in seconds.
    pub timeout_secs: u64,
    /// Max output bytes.
    pub max_output_bytes: usize,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            memory_mb: 256,
            cpu_cores: 0.5,
            max_pids: 32,
            timeout_secs: 30,
            max_output_bytes: 1024 * 1024,
        }
    }
}

/// Environment variable policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvPolicy {
    /// Clear all environment variables before execution.
    pub clear_env: bool,
    /// Explicit allowlist of env var names to pass through.
    pub allowed_vars: Vec<String>,
    /// Additional env vars to inject.
    pub inject_vars: HashMap<String, String>,
}

impl Default for EnvPolicy {
    fn default() -> Self {
        Self {
            clear_env: true,
            allowed_vars: vec![
                "PATH".to_string(),
                "HOME".to_string(),
                "LANG".to_string(),
                "TERM".to_string(),
            ],
            inject_vars: HashMap::new(),
        }
    }
}

impl SandboxProfile {
    /// Create a profile from a named level with built-in defaults.
    pub fn preset(level: SandboxLevel) -> Self {
        match level {
            SandboxLevel::Minimal => Self::minimal(),
            SandboxLevel::Standard => Self::standard(),
            SandboxLevel::Elevated => Self::elevated(),
            SandboxLevel::Unrestricted => Self::unrestricted(),
            SandboxLevel::Custom => Self::standard(), // fallback
        }
    }

    fn minimal() -> Self {
        Self {
            level: SandboxLevel::Minimal,
            name: "minimal".to_string(),
            filesystem: FilesystemAccess {
                read_only: true,
                writable_paths: Vec::new(),
                tmpfs_size_mb: 16,
                allow_devices: false,
            },
            network: NetworkAccess {
                enabled: false,
                allowed_domains: Vec::new(),
                block_private: true,
                block_metadata: true,
            },
            resources: ResourceLimits {
                memory_mb: 128,
                cpu_cores: 0.25,
                max_pids: 16,
                timeout_secs: 10,
                max_output_bytes: 256 * 1024,
            },
            env_policy: EnvPolicy {
                clear_env: true,
                allowed_vars: vec!["PATH".to_string(), "LANG".to_string()],
                inject_vars: HashMap::new(),
            },
        }
    }

    fn standard() -> Self {
        Self {
            level: SandboxLevel::Standard,
            name: "standard".to_string(),
            filesystem: FilesystemAccess::default(),
            network: NetworkAccess::default(),
            resources: ResourceLimits::default(),
            env_policy: EnvPolicy::default(),
        }
    }

    fn elevated() -> Self {
        Self {
            level: SandboxLevel::Elevated,
            name: "elevated".to_string(),
            filesystem: FilesystemAccess {
                read_only: true,
                writable_paths: vec!["/tmp".to_string(), "/var/tmp".to_string()],
                tmpfs_size_mb: 256,
                allow_devices: false,
            },
            network: NetworkAccess {
                enabled: true,
                allowed_domains: Vec::new(), // all domains
                block_private: true,
                block_metadata: true,
            },
            resources: ResourceLimits {
                memory_mb: 1024,
                cpu_cores: 2.0,
                max_pids: 128,
                timeout_secs: 120,
                max_output_bytes: 4 * 1024 * 1024,
            },
            env_policy: EnvPolicy {
                clear_env: true,
                allowed_vars: vec![
                    "PATH".to_string(),
                    "HOME".to_string(),
                    "LANG".to_string(),
                    "TERM".to_string(),
                    "USER".to_string(),
                    "SHELL".to_string(),
                ],
                inject_vars: HashMap::new(),
            },
        }
    }

    fn unrestricted() -> Self {
        warn!("Creating unrestricted sandbox profile -- this significantly reduces isolation");
        Self {
            level: SandboxLevel::Unrestricted,
            name: "unrestricted".to_string(),
            filesystem: FilesystemAccess {
                read_only: false,
                writable_paths: vec!["/".to_string()],
                tmpfs_size_mb: 512,
                allow_devices: false,
            },
            network: NetworkAccess {
                enabled: true,
                allowed_domains: Vec::new(),
                block_private: false,
                block_metadata: true, // always block metadata
            },
            resources: ResourceLimits {
                memory_mb: 4096,
                cpu_cores: 4.0,
                max_pids: 512,
                timeout_secs: 600,
                max_output_bytes: 16 * 1024 * 1024,
            },
            env_policy: EnvPolicy {
                clear_env: false,
                allowed_vars: Vec::new(),
                inject_vars: HashMap::new(),
            },
        }
    }

    /// Merge a partial override into this profile.
    /// Non-default override values take precedence.
    pub fn merge_with(&mut self, overrides: &SandboxProfileOverride) {
        if let Some(mem) = overrides.memory_mb {
            self.resources.memory_mb = mem;
        }
        if let Some(cpu) = overrides.cpu_cores {
            self.resources.cpu_cores = cpu;
        }
        if let Some(pids) = overrides.max_pids {
            self.resources.max_pids = pids;
        }
        if let Some(timeout) = overrides.timeout_secs {
            self.resources.timeout_secs = timeout;
        }
        if let Some(network) = overrides.network_enabled {
            self.network.enabled = network;
        }
        if let Some(ref domains) = overrides.allowed_domains {
            self.network.allowed_domains = domains.clone();
        }
        if let Some(ref paths) = overrides.writable_paths {
            self.filesystem.writable_paths = paths.clone();
        }
        if let Some(tmpfs) = overrides.tmpfs_size_mb {
            self.filesystem.tmpfs_size_mb = tmpfs;
        }
        if let Some(ref vars) = overrides.extra_env_vars {
            for (k, v) in vars {
                self.env_policy.inject_vars.insert(k.clone(), v.clone());
            }
        }
    }

    /// Convert this profile to a SandboxConfig for use with existing backends.
    pub fn to_sandbox_config(&self, base: &SandboxConfig) -> SandboxConfig {
        SandboxConfig {
            backend: base.backend.clone(),
            image: base.image.clone(),
            enforce: base.enforce,
            seccomp: base.seccomp.clone(),
            network_policy: if self.network.enabled {
                "allow".to_string()
            } else {
                "deny".to_string()
            },
            memory_limit: self.resources.memory_mb,
            cpu_limit: self.resources.cpu_cores,
            pids_limit: self.resources.max_pids,
            tmpfs_size: self.filesystem.tmpfs_size_mb,
        }
    }
}

// ---------------------------------------------------------------------------
// Profile Override (for config merging)
// ---------------------------------------------------------------------------

/// Partial overrides that can be applied to any base profile.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SandboxProfileOverride {
    pub memory_mb: Option<u64>,
    pub cpu_cores: Option<f64>,
    pub max_pids: Option<u32>,
    pub timeout_secs: Option<u64>,
    pub network_enabled: Option<bool>,
    pub allowed_domains: Option<Vec<String>>,
    pub writable_paths: Option<Vec<String>>,
    pub tmpfs_size_mb: Option<u64>,
    pub extra_env_vars: Option<HashMap<String, String>>,
}

// ---------------------------------------------------------------------------
// Profile Resolver
// ---------------------------------------------------------------------------

/// Resolves sandbox profiles from config or named presets.
///
/// Resolution order:
/// 1. Look for a skill-specific profile in `skill_profiles`.
/// 2. Fall back to the named level preset.
/// 3. Apply any overrides from config.
pub struct SandboxProfileResolver {
    /// Per-skill level assignments.
    skill_levels: HashMap<String, SandboxLevel>,
    /// Per-skill overrides.
    skill_overrides: HashMap<String, SandboxProfileOverride>,
    /// Default level for skills without explicit assignment.
    default_level: SandboxLevel,
    /// Named custom profiles.
    custom_profiles: HashMap<String, SandboxProfile>,
}

impl SandboxProfileResolver {
    pub fn new(default_level: SandboxLevel) -> Self {
        Self {
            skill_levels: HashMap::new(),
            skill_overrides: HashMap::new(),
            default_level,
            custom_profiles: HashMap::new(),
        }
    }

    /// Build a resolver from config entries.
    pub fn from_config(entries: &[SandboxProfileEntry]) -> Self {
        let mut resolver = Self::new(SandboxLevel::Standard);

        for entry in entries {
            let level = SandboxLevel::from_str(&entry.level);

            if let Some(ref skill) = entry.skill {
                resolver.skill_levels.insert(skill.clone(), level);

                if entry.overrides != SandboxProfileOverride::default() {
                    resolver
                        .skill_overrides
                        .insert(skill.clone(), entry.overrides.clone());
                }
            }

            if entry.is_default {
                resolver.default_level = level;
            }
        }

        info!(
            default_level = %resolver.default_level,
            skill_profiles = resolver.skill_levels.len(),
            "Sandbox profile resolver initialized"
        );

        resolver
    }

    /// Resolve the profile for a given skill name.
    pub fn resolve(&self, skill_name: &str) -> SandboxProfile {
        let level = self
            .skill_levels
            .get(skill_name)
            .copied()
            .unwrap_or(self.default_level);

        let mut profile = if level == SandboxLevel::Custom {
            self.custom_profiles
                .get(skill_name)
                .cloned()
                .unwrap_or_else(|| SandboxProfile::preset(SandboxLevel::Standard))
        } else {
            SandboxProfile::preset(level)
        };

        if let Some(overrides) = self.skill_overrides.get(skill_name) {
            profile.merge_with(overrides);
        }

        info!(
            skill = %skill_name,
            level = %profile.level,
            memory_mb = profile.resources.memory_mb,
            network = profile.network.enabled,
            "Resolved sandbox profile"
        );

        profile
    }

    /// Resolve the default profile (no skill context).
    pub fn resolve_default(&self) -> SandboxProfile {
        SandboxProfile::preset(self.default_level)
    }

    /// Register a custom named profile.
    pub fn register_custom(&mut self, name: &str, profile: SandboxProfile) {
        self.custom_profiles.insert(name.to_string(), profile);
    }

    /// Set the level for a specific skill.
    pub fn set_skill_level(&mut self, skill: &str, level: SandboxLevel) {
        self.skill_levels.insert(skill.to_string(), level);
    }

    /// List all registered skill-level mappings.
    pub fn list_assignments(&self) -> Vec<(&str, SandboxLevel)> {
        self.skill_levels
            .iter()
            .map(|(k, v)| (k.as_str(), *v))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Config types
// ---------------------------------------------------------------------------

/// Configuration entry for sandbox profiles (deserialized from config file).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxProfileEntry {
    /// Isolation level: "minimal", "standard", "elevated", "unrestricted".
    #[serde(default = "default_standard")]
    pub level: String,

    /// Skill name this entry applies to (None = global default).
    pub skill: Option<String>,

    /// Whether this is the default profile.
    #[serde(default)]
    pub is_default: bool,

    /// Partial overrides applied on top of the base level.
    #[serde(default)]
    pub overrides: SandboxProfileOverride,
}

/// Configuration section for sandbox profiles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxProfilesConfig {
    /// Default isolation level.
    #[serde(default = "default_standard")]
    pub default_level: String,

    /// Per-skill profile entries.
    #[serde(default)]
    pub profiles: Vec<SandboxProfileEntry>,
}

impl Default for SandboxProfilesConfig {
    fn default() -> Self {
        Self {
            default_level: "standard".to_string(),
            profiles: Vec::new(),
        }
    }
}

fn default_standard() -> String {
    "standard".to_string()
}

// Implement PartialEq for SandboxProfileOverride to support comparison
impl PartialEq for SandboxProfileOverride {
    fn eq(&self, other: &Self) -> bool {
        self.memory_mb == other.memory_mb
            && self.cpu_cores.map(|f| f.to_bits()) == other.cpu_cores.map(|f| f.to_bits())
            && self.max_pids == other.max_pids
            && self.timeout_secs == other.timeout_secs
            && self.network_enabled == other.network_enabled
            && self.allowed_domains == other.allowed_domains
            && self.writable_paths == other.writable_paths
            && self.tmpfs_size_mb == other.tmpfs_size_mb
            && self.extra_env_vars == other.extra_env_vars
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandbox_level_from_str() {
        assert_eq!(SandboxLevel::from_str("minimal"), SandboxLevel::Minimal);
        assert_eq!(SandboxLevel::from_str("standard"), SandboxLevel::Standard);
        assert_eq!(SandboxLevel::from_str("elevated"), SandboxLevel::Elevated);
        assert_eq!(
            SandboxLevel::from_str("unrestricted"),
            SandboxLevel::Unrestricted
        );
        assert_eq!(SandboxLevel::from_str("anything_else"), SandboxLevel::Custom);
    }

    #[test]
    fn test_sandbox_level_display() {
        assert_eq!(SandboxLevel::Minimal.to_string(), "minimal");
        assert_eq!(SandboxLevel::Standard.to_string(), "standard");
        assert_eq!(SandboxLevel::Elevated.to_string(), "elevated");
        assert_eq!(SandboxLevel::Unrestricted.to_string(), "unrestricted");
        assert_eq!(SandboxLevel::Custom.to_string(), "custom");
    }

    #[test]
    fn test_minimal_profile() {
        let p = SandboxProfile::preset(SandboxLevel::Minimal);
        assert_eq!(p.level, SandboxLevel::Minimal);
        assert!(p.filesystem.read_only);
        assert!(!p.network.enabled);
        assert_eq!(p.resources.memory_mb, 128);
        assert_eq!(p.resources.max_pids, 16);
        assert_eq!(p.resources.timeout_secs, 10);
    }

    #[test]
    fn test_standard_profile() {
        let p = SandboxProfile::preset(SandboxLevel::Standard);
        assert_eq!(p.level, SandboxLevel::Standard);
        assert!(p.filesystem.read_only);
        assert!(!p.network.enabled);
        assert_eq!(p.resources.memory_mb, 256);
    }

    #[test]
    fn test_elevated_profile() {
        let p = SandboxProfile::preset(SandboxLevel::Elevated);
        assert_eq!(p.level, SandboxLevel::Elevated);
        assert!(p.network.enabled);
        assert!(p.network.block_private);
        assert_eq!(p.resources.memory_mb, 1024);
        assert_eq!(p.resources.cpu_cores, 2.0);
        assert!(p.filesystem.writable_paths.contains(&"/tmp".to_string()));
    }

    #[test]
    fn test_unrestricted_profile() {
        let p = SandboxProfile::preset(SandboxLevel::Unrestricted);
        assert_eq!(p.level, SandboxLevel::Unrestricted);
        assert!(!p.filesystem.read_only);
        assert!(p.network.enabled);
        assert!(!p.network.block_private);
        assert!(p.network.block_metadata); // always block metadata
        assert_eq!(p.resources.memory_mb, 4096);
    }

    #[test]
    fn test_merge_with_overrides() {
        let mut profile = SandboxProfile::preset(SandboxLevel::Standard);
        assert_eq!(profile.resources.memory_mb, 256);
        assert!(!profile.network.enabled);

        let overrides = SandboxProfileOverride {
            memory_mb: Some(512),
            network_enabled: Some(true),
            timeout_secs: Some(60),
            ..Default::default()
        };

        profile.merge_with(&overrides);
        assert_eq!(profile.resources.memory_mb, 512);
        assert!(profile.network.enabled);
        assert_eq!(profile.resources.timeout_secs, 60);
        // Unchanged fields remain the same
        assert_eq!(profile.resources.cpu_cores, 0.5);
    }

    #[test]
    fn test_resolver_default() {
        let resolver = SandboxProfileResolver::new(SandboxLevel::Standard);
        let profile = resolver.resolve("unknown_skill");
        assert_eq!(profile.level, SandboxLevel::Standard);
    }

    #[test]
    fn test_resolver_skill_specific() {
        let mut resolver = SandboxProfileResolver::new(SandboxLevel::Standard);
        resolver.set_skill_level("web_scraper", SandboxLevel::Elevated);
        resolver.set_skill_level("calculator", SandboxLevel::Minimal);

        let web_profile = resolver.resolve("web_scraper");
        assert_eq!(web_profile.level, SandboxLevel::Elevated);
        assert!(web_profile.network.enabled);

        let calc_profile = resolver.resolve("calculator");
        assert_eq!(calc_profile.level, SandboxLevel::Minimal);
        assert!(!calc_profile.network.enabled);
    }

    #[test]
    fn test_resolver_from_config() {
        let entries = vec![
            SandboxProfileEntry {
                level: "elevated".to_string(),
                skill: Some("browser".to_string()),
                is_default: false,
                overrides: SandboxProfileOverride::default(),
            },
            SandboxProfileEntry {
                level: "minimal".to_string(),
                skill: None,
                is_default: true,
                overrides: SandboxProfileOverride::default(),
            },
        ];

        let resolver = SandboxProfileResolver::from_config(&entries);

        // Default should be minimal
        let default_profile = resolver.resolve_default();
        assert_eq!(default_profile.level, SandboxLevel::Minimal);

        // browser skill should be elevated
        let browser_profile = resolver.resolve("browser");
        assert_eq!(browser_profile.level, SandboxLevel::Elevated);

        // unknown skill gets the default
        let unknown = resolver.resolve("unknown");
        assert_eq!(unknown.level, SandboxLevel::Minimal);
    }

    #[test]
    fn test_resolver_with_overrides() {
        let entries = vec![SandboxProfileEntry {
            level: "standard".to_string(),
            skill: Some("data_processor".to_string()),
            is_default: false,
            overrides: SandboxProfileOverride {
                memory_mb: Some(2048),
                timeout_secs: Some(300),
                ..Default::default()
            },
        }];

        let resolver = SandboxProfileResolver::from_config(&entries);
        let profile = resolver.resolve("data_processor");
        assert_eq!(profile.level, SandboxLevel::Standard);
        assert_eq!(profile.resources.memory_mb, 2048);
        assert_eq!(profile.resources.timeout_secs, 300);
        // Other standard defaults preserved
        assert_eq!(profile.resources.cpu_cores, 0.5);
    }

    #[test]
    fn test_to_sandbox_config() {
        let base = SandboxConfig::default();
        let profile = SandboxProfile::preset(SandboxLevel::Elevated);
        let config = profile.to_sandbox_config(&base);

        assert_eq!(config.network_policy, "allow");
        assert_eq!(config.memory_limit, 1024);
        assert_eq!(config.cpu_limit, 2.0);
    }

    #[test]
    fn test_list_assignments() {
        let mut resolver = SandboxProfileResolver::new(SandboxLevel::Standard);
        resolver.set_skill_level("a", SandboxLevel::Minimal);
        resolver.set_skill_level("b", SandboxLevel::Elevated);

        let assignments = resolver.list_assignments();
        assert_eq!(assignments.len(), 2);
    }

    #[test]
    fn test_profile_serialization() {
        let profile = SandboxProfile::preset(SandboxLevel::Standard);
        let json = serde_json::to_string(&profile).unwrap();
        assert!(json.contains("\"standard\""));

        let deser: SandboxProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.level, SandboxLevel::Standard);
        assert_eq!(deser.resources.memory_mb, 256);
    }

    #[test]
    fn test_env_policy_injection() {
        let mut profile = SandboxProfile::preset(SandboxLevel::Standard);
        let mut extra = HashMap::new();
        extra.insert("MY_VAR".to_string(), "value1".to_string());

        let overrides = SandboxProfileOverride {
            extra_env_vars: Some(extra),
            ..Default::default()
        };

        profile.merge_with(&overrides);
        assert_eq!(
            profile.env_policy.inject_vars.get("MY_VAR"),
            Some(&"value1".to_string())
        );
    }
}
