use anyhow::Result;
use async_trait::async_trait;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

// ---------------------------------------------------------------------------
// Plugin trait
// ---------------------------------------------------------------------------

/// Core trait that every IronClaw plugin must implement.
///
/// Lifecycle: `init()` is called once when the plugin is loaded, and
/// `shutdown()` is called when the plugin is unloaded or the host exits.
#[async_trait]
pub trait Plugin: Send + Sync {
    /// Unique human-readable name of the plugin.
    fn name(&self) -> &str;

    /// SemVer version string.
    fn version(&self) -> &str;

    /// Initialize the plugin. Called exactly once after loading.
    async fn init(&mut self) -> Result<()>;

    /// Gracefully shut down the plugin. Called before unloading.
    async fn shutdown(&mut self) -> Result<()>;

    /// Declare the set of capabilities this plugin provides.
    fn capabilities(&self) -> Vec<PluginCapability>;
}

/// A capability that a plugin exposes to the host runtime.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginCapability {
    /// Identifier such as `tool:git_commit` or `provider:ollama`.
    pub id: String,
    /// Short human-readable description.
    pub description: String,
}

// ---------------------------------------------------------------------------
// Plugin manifest
// ---------------------------------------------------------------------------

/// Manifest file shipped with every plugin package.  The manifest is read and
/// validated before the plugin binary or script is loaded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    /// Plugin name (must match `Plugin::name()`).
    pub name: String,
    /// SemVer version.
    pub version: String,
    /// Author / organisation.
    pub author: String,
    /// One-line description.
    pub description: String,
    /// Permissions the plugin requires to operate.
    pub permissions_required: Vec<PluginPermission>,
    /// Relative path to the entry point inside the plugin directory.
    pub entry_point: String,
    /// SHA-256 hex digest of the entry-point file.
    pub checksum: String,
    /// Optional minimum IronClaw version required.
    #[serde(default)]
    pub min_host_version: Option<String>,
    /// Where the plugin was obtained from.
    #[serde(default)]
    pub source: PluginSourceKind,
}

/// Granular permission a plugin may request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PluginPermission {
    /// Read files matching the given glob.
    FileRead(String),
    /// Write files matching the given glob.
    FileWrite(String),
    /// Make outbound network requests to the given domain.
    Network(String),
    /// Execute shell commands.
    ShellExec,
    /// Access environment variables.
    EnvAccess,
    /// Interact with the LLM provider on behalf of the user.
    LlmAccess,
}

impl std::fmt::Display for PluginPermission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FileRead(g) => write!(f, "file:read({})", g),
            Self::FileWrite(g) => write!(f, "file:write({})", g),
            Self::Network(d) => write!(f, "net:{}", d),
            Self::ShellExec => write!(f, "shell:exec"),
            Self::EnvAccess => write!(f, "env:access"),
            Self::LlmAccess => write!(f, "llm:access"),
        }
    }
}

/// Where the plugin was obtained from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PluginSourceKind {
    Local,
    GitRepository(String),
    Registry(String),
}

impl Default for PluginSourceKind {
    fn default() -> Self {
        Self::Local
    }
}

// ---------------------------------------------------------------------------
// Plugin lifecycle
// ---------------------------------------------------------------------------

/// Tracks the state of a plugin through its lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PluginState {
    /// Manifest discovered on disk / registry, not yet validated.
    Discovered,
    /// Manifest parsed and checksum verified.
    Validated,
    /// Entry point loaded into memory.
    Loaded,
    /// `init()` completed successfully; the plugin is serving.
    Active,
    /// `shutdown()` completed; ready for removal.
    Unloaded,
}

impl std::fmt::Display for PluginState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Discovered => write!(f, "discovered"),
            Self::Validated => write!(f, "validated"),
            Self::Loaded => write!(f, "loaded"),
            Self::Active => write!(f, "active"),
            Self::Unloaded => write!(f, "unloaded"),
        }
    }
}

/// Internal bookkeeping for a managed plugin.
struct ManagedPlugin {
    manifest: PluginManifest,
    state: PluginState,
    path: PathBuf,
    instance: Option<Box<dyn Plugin>>,
}

// ---------------------------------------------------------------------------
// Sandbox context  --  restricts what a plugin can do at runtime
// ---------------------------------------------------------------------------

/// A restricted execution context for plugins.  The host checks every
/// operation the plugin attempts against its declared permissions.
pub struct PluginSandbox {
    allowed_permissions: Vec<PluginPermission>,
}

impl PluginSandbox {
    pub fn new(permissions: Vec<PluginPermission>) -> Self {
        Self {
            allowed_permissions: permissions,
        }
    }

    /// Returns `true` if the given permission is granted.
    pub fn check(&self, requested: &PluginPermission) -> bool {
        self.allowed_permissions.contains(requested)
    }

    /// Sanitize output from a plugin: strip ANSI control codes, limit length,
    /// and remove null bytes.
    pub fn sanitize_output(raw: &str) -> String {
        let stripped = strip_ansi_codes(raw);
        let without_nulls: String = stripped.chars().filter(|c| *c != '\0').collect();
        // Limit to 1 MiB of output
        const MAX_OUTPUT: usize = 1_048_576;
        if without_nulls.len() > MAX_OUTPUT {
            without_nulls[..MAX_OUTPUT].to_string()
        } else {
            without_nulls
        }
    }
}

/// Naively strip common ANSI escape sequences.
fn strip_ansi_codes(input: &str) -> String {
    let re = regex::Regex::new(r"\x1b\[[0-9;]*[a-zA-Z]").unwrap();
    re.replace_all(input, "").to_string()
}

// ---------------------------------------------------------------------------
// PluginManager  --  the main orchestrator
// ---------------------------------------------------------------------------

/// Manages the full lifecycle of IronClaw plugins: discovery, validation,
/// loading, unloading, and hot-reload.
pub struct PluginManager {
    plugins: RwLock<HashMap<String, ManagedPlugin>>,
    plugin_dirs: Vec<PathBuf>,
    allowed_permissions: Vec<PluginPermission>,
}

impl PluginManager {
    /// Create a new `PluginManager` that scans the given directories.
    pub fn new(plugin_dirs: Vec<PathBuf>, allowed_permissions: Vec<PluginPermission>) -> Self {
        info!(
            dirs = ?plugin_dirs,
            allowed_perms = allowed_permissions.len(),
            "Plugin manager initialized"
        );
        Self {
            plugins: RwLock::new(HashMap::new()),
            plugin_dirs,
            allowed_permissions,
        }
    }

    // ----- Discovery -----

    /// Scan all configured directories for plugin manifests.
    pub fn discover(&self) -> Result<Vec<String>> {
        let mut discovered = Vec::new();

        for dir in &self.plugin_dirs {
            if !dir.exists() {
                debug!(dir = %dir.display(), "Plugin directory does not exist, skipping");
                continue;
            }

            for entry in std::fs::read_dir(dir)? {
                let entry = entry?;
                if !entry.file_type()?.is_dir() {
                    continue;
                }

                let manifest_path = entry.path().join("plugin.json");
                if !manifest_path.exists() {
                    continue;
                }

                match std::fs::read_to_string(&manifest_path) {
                    Ok(raw) => match serde_json::from_str::<PluginManifest>(&raw) {
                        Ok(manifest) => {
                            let name = manifest.name.clone();
                            let mut plugins = self.plugins.write();
                            plugins.insert(
                                name.clone(),
                                ManagedPlugin {
                                    manifest,
                                    state: PluginState::Discovered,
                                    path: entry.path(),
                                    instance: None,
                                },
                            );
                            discovered.push(name);
                        }
                        Err(e) => {
                            warn!(
                                path = %manifest_path.display(),
                                error = %e,
                                "Invalid plugin manifest"
                            );
                        }
                    },
                    Err(e) => {
                        warn!(
                            path = %manifest_path.display(),
                            error = %e,
                            "Could not read plugin manifest"
                        );
                    }
                }
            }
        }

        info!(count = discovered.len(), "Plugin discovery complete");
        Ok(discovered)
    }

    // ----- Validation -----

    /// Validate a discovered plugin: checksum verification, permission check,
    /// and path-traversal guard.
    pub fn validate(&self, name: &str) -> Result<()> {
        let mut plugins = self.plugins.write();
        let managed = plugins
            .get_mut(name)
            .ok_or_else(|| anyhow::anyhow!("Plugin '{}' not found", name))?;

        if managed.state != PluginState::Discovered {
            anyhow::bail!(
                "Plugin '{}' is in state '{}', expected 'discovered'",
                name,
                managed.state
            );
        }

        // 1. Path-traversal guard on entry_point
        let entry_path = managed.path.join(&managed.manifest.entry_point);
        let canonical_dir = std::fs::canonicalize(&managed.path)?;
        let canonical_entry = std::fs::canonicalize(&entry_path)
            .map_err(|_| anyhow::anyhow!("Entry point does not exist: {}", entry_path.display()))?;
        if !canonical_entry.starts_with(&canonical_dir) {
            anyhow::bail!(
                "Plugin '{}' entry point escapes plugin directory (path traversal)",
                name
            );
        }

        // 2. Checksum verification (SHA-256)
        let content = std::fs::read(&canonical_entry)?;
        let mut hasher = Sha256::new();
        hasher.update(&content);
        let computed = hex::encode(hasher.finalize());
        if computed != managed.manifest.checksum {
            anyhow::bail!(
                "Plugin '{}' checksum mismatch: expected {}, computed {}",
                name,
                managed.manifest.checksum,
                computed
            );
        }

        // 3. Permission check -- every requested permission must be allowed
        for perm in &managed.manifest.permissions_required {
            if !self.allowed_permissions.contains(perm) {
                anyhow::bail!(
                    "Plugin '{}' requests disallowed permission: {}",
                    name,
                    perm
                );
            }
        }

        managed.state = PluginState::Validated;
        info!(plugin = %name, "Plugin validated");
        Ok(())
    }

    // ----- Loading -----

    /// Load a validated plugin by instantiating its `Plugin` implementation.
    ///
    /// The caller must provide a factory that turns a path into a boxed `Plugin`
    /// because the concrete loading strategy (dylib, WASM, subprocess) is
    /// host-specific.
    pub fn load<F>(&self, name: &str, factory: F) -> Result<()>
    where
        F: FnOnce(&Path, &PluginManifest) -> Result<Box<dyn Plugin>>,
    {
        let mut plugins = self.plugins.write();
        let managed = plugins
            .get_mut(name)
            .ok_or_else(|| anyhow::anyhow!("Plugin '{}' not found", name))?;

        if managed.state != PluginState::Validated {
            anyhow::bail!(
                "Plugin '{}' must be validated before loading (current: {})",
                name,
                managed.state
            );
        }

        let instance = factory(&managed.path, &managed.manifest)?;
        managed.instance = Some(instance);
        managed.state = PluginState::Loaded;
        info!(plugin = %name, "Plugin loaded");
        Ok(())
    }

    /// Activate a loaded plugin by calling its `init()` method.
    pub async fn activate(&self, name: &str) -> Result<()> {
        // Take the instance out so we can call async init without holding the lock.
        let mut instance = {
            let mut plugins = self.plugins.write();
            let managed = plugins
                .get_mut(name)
                .ok_or_else(|| anyhow::anyhow!("Plugin '{}' not found", name))?;

            if managed.state != PluginState::Loaded {
                anyhow::bail!(
                    "Plugin '{}' must be loaded before activation (current: {})",
                    name,
                    managed.state
                );
            }

            managed
                .instance
                .take()
                .ok_or_else(|| anyhow::anyhow!("Plugin '{}' has no instance", name))?
        };

        // Call init outside the lock
        instance.init().await?;

        // Put it back and mark active
        {
            let mut plugins = self.plugins.write();
            if let Some(managed) = plugins.get_mut(name) {
                managed.instance = Some(instance);
                managed.state = PluginState::Active;
            }
        }

        info!(plugin = %name, "Plugin activated");
        Ok(())
    }

    // ----- Unloading -----

    /// Shut down and unload an active plugin.
    pub async fn unload(&self, name: &str) -> Result<()> {
        let mut instance = {
            let mut plugins = self.plugins.write();
            let managed = plugins
                .get_mut(name)
                .ok_or_else(|| anyhow::anyhow!("Plugin '{}' not found", name))?;

            if managed.state != PluginState::Active {
                anyhow::bail!(
                    "Plugin '{}' is not active (current: {})",
                    name,
                    managed.state
                );
            }

            managed
                .instance
                .take()
                .ok_or_else(|| anyhow::anyhow!("Plugin '{}' has no instance", name))?
        };

        instance.shutdown().await?;

        {
            let mut plugins = self.plugins.write();
            if let Some(managed) = plugins.get_mut(name) {
                managed.state = PluginState::Unloaded;
            }
        }

        info!(plugin = %name, "Plugin unloaded");
        Ok(())
    }

    // ----- Hot reload -----

    /// Hot-reload a plugin: unload the current instance, re-validate, re-load,
    /// and re-activate without restarting the host.
    pub async fn hot_reload<F>(&self, name: &str, factory: F) -> Result<()>
    where
        F: FnOnce(&Path, &PluginManifest) -> Result<Box<dyn Plugin>>,
    {
        info!(plugin = %name, "Hot-reloading plugin");

        // If the plugin is active, shut it down first
        {
            let plugins = self.plugins.read();
            if let Some(managed) = plugins.get(name) {
                if managed.state == PluginState::Active {
                    drop(plugins); // release read lock before async call
                    self.unload(name).await?;
                }
            }
        }

        // Reset state to Discovered so we can re-validate
        {
            let mut plugins = self.plugins.write();
            if let Some(managed) = plugins.get_mut(name) {
                managed.state = PluginState::Discovered;
            }
        }

        self.validate(name)?;
        self.load(name, factory)?;
        self.activate(name).await?;

        info!(plugin = %name, "Hot-reload complete");
        Ok(())
    }

    // ----- Queries -----

    /// List all known plugins with their current state.
    pub fn list(&self) -> Vec<(String, PluginState)> {
        let plugins = self.plugins.read();
        plugins
            .iter()
            .map(|(name, managed)| (name.clone(), managed.state))
            .collect()
    }

    /// Get a reference to a plugin manifest by name.
    pub fn get_manifest(&self, name: &str) -> Option<PluginManifest> {
        let plugins = self.plugins.read();
        plugins.get(name).map(|m| m.manifest.clone())
    }

    /// Get the current state of a plugin.
    pub fn get_state(&self, name: &str) -> Option<PluginState> {
        let plugins = self.plugins.read();
        plugins.get(name).map(|m| m.state)
    }

    /// Total number of managed plugins.
    pub fn count(&self) -> usize {
        self.plugins.read().len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_permission_display() {
        assert_eq!(
            PluginPermission::FileRead("*.rs".into()).to_string(),
            "file:read(*.rs)"
        );
        assert_eq!(
            PluginPermission::Network("api.example.com".into()).to_string(),
            "net:api.example.com"
        );
        assert_eq!(PluginPermission::ShellExec.to_string(), "shell:exec");
        assert_eq!(PluginPermission::EnvAccess.to_string(), "env:access");
        assert_eq!(PluginPermission::LlmAccess.to_string(), "llm:access");
    }

    #[test]
    fn test_plugin_state_display() {
        assert_eq!(PluginState::Discovered.to_string(), "discovered");
        assert_eq!(PluginState::Validated.to_string(), "validated");
        assert_eq!(PluginState::Loaded.to_string(), "loaded");
        assert_eq!(PluginState::Active.to_string(), "active");
        assert_eq!(PluginState::Unloaded.to_string(), "unloaded");
    }

    #[test]
    fn test_sandbox_check() {
        let sandbox = PluginSandbox::new(vec![
            PluginPermission::FileRead("*.rs".into()),
            PluginPermission::LlmAccess,
        ]);

        assert!(sandbox.check(&PluginPermission::FileRead("*.rs".into())));
        assert!(sandbox.check(&PluginPermission::LlmAccess));
        assert!(!sandbox.check(&PluginPermission::ShellExec));
        assert!(!sandbox.check(&PluginPermission::EnvAccess));
    }

    #[test]
    fn test_sanitize_output() {
        // Strip ANSI codes
        let raw = "\x1b[31mERROR\x1b[0m: something failed";
        let clean = PluginSandbox::sanitize_output(raw);
        assert_eq!(clean, "ERROR: something failed");

        // Remove null bytes
        let raw_null = "hello\0world";
        let clean_null = PluginSandbox::sanitize_output(raw_null);
        assert_eq!(clean_null, "helloworld");
    }

    #[test]
    fn test_sanitize_output_length_limit() {
        let huge = "A".repeat(2_000_000);
        let clean = PluginSandbox::sanitize_output(&huge);
        assert_eq!(clean.len(), 1_048_576);
    }

    #[test]
    fn test_plugin_manager_empty() {
        let mgr = PluginManager::new(vec![], vec![]);
        assert_eq!(mgr.count(), 0);
        assert!(mgr.list().is_empty());
        assert!(mgr.get_manifest("nonexistent").is_none());
        assert!(mgr.get_state("nonexistent").is_none());
    }

    #[test]
    fn test_plugin_manager_discover_missing_dir() {
        let mgr = PluginManager::new(
            vec![PathBuf::from("/tmp/ironclaw_nonexistent_plugin_dir")],
            vec![],
        );
        let result = mgr.discover().unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_manifest_deserialization() {
        let json = r#"{
            "name": "test-plugin",
            "version": "1.0.0",
            "author": "Test Author",
            "description": "A test plugin",
            "permissions_required": ["ShellExec", "EnvAccess"],
            "entry_point": "main.wasm",
            "checksum": "abc123"
        }"#;
        let manifest: PluginManifest = serde_json::from_str(json).unwrap();
        assert_eq!(manifest.name, "test-plugin");
        assert_eq!(manifest.version, "1.0.0");
        assert_eq!(manifest.permissions_required.len(), 2);
        assert_eq!(manifest.entry_point, "main.wasm");
    }

    #[test]
    fn test_source_kind_default() {
        assert_eq!(PluginSourceKind::default(), PluginSourceKind::Local);
    }

    #[test]
    fn test_strip_ansi_codes() {
        let input = "\x1b[1;32mOK\x1b[0m done";
        assert_eq!(strip_ansi_codes(input), "OK done");
    }
}
