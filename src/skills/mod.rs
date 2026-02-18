pub mod community;
pub mod scanner;

use anyhow::Result;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use regex::Regex;
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

use crate::core::config::SkillsConfig;

// Re-export scanner types for convenience
pub use scanner::{ScanFinding, ScanReport, ScanRecommendation, ScanSeverity, SkillScanner};

// ---------------------------------------------------------------------------
// Skill manifest and metadata
// ---------------------------------------------------------------------------

/// Manifest describing a skill's identity, content hash, and signature.
#[derive(Debug, Clone, Serialize)]
pub struct SkillManifest {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub content_hash: String,
    pub signature: Option<String>,
    pub entry_point: String,
    /// Source this skill was discovered from.
    #[serde(default)]
    pub source: SkillSource,
    /// Permissions the skill requires.
    #[serde(default)]
    pub permissions: Vec<String>,
    /// Tags for categorization and search.
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Where a skill was discovered / loaded from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SkillSource {
    /// Local filesystem directory.
    Local,
    /// OpenClaw npm-based skill registry.
    OpenClaw,
    /// ZeroClaw Rust-based skill registry.
    ZeroClaw,
    /// Custom third-party registry.
    Custom(String),
}

impl Default for SkillSource {
    fn default() -> Self {
        Self::Local
    }
}

impl std::fmt::Display for SkillSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SkillSource::Local => write!(f, "local"),
            SkillSource::OpenClaw => write!(f, "openclaw"),
            SkillSource::ZeroClaw => write!(f, "zeroclaw"),
            SkillSource::Custom(name) => write!(f, "custom:{}", name),
        }
    }
}

// ---------------------------------------------------------------------------
// Signature verification result
// ---------------------------------------------------------------------------

/// Outcome of verifying a skill's cryptographic signature.
#[derive(Debug)]
pub enum VerifyResult {
    /// Signature is valid and from a trusted key.
    Valid,
    /// Skill is unsigned (permitted when `require_signatures` is false).
    Unsigned,
    /// Content hash does not match manifest.
    HashMismatch { expected: String, computed: String },
    /// No signature present but one is required.
    MissingSignature,
    /// Signature format is invalid.
    InvalidSignature(String),
    /// Signature is valid but not from any trusted key.
    UntrustedSignature,
}

// ---------------------------------------------------------------------------
// SkillVerifier  --  Ed25519 + SHA-256 verification
// ---------------------------------------------------------------------------

/// Verifies skill integrity with SHA-256 content hashing and Ed25519 signatures.
///
/// Verification pipeline:
/// 1. Compute SHA-256 of the skill content bytes.
/// 2. Compare against the hash declared in the manifest.
/// 3. If signatures are required, decode the Ed25519 signature.
/// 4. Verify the signature against every trusted public key.
///
/// This prevents tampered skills, unauthorized injection, and supply-chain attacks.
pub struct SkillVerifier {
    require_signatures: bool,
    trusted_keys: Vec<VerifyingKey>,
}

impl SkillVerifier {
    pub fn new(config: &SkillsConfig) -> Result<Self> {
        let mut trusted_keys = Vec::new();

        for key_hex in &config.trusted_keys {
            let key_bytes = hex::decode(key_hex)
                .map_err(|e| anyhow::anyhow!("Invalid trusted key hex: {}", e))?;

            if key_bytes.len() != 32 {
                anyhow::bail!(
                    "Invalid Ed25519 public key length: expected 32, got {}",
                    key_bytes.len()
                );
            }

            let mut key_array = [0u8; 32];
            key_array.copy_from_slice(&key_bytes);

            let verifying_key = VerifyingKey::from_bytes(&key_array)
                .map_err(|e| anyhow::anyhow!("Invalid Ed25519 public key: {}", e))?;

            trusted_keys.push(verifying_key);
        }

        info!(
            require_signatures = config.require_signatures,
            trusted_keys = trusted_keys.len(),
            "Skill verifier initialized"
        );

        Ok(Self {
            require_signatures: config.require_signatures,
            trusted_keys,
        })
    }

    /// Compute the SHA-256 hash of raw content and return it hex-encoded.
    pub fn hash_content(content: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content);
        hex::encode(hasher.finalize())
    }

    /// Verify a skill against its manifest.
    pub fn verify_skill(&self, manifest: &SkillManifest, content: &[u8]) -> Result<VerifyResult> {
        // Step 1: Verify content hash matches
        let computed_hash = Self::hash_content(content);
        if computed_hash != manifest.content_hash {
            return Ok(VerifyResult::HashMismatch {
                expected: manifest.content_hash.clone(),
                computed: computed_hash,
            });
        }

        // Step 2: If signatures not required, accept as unsigned
        if !self.require_signatures {
            warn!(
                skill = %manifest.name,
                "Signature verification disabled -- skill loaded without verification"
            );
            return Ok(VerifyResult::Unsigned);
        }

        // Step 3: Require the signature field
        let signature_hex = match &manifest.signature {
            Some(sig) => sig,
            None => {
                return Ok(VerifyResult::MissingSignature);
            }
        };

        // Step 4: Decode the signature bytes
        let signature_bytes = hex::decode(signature_hex)
            .map_err(|e| anyhow::anyhow!("Invalid signature hex: {}", e))?;

        if signature_bytes.len() != 64 {
            return Ok(VerifyResult::InvalidSignature(
                "Signature must be 64 bytes".to_string(),
            ));
        }

        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid Ed25519 signature: {}", e))?;

        // Step 5: Check against every trusted public key
        let hash_bytes = hex::decode(&computed_hash)?;
        for key in &self.trusted_keys {
            if key.verify(&hash_bytes, &signature).is_ok() {
                info!(skill = %manifest.name, "Skill signature verified successfully");
                return Ok(VerifyResult::Valid);
            }
        }

        Ok(VerifyResult::UntrustedSignature)
    }

    /// Load a skill manifest from disk and verify its content.
    pub fn load_skill(&self, path: &Path) -> Result<SkillManifest> {
        let manifest_path = path.join("skill.yaml");
        if !manifest_path.exists() {
            anyhow::bail!("Skill manifest not found: {}", manifest_path.display());
        }

        let manifest_content = std::fs::read_to_string(&manifest_path)?;
        let manifest: SkillManifest = serde_yaml::from_str(&manifest_content)?;

        // Read the skill entry point
        let entry_path = path.join(&manifest.entry_point);
        if !entry_path.exists() {
            anyhow::bail!("Skill entry point not found: {}", entry_path.display());
        }

        // Prevent path traversal
        let canonical_dir = std::fs::canonicalize(path)?;
        let canonical_entry = std::fs::canonicalize(&entry_path)?;
        if !canonical_entry.starts_with(&canonical_dir) {
            anyhow::bail!("Skill entry point escapes skill directory (path traversal detected)");
        }

        let content = std::fs::read(&entry_path)?;
        let verify_result = self.verify_skill(&manifest, &content)?;

        match verify_result {
            VerifyResult::Valid | VerifyResult::Unsigned => Ok(manifest),
            VerifyResult::HashMismatch { expected, computed } => {
                anyhow::bail!(
                    "Skill content hash mismatch: expected {}, computed {}",
                    expected,
                    computed
                );
            }
            VerifyResult::MissingSignature => {
                anyhow::bail!(
                    "Skill '{}' has no signature and signatures are required",
                    manifest.name
                );
            }
            VerifyResult::InvalidSignature(reason) => {
                anyhow::bail!("Skill '{}' has invalid signature: {}", manifest.name, reason);
            }
            VerifyResult::UntrustedSignature => {
                anyhow::bail!("Skill '{}' is signed with an untrusted key", manifest.name);
            }
        }
    }

    /// List skill names in a local directory.
    pub fn list_skills(dir: &Path) -> Result<Vec<String>> {
        if !dir.exists() {
            return Ok(Vec::new());
        }

        let mut skills = Vec::new();
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                let manifest_path = entry.path().join("skill.yaml");
                if manifest_path.exists() {
                    if let Some(name) = entry.file_name().to_str() {
                        skills.push(name.to_string());
                    }
                }
            }
        }

        Ok(skills)
    }
}

// ---------------------------------------------------------------------------
// SkillLoader  --  load and validate skills before registration
// ---------------------------------------------------------------------------

/// Loads skill content from disk and runs security checks before handing
/// skills to the registry.
pub struct SkillLoader {
    verifier: SkillVerifier,
    scanner: SkillScanner,
}

impl SkillLoader {
    pub fn new(config: &SkillsConfig) -> Result<Self> {
        let verifier = SkillVerifier::new(config)?;
        let scanner = SkillScanner::new()?;
        Ok(Self { verifier, scanner })
    }

    /// Load and fully validate a skill from a directory.
    ///
    /// Returns the manifest together with the scan report so the caller can
    /// decide whether to proceed.
    pub fn load(&self, path: &Path) -> Result<(SkillManifest, ScanReport)> {
        info!(path = %path.display(), "Loading skill");

        // Step 1: Verify manifest + signature
        let manifest = self.verifier.load_skill(path)?;

        // Step 2: Read entry-point source for static analysis
        let entry_path = path.join(&manifest.entry_point);
        let source = std::fs::read_to_string(&entry_path)?;

        // Step 3: Run the static scanner
        let report = self.scanner.scan_source(&source, &manifest.entry_point);

        if self.scanner.should_block(&report) {
            anyhow::bail!(
                "Skill '{}' blocked by scanner: risk_score={}, recommendation={}",
                manifest.name,
                report.risk_score,
                report.recommendation
            );
        }

        info!(
            skill = %manifest.name,
            risk_score = report.risk_score,
            recommendation = %report.recommendation,
            "Skill loaded and validated"
        );

        Ok((manifest, report))
    }

    /// Convenience: load but only return the manifest (for simple callers).
    pub fn load_manifest(&self, path: &Path) -> Result<SkillManifest> {
        let (manifest, _) = self.load(path)?;
        Ok(manifest)
    }
}

// ---------------------------------------------------------------------------
// SkillRegistry  --  multi-source skill discovery and management
// ---------------------------------------------------------------------------

/// Registered skill entry with metadata.
#[derive(Debug, Clone)]
pub struct RegisteredSkill {
    pub manifest: SkillManifest,
    pub path: PathBuf,
    pub scan_report: Option<ScanReport>,
    pub active: bool,
}

/// Adapter trait for external skill sources (OpenClaw, ZeroClaw, custom).
pub trait SkillSourceAdapter: Send + Sync {
    /// Human-readable name of this source.
    fn name(&self) -> &str;

    /// Discover available skills from this source.
    fn discover(&self) -> Result<Vec<SkillManifest>>;

    /// Download / fetch a skill by name into the given local directory.
    fn fetch(&self, skill_name: &str, dest: &Path) -> Result<PathBuf>;
}

/// OpenClaw adapter -- discovers and fetches skills from an npm-based registry.
pub struct OpenClawAdapter {
    registry_url: String,
}

impl OpenClawAdapter {
    pub fn new(registry_url: &str) -> Self {
        Self {
            registry_url: registry_url.to_string(),
        }
    }
}

impl SkillSourceAdapter for OpenClawAdapter {
    fn name(&self) -> &str {
        "openclaw"
    }

    fn discover(&self) -> Result<Vec<SkillManifest>> {
        // In production this would query the npm-compatible registry at
        // self.registry_url for packages tagged `ironclaw-skill`.
        debug!(registry = %self.registry_url, "Querying OpenClaw registry");
        Ok(Vec::new())
    }

    fn fetch(&self, skill_name: &str, dest: &Path) -> Result<PathBuf> {
        let target = dest.join(skill_name);
        info!(
            skill = %skill_name,
            registry = %self.registry_url,
            dest = %target.display(),
            "Fetching OpenClaw skill (npm adapter)"
        );
        // Stub: would run `npm pack` or fetch the tarball and extract.
        Ok(target)
    }
}

/// ZeroClaw adapter -- discovers and fetches Rust-native skills.
pub struct ZeroClawAdapter {
    index_url: String,
}

impl ZeroClawAdapter {
    pub fn new(index_url: &str) -> Self {
        Self {
            index_url: index_url.to_string(),
        }
    }
}

impl SkillSourceAdapter for ZeroClawAdapter {
    fn name(&self) -> &str {
        "zeroclaw"
    }

    fn discover(&self) -> Result<Vec<SkillManifest>> {
        debug!(index = %self.index_url, "Querying ZeroClaw index");
        Ok(Vec::new())
    }

    fn fetch(&self, skill_name: &str, dest: &Path) -> Result<PathBuf> {
        let target = dest.join(skill_name);
        info!(
            skill = %skill_name,
            index = %self.index_url,
            dest = %target.display(),
            "Fetching ZeroClaw skill (Rust adapter)"
        );
        Ok(target)
    }
}

/// Central skill registry that aggregates multiple sources.
pub struct SkillRegistry {
    local_dir: PathBuf,
    skills: HashMap<String, RegisteredSkill>,
    loader: SkillLoader,
    adapters: Vec<Box<dyn SkillSourceAdapter>>,
}

impl SkillRegistry {
    /// Create a new registry rooted at the given local directory.
    pub fn new(config: &SkillsConfig) -> Result<Self> {
        let local_dir = PathBuf::from(shellexpand(&config.directory));
        let loader = SkillLoader::new(config)?;

        let mut adapters: Vec<Box<dyn SkillSourceAdapter>> = Vec::new();

        // Automatically register the OpenClaw adapter if a registry URL is set.
        if let Some(ref url) = config.registry_url {
            adapters.push(Box::new(OpenClawAdapter::new(url)));
        }

        info!(
            local_dir = %local_dir.display(),
            adapters = adapters.len(),
            "Skill registry initialized"
        );

        Ok(Self {
            local_dir,
            skills: HashMap::new(),
            loader,
            adapters,
        })
    }

    /// Register an external skill source adapter.
    pub fn add_adapter(&mut self, adapter: Box<dyn SkillSourceAdapter>) {
        info!(adapter = adapter.name(), "Registered skill source adapter");
        self.adapters.push(adapter);
    }

    /// Discover skills from all sources (local directory + adapters).
    pub fn discover(&mut self) -> Result<Vec<String>> {
        let mut discovered = Vec::new();

        // 1. Local directory
        if self.local_dir.exists() {
            let local_skills = SkillVerifier::list_skills(&self.local_dir)?;
            for name in &local_skills {
                let skill_path = self.local_dir.join(name);
                match self.loader.load(&skill_path) {
                    Ok((manifest, report)) => {
                        self.skills.insert(
                            manifest.name.clone(),
                            RegisteredSkill {
                                manifest,
                                path: skill_path,
                                scan_report: Some(report),
                                active: true,
                            },
                        );
                        discovered.push(name.clone());
                    }
                    Err(e) => {
                        warn!(skill = %name, error = %e, "Skipping local skill");
                    }
                }
            }
        }

        // 2. External adapters
        for adapter in &self.adapters {
            match adapter.discover() {
                Ok(manifests) => {
                    for manifest in manifests {
                        discovered.push(manifest.name.clone());
                        self.skills.insert(
                            manifest.name.clone(),
                            RegisteredSkill {
                                path: self.local_dir.join(&manifest.name),
                                manifest,
                                scan_report: None,
                                active: false,
                            },
                        );
                    }
                }
                Err(e) => {
                    warn!(
                        adapter = adapter.name(),
                        error = %e,
                        "Failed to discover skills from adapter"
                    );
                }
            }
        }

        info!(total = discovered.len(), "Skill discovery complete");
        Ok(discovered)
    }

    /// Install a skill from the first adapter that has it.
    pub fn install(&mut self, skill_name: &str) -> Result<()> {
        for adapter in &self.adapters {
            match adapter.fetch(skill_name, &self.local_dir) {
                Ok(path) => {
                    let (manifest, report) = self.loader.load(&path)?;
                    self.skills.insert(
                        manifest.name.clone(),
                        RegisteredSkill {
                            manifest,
                            path,
                            scan_report: Some(report),
                            active: true,
                        },
                    );
                    info!(skill = %skill_name, "Skill installed successfully");
                    return Ok(());
                }
                Err(e) => {
                    debug!(
                        adapter = adapter.name(),
                        skill = %skill_name,
                        error = %e,
                        "Adapter could not fetch skill, trying next"
                    );
                }
            }
        }

        anyhow::bail!("Skill '{}' not found in any registered source", skill_name);
    }

    /// Get a registered skill by name.
    pub fn get(&self, name: &str) -> Option<&RegisteredSkill> {
        self.skills.get(name)
    }

    /// List all registered skill names.
    pub fn list(&self) -> Vec<&str> {
        self.skills.keys().map(|s| s.as_str()).collect()
    }

    /// Number of registered skills.
    pub fn count(&self) -> usize {
        self.skills.len()
    }
}

// ---------------------------------------------------------------------------
// Deserialization for SkillManifest
// ---------------------------------------------------------------------------

impl<'de> Deserialize<'de> for SkillManifest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Raw {
            name: String,
            version: String,
            description: String,
            author: String,
            content_hash: String,
            signature: Option<String>,
            entry_point: String,
            #[serde(default)]
            source: Option<String>,
            #[serde(default)]
            permissions: Vec<String>,
            #[serde(default)]
            tags: Vec<String>,
        }

        let raw = Raw::deserialize(deserializer)?;

        let source = match raw.source.as_deref() {
            Some("openclaw") => SkillSource::OpenClaw,
            Some("zeroclaw") => SkillSource::ZeroClaw,
            Some(other) => SkillSource::Custom(other.to_string()),
            None => SkillSource::Local,
        };

        Ok(SkillManifest {
            name: raw.name,
            version: raw.version,
            description: raw.description,
            author: raw.author,
            content_hash: raw.content_hash,
            signature: raw.signature,
            entry_point: raw.entry_point,
            source,
            permissions: raw.permissions,
            tags: raw.tags,
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn shellexpand(path: &str) -> String {
    if path.starts_with("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return path.replacen("~", &home, 1);
        }
    }
    path.to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_content() {
        let hash = SkillVerifier::hash_content(b"hello world");
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_verify_hash_mismatch() {
        let config = SkillsConfig {
            directory: "/tmp".to_string(),
            require_signatures: false,
            trusted_keys: vec![],
            registry_url: None,
            auto_update: false,
            sources: vec![],
        };
        let verifier = SkillVerifier::new(&config).unwrap();

        let manifest = SkillManifest {
            name: "test".to_string(),
            version: "1.0".to_string(),
            description: "test skill".to_string(),
            author: "test".to_string(),
            content_hash: "wrong_hash".to_string(),
            signature: None,
            entry_point: "main.py".to_string(),
            source: SkillSource::Local,
            permissions: vec![],
            tags: vec![],
        };

        let result = verifier.verify_skill(&manifest, b"hello world").unwrap();
        assert!(matches!(result, VerifyResult::HashMismatch { .. }));
    }

    #[test]
    fn test_verify_unsigned_when_not_required() {
        let config = SkillsConfig {
            directory: "/tmp".to_string(),
            require_signatures: false,
            trusted_keys: vec![],
            registry_url: None,
            auto_update: false,
            sources: vec![],
        };
        let verifier = SkillVerifier::new(&config).unwrap();

        let content = b"hello world";
        let hash = SkillVerifier::hash_content(content);

        let manifest = SkillManifest {
            name: "test".to_string(),
            version: "1.0".to_string(),
            description: "test skill".to_string(),
            author: "test".to_string(),
            content_hash: hash,
            signature: None,
            entry_point: "main.py".to_string(),
            source: SkillSource::Local,
            permissions: vec![],
            tags: vec![],
        };

        let result = verifier.verify_skill(&manifest, content).unwrap();
        assert!(matches!(result, VerifyResult::Unsigned));
    }

    #[test]
    fn test_missing_signature_when_required() {
        let config = SkillsConfig {
            directory: "/tmp".to_string(),
            require_signatures: true,
            trusted_keys: vec![],
            registry_url: None,
            auto_update: false,
            sources: vec![],
        };
        let verifier = SkillVerifier::new(&config).unwrap();

        let content = b"hello world";
        let hash = SkillVerifier::hash_content(content);

        let manifest = SkillManifest {
            name: "test".to_string(),
            version: "1.0".to_string(),
            description: "test skill".to_string(),
            author: "test".to_string(),
            content_hash: hash,
            signature: None,
            entry_point: "main.py".to_string(),
            source: SkillSource::Local,
            permissions: vec![],
            tags: vec![],
        };

        let result = verifier.verify_skill(&manifest, content).unwrap();
        assert!(matches!(result, VerifyResult::MissingSignature));
    }

    #[test]
    fn test_skill_source_display() {
        assert_eq!(SkillSource::Local.to_string(), "local");
        assert_eq!(SkillSource::OpenClaw.to_string(), "openclaw");
        assert_eq!(SkillSource::ZeroClaw.to_string(), "zeroclaw");
        assert_eq!(
            SkillSource::Custom("myregistry".into()).to_string(),
            "custom:myregistry"
        );
    }

    #[test]
    fn test_registry_creation() {
        let config = SkillsConfig {
            directory: "/tmp/ironclaw_test_skills".to_string(),
            require_signatures: false,
            trusted_keys: vec![],
            registry_url: None,
            auto_update: false,
            sources: vec![],
        };
        let registry = SkillRegistry::new(&config).unwrap();
        assert_eq!(registry.count(), 0);
        assert!(registry.list().is_empty());
    }

    #[test]
    fn test_loader_creation() {
        let config = SkillsConfig {
            directory: "/tmp".to_string(),
            require_signatures: false,
            trusted_keys: vec![],
            registry_url: None,
            auto_update: false,
            sources: vec![],
        };
        let loader = SkillLoader::new(&config);
        assert!(loader.is_ok());
    }

    #[test]
    fn test_shellexpand_absolute() {
        let result = shellexpand("/absolute/path");
        assert_eq!(result, "/absolute/path");
    }
}
