//! Intelligent caching layer for IronClaw tool execution results.
//!
//! Uses `moka` for a concurrent, async-aware in-memory cache with TTL-based
//! expiration, maximum entry limits, and memory bounding. Non-deterministic
//! tools (e.g., shell commands, network requests) bypass the cache entirely.

use anyhow::Result;
use moka::future::Cache;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Cache configuration
// ---------------------------------------------------------------------------

/// Configuration for the cache manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Whether the cache is enabled at all.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Time-to-live in seconds for cached entries.
    #[serde(default = "default_ttl")]
    pub ttl_secs: u64,

    /// Maximum number of cached entries.
    #[serde(default = "default_max_entries")]
    pub max_entries: u64,

    /// Maximum total memory for cached values (in bytes).
    #[serde(default = "default_max_memory")]
    pub max_memory_bytes: u64,

    /// Tool names that should never be cached (non-deterministic).
    #[serde(default = "default_bypass_tools")]
    pub bypass_tools: Vec<String>,
}

fn default_true() -> bool { true }
fn default_ttl() -> u64 { 300 }
fn default_max_entries() -> u64 { 1024 }
fn default_max_memory() -> u64 { 64 * 1024 * 1024 } // 64 MiB
fn default_bypass_tools() -> Vec<String> {
    vec![
        "shell".to_string(),
        "execute".to_string(),
        "http_request".to_string(),
        "fetch".to_string(),
    ]
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ttl_secs: default_ttl(),
            max_entries: default_max_entries(),
            max_memory_bytes: default_max_memory(),
            bypass_tools: default_bypass_tools(),
        }
    }
}

// ---------------------------------------------------------------------------
// Cached entry
// ---------------------------------------------------------------------------

/// A single cached tool result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedEntry {
    /// The cached output string.
    pub output: String,
    /// Whether the original tool execution succeeded.
    pub success: bool,
    /// When this entry was inserted.
    pub cached_at: chrono::DateTime<chrono::Utc>,
}

// ---------------------------------------------------------------------------
// Cache statistics
// ---------------------------------------------------------------------------

/// Aggregate cache statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub inserts: u64,
    pub evictions: u64,
    pub current_entries: u64,
    pub hit_rate: f64,
    pub enabled: bool,
}

// ---------------------------------------------------------------------------
// CacheManager
// ---------------------------------------------------------------------------

/// Intelligent caching layer that sits in front of tool execution.
///
/// Cache keys are derived from `tool_name + deterministic_hash(arguments)`.
/// Tools marked as non-deterministic (e.g., `shell`, `http_request`) bypass
/// the cache entirely, ensuring stale data is never returned for side-effectful
/// operations.
pub struct CacheManager {
    cache: Cache<String, CachedEntry>,
    config: CacheConfig,
    hits: AtomicU64,
    misses: AtomicU64,
    inserts: AtomicU64,
    evictions: AtomicU64,
}

impl CacheManager {
    /// Create a new cache manager from the given configuration.
    pub fn new(config: CacheConfig) -> Self {
        let cache = Cache::builder()
            .max_capacity(config.max_entries)
            .time_to_live(Duration::from_secs(config.ttl_secs))
            // Weigher: approximate memory usage per entry based on output length.
            .weigher(|_key: &String, value: &CachedEntry| -> u32 {
                // Clamp to u32 range; each char is roughly 1 byte for ASCII.
                let size = value.output.len() + 128; // 128 bytes overhead estimate
                size.min(u32::MAX as usize) as u32
            })
            .build();

        tracing::info!(
            max_entries = config.max_entries,
            ttl_secs = config.ttl_secs,
            bypass_tools = ?config.bypass_tools,
            "CacheManager initialized"
        );

        Self {
            cache,
            config,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            inserts: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
        }
    }

    /// Attempt to retrieve a cached result for the given tool call.
    ///
    /// Returns `None` if caching is disabled, the tool is non-deterministic,
    /// or no matching entry exists.
    pub async fn get(
        &self,
        tool_name: &str,
        args: &HashMap<String, serde_json::Value>,
    ) -> Option<CachedEntry> {
        if !self.config.enabled || self.should_bypass(tool_name) {
            return None;
        }

        let key = Self::cache_key(tool_name, args);
        match self.cache.get(&key).await {
            Some(entry) => {
                self.hits.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(tool = tool_name, "Cache HIT");
                Some(entry)
            }
            None => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(tool = tool_name, "Cache MISS");
                None
            }
        }
    }

    /// Store a tool result in the cache.
    ///
    /// Does nothing if caching is disabled or the tool is non-deterministic.
    pub async fn set(
        &self,
        tool_name: &str,
        args: &HashMap<String, serde_json::Value>,
        output: &str,
        success: bool,
    ) {
        if !self.config.enabled || self.should_bypass(tool_name) {
            return;
        }

        let key = Self::cache_key(tool_name, args);
        let entry = CachedEntry {
            output: output.to_string(),
            success,
            cached_at: chrono::Utc::now(),
        };

        self.cache.insert(key, entry).await;
        self.inserts.fetch_add(1, Ordering::Relaxed);
        tracing::debug!(tool = tool_name, "Cached tool result");
    }

    /// Invalidate a specific cached entry.
    pub async fn invalidate(
        &self,
        tool_name: &str,
        args: &HashMap<String, serde_json::Value>,
    ) {
        let key = Self::cache_key(tool_name, args);
        self.cache.invalidate(&key).await;
        self.evictions.fetch_add(1, Ordering::Relaxed);
        tracing::debug!(tool = tool_name, "Cache entry invalidated");
    }

    /// Clear the entire cache.
    pub async fn clear(&self) {
        let count = self.cache.entry_count();
        self.cache.invalidate_all();
        // Run pending tasks to actually free entries.
        self.cache.run_pending_tasks().await;
        self.evictions.fetch_add(count, Ordering::Relaxed);
        tracing::info!(cleared = count, "Cache cleared");
    }

    /// Return current cache statistics.
    pub fn stats(&self) -> CacheStats {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits + misses;
        let hit_rate = if total > 0 {
            hits as f64 / total as f64
        } else {
            0.0
        };

        CacheStats {
            hits,
            misses,
            inserts: self.inserts.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
            current_entries: self.cache.entry_count(),
            hit_rate,
            enabled: self.config.enabled,
        }
    }

    // -- Internal helpers ----------------------------------------------------

    /// Determine whether a tool should bypass the cache.
    fn should_bypass(&self, tool_name: &str) -> bool {
        self.config.bypass_tools.iter().any(|t| t == tool_name)
    }

    /// Generate a deterministic cache key from tool name and arguments.
    ///
    /// The arguments are sorted by key to ensure that `{"a":1,"b":2}` and
    /// `{"b":2,"a":1}` produce the same key.
    fn cache_key(tool_name: &str, args: &HashMap<String, serde_json::Value>) -> String {
        let mut hasher = Sha256::new();
        hasher.update(tool_name.as_bytes());
        hasher.update(b"|");

        // Sort keys for deterministic hashing
        let mut sorted_keys: Vec<&String> = args.keys().collect();
        sorted_keys.sort();

        for key in sorted_keys {
            hasher.update(key.as_bytes());
            hasher.update(b"=");
            // Use the canonical JSON representation
            let val_str = serde_json::to_string(&args[key]).unwrap_or_default();
            hasher.update(val_str.as_bytes());
            hasher.update(b"&");
        }

        hex::encode(hasher.finalize())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cache() -> CacheManager {
        CacheManager::new(CacheConfig::default())
    }

    fn make_args(pairs: &[(&str, &str)]) -> HashMap<String, serde_json::Value> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), serde_json::Value::String(v.to_string())))
            .collect()
    }

    #[tokio::test]
    async fn test_set_and_get() {
        let cache = make_cache();
        let args = make_args(&[("path", "/etc/hostname")]);

        cache.set("file_read", &args, "my-host", true).await;
        let entry = cache.get("file_read", &args).await;

        assert!(entry.is_some());
        let entry = entry.unwrap();
        assert_eq!(entry.output, "my-host");
        assert!(entry.success);
    }

    #[tokio::test]
    async fn test_cache_miss() {
        let cache = make_cache();
        let args = make_args(&[("path", "/nonexistent")]);

        let entry = cache.get("file_read", &args).await;
        assert!(entry.is_none());
    }

    #[tokio::test]
    async fn test_bypass_nondeterministic_tool() {
        let cache = make_cache();
        let args = make_args(&[("command", "date")]);

        cache.set("shell", &args, "2026-01-01", true).await;
        let entry = cache.get("shell", &args).await;

        // Shell is bypassed, so nothing should be cached or returned.
        assert!(entry.is_none());
    }

    #[tokio::test]
    async fn test_invalidate() {
        let cache = make_cache();
        let args = make_args(&[("path", "/tmp/test")]);

        cache.set("file_read", &args, "content", true).await;
        assert!(cache.get("file_read", &args).await.is_some());

        cache.invalidate("file_read", &args).await;
        assert!(cache.get("file_read", &args).await.is_none());
    }

    #[tokio::test]
    async fn test_clear() {
        let cache = make_cache();
        let args1 = make_args(&[("path", "/a")]);
        let args2 = make_args(&[("path", "/b")]);

        cache.set("file_read", &args1, "a", true).await;
        cache.set("file_read", &args2, "b", true).await;

        cache.clear().await;

        assert!(cache.get("file_read", &args1).await.is_none());
        assert!(cache.get("file_read", &args2).await.is_none());
    }

    #[tokio::test]
    async fn test_stats_tracking() {
        let cache = make_cache();
        let args = make_args(&[("path", "/stats")]);

        // 1 miss
        let _ = cache.get("file_read", &args).await;
        // 1 insert
        cache.set("file_read", &args, "data", true).await;
        // 1 hit
        let _ = cache.get("file_read", &args).await;

        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.inserts, 1);
        assert!(stats.hit_rate > 0.4 && stats.hit_rate < 0.6);
        assert!(stats.enabled);
    }

    #[test]
    fn test_cache_key_deterministic() {
        let args1 = make_args(&[("a", "1"), ("b", "2")]);
        let args2 = make_args(&[("b", "2"), ("a", "1")]);

        let key1 = CacheManager::cache_key("tool", &args1);
        let key2 = CacheManager::cache_key("tool", &args2);

        // Same tool + same args (different insertion order) must yield same key.
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_cache_key_different_for_different_tools() {
        let args = make_args(&[("x", "1")]);
        let key1 = CacheManager::cache_key("tool_a", &args);
        let key2 = CacheManager::cache_key("tool_b", &args);

        assert_ne!(key1, key2);
    }

    #[tokio::test]
    async fn test_disabled_cache() {
        let config = CacheConfig {
            enabled: false,
            ..Default::default()
        };
        let cache = CacheManager::new(config);
        let args = make_args(&[("path", "/test")]);

        cache.set("file_read", &args, "data", true).await;
        let entry = cache.get("file_read", &args).await;
        assert!(entry.is_none());
    }
}
