use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

// ---------------------------------------------------------------------------
// Root configuration
// ---------------------------------------------------------------------------

/// Root configuration for IronClaw v0.2.
/// Loaded from TOML. All security settings are explicit -- no implicit
/// defaults that weaken the security posture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub agent: AgentConfig,

    #[serde(default)]
    pub permissions: PermissionsConfig,

    #[serde(default)]
    pub guardian: GuardianConfig,

    #[serde(default)]
    pub sandbox: SandboxConfig,

    #[serde(default)]
    pub memory: MemoryConfig,

    #[serde(default)]
    pub providers: HashMap<String, ProviderConfig>,

    #[serde(default)]
    pub channels: HashMap<String, ChannelConfig>,

    #[serde(default)]
    pub skills: SkillsConfig,

    #[serde(default)]
    pub plugins: PluginsConfig,

    #[serde(default)]
    pub gateway: GatewayConfig,

    #[serde(default)]
    pub tunnel: TunnelConfig,

    #[serde(default)]
    pub audit: AuditConfig,

    #[serde(default)]
    pub observability: ObservabilityConfig,

    #[serde(default)]
    pub cache: CacheConfig,

    #[serde(default)]
    pub history: HistoryConfig,

    #[serde(default)]
    pub scheduler: SchedulerConfig,

    #[serde(default)]
    pub antitheft: AntiTheftConfig,

    #[serde(default)]
    pub dlp: DlpConfig,

    #[serde(default)]
    pub ssrf: SsrfConfig,

    #[serde(default)]
    pub ui: UiConfig,

    #[serde(default)]
    pub cost: CostConfig,

    #[serde(default)]
    pub session_auth: SessionAuthConfig,

    #[serde(default)]
    pub sandbox_profiles: SandboxProfilesConfig,

    #[serde(default)]
    pub workflow: WorkflowEngineConfig,

    #[serde(default)]
    pub agents: AgentsConfig,
}

// ---------------------------------------------------------------------------
// Agent
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// System prompt injected at the beginning of every conversation.
    #[serde(default = "default_system_prompt")]
    pub system_prompt: String,

    /// Maximum conversation turns before forced reset.
    #[serde(default = "default_max_turns")]
    pub max_turns: u32,

    /// Timeout per tool execution in seconds.
    #[serde(default = "default_tool_timeout")]
    pub tool_timeout_secs: u64,

    /// Maximum cost per day in USD cents.
    #[serde(default = "default_max_daily_cost")]
    pub max_daily_cost_cents: u64,

    /// Name of the default provider (key in `providers`).
    #[serde(default = "default_provider_name")]
    pub default_provider: String,

    /// Default model to use when the provider does not specify one.
    #[serde(default = "default_model_name")]
    pub default_model: String,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            system_prompt: default_system_prompt(),
            max_turns: default_max_turns(),
            tool_timeout_secs: default_tool_timeout(),
            max_daily_cost_cents: default_max_daily_cost(),
            default_provider: default_provider_name(),
            default_model: default_model_name(),
        }
    }
}

// ---------------------------------------------------------------------------
// Permissions
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionsConfig {
    #[serde(default)]
    pub filesystem: FilesystemPermissions,

    #[serde(default)]
    pub network: NetworkPermissions,

    #[serde(default)]
    pub system: SystemPermissions,

    /// Per-tool permission overrides keyed by tool name.
    #[serde(default)]
    pub tools: HashMap<String, ToolPermissions>,
}

impl Default for PermissionsConfig {
    fn default() -> Self {
        Self {
            filesystem: FilesystemPermissions::default(),
            network: NetworkPermissions::default(),
            system: SystemPermissions::default(),
            tools: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemPermissions {
    /// Allowed read paths (glob patterns).
    #[serde(default)]
    pub read: Vec<String>,

    /// Allowed write paths (glob patterns).
    #[serde(default)]
    pub write: Vec<String>,

    /// Explicitly denied paths -- takes precedence over allow lists.
    #[serde(default = "default_denied_paths")]
    pub deny: Vec<String>,
}

impl Default for FilesystemPermissions {
    fn default() -> Self {
        Self {
            read: Vec::new(),
            write: Vec::new(),
            deny: default_denied_paths(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPermissions {
    /// Allowed domains for outbound requests.
    #[serde(default)]
    pub allow_domains: Vec<String>,

    /// Blocked domains -- takes precedence over allow list.
    #[serde(default = "default_blocked_domains")]
    pub block_domains: Vec<String>,

    /// Whether to block requests to private/internal RFC-1918 addresses.
    #[serde(default = "default_true")]
    pub block_private: bool,

    /// Maximum outbound HTTP requests per hour.
    #[serde(default = "default_max_requests_per_hour")]
    pub max_requests_per_hour: u32,
}

impl Default for NetworkPermissions {
    fn default() -> Self {
        Self {
            allow_domains: Vec::new(),
            block_domains: default_blocked_domains(),
            block_private: true,
            max_requests_per_hour: default_max_requests_per_hour(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemPermissions {
    /// Whether shell execution is allowed at all.
    #[serde(default)]
    pub allow_shell: bool,

    /// Whether to require human approval for high-risk commands.
    #[serde(default = "default_true")]
    pub require_approval: bool,

    /// Maximum concurrent tool executions.
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent: usize,
}

impl Default for SystemPermissions {
    fn default() -> Self {
        Self {
            allow_shell: false,
            require_approval: true,
            max_concurrent: default_max_concurrent(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ToolPermissions {
    /// Whether this tool is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Risk level override (low / medium / high / critical).
    pub risk_level: Option<String>,

    /// Whether to require approval for every invocation.
    #[serde(default)]
    pub require_approval: bool,

    /// Rate limit (invocations per hour).
    pub rate_limit: Option<u32>,
}

// ---------------------------------------------------------------------------
// Guardian
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardianConfig {
    /// Additional blocked command patterns (regex).
    #[serde(default)]
    pub blocked_patterns: Vec<String>,

    /// Commands that override the blocklist.
    #[serde(default)]
    pub allowed_commands: Vec<String>,

    /// Block pipe operators in shell commands.
    #[serde(default = "default_true")]
    pub block_pipes: bool,

    /// Block output redirection operators.
    #[serde(default = "default_true")]
    pub block_redirects: bool,

    /// Block subshell operators ($(), backticks).
    #[serde(default = "default_true")]
    pub block_subshells: bool,
}

impl Default for GuardianConfig {
    fn default() -> Self {
        Self {
            blocked_patterns: Vec::new(),
            allowed_commands: Vec::new(),
            block_pipes: true,
            block_redirects: true,
            block_subshells: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Sandbox
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    /// Sandbox backend: "docker", "bubblewrap", "native".
    #[serde(default = "default_sandbox_backend")]
    pub backend: String,

    /// Docker/OCI image for sandbox execution.
    #[serde(default = "default_sandbox_image")]
    pub image: String,

    /// Enforce sandbox for all tool execution.
    #[serde(default = "default_true")]
    pub enforce: bool,

    /// Seccomp profile path.
    pub seccomp: Option<String>,

    /// Network policy for sandboxed execution: "deny", "allow", "restricted".
    #[serde(default = "default_network_policy")]
    pub network_policy: String,

    /// Memory limit in MB.
    #[serde(default = "default_memory_limit")]
    pub memory_limit: u64,

    /// CPU limit (fractional cores, e.g. 0.5).
    #[serde(default = "default_cpu_limit")]
    pub cpu_limit: f64,

    /// Maximum number of PIDs inside the sandbox.
    #[serde(default = "default_pids_limit")]
    pub pids_limit: u32,

    /// Tmpfs size in MB for ephemeral scratch space.
    #[serde(default = "default_tmpfs_size")]
    pub tmpfs_size: u64,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            backend: default_sandbox_backend(),
            image: default_sandbox_image(),
            enforce: true,
            seccomp: None,
            network_policy: default_network_policy(),
            memory_limit: default_memory_limit(),
            cpu_limit: default_cpu_limit(),
            pids_limit: default_pids_limit(),
            tmpfs_size: default_tmpfs_size(),
        }
    }
}

// ---------------------------------------------------------------------------
// Memory
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryConfig {
    /// Backend: "sqlite", "postgres", "redis", "file", "none".
    #[serde(default = "default_memory_backend")]
    pub backend: String,

    /// Path to the memory store (for sqlite / file backends).
    #[serde(default = "default_memory_path")]
    pub path: String,

    /// Encrypt memory at rest (AES-256-GCM).
    #[serde(default = "default_true")]
    pub encrypt_at_rest: bool,

    /// Maximum entries before compaction.
    #[serde(default = "default_max_memory_entries")]
    pub max_entries: usize,

    /// Segregate memory by security context.
    #[serde(default = "default_true")]
    pub context_isolation: bool,

    /// Number of entries that triggers automatic compaction.
    #[serde(default = "default_compaction_threshold")]
    pub compaction_threshold: usize,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            backend: default_memory_backend(),
            path: default_memory_path(),
            encrypt_at_rest: true,
            max_entries: default_max_memory_entries(),
            context_isolation: true,
            compaction_threshold: default_compaction_threshold(),
        }
    }
}

// ---------------------------------------------------------------------------
// Providers (25+)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    /// Provider type, e.g. "anthropic", "openai", "google", "mistral",
    /// "cohere", "ollama", "groq", "together", "fireworks", "deepseek",
    /// "perplexity", "anyscale", "replicate", "huggingface", "bedrock",
    /// "vertex", "azure_openai", "openrouter", "lepton", "octo",
    /// "deepinfra", "cerebras", "sambanova", "aleph_alpha",
    /// "ai21", "writer", "custom_openai".
    pub provider_type: String,

    /// API key -- prefer env var references like "$ANTHROPIC_API_KEY".
    pub api_key: Option<String>,

    /// Override the provider's default base URL.
    pub base_url: Option<String>,

    /// Default model identifier for this provider.
    pub model: Option<String>,

    /// Maximum tokens per request.
    pub max_tokens: Option<u32>,

    /// Sampling temperature.
    pub temperature: Option<f64>,

    /// Cost per 1k input tokens in USD cents.
    #[serde(default)]
    pub cost_per_1k_input: f64,

    /// Cost per 1k output tokens in USD cents.
    #[serde(default)]
    pub cost_per_1k_output: f64,
}

// ---------------------------------------------------------------------------
// Channels (15+)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelConfig {
    /// Channel type, e.g. "cli", "slack", "discord", "telegram",
    /// "matrix", "teams", "webhook", "websocket", "rest_api",
    /// "grpc", "irc", "xmpp", "email", "mattermost",
    /// "rocket_chat", "signal".
    pub channel_type: String,

    /// Whether this channel is active.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Authentication token for the channel (bot token, etc.).
    pub token: Option<String>,

    /// Webhook URL for push-based channels.
    pub webhook_url: Option<String>,

    /// Users allowed to interact through this channel.
    #[serde(default)]
    pub allowed_users: Vec<String>,

    /// Rate limit (messages per minute).
    #[serde(default = "default_channel_rate_limit")]
    pub rate_limit: u32,
}

// ---------------------------------------------------------------------------
// Skills
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillsConfig {
    /// Directory containing skill definitions.
    #[serde(default = "default_skills_dir")]
    pub directory: String,

    /// Require cryptographic signatures for all skills.
    #[serde(default = "default_true")]
    pub require_signatures: bool,

    /// Trusted Ed25519 public keys (hex-encoded).
    #[serde(default)]
    pub trusted_keys: Vec<String>,

    /// Registry URL for skill discovery.
    pub registry_url: Option<String>,

    /// Auto-update skills on startup.
    #[serde(default)]
    pub auto_update: bool,

    /// Skill sources to enable.
    #[serde(default = "default_skill_sources")]
    pub sources: Vec<String>,
}

impl Default for SkillsConfig {
    fn default() -> Self {
        Self {
            directory: default_skills_dir(),
            require_signatures: true,
            trusted_keys: Vec::new(),
            registry_url: None,
            auto_update: false,
            sources: default_skill_sources(),
        }
    }
}

// ---------------------------------------------------------------------------
// Plugins
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginsConfig {
    /// Directory containing plugin shared objects / WASM modules.
    #[serde(default = "default_plugins_dir")]
    pub directory: String,

    /// Whether the plugin subsystem is active.
    #[serde(default)]
    pub enabled: bool,

    /// Run plugins inside the sandbox.
    #[serde(default = "default_true")]
    pub sandboxed: bool,

    /// Maximum number of loaded plugins.
    #[serde(default = "default_max_plugins")]
    pub max_plugins: usize,

    /// Discover plugins automatically from the directory.
    #[serde(default)]
    pub auto_discover: bool,
}

impl Default for PluginsConfig {
    fn default() -> Self {
        Self {
            directory: default_plugins_dir(),
            enabled: false,
            sandboxed: true,
            max_plugins: default_max_plugins(),
            auto_discover: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Gateway (API server)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
    /// Whether the HTTP gateway is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// Address to bind the gateway listener.
    #[serde(default = "default_gateway_bind")]
    pub bind_address: String,

    /// TCP port for the gateway.
    #[serde(default = "default_gateway_port")]
    pub port: u16,

    /// Path to TLS certificate (PEM).
    pub tls_cert: Option<String>,

    /// Path to TLS private key (PEM).
    pub tls_key: Option<String>,

    /// CORS allowed origins.
    #[serde(default)]
    pub cors_origins: Vec<String>,

    /// Requests per minute rate limit.
    #[serde(default = "default_gateway_rate_limit")]
    pub rate_limit: u32,

    /// Maximum request body size in bytes.
    #[serde(default = "default_max_body_size")]
    pub max_body_size: usize,

    /// Auth method: "jwt", "api_key", "oauth".
    #[serde(default = "default_auth_method")]
    pub auth_method: String,

    /// JWT signing secret (if auth_method = "jwt").
    pub jwt_secret: Option<String>,

    /// Static API keys (if auth_method = "api_key").
    #[serde(default)]
    pub api_keys: Vec<String>,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_address: default_gateway_bind(),
            port: default_gateway_port(),
            tls_cert: None,
            tls_key: None,
            cors_origins: Vec::new(),
            rate_limit: default_gateway_rate_limit(),
            max_body_size: default_max_body_size(),
            auth_method: default_auth_method(),
            jwt_secret: None,
            api_keys: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Tunnel
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelConfig {
    /// Tunnel provider: "cloudflare", "ngrok", "custom".
    #[serde(default = "default_tunnel_provider")]
    pub provider: String,

    /// Whether the tunnel is active.
    #[serde(default)]
    pub enabled: bool,

    /// Authentication token for the tunnel service.
    pub token: Option<String>,

    /// Custom command to establish the tunnel (provider = "custom").
    pub custom_command: Option<String>,

    /// Custom domain for the tunnel.
    pub domain: Option<String>,
}

impl Default for TunnelConfig {
    fn default() -> Self {
        Self {
            provider: default_tunnel_provider(),
            enabled: false,
            token: None,
            custom_command: None,
            domain: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Path to the audit log.
    #[serde(default = "default_audit_path")]
    pub path: String,

    /// Enable audit logging.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Max audit log size in MB before rotation.
    #[serde(default = "default_audit_max_size")]
    pub max_size_mb: u64,

    /// Rotation strategy: "daily", "size", "both".
    #[serde(default = "default_audit_rotation")]
    pub rotation: String,

    /// Whether to export to a SIEM.
    #[serde(default)]
    pub siem_export: bool,

    /// SIEM endpoint URL or address.
    pub siem_endpoint: Option<String>,

    /// SIEM protocol: "syslog", "http", "kafka".
    #[serde(default = "default_siem_protocol")]
    pub siem_protocol: String,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            path: default_audit_path(),
            enabled: true,
            max_size_mb: default_audit_max_size(),
            rotation: default_audit_rotation(),
            siem_export: false,
            siem_endpoint: None,
            siem_protocol: default_siem_protocol(),
        }
    }
}

// ---------------------------------------------------------------------------
// Observability
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilityConfig {
    /// Log level: "trace", "debug", "info", "warn", "error".
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Emit structured JSON logs.
    #[serde(default = "default_true")]
    pub structured_logs: bool,

    /// Redact PII from logs.
    #[serde(default = "default_true")]
    pub redact_pii: bool,

    /// Regex patterns whose matches are redacted.
    #[serde(default = "default_redact_patterns")]
    pub redact_patterns: Vec<String>,

    /// OTLP exporter endpoint.
    #[serde(default = "default_otlp_endpoint")]
    pub otlp_endpoint: String,

    /// Whether OTLP export is active.
    #[serde(default)]
    pub otlp_enabled: bool,

    /// Whether Prometheus-style metrics are enabled.
    #[serde(default)]
    pub metrics_enabled: bool,

    /// External log aggregator endpoint (Loki, Datadog, etc.).
    pub external_log_endpoint: Option<String>,

    /// External log format: "json", "logfmt", "otlp".
    #[serde(default = "default_external_log_format")]
    pub external_log_format: String,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            log_level: default_log_level(),
            structured_logs: true,
            redact_pii: true,
            redact_patterns: default_redact_patterns(),
            otlp_endpoint: default_otlp_endpoint(),
            otlp_enabled: false,
            metrics_enabled: false,
            external_log_endpoint: None,
            external_log_format: default_external_log_format(),
        }
    }
}

// ---------------------------------------------------------------------------
// Cache
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Enable the response cache.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Backend: "memory", "redis", "file".
    #[serde(default = "default_cache_backend")]
    pub backend: String,

    /// Maximum cache entries.
    #[serde(default = "default_cache_max_entries")]
    pub max_entries: u64,

    /// Time-to-live in seconds.
    #[serde(default = "default_cache_ttl")]
    pub ttl_secs: u64,

    /// Maximum memory for in-memory cache in MB.
    #[serde(default = "default_cache_max_memory")]
    pub max_memory_mb: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            backend: default_cache_backend(),
            max_entries: default_cache_max_entries(),
            ttl_secs: default_cache_ttl(),
            max_memory_mb: default_cache_max_memory(),
        }
    }
}

// ---------------------------------------------------------------------------
// History
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryConfig {
    /// Enable conversation history persistence.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Backend: "sqlite", "file".
    #[serde(default = "default_history_backend")]
    pub backend: String,

    /// Path to the history store.
    #[serde(default = "default_history_path")]
    pub path: String,

    /// Maximum stored conversations.
    #[serde(default = "default_max_conversations")]
    pub max_conversations: usize,

    /// Maximum messages per conversation.
    #[serde(default = "default_max_messages_per_conversation")]
    pub max_messages_per_conversation: usize,

    /// Compress old conversations (lz4).
    #[serde(default = "default_true")]
    pub compress_old: bool,
}

impl Default for HistoryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            backend: default_history_backend(),
            path: default_history_path(),
            max_conversations: default_max_conversations(),
            max_messages_per_conversation: default_max_messages_per_conversation(),
            compress_old: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Scheduler
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedulerConfig {
    /// Enable the built-in task scheduler.
    #[serde(default)]
    pub enabled: bool,

    /// Maximum concurrent scheduled tasks.
    #[serde(default = "default_scheduler_max_concurrent")]
    pub max_concurrent_tasks: usize,

    /// Cron-style scheduled jobs.
    #[serde(default)]
    pub cron_jobs: Vec<CronJob>,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_concurrent_tasks: default_scheduler_max_concurrent(),
            cron_jobs: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronJob {
    /// Cron schedule expression (e.g. "0 */6 * * *").
    pub schedule: String,

    /// Command or skill to execute.
    pub command: String,

    /// Whether this job is active.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

// ---------------------------------------------------------------------------
// Anti-Theft
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiTheftConfig {
    /// Enforce anti-theft detection (blocks suspicious read-then-send).
    #[serde(default = "default_true")]
    pub enforce: bool,

    /// Correlation window to detect read -> exfiltrate patterns (seconds).
    #[serde(default = "default_correlation_window")]
    pub correlation_window_secs: u64,

    /// Additional sensitive path patterns to watch.
    #[serde(default)]
    pub extra_sensitive_paths: Vec<String>,
}

impl Default for AntiTheftConfig {
    fn default() -> Self {
        Self {
            enforce: true,
            correlation_window_secs: default_correlation_window(),
            extra_sensitive_paths: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// DLP
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpConfig {
    /// Enable Data Loss Prevention scanning.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Default action: "block", "redact", "warn".
    #[serde(default = "default_dlp_action")]
    pub default_action: String,

    /// Scan tool outputs before they reach the LLM.
    #[serde(default = "default_true")]
    pub scan_tool_outputs: bool,

    /// Scan LLM responses before displaying to the user.
    #[serde(default = "default_true")]
    pub scan_llm_responses: bool,
}

impl Default for DlpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_action: default_dlp_action(),
            scan_tool_outputs: true,
            scan_llm_responses: true,
        }
    }
}

// ---------------------------------------------------------------------------
// SSRF
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsrfConfig {
    /// Block requests to private/internal IP ranges.
    #[serde(default = "default_true")]
    pub block_private_ips: bool,

    /// Block cloud metadata endpoints (169.254.169.254, etc.).
    #[serde(default = "default_true")]
    pub block_metadata: bool,

    /// Blocked URL schemes beyond http/https.
    #[serde(default = "default_blocked_schemes")]
    pub blocked_schemes: Vec<String>,
}

impl Default for SsrfConfig {
    fn default() -> Self {
        Self {
            block_private_ips: true,
            block_metadata: true,
            blocked_schemes: default_blocked_schemes(),
        }
    }
}

// ---------------------------------------------------------------------------
// UI
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiConfig {
    /// Enable the built-in web UI.
    #[serde(default)]
    pub enabled: bool,

    /// Address to bind the UI server.
    #[serde(default = "default_ui_bind")]
    pub bind_address: String,

    /// TCP port for the UI server.
    #[serde(default = "default_ui_port")]
    pub port: u16,

    /// Theme: "dark", "light".
    #[serde(default = "default_ui_theme")]
    pub theme: String,

    /// Require authentication to access the UI.
    #[serde(default = "default_true")]
    pub require_auth: bool,
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_address: default_ui_bind(),
            port: default_ui_port(),
            theme: default_ui_theme(),
            require_auth: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Session Authentication
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionAuthConfig {
    /// Enable LLM session-based authentication.
    #[serde(default)]
    pub enabled: bool,

    /// Token time-to-live in seconds.
    #[serde(default = "default_session_auth_ttl")]
    pub ttl_secs: u64,

    /// HMAC secret for signing session tokens (hex or plain string).
    pub secret: Option<String>,
}

impl Default for SessionAuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ttl_secs: default_session_auth_ttl(),
            secret: None,
        }
    }
}

fn default_session_auth_ttl() -> u64 {
    3600
}

// ---------------------------------------------------------------------------
// Sandbox Profiles
// ---------------------------------------------------------------------------

/// Configuration for multi-level sandbox profiles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxProfilesConfig {
    /// Default isolation level: "minimal", "standard", "elevated", "unrestricted".
    #[serde(default = "default_sandbox_profile_level")]
    pub default_level: String,

    /// Per-skill profile entries with optional overrides.
    #[serde(default)]
    pub profiles: Vec<SandboxProfileEntryConfig>,
}

impl Default for SandboxProfilesConfig {
    fn default() -> Self {
        Self {
            default_level: default_sandbox_profile_level(),
            profiles: Vec::new(),
        }
    }
}

/// A sandbox profile entry in the config file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxProfileEntryConfig {
    /// Isolation level: "minimal", "standard", "elevated", "unrestricted".
    #[serde(default = "default_sandbox_profile_level")]
    pub level: String,

    /// Skill name this profile applies to.
    pub skill: Option<String>,

    /// Whether this is the global default profile.
    #[serde(default)]
    pub is_default: bool,

    /// Memory limit override (MB).
    pub memory_mb: Option<u64>,

    /// CPU cores override.
    pub cpu_cores: Option<f64>,

    /// Max PIDs override.
    pub max_pids: Option<u32>,

    /// Timeout override (seconds).
    pub timeout_secs: Option<u64>,

    /// Network enabled override.
    pub network_enabled: Option<bool>,
}

fn default_sandbox_profile_level() -> String {
    "standard".to_string()
}

// ---------------------------------------------------------------------------
// Workflow Engine
// ---------------------------------------------------------------------------

/// Configuration for the workflow/automation engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowEngineConfig {
    /// Enable the workflow engine.
    #[serde(default)]
    pub enabled: bool,

    /// Maximum concurrent workflow executions.
    #[serde(default = "default_max_concurrent_workflows")]
    pub max_concurrent: usize,

    /// Directory to load workflow definitions from.
    pub workflows_dir: Option<String>,

    /// Default timeout per workflow execution in seconds.
    #[serde(default = "default_workflow_timeout")]
    pub default_timeout_secs: u64,
}

impl Default for WorkflowEngineConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_concurrent: default_max_concurrent_workflows(),
            workflows_dir: None,
            default_timeout_secs: default_workflow_timeout(),
        }
    }
}

fn default_max_concurrent_workflows() -> usize {
    4
}

fn default_workflow_timeout() -> u64 {
    300
}

// ---------------------------------------------------------------------------
// Collaborative Agents
// ---------------------------------------------------------------------------

/// Configuration for the multi-agent orchestration system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentsConfig {
    /// Enable the agents subsystem.
    #[serde(default)]
    pub enabled: bool,

    /// Maximum concurrent collaboration sessions.
    #[serde(default = "default_max_agent_sessions")]
    pub max_concurrent_sessions: usize,
}

impl Default for AgentsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_concurrent_sessions: default_max_agent_sessions(),
        }
    }
}

fn default_max_agent_sessions() -> usize {
    4
}

// ---------------------------------------------------------------------------
// Cost tracking
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostConfig {
    /// Enable cost tracking.
    #[serde(default = "default_true")]
    pub track_costs: bool,

    /// Daily budget in USD cents.
    #[serde(default = "default_daily_budget")]
    pub daily_budget_cents: u64,

    /// Monthly budget in USD cents.
    #[serde(default = "default_monthly_budget")]
    pub monthly_budget_cents: u64,

    /// Alert when spend exceeds this percentage of the budget.
    #[serde(default = "default_alert_threshold")]
    pub alert_threshold_pct: u8,

    /// Currency code for display.
    #[serde(default = "default_currency")]
    pub currency: String,
}

impl Default for CostConfig {
    fn default() -> Self {
        Self {
            track_costs: true,
            daily_budget_cents: default_daily_budget(),
            monthly_budget_cents: default_monthly_budget(),
            alert_threshold_pct: default_alert_threshold(),
            currency: default_currency(),
        }
    }
}

// ---------------------------------------------------------------------------
// Root Config impl
// ---------------------------------------------------------------------------

impl Default for Config {
    fn default() -> Self {
        Self {
            agent: AgentConfig::default(),
            permissions: PermissionsConfig::default(),
            guardian: GuardianConfig::default(),
            sandbox: SandboxConfig::default(),
            memory: MemoryConfig::default(),
            providers: HashMap::new(),
            channels: HashMap::new(),
            skills: SkillsConfig::default(),
            plugins: PluginsConfig::default(),
            gateway: GatewayConfig::default(),
            tunnel: TunnelConfig::default(),
            audit: AuditConfig::default(),
            observability: ObservabilityConfig::default(),
            cache: CacheConfig::default(),
            history: HistoryConfig::default(),
            scheduler: SchedulerConfig::default(),
            antitheft: AntiTheftConfig::default(),
            dlp: DlpConfig::default(),
            ssrf: SsrfConfig::default(),
            ui: UiConfig::default(),
            cost: CostConfig::default(),
            session_auth: SessionAuthConfig::default(),
            sandbox_profiles: SandboxProfilesConfig::default(),
            workflow: WorkflowEngineConfig::default(),
            agents: AgentsConfig::default(),
        }
    }
}

impl Config {
    /// Load configuration from a TOML file.
    ///
    /// If the file does not exist, secure defaults are returned.
    /// After deserialization the configuration is validated against
    /// mandatory security invariants.
    pub fn load(path: &str) -> Result<Self> {
        let path = Path::new(path);
        if !path.exists() {
            tracing::warn!(
                "Config file not found at {}, using secure defaults",
                path.display()
            );
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config: {}", path.display()))?;

        let config: Config = toml::from_str(&content)
            .with_context(|| format!("Failed to parse TOML config: {}", path.display()))?;

        config.validate()?;
        Ok(config)
    }

    /// Load configuration from an in-memory TOML string.
    pub fn from_toml(toml_str: &str) -> Result<Self> {
        let config: Config =
            toml::from_str(toml_str).with_context(|| "Failed to parse TOML config string")?;
        config.validate()?;
        Ok(config)
    }

    /// Serialize the configuration back to TOML.
    pub fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(self).with_context(|| "Failed to serialize config to TOML")
    }

    /// Validate security invariants that must never be weakened.
    pub fn validate(&self) -> Result<()> {
        // 1. Critical paths must always be denied.
        let required_denies = [
            "/etc/shadow",
            "/etc/gshadow",
            "/root/.ssh",
            "**/.ssh/id_*",
            "**/.aws/credentials",
            "**/.gnupg/private-keys",
        ];
        for required in &required_denies {
            let present = self
                .permissions
                .filesystem
                .deny
                .iter()
                .any(|d| d.contains(required));
            if !present {
                anyhow::bail!(
                    "Security violation: '{}' must be in filesystem deny list",
                    required
                );
            }
        }

        // 2. Cloud metadata endpoints must always be blocked.
        let required_blocks = [
            "169.254.169.254",
            "metadata.google.internal",
            "metadata.azure.com",
        ];
        for required in &required_blocks {
            let present = self
                .permissions
                .network
                .block_domains
                .iter()
                .any(|d| d.contains(required));
            if !present {
                anyhow::bail!(
                    "Security violation: '{}' must be in network block list",
                    required
                );
            }
        }

        // 3. Sandbox must be enforced when shell is allowed.
        if self.permissions.system.allow_shell && !self.sandbox.enforce {
            anyhow::bail!(
                "Security violation: sandbox must be enforced when shell execution is allowed"
            );
        }

        // 4. Gateway must have an auth method when enabled.
        if self.gateway.enabled {
            match self.gateway.auth_method.as_str() {
                "jwt" => {
                    if self.gateway.jwt_secret.is_none() {
                        anyhow::bail!(
                            "Security violation: jwt_secret is required when auth_method is 'jwt'"
                        );
                    }
                }
                "api_key" => {
                    if self.gateway.api_keys.is_empty() {
                        anyhow::bail!(
                            "Security violation: at least one api_key is required when auth_method is 'api_key'"
                        );
                    }
                }
                "oauth" => {} // OAuth validated at runtime
                other => {
                    anyhow::bail!(
                        "Unknown gateway auth_method '{}'; expected jwt, api_key, or oauth",
                        other
                    );
                }
            }
        }

        // 5. DLP must be enabled when shell is allowed.
        if self.permissions.system.allow_shell && !self.dlp.enabled {
            anyhow::bail!(
                "Security violation: DLP must be enabled when shell execution is allowed"
            );
        }

        // 6. Anti-theft must be enforced when network access is unrestricted.
        if self.permissions.network.allow_domains.is_empty()
            && !self.permissions.network.block_private
            && !self.antitheft.enforce
        {
            anyhow::bail!(
                "Security violation: anti-theft must be enforced when network is unrestricted"
            );
        }

        // 7. Audit must be enabled when gateway is public.
        if self.gateway.enabled && !self.audit.enabled {
            anyhow::bail!(
                "Security violation: audit logging must be enabled when the gateway is active"
            );
        }

        // 8. SSRF protection must be active.
        if !self.ssrf.block_private_ips || !self.ssrf.block_metadata {
            tracing::warn!("SSRF protections are partially disabled -- ensure this is intentional");
        }

        Ok(())
    }
}

// ===========================================================================
// Default value helper functions
// ===========================================================================

fn default_true() -> bool {
    true
}

// -- Agent ------------------------------------------------------------------
fn default_system_prompt() -> String {
    "You are IronClaw, a secure AI assistant. Follow security policies strictly.".to_string()
}
fn default_max_turns() -> u32 {
    100
}
fn default_tool_timeout() -> u64 {
    30
}
fn default_max_daily_cost() -> u64 {
    500
}
fn default_provider_name() -> String {
    "anthropic".to_string()
}
fn default_model_name() -> String {
    "claude-sonnet-4-5-20250514".to_string()
}

// -- Permissions / Network --------------------------------------------------
fn default_max_requests_per_hour() -> u32 {
    100
}
fn default_max_concurrent() -> usize {
    4
}

// -- Sandbox ----------------------------------------------------------------
fn default_sandbox_backend() -> String {
    "docker".to_string()
}
fn default_sandbox_image() -> String {
    "ironclaw-sandbox:latest".to_string()
}
fn default_network_policy() -> String {
    "deny".to_string()
}
fn default_memory_limit() -> u64 {
    512
}
fn default_cpu_limit() -> f64 {
    1.0
}
fn default_pids_limit() -> u32 {
    64
}
fn default_tmpfs_size() -> u64 {
    64
}

// -- Memory -----------------------------------------------------------------
fn default_memory_backend() -> String {
    "sqlite".to_string()
}
fn default_memory_path() -> String {
    "~/.ironclaw/memory.db".to_string()
}
fn default_max_memory_entries() -> usize {
    10_000
}
fn default_compaction_threshold() -> usize {
    8_000
}

// -- Skills -----------------------------------------------------------------
fn default_skills_dir() -> String {
    "~/.ironclaw/skills".to_string()
}
fn default_skill_sources() -> Vec<String> {
    vec![
        "openclaw".to_string(),
        "zeroclaw".to_string(),
    ]
}

// -- Plugins ----------------------------------------------------------------
fn default_plugins_dir() -> String {
    "~/.ironclaw/plugins".to_string()
}
fn default_max_plugins() -> usize {
    32
}

// -- Gateway ----------------------------------------------------------------
fn default_gateway_bind() -> String {
    "127.0.0.1".to_string()
}
fn default_gateway_port() -> u16 {
    8443
}
fn default_gateway_rate_limit() -> u32 {
    120
}
fn default_max_body_size() -> usize {
    // 1 MB
    1_048_576
}
fn default_auth_method() -> String {
    "jwt".to_string()
}

// -- Tunnel -----------------------------------------------------------------
fn default_tunnel_provider() -> String {
    "cloudflare".to_string()
}

// -- Channels ---------------------------------------------------------------
fn default_channel_rate_limit() -> u32 {
    30
}

// -- Audit ------------------------------------------------------------------
fn default_audit_path() -> String {
    "~/.ironclaw/audit.log".to_string()
}
fn default_audit_max_size() -> u64 {
    100
}
fn default_audit_rotation() -> String {
    "both".to_string()
}
fn default_siem_protocol() -> String {
    "syslog".to_string()
}

// -- Observability ----------------------------------------------------------
fn default_log_level() -> String {
    "info".to_string()
}
fn default_otlp_endpoint() -> String {
    "http://localhost:4317".to_string()
}
fn default_external_log_format() -> String {
    "json".to_string()
}

// -- Cache ------------------------------------------------------------------
fn default_cache_backend() -> String {
    "memory".to_string()
}
fn default_cache_max_entries() -> u64 {
    10_000
}
fn default_cache_ttl() -> u64 {
    300
}
fn default_cache_max_memory() -> u64 {
    128
}

// -- History ----------------------------------------------------------------
fn default_history_backend() -> String {
    "sqlite".to_string()
}
fn default_history_path() -> String {
    "~/.ironclaw/history.db".to_string()
}
fn default_max_conversations() -> usize {
    1_000
}
fn default_max_messages_per_conversation() -> usize {
    500
}

// -- Scheduler --------------------------------------------------------------
fn default_scheduler_max_concurrent() -> usize {
    4
}

// -- Anti-Theft -------------------------------------------------------------
fn default_correlation_window() -> u64 {
    300
}

// -- DLP --------------------------------------------------------------------
fn default_dlp_action() -> String {
    "redact".to_string()
}

// -- SSRF -------------------------------------------------------------------
fn default_blocked_schemes() -> Vec<String> {
    vec![
        "file".to_string(),
        "ftp".to_string(),
        "gopher".to_string(),
        "dict".to_string(),
        "ldap".to_string(),
        "tftp".to_string(),
    ]
}

// -- UI ---------------------------------------------------------------------
fn default_ui_bind() -> String {
    "127.0.0.1".to_string()
}
fn default_ui_port() -> u16 {
    3000
}
fn default_ui_theme() -> String {
    "dark".to_string()
}

// -- Cost -------------------------------------------------------------------
fn default_daily_budget() -> u64 {
    500
}
fn default_monthly_budget() -> u64 {
    10_000
}
fn default_alert_threshold() -> u8 {
    80
}
fn default_currency() -> String {
    "USD".to_string()
}

// -- Redact patterns --------------------------------------------------------
fn default_redact_patterns() -> Vec<String> {
    vec![
        r"(?i)(api[_-]?key|token|secret|password|credential)\s*[:=]\s*\S+".to_string(),
        r"(?i)bearer\s+\S+".to_string(),
        r"\b[A-Za-z0-9+/]{40,}={0,2}\b".to_string(),
        r"(?i)ghp_[A-Za-z0-9]{36,}".to_string(),
        r"(?i)sk-[A-Za-z0-9]{20,}".to_string(),
        r"AKIA[0-9A-Z]{16}".to_string(),
    ]
}

// ===========================================================================
// Denied filesystem paths (60+ entries)
// ===========================================================================

fn default_denied_paths() -> Vec<String> {
    vec![
        // ---- System credentials ----
        "/etc/shadow".to_string(),
        "/etc/gshadow".to_string(),
        "/etc/passwd".to_string(),
        "/etc/sudoers".to_string(),
        "/etc/sudoers.d/**".to_string(),
        "/etc/master.passwd".to_string(),
        "/etc/security/**".to_string(),
        // ---- SSH ----
        "/root/.ssh/**".to_string(),
        "**/.ssh/id_*".to_string(),
        "**/.ssh/authorized_keys".to_string(),
        "**/.ssh/known_hosts".to_string(),
        "**/.ssh/config".to_string(),
        "**/.ssh/*.pub".to_string(),
        // ---- Environment / dotenv ----
        "**/.env".to_string(),
        "**/.env.*".to_string(),
        "**/.env.local".to_string(),
        "**/.env.production".to_string(),
        "**/.netrc".to_string(),
        // ---- AWS ----
        "**/.aws/credentials".to_string(),
        "**/.aws/config".to_string(),
        "**/.aws/sso/cache/**".to_string(),
        // ---- GCP ----
        "**/.config/gcloud/credentials.db".to_string(),
        "**/.config/gcloud/application_default_credentials.json".to_string(),
        "**/.config/gcloud/access_tokens.db".to_string(),
        "**/.config/gcloud/properties".to_string(),
        // ---- Azure ----
        "**/.azure/accessTokens.json".to_string(),
        "**/.azure/azureProfile.json".to_string(),
        "**/.azure/msal_token_cache.json".to_string(),
        // ---- Kubernetes ----
        "**/.kube/config".to_string(),
        "**/.kube/cache/**".to_string(),
        "**/.minikube/**".to_string(),
        // ---- Docker ----
        "**/.docker/config.json".to_string(),
        "**/.docker/daemon.json".to_string(),
        // ---- Terraform / Vault ----
        "**/.terraform/**".to_string(),
        "**/terraform.tfstate*".to_string(),
        "**/.vault-token".to_string(),
        // ---- Crypto wallets ----
        "**/.bitcoin/**".to_string(),
        "**/.ethereum/**".to_string(),
        "**/.solana/**".to_string(),
        "**/.monero/**".to_string(),
        "**/.electrum/**".to_string(),
        "**/.zcash/**".to_string(),
        "**/.litecoin/**".to_string(),
        "**/wallet.dat".to_string(),
        "**/wallet.json".to_string(),
        "**/keystore/**".to_string(),
        // ---- Browser profiles ----
        "**/.mozilla/**/cookies.sqlite".to_string(),
        "**/.mozilla/**/logins.json".to_string(),
        "**/.mozilla/**/key4.db".to_string(),
        "**/.config/google-chrome/**/Login Data".to_string(),
        "**/.config/google-chrome/**/Cookies".to_string(),
        "**/.config/google-chrome/**/Web Data".to_string(),
        "**/.config/chromium/**/Login Data".to_string(),
        "**/.config/chromium/**/Cookies".to_string(),
        "**/Library/Application Support/Google/Chrome/**/Login Data".to_string(),
        "**/Library/Application Support/Google/Chrome/**/Cookies".to_string(),
        "**/Library/Application Support/Firefox/**/logins.json".to_string(),
        "**/Library/Application Support/Firefox/**/key4.db".to_string(),
        "**/AppData/Local/Google/Chrome/**/Login Data".to_string(),
        "**/AppData/Local/Google/Chrome/**/Cookies".to_string(),
        "**/AppData/Roaming/Mozilla/Firefox/**/logins.json".to_string(),
        // ---- Password stores / keyrings ----
        "**/.password-store/**".to_string(),
        "**/.local/share/keyrings/**".to_string(),
        "**/Library/Keychains/**".to_string(),
        "**/*.kdbx".to_string(),
        "**/*.kdb".to_string(),
        "**/Bitwarden/**".to_string(),
        // ---- Certificates and private keys ----
        "**/*.pem".to_string(),
        "**/*.key".to_string(),
        "**/*.p12".to_string(),
        "**/*.pfx".to_string(),
        "**/*.jks".to_string(),
        "**/*.keystore".to_string(),
        "**/tls.crt".to_string(),
        "**/tls.key".to_string(),
        // ---- GPG ----
        "**/.gnupg/private-keys*".to_string(),
        "**/.gnupg/secring*".to_string(),
        "**/.gnupg/trustdb.gpg".to_string(),
        // ---- Package registry credentials ----
        "**/.npmrc".to_string(),
        "**/.yarnrc".to_string(),
        "**/.pypirc".to_string(),
        "**/.gem/credentials".to_string(),
        "**/.cargo/credentials".to_string(),
        "**/.cargo/credentials.toml".to_string(),
        "**/.nuget/NuGet.Config".to_string(),
        "**/.composer/auth.json".to_string(),
        "**/.m2/settings.xml".to_string(),
        "**/.gradle/gradle.properties".to_string(),
        // ---- Database credentials ----
        "**/.pgpass".to_string(),
        "**/.my.cnf".to_string(),
        "**/.mongorc.js".to_string(),
        "**/.dbshell".to_string(),
        "**/.rediscli_history".to_string(),
        // ---- Secrets / credentials catch-all ----
        "**/credentials*".to_string(),
        "**/secrets*".to_string(),
        "**/*secret*.json".to_string(),
        "**/*secret*.yaml".to_string(),
        "**/*secret*.yml".to_string(),
        "**/*secret*.toml".to_string(),
        // ---- Kernel / system ----
        "/proc/**".to_string(),
        "/sys/**".to_string(),
        "/dev/**".to_string(),
        // ---- Snap / Flatpak secrets ----
        "**/.local/share/gnome-keyring/**".to_string(),
        // ---- Miscellaneous ----
        "**/.history".to_string(),
        "**/.bash_history".to_string(),
        "**/.zsh_history".to_string(),
        "**/.python_history".to_string(),
        "**/.node_repl_history".to_string(),
        "**/.ironclaw/master.key".to_string(),
    ]
}

// ===========================================================================
// Blocked domains
// ===========================================================================

fn default_blocked_domains() -> Vec<String> {
    vec![
        // Cloud metadata endpoints
        "169.254.169.254".to_string(),
        "metadata.google.internal".to_string(),
        "metadata.azure.com".to_string(),
        "169.254.170.2".to_string(),          // ECS task metadata
        "100.100.100.200".to_string(),         // Alibaba Cloud metadata
        "fd00:ec2::254".to_string(),           // AWS IPv6 metadata
        // Common exfiltration / data-capture services
        "requestbin.com".to_string(),
        "webhook.site".to_string(),
        "pipedream.net".to_string(),
        "hookbin.com".to_string(),
        "burpcollaborator.net".to_string(),
        "interact.sh".to_string(),
        "oastify.com".to_string(),
        "canarytokens.com".to_string(),
        "requestcatcher.com".to_string(),
        "beeceptor.com".to_string(),
        "mockbin.io".to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_validates() {
        let config = Config::default();
        config.validate().expect("default config must validate");
    }

    #[test]
    fn test_denied_paths_count() {
        let paths = default_denied_paths();
        assert!(
            paths.len() >= 60,
            "expected >= 60 denied paths, got {}",
            paths.len()
        );
    }

    #[test]
    fn test_empty_toml_parses() {
        let config = Config::from_toml("").expect("empty TOML should parse to defaults");
        config.validate().expect("parsed empty TOML must validate");
    }

    #[test]
    fn test_partial_toml_merges() {
        let toml_str = r#"
[agent]
max_turns = 50

[observability]
log_level = "debug"
"#;
        let config = Config::from_toml(toml_str).expect("partial TOML should parse");
        assert_eq!(config.agent.max_turns, 50);
        assert_eq!(config.observability.log_level, "debug");
        // Defaults still present
        assert!(config.sandbox.enforce);
    }

    #[test]
    fn test_shell_without_sandbox_fails() {
        let toml_str = r#"
[permissions.system]
allow_shell = true

[sandbox]
enforce = false
"#;
        let result = Config::from_toml(toml_str);
        assert!(result.is_err(), "shell without sandbox should fail validation");
    }
}
