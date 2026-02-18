use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Risk classification
// ---------------------------------------------------------------------------

/// Risk level classification for commands, tools, and operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RiskLevel {
    /// Safe operations with no side effects.
    Low,
    /// Operations that may modify local state.
    Medium,
    /// Operations that can cause irreversible damage.
    High,
    /// Operations that compromise system security.
    Critical,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::Low => write!(f, "LOW"),
            RiskLevel::Medium => write!(f, "MEDIUM"),
            RiskLevel::High => write!(f, "HIGH"),
            RiskLevel::Critical => write!(f, "CRITICAL"),
        }
    }
}

impl RiskLevel {
    /// Returns `true` if this risk level requires human approval by default.
    pub fn requires_approval(&self) -> bool {
        matches!(self, RiskLevel::High | RiskLevel::Critical)
    }
}

// ---------------------------------------------------------------------------
// Tool execution results
// ---------------------------------------------------------------------------

/// Result of a tool execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    /// Whether the tool executed successfully.
    pub success: bool,

    /// Primary output from the tool.
    pub output: String,

    /// Error message if execution failed.
    pub error: Option<String>,

    /// Structured metadata about the execution.
    pub metadata: ToolResultMetadata,
}

/// Metadata attached to every tool execution for auditing and observability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResultMetadata {
    /// Tool name.
    pub tool_name: String,

    /// Execution duration in milliseconds.
    pub duration_ms: u64,

    /// Whether the execution was sandboxed.
    pub sandboxed: bool,

    /// Risk level of the executed operation.
    pub risk_level: RiskLevel,

    /// Unique execution ID for audit trail linkage.
    pub execution_id: String,

    /// Timestamp when execution started.
    pub started_at: DateTime<Utc>,

    /// Timestamp when execution completed.
    pub completed_at: DateTime<Utc>,

    /// Exit code if the tool was a process.
    pub exit_code: Option<i32>,

    /// Bytes read during execution.
    pub bytes_read: u64,

    /// Bytes written during execution.
    pub bytes_written: u64,

    /// Whether the output was truncated.
    pub truncated: bool,

    /// Provider usage associated with this tool call (if applicable).
    pub provider_usage: Option<ProviderUsage>,
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// A message in the conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// Role of the message author.
    pub role: MessageRole,

    /// Textual content of the message.
    pub content: String,

    /// Tool calls requested by the assistant.
    #[serde(default)]
    pub tool_calls: Vec<ToolCall>,

    /// Results from tool executions.
    #[serde(default)]
    pub tool_results: Vec<ToolResult>,

    /// Timestamp when the message was created.
    #[serde(default = "Utc::now")]
    pub timestamp: DateTime<Utc>,

    /// Unique message identifier.
    #[serde(default = "generate_message_id")]
    pub id: String,

    /// Multimodal content blocks (when content alone is insufficient).
    #[serde(default)]
    pub content_blocks: Vec<ContentBlock>,
}

fn generate_message_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

// ---------------------------------------------------------------------------
// Multimodal content blocks
// ---------------------------------------------------------------------------

/// A content block within a message — supports text, images, audio, and video.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ContentBlock {
    /// Plain text content.
    Text { text: String },
    /// Image content (base64-encoded or URL reference).
    Image {
        data: Option<String>,
        url: Option<String>,
        media_type: String,
        alt_text: Option<String>,
    },
    /// Audio content (base64-encoded or URL reference).
    Audio {
        data: Option<String>,
        url: Option<String>,
        media_type: String,
        duration_secs: Option<f64>,
        transcript: Option<String>,
    },
    /// Video content (URL reference — too large for inline).
    Video {
        url: String,
        media_type: String,
        duration_secs: Option<f64>,
        thumbnail: Option<String>,
        transcript: Option<String>,
    },
    /// File attachment.
    File {
        data: Option<String>,
        url: Option<String>,
        filename: String,
        media_type: String,
        size_bytes: Option<u64>,
    },
}

impl ContentBlock {
    /// Create a text block.
    pub fn text(s: impl Into<String>) -> Self {
        Self::Text { text: s.into() }
    }

    /// Create an image block from base64 data.
    pub fn image_base64(data: String, media_type: &str) -> Self {
        Self::Image {
            data: Some(data),
            url: None,
            media_type: media_type.to_string(),
            alt_text: None,
        }
    }

    /// Create an image block from a URL.
    pub fn image_url(url: String, media_type: &str) -> Self {
        Self::Image {
            data: None,
            url: Some(url),
            media_type: media_type.to_string(),
            alt_text: None,
        }
    }

    /// Create an audio block from base64 data.
    pub fn audio_base64(data: String, media_type: &str) -> Self {
        Self::Audio {
            data: Some(data),
            url: None,
            media_type: media_type.to_string(),
            duration_secs: None,
            transcript: None,
        }
    }

    /// Create a video block from a URL.
    pub fn video_url(url: String, media_type: &str) -> Self {
        Self::Video {
            url,
            media_type: media_type.to_string(),
            duration_secs: None,
            thumbnail: None,
            transcript: None,
        }
    }

    /// Whether this block contains binary media (not text).
    pub fn is_media(&self) -> bool {
        !matches!(self, Self::Text { .. })
    }

    /// Extract text content if this is a text block.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text { text } => Some(text),
            _ => None,
        }
    }

    /// Estimate size in bytes (for DLP/cost purposes).
    pub fn estimated_size(&self) -> usize {
        match self {
            Self::Text { text } => text.len(),
            Self::Image { data, .. } => data.as_ref().map_or(0, |d| d.len()),
            Self::Audio { data, .. } => data.as_ref().map_or(0, |d| d.len()),
            Self::Video { .. } => 0,
            Self::File { data, size_bytes, .. } => {
                data.as_ref().map_or(size_bytes.unwrap_or(0) as usize, |d| d.len())
            }
        }
    }
}

/// Role of a message participant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MessageRole {
    /// System-level instructions injected by IronClaw.
    System,
    /// Input from the human user.
    User,
    /// Response from the LLM.
    Assistant,
    /// Output from a tool execution.
    Tool,
}

impl std::fmt::Display for MessageRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageRole::System => write!(f, "system"),
            MessageRole::User => write!(f, "user"),
            MessageRole::Assistant => write!(f, "assistant"),
            MessageRole::Tool => write!(f, "tool"),
        }
    }
}

// ---------------------------------------------------------------------------
// Tool calls
// ---------------------------------------------------------------------------

/// A tool call requested by the LLM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    /// Unique ID for this tool call (provider-assigned).
    pub id: String,

    /// Tool name.
    pub name: String,

    /// Tool arguments as a JSON map.
    pub arguments: HashMap<String, serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Security context
// ---------------------------------------------------------------------------

/// Security context carried through the request pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityContext {
    /// RBAC role of the caller.
    pub role: String,

    /// Active permission labels.
    pub permissions: Vec<String>,

    /// Session identifier for audit trail correlation.
    pub session_id: String,

    /// Whether an explicit human approval was granted for this action.
    pub approved: bool,

    /// IP address of the caller (if applicable).
    pub source_ip: Option<String>,

    /// Channel through which the request arrived.
    pub channel: Option<String>,

    /// User identifier (channel-specific).
    pub user_id: Option<String>,

    /// Timestamp of context creation.
    pub created_at: DateTime<Utc>,
}

impl SecurityContext {
    /// Create a new security context with minimal privileges.
    pub fn new(session_id: String) -> Self {
        Self {
            role: "default".to_string(),
            permissions: Vec::new(),
            session_id,
            approved: false,
            source_ip: None,
            channel: None,
            user_id: None,
            created_at: Utc::now(),
        }
    }

    /// Returns `true` if this context has the given permission.
    pub fn has_permission(&self, perm: &str) -> bool {
        self.permissions.iter().any(|p| p == perm)
    }
}

// ---------------------------------------------------------------------------
// Provider usage / cost tracking
// ---------------------------------------------------------------------------

/// Token usage and cost data for a single provider call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderUsage {
    /// Name of the provider (key in config).
    pub provider: String,

    /// Model used for this call.
    pub model: String,

    /// Number of input (prompt) tokens consumed.
    pub input_tokens: u64,

    /// Number of output (completion) tokens generated.
    pub output_tokens: u64,

    /// Total tokens (input + output).
    pub total_tokens: u64,

    /// Cost of input tokens in USD cents.
    pub input_cost_cents: f64,

    /// Cost of output tokens in USD cents.
    pub output_cost_cents: f64,

    /// Total cost in USD cents.
    pub total_cost_cents: f64,

    /// Latency of the provider call in milliseconds.
    pub latency_ms: u64,

    /// Timestamp of the call.
    pub timestamp: DateTime<Utc>,

    /// Whether the response was served from cache.
    pub cached: bool,
}

impl ProviderUsage {
    /// Build a new `ProviderUsage` computing totals automatically.
    pub fn new(
        provider: String,
        model: String,
        input_tokens: u64,
        output_tokens: u64,
        cost_per_1k_input: f64,
        cost_per_1k_output: f64,
        latency_ms: u64,
    ) -> Self {
        let input_cost_cents = (input_tokens as f64 / 1000.0) * cost_per_1k_input;
        let output_cost_cents = (output_tokens as f64 / 1000.0) * cost_per_1k_output;
        Self {
            provider,
            model,
            input_tokens,
            output_tokens,
            total_tokens: input_tokens + output_tokens,
            input_cost_cents,
            output_cost_cents,
            total_cost_cents: input_cost_cents + output_cost_cents,
            latency_ms,
            timestamp: Utc::now(),
            cached: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Channel messages
// ---------------------------------------------------------------------------

/// A message arriving from or destined to an external channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelMessage {
    /// Name of the channel (key in config).
    pub channel: String,

    /// Channel-specific sender identifier.
    pub sender_id: String,

    /// Display name of the sender.
    pub sender_name: Option<String>,

    /// Textual content of the message.
    pub content: String,

    /// Optional attachments (URLs or base64-encoded data).
    #[serde(default)]
    pub attachments: Vec<String>,

    /// Channel-native message ID for threading.
    pub message_id: Option<String>,

    /// Channel-native thread/conversation ID.
    pub thread_id: Option<String>,

    /// Timestamp when the message was received.
    pub received_at: DateTime<Utc>,

    /// Arbitrary metadata from the channel adapter.
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Session info
// ---------------------------------------------------------------------------

/// Information about an active agent session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    /// Unique session identifier.
    pub session_id: String,

    /// When the session started.
    pub started_at: DateTime<Utc>,

    /// When the session was last active.
    pub last_active_at: DateTime<Utc>,

    /// Number of turns completed so far.
    pub turn_count: u32,

    /// Number of tool calls executed.
    pub tool_call_count: u32,

    /// Accumulated provider usage for this session.
    pub total_usage: SessionUsageSummary,

    /// Active provider name.
    pub provider: String,

    /// Active model name.
    pub model: String,

    /// Channel this session is connected to (if any).
    pub channel: Option<String>,

    /// Security context for the session.
    pub security_context: SecurityContext,
}

/// Aggregated usage statistics for a session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionUsageSummary {
    /// Total input tokens across all calls.
    pub total_input_tokens: u64,

    /// Total output tokens across all calls.
    pub total_output_tokens: u64,

    /// Total cost in USD cents.
    pub total_cost_cents: f64,

    /// Number of provider API calls made.
    pub api_call_count: u64,

    /// Number of cache hits.
    pub cache_hits: u64,

    /// Average latency in milliseconds.
    pub avg_latency_ms: f64,
}

impl SessionUsageSummary {
    /// Accumulate a single provider usage record into this summary.
    pub fn record(&mut self, usage: &ProviderUsage) {
        self.total_input_tokens += usage.input_tokens;
        self.total_output_tokens += usage.output_tokens;
        self.total_cost_cents += usage.total_cost_cents;
        self.api_call_count += 1;
        if usage.cached {
            self.cache_hits += 1;
        }
        // Running average
        let n = self.api_call_count as f64;
        self.avg_latency_ms =
            self.avg_latency_ms * ((n - 1.0) / n) + (usage.latency_ms as f64 / n);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_level_ordering() {
        assert!(RiskLevel::Low < RiskLevel::Medium);
        assert!(RiskLevel::Medium < RiskLevel::High);
        assert!(RiskLevel::High < RiskLevel::Critical);
    }

    #[test]
    fn test_risk_level_display() {
        assert_eq!(RiskLevel::Low.to_string(), "LOW");
        assert_eq!(RiskLevel::Critical.to_string(), "CRITICAL");
    }

    #[test]
    fn test_risk_level_requires_approval() {
        assert!(!RiskLevel::Low.requires_approval());
        assert!(!RiskLevel::Medium.requires_approval());
        assert!(RiskLevel::High.requires_approval());
        assert!(RiskLevel::Critical.requires_approval());
    }

    #[test]
    fn test_provider_usage_cost_calculation() {
        let usage = ProviderUsage::new(
            "anthropic".to_string(),
            "claude-sonnet-4-20250514".to_string(),
            1000,
            500,
            0.3,  // $0.003 per 1k input
            1.5,  // $0.015 per 1k output
            200,
        );
        assert_eq!(usage.total_tokens, 1500);
        assert!((usage.input_cost_cents - 0.3).abs() < f64::EPSILON);
        assert!((usage.output_cost_cents - 0.75).abs() < f64::EPSILON);
        assert!((usage.total_cost_cents - 1.05).abs() < f64::EPSILON);
    }

    #[test]
    fn test_security_context_permissions() {
        let mut ctx = SecurityContext::new("test-session".to_string());
        assert!(!ctx.has_permission("admin"));
        ctx.permissions.push("admin".to_string());
        assert!(ctx.has_permission("admin"));
    }

    #[test]
    fn test_session_usage_summary_record() {
        let mut summary = SessionUsageSummary::default();
        let usage = ProviderUsage::new(
            "openai".to_string(),
            "gpt-4".to_string(),
            100,
            50,
            3.0,
            6.0,
            150,
        );
        summary.record(&usage);
        assert_eq!(summary.total_input_tokens, 100);
        assert_eq!(summary.total_output_tokens, 50);
        assert_eq!(summary.api_call_count, 1);
        assert!((summary.avg_latency_ms - 150.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_message_role_display() {
        assert_eq!(MessageRole::System.to_string(), "system");
        assert_eq!(MessageRole::User.to_string(), "user");
        assert_eq!(MessageRole::Assistant.to_string(), "assistant");
        assert_eq!(MessageRole::Tool.to_string(), "tool");
    }

    #[test]
    fn test_content_block_text() {
        let block = ContentBlock::text("hello world");
        assert_eq!(block.as_text(), Some("hello world"));
        assert!(!block.is_media());
    }

    #[test]
    fn test_content_block_image_base64() {
        let block = ContentBlock::image_base64("abc123".to_string(), "image/png");
        assert!(block.is_media());
        assert_eq!(block.as_text(), None);
    }

    #[test]
    fn test_content_block_is_media() {
        assert!(!ContentBlock::text("hi").is_media());
        assert!(ContentBlock::image_url("http://x".into(), "image/png").is_media());
        assert!(ContentBlock::audio_base64("data".into(), "audio/mp3").is_media());
        assert!(ContentBlock::video_url("http://v".into(), "video/mp4").is_media());
    }

    #[test]
    fn test_content_block_estimated_size() {
        assert_eq!(ContentBlock::text("hello").estimated_size(), 5);
        assert_eq!(
            ContentBlock::image_base64("abcdef".to_string(), "image/png").estimated_size(),
            6
        );
        assert_eq!(ContentBlock::video_url("http://x".into(), "video/mp4").estimated_size(), 0);
    }

    #[test]
    fn test_content_block_serialization() {
        let block = ContentBlock::text("test");
        let json = serde_json::to_string(&block).unwrap();
        assert!(json.contains("\"type\":\"Text\""));
        assert!(json.contains("\"text\":\"test\""));
    }
}
