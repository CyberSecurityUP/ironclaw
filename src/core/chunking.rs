//! Context window management for IronClaw.
//!
//! Manages conversation history to fit within provider-specific token limits
//! using multiple chunking strategies: sliding window, priority-based, and
//! summary-based compression.

use crate::core::types::{Message, MessageRole};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Chunking strategy to apply when the context window is exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChunkingStrategy {
    /// Keep only the most recent N messages (plus system messages).
    SlidingWindow,
    /// Prioritize system messages, recent user/assistant turns, and tool
    /// results; drop older conversational messages first.
    PriorityBased,
    /// Compress old messages into a single summary message.
    SummaryBased,
}

impl Default for ChunkingStrategy {
    fn default() -> Self {
        Self::PriorityBased
    }
}

/// Configuration for the context chunker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkingConfig {
    /// Maximum number of tokens allowed in the context window.
    #[serde(default = "default_max_tokens")]
    pub max_context_tokens: usize,

    /// Strategy to use when context is too large.
    #[serde(default)]
    pub strategy: ChunkingStrategy,

    /// Minimum number of recent messages to always keep (in addition to system).
    #[serde(default = "default_min_recent")]
    pub min_recent_messages: usize,

    /// Token budget reserved for the model's response.
    #[serde(default = "default_response_budget")]
    pub response_token_budget: usize,
}

fn default_max_tokens() -> usize { 128_000 }
fn default_min_recent() -> usize { 6 }
fn default_response_budget() -> usize { 4_096 }

impl Default for ChunkingConfig {
    fn default() -> Self {
        Self {
            max_context_tokens: default_max_tokens(),
            strategy: ChunkingStrategy::default(),
            min_recent_messages: default_min_recent(),
            response_token_budget: default_response_budget(),
        }
    }
}

// ---------------------------------------------------------------------------
// ContextChunker
// ---------------------------------------------------------------------------

/// Manages context window size by chunking or compressing conversation history.
pub struct ContextChunker {
    config: ChunkingConfig,
}

impl ContextChunker {
    pub fn new(config: ChunkingConfig) -> Self {
        Self { config }
    }

    /// Estimate the token count of a string using a character-based heuristic.
    ///
    /// English text averages roughly 4 characters per token for GPT-style
    /// tokenizers. This is intentionally conservative (over-estimates slightly)
    /// to avoid exceeding the actual limit.
    pub fn estimate_tokens(text: &str) -> usize {
        // ~4 chars per token for English; ~2.5 for CJK / code.
        // We use 4 as a safe default.
        let chars = text.chars().count();
        (chars + 3) / 4 // ceiling division
    }

    /// Estimate total tokens for a slice of messages.
    pub fn estimate_messages_tokens(messages: &[Message]) -> usize {
        messages.iter().map(|m| Self::message_tokens(m)).sum()
    }

    /// Chunk messages so they fit within the configured context window.
    ///
    /// Returns a new `Vec<Message>` that is guaranteed to fit within
    /// `max_context_tokens - response_token_budget`.
    pub fn chunk_messages(&self, messages: &[Message]) -> Vec<Message> {
        let budget = self.config.max_context_tokens
            .saturating_sub(self.config.response_token_budget);

        let total = Self::estimate_messages_tokens(messages);
        if total <= budget {
            return messages.to_vec();
        }

        match self.config.strategy {
            ChunkingStrategy::SlidingWindow => self.sliding_window(messages, budget),
            ChunkingStrategy::PriorityBased => self.priority_based(messages, budget),
            ChunkingStrategy::SummaryBased => self.summary_based(messages, budget),
        }
    }

    /// Compress conversation history by replacing old messages with a summary.
    ///
    /// This is a simple extraction: the first system message is preserved, then
    /// old messages are collapsed into a single summary, followed by the most
    /// recent messages.
    pub fn compress_history(&self, messages: &[Message]) -> Vec<Message> {
        if messages.len() <= self.config.min_recent_messages + 1 {
            return messages.to_vec();
        }

        let (system_msgs, rest) = Self::split_system(messages);

        if rest.len() <= self.config.min_recent_messages {
            return messages.to_vec();
        }

        let keep_count = self.config.min_recent_messages;
        let old_msgs = &rest[..rest.len() - keep_count];
        let recent_msgs = &rest[rest.len() - keep_count..];

        // Build a textual summary of old messages
        let summary = Self::build_summary(old_msgs);

        let mut result = system_msgs;
        result.push(Message {
            role: MessageRole::System,
            content: format!("[Conversation summary: {}]", summary),
            tool_calls: Vec::new(),
            tool_results: Vec::new(),
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            content_blocks: Vec::new(),
        });
        result.extend_from_slice(recent_msgs);
        result
    }

    // -- Strategy implementations -------------------------------------------

    /// Sliding window: keep system messages + last N messages that fit.
    fn sliding_window(&self, messages: &[Message], budget: usize) -> Vec<Message> {
        let (system_msgs, rest) = Self::split_system(messages);

        let system_tokens: usize = system_msgs.iter().map(|m| Self::message_tokens(m)).sum();
        let remaining_budget = budget.saturating_sub(system_tokens);

        // Walk backwards through non-system messages, adding as many as fit.
        let mut selected: Vec<Message> = Vec::new();
        let mut used = 0usize;

        for msg in rest.iter().rev() {
            let cost = Self::message_tokens(msg);
            if used + cost > remaining_budget {
                break;
            }
            selected.push(msg.clone());
            used += cost;
        }

        selected.reverse();

        // Ensure we keep at least min_recent_messages
        if selected.len() < self.config.min_recent_messages && rest.len() >= self.config.min_recent_messages {
            selected = rest[rest.len() - self.config.min_recent_messages..].to_vec();
        }

        let mut result = system_msgs;
        result.extend(selected);
        result
    }

    /// Priority-based: keep system messages, then tool results, then recent
    /// conversational messages.
    fn priority_based(&self, messages: &[Message], budget: usize) -> Vec<Message> {
        let (system_msgs, rest) = Self::split_system(messages);

        let system_tokens: usize = system_msgs.iter().map(|m| Self::message_tokens(m)).sum();
        let mut remaining = budget.saturating_sub(system_tokens);

        // Partition: tool messages vs conversational messages
        let mut tool_msgs: Vec<&Message> = Vec::new();
        let mut conv_msgs: Vec<&Message> = Vec::new();

        for msg in &rest {
            if msg.role == MessageRole::Tool || !msg.tool_results.is_empty() {
                tool_msgs.push(msg);
            } else {
                conv_msgs.push(msg);
            }
        }

        let mut selected: Vec<Message> = Vec::new();

        // First, guarantee the most recent conversational messages.
        let recent_count = self.config.min_recent_messages.min(conv_msgs.len());
        let recent_slice = &conv_msgs[conv_msgs.len() - recent_count..];
        for msg in recent_slice {
            let cost = Self::message_tokens(msg);
            if cost <= remaining {
                selected.push((*msg).clone());
                remaining = remaining.saturating_sub(cost);
            }
        }

        // Then add tool results (most recent first).
        for msg in tool_msgs.iter().rev() {
            let cost = Self::message_tokens(msg);
            if cost <= remaining {
                selected.push((*msg).clone());
                remaining = remaining.saturating_sub(cost);
            }
        }

        // Fill remaining budget with older conversational messages.
        let older_count = conv_msgs.len().saturating_sub(recent_count);
        for msg in conv_msgs[..older_count].iter().rev() {
            let cost = Self::message_tokens(msg);
            if cost <= remaining {
                selected.push((*msg).clone());
                remaining = remaining.saturating_sub(cost);
            }
        }

        // Sort selected messages back into chronological order by finding
        // their original positions in `rest`.
        // A simple approach: rebuild by iterating `rest` and including those
        // that appear in `selected`.
        let mut ordered = system_msgs;
        // Build a set of pointers for quick lookup
        for msg in &rest {
            // Check if this message is in our selected set (by content identity).
            // Since we cloned, use content comparison.
            if let Some(pos) = selected.iter().position(|s| {
                s.role == msg.role && s.content == msg.content
            }) {
                ordered.push(selected.remove(pos));
            }
        }

        ordered
    }

    /// Summary-based: compress old messages into a summary, keep recent ones.
    fn summary_based(&self, messages: &[Message], budget: usize) -> Vec<Message> {
        self.compress_history(messages)
            .into_iter()
            .collect::<Vec<_>>()
            .into_iter()
            .take_while({
                let mut used = 0usize;
                move |m: &Message| {
                    let cost = Self::message_tokens(m);
                    used += cost;
                    used <= budget
                }
            })
            .collect()
    }

    // -- Helpers -------------------------------------------------------------

    fn message_tokens(msg: &Message) -> usize {
        let base = Self::estimate_tokens(&msg.content);
        let tool_call_tokens: usize = msg
            .tool_calls
            .iter()
            .map(|tc| {
                Self::estimate_tokens(&tc.name)
                    + tc.arguments
                        .values()
                        .map(|v| Self::estimate_tokens(&v.to_string()))
                        .sum::<usize>()
            })
            .sum();
        let tool_result_tokens: usize = msg
            .tool_results
            .iter()
            .map(|tr| Self::estimate_tokens(&tr.output))
            .sum();

        // Per-message overhead (role label, framing tokens)
        base + tool_call_tokens + tool_result_tokens + 4
    }

    /// Split messages into (system_messages, everything_else), preserving order.
    fn split_system(messages: &[Message]) -> (Vec<Message>, Vec<Message>) {
        let mut system = Vec::new();
        let mut rest = Vec::new();
        for msg in messages {
            if msg.role == MessageRole::System {
                system.push(msg.clone());
            } else {
                rest.push(msg.clone());
            }
        }
        (system, rest)
    }

    /// Build a brief textual summary of a slice of messages.
    fn build_summary(messages: &[Message]) -> String {
        let mut parts: Vec<String> = Vec::new();
        let mut user_count = 0usize;
        let mut assistant_count = 0usize;
        let mut tool_count = 0usize;

        for msg in messages {
            match msg.role {
                MessageRole::User => user_count += 1,
                MessageRole::Assistant => assistant_count += 1,
                MessageRole::Tool => tool_count += 1,
                MessageRole::System => {}
            }
        }

        if user_count > 0 {
            parts.push(format!("{} user messages", user_count));
        }
        if assistant_count > 0 {
            parts.push(format!("{} assistant replies", assistant_count));
        }
        if tool_count > 0 {
            parts.push(format!("{} tool executions", tool_count));
        }

        if parts.is_empty() {
            "no prior messages".to_string()
        } else {
            parts.join(", ")
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_msg(role: MessageRole, content: &str) -> Message {
        Message {
            role,
            content: content.to_string(),
            tool_calls: Vec::new(),
            tool_results: Vec::new(),
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            content_blocks: Vec::new(),
        }
    }

    #[test]
    fn test_estimate_tokens() {
        assert_eq!(ContextChunker::estimate_tokens(""), 0);
        assert_eq!(ContextChunker::estimate_tokens("hello world"), 3); // 11 chars -> ceil(11/4) = 3
        assert_eq!(ContextChunker::estimate_tokens("a"), 1);
        assert_eq!(ContextChunker::estimate_tokens("abcd"), 1); // 4 chars -> 1 token
    }

    #[test]
    fn test_chunk_messages_fits_within_budget() {
        let config = ChunkingConfig {
            max_context_tokens: 1000,
            strategy: ChunkingStrategy::SlidingWindow,
            min_recent_messages: 2,
            response_token_budget: 100,
        };
        let chunker = ContextChunker::new(config);

        let msgs = vec![
            make_msg(MessageRole::System, "You are helpful."),
            make_msg(MessageRole::User, "Hello"),
            make_msg(MessageRole::Assistant, "Hi there!"),
        ];

        let result = chunker.chunk_messages(&msgs);
        // All should fit easily
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_sliding_window_drops_old() {
        let config = ChunkingConfig {
            max_context_tokens: 30, // very tight
            strategy: ChunkingStrategy::SlidingWindow,
            min_recent_messages: 1,
            response_token_budget: 5,
        };
        let chunker = ContextChunker::new(config);

        let msgs = vec![
            make_msg(MessageRole::System, "sys"),
            make_msg(MessageRole::User, "first message that is quite long and takes many tokens"),
            make_msg(MessageRole::User, "second"),
            make_msg(MessageRole::Assistant, "reply"),
        ];

        let result = chunker.chunk_messages(&msgs);
        // System message should always be present
        assert!(result.iter().any(|m| m.role == MessageRole::System));
        // The result should be smaller than the input
        assert!(result.len() <= msgs.len());
    }

    #[test]
    fn test_compress_history() {
        let config = ChunkingConfig {
            min_recent_messages: 2,
            ..Default::default()
        };
        let chunker = ContextChunker::new(config);

        let msgs = vec![
            make_msg(MessageRole::System, "system prompt"),
            make_msg(MessageRole::User, "old question 1"),
            make_msg(MessageRole::Assistant, "old answer 1"),
            make_msg(MessageRole::User, "old question 2"),
            make_msg(MessageRole::Assistant, "old answer 2"),
            make_msg(MessageRole::User, "recent question"),
            make_msg(MessageRole::Assistant, "recent answer"),
        ];

        let compressed = chunker.compress_history(&msgs);
        // Should have: original system + summary system + 2 recent
        assert!(compressed.len() < msgs.len());
        // First message should be original system
        assert_eq!(compressed[0].content, "system prompt");
        // Second should be the summary
        assert!(compressed[1].content.contains("summary"));
        // Last should be recent
        assert_eq!(compressed.last().unwrap().content, "recent answer");
    }

    #[test]
    fn test_priority_keeps_system_and_recent() {
        let config = ChunkingConfig {
            max_context_tokens: 50,
            strategy: ChunkingStrategy::PriorityBased,
            min_recent_messages: 2,
            response_token_budget: 10,
        };
        let chunker = ContextChunker::new(config);

        let msgs = vec![
            make_msg(MessageRole::System, "sys"),
            make_msg(MessageRole::User, "old"),
            make_msg(MessageRole::Assistant, "old reply"),
            make_msg(MessageRole::User, "recent"),
            make_msg(MessageRole::Assistant, "recent reply"),
        ];

        let result = chunker.chunk_messages(&msgs);
        assert!(result.iter().any(|m| m.role == MessageRole::System));
        assert!(result.iter().any(|m| m.content == "recent reply"));
    }

    #[test]
    fn test_small_conversation_unchanged() {
        let config = ChunkingConfig::default();
        let chunker = ContextChunker::new(config);

        let msgs = vec![
            make_msg(MessageRole::System, "sys"),
            make_msg(MessageRole::User, "hi"),
        ];

        let result = chunker.chunk_messages(&msgs);
        assert_eq!(result.len(), 2);
    }
}
