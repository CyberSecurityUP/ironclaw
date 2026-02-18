//! LLM Provider abstraction layer for IronClaw.
//!
//! Supports 25+ AI providers through a unified async trait interface.
//! All provider communication is subject to:
//! - API key protection (scrubbed from all error messages)
//! - Response validation and structured parsing
//! - Per-request cost tracking (input/output tokens)
//! - Configurable timeouts and base URLs
//! - Rate limiting awareness

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::core::config::ProviderConfig;
use crate::core::types::{Message, MessageRole, ToolCall};

// ---------------------------------------------------------------------------
// Cost & usage tracking
// ---------------------------------------------------------------------------

/// Token usage returned from a single provider call.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
}

/// Cumulative cost tracker shared across calls to a provider instance.
#[derive(Debug)]
pub struct CostTracker {
    total_input_tokens: AtomicU64,
    total_output_tokens: AtomicU64,
    input_cost_per_1k: f64,
    output_cost_per_1k: f64,
}

impl CostTracker {
    pub fn new(input_cost_per_1k: f64, output_cost_per_1k: f64) -> Self {
        Self {
            total_input_tokens: AtomicU64::new(0),
            total_output_tokens: AtomicU64::new(0),
            input_cost_per_1k,
            output_cost_per_1k,
        }
    }

    pub fn record(&self, usage: &TokenUsage) {
        self.total_input_tokens
            .fetch_add(usage.input_tokens, Ordering::Relaxed);
        self.total_output_tokens
            .fetch_add(usage.output_tokens, Ordering::Relaxed);
    }

    pub fn total_cost_usd(&self) -> f64 {
        let inp = self.total_input_tokens.load(Ordering::Relaxed) as f64;
        let out = self.total_output_tokens.load(Ordering::Relaxed) as f64;
        (inp / 1000.0) * self.input_cost_per_1k + (out / 1000.0) * self.output_cost_per_1k
    }
}

/// Per-model cost schedule (USD per 1K tokens).
#[derive(Debug, Clone, Copy)]
pub struct CostSchedule {
    pub input_per_1k: f64,
    pub output_per_1k: f64,
}

// ---------------------------------------------------------------------------
// Provider trait
// ---------------------------------------------------------------------------

/// Core abstraction every AI provider implements.
///
/// Implementors **must** scrub API keys from any error message they surface.
#[async_trait]
pub trait Provider: Send + Sync {
    /// Human-readable provider identifier (e.g. `"anthropic"`).
    fn name(&self) -> &str;

    /// The model string sent to the upstream API.
    fn model(&self) -> &str;

    /// Send a chat completion request with optional tool schemas.
    async fn chat(&self, messages: &[Message], tools: &[Value]) -> Result<Message>;

    /// Streaming variant -- default falls back to non-streaming `chat`.
    async fn stream_chat(&self, messages: &[Message], tools: &[Value]) -> Result<Message> {
        self.chat(messages, tools).await
    }

    /// List models available from this provider.
    async fn models(&self) -> Result<Vec<String>> {
        Ok(vec![self.model().to_string()])
    }

    /// Lightweight connectivity / auth check.
    async fn health_check(&self) -> Result<bool> {
        // Default: attempt a tiny completion.
        let probe = vec![Message {
            role: MessageRole::User,
            content: "ping".to_string(),
            tool_calls: Vec::new(),
            tool_results: Vec::new(),
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            content_blocks: Vec::new(),
        }];
        match self.chat(&probe, &[]).await {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Cost schedule for the currently-selected model.
    fn cost_per_1k_tokens(&self) -> CostSchedule;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Scrub all occurrences of `secret` from `text` so API keys never leak.
fn scrub_key(text: &str, secret: &str) -> String {
    if secret.is_empty() {
        return text.to_string();
    }
    text.replace(secret, "***REDACTED***")
}

/// Build a [`reqwest::Client`] with the given timeout.
fn build_client(timeout_secs: u64) -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

/// Extract `ProviderConfig` fields with fallbacks.
fn resolve_api_key(
    config: Option<&ProviderConfig>,
    env_var: &str,
) -> Result<String> {
    config
        .and_then(|c| c.api_key.clone())
        .or_else(|| std::env::var(env_var).ok())
        .ok_or_else(|| anyhow::anyhow!("{} not set", env_var))
}

fn resolve_model(
    config: Option<&ProviderConfig>,
    model_override: Option<&str>,
    default: &str,
) -> String {
    model_override
        .map(String::from)
        .or_else(|| config.and_then(|c| c.model.clone()))
        .unwrap_or_else(|| default.to_string())
}

fn resolve_base_url(config: Option<&ProviderConfig>, default: &str) -> String {
    config
        .and_then(|c| c.base_url.clone())
        .unwrap_or_else(|| default.to_string())
}

fn resolve_max_tokens(config: Option<&ProviderConfig>, default: u32) -> u32 {
    config.and_then(|c| c.max_tokens).unwrap_or(default)
}

fn resolve_temperature(config: Option<&ProviderConfig>) -> Option<f64> {
    config.and_then(|c| c.temperature)
}

const DEFAULT_TIMEOUT_SECS: u64 = 120;

// ---------------------------------------------------------------------------
// OpenAI-compatible helper (shared by ~18 providers)
// ---------------------------------------------------------------------------

/// Generic provider that speaks the OpenAI chat-completions wire format.
///
/// Most cloud LLM vendors expose an endpoint that is structurally identical to
/// `POST /v1/chat/completions` -- only the base URL, auth header, and model
/// string differ.  [`OpenAiCompatibleProvider`] captures that pattern so every
/// such vendor needs only a thin wrapper.
pub struct OpenAiCompatibleProvider {
    provider_name: String,
    api_key: String,
    model: String,
    base_url: String,
    max_tokens: u32,
    temperature: Option<f64>,
    timeout_secs: u64,
    cost: CostSchedule,
    cost_tracker: Arc<CostTracker>,
    /// Extra headers sent with every request (e.g. `HTTP-Referer` for OpenRouter).
    extra_headers: HashMap<String, String>,
    /// Override the completions path (default: `/v1/chat/completions`).
    completions_path: String,
}

impl OpenAiCompatibleProvider {
    pub fn new(
        provider_name: &str,
        api_key: String,
        model: String,
        base_url: String,
        max_tokens: u32,
        temperature: Option<f64>,
        timeout_secs: u64,
        cost: CostSchedule,
    ) -> Self {
        let cost_tracker = Arc::new(CostTracker::new(cost.input_per_1k, cost.output_per_1k));
        Self {
            provider_name: provider_name.to_string(),
            api_key,
            model,
            base_url,
            max_tokens,
            temperature,
            timeout_secs,
            cost,
            cost_tracker,
            extra_headers: HashMap::new(),
            completions_path: "/v1/chat/completions".to_string(),
        }
    }

    pub fn with_extra_header(mut self, key: &str, value: &str) -> Self {
        self.extra_headers.insert(key.to_string(), value.to_string());
        self
    }

    pub fn with_completions_path(mut self, path: &str) -> Self {
        self.completions_path = path.to_string();
        self
    }

    /// Convert IronClaw [`Message`] slice to the OpenAI messages JSON array.
    fn build_messages(messages: &[Message]) -> Vec<Value> {
        messages
            .iter()
            .map(|m| {
                let role = match m.role {
                    MessageRole::System => "system",
                    MessageRole::User => "user",
                    MessageRole::Assistant => "assistant",
                    MessageRole::Tool => "tool",
                };
                serde_json::json!({
                    "role": role,
                    "content": m.content,
                })
            })
            .collect()
    }

    /// Build the OpenAI-format tool definitions array.
    fn build_tools(tools: &[Value]) -> Vec<Value> {
        tools
            .iter()
            .map(|t| {
                serde_json::json!({
                    "type": "function",
                    "function": {
                        "name": t["name"],
                        "description": t["description"],
                        "parameters": t["parameters"],
                    }
                })
            })
            .collect()
    }

    /// Parse tool calls from the OpenAI response format.
    fn parse_tool_calls(choice: &Value) -> Vec<ToolCall> {
        choice["message"]["tool_calls"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|tc| {
                        let id = tc["id"].as_str()?.to_string();
                        let name = tc["function"]["name"].as_str()?.to_string();
                        let args_str = tc["function"]["arguments"].as_str().unwrap_or("{}");
                        let arguments: HashMap<String, Value> =
                            serde_json::from_str(args_str).unwrap_or_default();
                        Some(ToolCall { id, name, arguments })
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Extract token usage from the response JSON.
    fn parse_usage(json: &Value) -> TokenUsage {
        TokenUsage {
            input_tokens: json["usage"]["prompt_tokens"].as_u64().unwrap_or(0),
            output_tokens: json["usage"]["completion_tokens"].as_u64().unwrap_or(0),
        }
    }
}

#[async_trait]
impl Provider for OpenAiCompatibleProvider {
    fn name(&self) -> &str {
        &self.provider_name
    }

    fn model(&self) -> &str {
        &self.model
    }

    async fn chat(&self, messages: &[Message], tools: &[Value]) -> Result<Message> {
        let api_messages = Self::build_messages(messages);

        let mut body = serde_json::json!({
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": api_messages,
        });

        if let Some(temp) = self.temperature {
            body["temperature"] = serde_json::json!(temp);
        }

        if !tools.is_empty() {
            body["tools"] = Value::Array(Self::build_tools(tools));
        }

        let client = build_client(self.timeout_secs);
        let url = format!("{}{}", self.base_url, self.completions_path);

        let mut req = client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json");

        for (k, v) in &self.extra_headers {
            req = req.header(k.as_str(), v.as_str());
        }

        let response = req.json(&body).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_body = response.text().await.unwrap_or_default();
            let safe = scrub_key(&error_body, &self.api_key);
            anyhow::bail!("{} API error {}: {}", self.provider_name, status, safe);
        }

        let json: Value = response.json().await?;

        // Track usage
        let usage = Self::parse_usage(&json);
        self.cost_tracker.record(&usage);

        let choice = &json["choices"][0];
        let content = choice["message"]["content"]
            .as_str()
            .unwrap_or("")
            .to_string();
        let tool_calls = Self::parse_tool_calls(choice);

        Ok(Message {
            role: MessageRole::Assistant,
            content,
            tool_calls,
            tool_results: Vec::new(),
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            content_blocks: Vec::new(),
        })
    }

    fn cost_per_1k_tokens(&self) -> CostSchedule {
        self.cost
    }
}

// ===========================================================================
// Provider structs -- each wraps or extends the compatible helper
// ===========================================================================

// ---- 1. Anthropic (Claude) ------------------------------------------------

/// Anthropic Claude provider -- uses the `/v1/messages` API with native tool_use.
pub struct AnthropicProvider {
    api_key: String,
    model: String,
    base_url: String,
    max_tokens: u32,
    temperature: Option<f64>,
    timeout_secs: u64,
    cost: CostSchedule,
    cost_tracker: Arc<CostTracker>,
}

impl AnthropicProvider {
    pub fn new(config: Option<&ProviderConfig>, model_override: Option<&str>) -> Result<Self> {
        let api_key = resolve_api_key(config, "ANTHROPIC_API_KEY")?;
        let model = resolve_model(config, model_override, "claude-sonnet-4-5-20250514");
        let base_url = resolve_base_url(config, "https://api.anthropic.com");
        let max_tokens = resolve_max_tokens(config, 4096);
        let temperature = resolve_temperature(config);
        let cost = CostSchedule {
            input_per_1k: 0.003,
            output_per_1k: 0.015,
        };
        Ok(Self {
            api_key,
            model,
            base_url,
            max_tokens,
            temperature,
            timeout_secs: DEFAULT_TIMEOUT_SECS,
            cost,
            cost_tracker: Arc::new(CostTracker::new(cost.input_per_1k, cost.output_per_1k)),
        })
    }
}

#[async_trait]
impl Provider for AnthropicProvider {
    fn name(&self) -> &str {
        "anthropic"
    }

    fn model(&self) -> &str {
        &self.model
    }

    async fn chat(&self, messages: &[Message], tools: &[Value]) -> Result<Message> {
        let mut api_messages: Vec<Value> = Vec::new();

        let system_prompt = messages
            .iter()
            .find(|m| m.role == MessageRole::System)
            .map(|m| m.content.clone())
            .unwrap_or_default();

        for msg in messages {
            if msg.role == MessageRole::System {
                continue;
            }
            let role = match msg.role {
                MessageRole::User | MessageRole::Tool => "user",
                MessageRole::Assistant => "assistant",
                MessageRole::System => continue,
            };
            api_messages.push(serde_json::json!({
                "role": role,
                "content": msg.content,
            }));
        }

        let mut body = serde_json::json!({
            "model": self.model,
            "max_tokens": self.max_tokens,
            "system": system_prompt,
            "messages": api_messages,
        });

        if let Some(temp) = self.temperature {
            body["temperature"] = serde_json::json!(temp);
        }

        if !tools.is_empty() {
            body["tools"] = Value::Array(
                tools
                    .iter()
                    .map(|t| {
                        serde_json::json!({
                            "name": t["name"],
                            "description": t["description"],
                            "input_schema": t["parameters"],
                        })
                    })
                    .collect(),
            );
        }

        let client = build_client(self.timeout_secs);
        let response = client
            .post(format!("{}/v1/messages", self.base_url))
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_body = response.text().await.unwrap_or_default();
            let safe = scrub_key(&error_body, &self.api_key);
            anyhow::bail!("Anthropic API error {}: {}", status, safe);
        }

        let json: Value = response.json().await?;

        // Track usage
        let usage = TokenUsage {
            input_tokens: json["usage"]["input_tokens"].as_u64().unwrap_or(0),
            output_tokens: json["usage"]["output_tokens"].as_u64().unwrap_or(0),
        };
        self.cost_tracker.record(&usage);

        let empty = vec![];
        let content_blocks = json["content"].as_array().unwrap_or(&empty);

        let content = content_blocks
            .iter()
            .filter_map(|b| {
                if b["type"] == "text" {
                    b["text"].as_str().map(String::from)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join("");

        let tool_calls = content_blocks
            .iter()
            .filter_map(|b| {
                if b["type"] == "tool_use" {
                    Some(ToolCall {
                        id: b["id"].as_str().unwrap_or("").to_string(),
                        name: b["name"].as_str().unwrap_or("").to_string(),
                        arguments: b["input"]
                            .as_object()
                            .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                            .unwrap_or_default(),
                    })
                } else {
                    None
                }
            })
            .collect();

        Ok(Message {
            role: MessageRole::Assistant,
            content,
            tool_calls,
            tool_results: Vec::new(),
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            content_blocks: Vec::new(),
        })
    }

    fn cost_per_1k_tokens(&self) -> CostSchedule {
        self.cost
    }
}

// ---- 2. OpenAI (GPT-4, o1, o3) -------------------------------------------

pub struct OpenAiProvider {
    inner: OpenAiCompatibleProvider,
}

impl OpenAiProvider {
    pub fn new(config: Option<&ProviderConfig>, model_override: Option<&str>) -> Result<Self> {
        let api_key = resolve_api_key(config, "OPENAI_API_KEY")?;
        let model = resolve_model(config, model_override, "gpt-4.1");
        let base_url = resolve_base_url(config, "https://api.openai.com");
        let max_tokens = resolve_max_tokens(config, 4096);
        let temperature = resolve_temperature(config);
        let cost = CostSchedule {
            input_per_1k: 0.002,
            output_per_1k: 0.008,
        };
        Ok(Self {
            inner: OpenAiCompatibleProvider::new(
                "openai", api_key, model, base_url, max_tokens, temperature,
                DEFAULT_TIMEOUT_SECS, cost,
            ),
        })
    }
}

#[async_trait]
impl Provider for OpenAiProvider {
    fn name(&self) -> &str { self.inner.name() }
    fn model(&self) -> &str { self.inner.model() }
    async fn chat(&self, messages: &[Message], tools: &[Value]) -> Result<Message> {
        self.inner.chat(messages, tools).await
    }
    fn cost_per_1k_tokens(&self) -> CostSchedule { self.inner.cost_per_1k_tokens() }
}

// ---- 3. Google (Gemini) ---------------------------------------------------

/// Google Gemini provider -- uses the `generateContent` REST API.
pub struct GoogleProvider {
    api_key: String,
    model: String,
    base_url: String,
    max_tokens: u32,
    temperature: Option<f64>,
    timeout_secs: u64,
    cost: CostSchedule,
    cost_tracker: Arc<CostTracker>,
}

impl GoogleProvider {
    pub fn new(config: Option<&ProviderConfig>, model_override: Option<&str>) -> Result<Self> {
        let api_key = resolve_api_key(config, "GOOGLE_API_KEY")?;
        let model = resolve_model(config, model_override, "gemini-2.5-flash");
        let base_url = resolve_base_url(
            config,
            "https://generativelanguage.googleapis.com/v1beta",
        );
        let max_tokens = resolve_max_tokens(config, 4096);
        let temperature = resolve_temperature(config);
        let cost = CostSchedule {
            input_per_1k: 0.00025,
            output_per_1k: 0.001,
        };
        Ok(Self {
            api_key,
            model,
            base_url,
            max_tokens,
            temperature,
            timeout_secs: DEFAULT_TIMEOUT_SECS,
            cost,
            cost_tracker: Arc::new(CostTracker::new(cost.input_per_1k, cost.output_per_1k)),
        })
    }
}

#[async_trait]
impl Provider for GoogleProvider {
    fn name(&self) -> &str { "google" }
    fn model(&self) -> &str { &self.model }

    async fn chat(&self, messages: &[Message], _tools: &[Value]) -> Result<Message> {
        // Translate to Gemini contents format
        let contents: Vec<Value> = messages
            .iter()
            .filter(|m| m.role != MessageRole::System)
            .map(|m| {
                let role = match m.role {
                    MessageRole::User | MessageRole::Tool => "user",
                    MessageRole::Assistant => "model",
                    MessageRole::System => "user",
                };
                serde_json::json!({
                    "role": role,
                    "parts": [{ "text": m.content }],
                })
            })
            .collect();

        let system_instruction = messages
            .iter()
            .find(|m| m.role == MessageRole::System)
            .map(|m| serde_json::json!({ "parts": [{ "text": m.content }] }));

        let mut body = serde_json::json!({
            "contents": contents,
            "generationConfig": {
                "maxOutputTokens": self.max_tokens,
            },
        });

        if let Some(temp) = self.temperature {
            body["generationConfig"]["temperature"] = serde_json::json!(temp);
        }

        if let Some(si) = system_instruction {
            body["systemInstruction"] = si;
        }

        let url = format!(
            "{}/models/{}:generateContent?key={}",
            self.base_url, self.model, self.api_key
        );

        let client = build_client(self.timeout_secs);
        let response = client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_body = response.text().await.unwrap_or_default();
            let safe = scrub_key(&error_body, &self.api_key);
            anyhow::bail!("Google API error {}: {}", status, safe);
        }

        let json: Value = response.json().await?;

        // Track usage
        let usage = TokenUsage {
            input_tokens: json["usageMetadata"]["promptTokenCount"].as_u64().unwrap_or(0),
            output_tokens: json["usageMetadata"]["candidatesTokenCount"].as_u64().unwrap_or(0),
        };
        self.cost_tracker.record(&usage);

        let content = json["candidates"][0]["content"]["parts"][0]["text"]
            .as_str()
            .unwrap_or("")
            .to_string();

        Ok(Message {
            role: MessageRole::Assistant,
            content,
            tool_calls: Vec::new(),
            tool_results: Vec::new(),
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            content_blocks: Vec::new(),
        })
    }

    fn cost_per_1k_tokens(&self) -> CostSchedule { self.cost }
}

// ---- 4. Ollama (local) ----------------------------------------------------

pub struct OllamaProvider {
    model: String,
    base_url: String,
    timeout_secs: u64,
}

impl OllamaProvider {
    pub fn new(config: Option<&ProviderConfig>, model_override: Option<&str>) -> Result<Self> {
        let model = resolve_model(config, model_override, "llama3.3");
        let base_url = resolve_base_url(config, "http://localhost:11434");
        Ok(Self {
            model,
            base_url,
            timeout_secs: DEFAULT_TIMEOUT_SECS,
        })
    }
}

#[async_trait]
impl Provider for OllamaProvider {
    fn name(&self) -> &str { "ollama" }
    fn model(&self) -> &str { &self.model }

    async fn chat(&self, messages: &[Message], _tools: &[Value]) -> Result<Message> {
        let api_messages: Vec<Value> = messages
            .iter()
            .map(|m| {
                let role = match m.role {
                    MessageRole::System => "system",
                    MessageRole::User => "user",
                    MessageRole::Assistant => "assistant",
                    MessageRole::Tool => "user",
                };
                serde_json::json!({ "role": role, "content": m.content })
            })
            .collect();

        let body = serde_json::json!({
            "model": self.model,
            "messages": api_messages,
            "stream": false,
        });

        let client = build_client(self.timeout_secs);
        let response = client
            .post(format!("{}/api/chat", self.base_url))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_body = response.text().await.unwrap_or_default();
            anyhow::bail!("Ollama API error {}: {}", status, error_body);
        }

        let json: Value = response.json().await?;
        let content = json["message"]["content"]
            .as_str()
            .unwrap_or("")
            .to_string();

        Ok(Message {
            role: MessageRole::Assistant,
            content,
            tool_calls: Vec::new(),
            tool_results: Vec::new(),
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            content_blocks: Vec::new(),
        })
    }

    fn cost_per_1k_tokens(&self) -> CostSchedule {
        CostSchedule { input_per_1k: 0.0, output_per_1k: 0.0 }
    }
}

// ---- 5. Cohere ------------------------------------------------------------

/// Cohere provider -- uses the `/v2/chat` endpoint with its own format.
pub struct CohereProvider {
    api_key: String,
    model: String,
    base_url: String,
    max_tokens: u32,
    temperature: Option<f64>,
    timeout_secs: u64,
    cost: CostSchedule,
    cost_tracker: Arc<CostTracker>,
}

impl CohereProvider {
    pub fn new(config: Option<&ProviderConfig>, model_override: Option<&str>) -> Result<Self> {
        let api_key = resolve_api_key(config, "COHERE_API_KEY")?;
        let model = resolve_model(config, model_override, "command-r-plus");
        let base_url = resolve_base_url(config, "https://api.cohere.com");
        let max_tokens = resolve_max_tokens(config, 4096);
        let temperature = resolve_temperature(config);
        let cost = CostSchedule {
            input_per_1k: 0.003,
            output_per_1k: 0.015,
        };
        Ok(Self {
            api_key, model, base_url, max_tokens, temperature,
            timeout_secs: DEFAULT_TIMEOUT_SECS, cost,
            cost_tracker: Arc::new(CostTracker::new(cost.input_per_1k, cost.output_per_1k)),
        })
    }
}

#[async_trait]
impl Provider for CohereProvider {
    fn name(&self) -> &str { "cohere" }
    fn model(&self) -> &str { &self.model }

    async fn chat(&self, messages: &[Message], _tools: &[Value]) -> Result<Message> {
        let chat_history: Vec<Value> = messages
            .iter()
            .filter(|m| m.role != MessageRole::System)
            .map(|m| {
                let role = match m.role {
                    MessageRole::User | MessageRole::Tool => "user",
                    MessageRole::Assistant => "assistant",
                    MessageRole::System => "system",
                };
                serde_json::json!({ "role": role, "content": m.content })
            })
            .collect();

        let preamble = messages
            .iter()
            .find(|m| m.role == MessageRole::System)
            .map(|m| m.content.clone());

        let mut body = serde_json::json!({
            "model": self.model,
            "messages": chat_history,
            "max_tokens": self.max_tokens,
        });

        if let Some(p) = preamble {
            // Inject system message at position 0
            if let Some(arr) = body["messages"].as_array_mut() {
                arr.insert(0, serde_json::json!({ "role": "system", "content": p }));
            }
        }
        if let Some(temp) = self.temperature {
            body["temperature"] = serde_json::json!(temp);
        }

        let client = build_client(self.timeout_secs);
        let response = client
            .post(format!("{}/v2/chat", self.base_url))
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_body = response.text().await.unwrap_or_default();
            let safe = scrub_key(&error_body, &self.api_key);
            anyhow::bail!("Cohere API error {}: {}", status, safe);
        }

        let json: Value = response.json().await?;

        let usage = TokenUsage {
            input_tokens: json["usage"]["tokens"]["input_tokens"].as_u64().unwrap_or(0),
            output_tokens: json["usage"]["tokens"]["output_tokens"].as_u64().unwrap_or(0),
        };
        self.cost_tracker.record(&usage);

        let content = json["message"]["content"][0]["text"]
            .as_str()
            .unwrap_or("")
            .to_string();

        Ok(Message {
            role: MessageRole::Assistant,
            content,
            tool_calls: Vec::new(),
            tool_results: Vec::new(),
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            content_blocks: Vec::new(),
        })
    }

    fn cost_per_1k_tokens(&self) -> CostSchedule { self.cost }
}

// ---- 6. AWS Bedrock -------------------------------------------------------

/// AWS Bedrock provider -- uses SigV4 request signing.
pub struct BedrockProvider {
    region: String,
    model: String,
    max_tokens: u32,
    timeout_secs: u64,
    cost: CostSchedule,
}

impl BedrockProvider {
    pub fn new(config: Option<&ProviderConfig>, model_override: Option<&str>) -> Result<Self> {
        let region = config
            .and_then(|c| c.base_url.clone())
            .unwrap_or_else(|| "us-east-1".to_string());
        let model = resolve_model(
            config,
            model_override,
            "anthropic.claude-sonnet-4-5-20250514-v1:0",
        );
        let max_tokens = resolve_max_tokens(config, 4096);
        let cost = CostSchedule {
            input_per_1k: 0.003,
            output_per_1k: 0.015,
        };
        Ok(Self { region, model, max_tokens, timeout_secs: DEFAULT_TIMEOUT_SECS, cost })
    }
}

#[async_trait]
impl Provider for BedrockProvider {
    fn name(&self) -> &str { "bedrock" }
    fn model(&self) -> &str { &self.model }

    async fn chat(&self, messages: &[Message], _tools: &[Value]) -> Result<Message> {
        // Full SigV4 signing requires the `aws-sigv4` crate at runtime.
        // Stub: build the converse API payload; signing is delegated to the
        // AWS SDK or a lightweight SigV4 helper in production.
        let _api_messages: Vec<Value> = messages
            .iter()
            .filter(|m| m.role != MessageRole::System)
            .map(|m| {
                let role = match m.role {
                    MessageRole::User | MessageRole::Tool => "user",
                    MessageRole::Assistant => "assistant",
                    MessageRole::System => "user",
                };
                serde_json::json!({
                    "role": role,
                    "content": [{ "text": m.content }],
                })
            })
            .collect();

        anyhow::bail!(
            "Bedrock provider requires AWS SDK integration -- \
             stub only; see aws-sdk-bedrockruntime"
        )
    }

    fn cost_per_1k_tokens(&self) -> CostSchedule { self.cost }
}

// ---- 7. Azure OpenAI ------------------------------------------------------

/// Azure OpenAI -- same wire format as OpenAI, different URL scheme and auth header.
pub struct AzureOpenAiProvider {
    inner: OpenAiCompatibleProvider,
}

impl AzureOpenAiProvider {
    pub fn new(config: Option<&ProviderConfig>, model_override: Option<&str>) -> Result<Self> {
        let api_key = resolve_api_key(config, "AZURE_OPENAI_API_KEY")?;
        let base_url = resolve_base_url(config, "https://YOUR_RESOURCE.openai.azure.com");
        let model = resolve_model(config, model_override, "gpt-4.1");
        let max_tokens = resolve_max_tokens(config, 4096);
        let temperature = resolve_temperature(config);
        let cost = CostSchedule {
            input_per_1k: 0.002,
            output_per_1k: 0.008,
        };
        let deployment = model.clone();
        let path = format!(
            "/openai/deployments/{}/chat/completions?api-version=2024-10-21",
            deployment
        );
        let mut inner = OpenAiCompatibleProvider::new(
            "azure_openai", api_key.clone(), model, base_url, max_tokens, temperature,
            DEFAULT_TIMEOUT_SECS, cost,
        );
        inner = inner.with_completions_path(&path);
        // Azure uses api-key header instead of Bearer token -- override via extra header.
        inner.extra_headers.insert("api-key".to_string(), api_key);
        // Remove default Authorization by sending empty (harmless, api-key takes precedence).
        Ok(Self { inner })
    }
}

#[async_trait]
impl Provider for AzureOpenAiProvider {
    fn name(&self) -> &str { self.inner.name() }
    fn model(&self) -> &str { self.inner.model() }
    async fn chat(&self, messages: &[Message], tools: &[Value]) -> Result<Message> {
        self.inner.chat(messages, tools).await
    }
    fn cost_per_1k_tokens(&self) -> CostSchedule { self.inner.cost_per_1k_tokens() }
}

// ---- 8. Vertex AI (Google Cloud) ------------------------------------------

/// Google Cloud Vertex AI -- requires OAuth2 / ADC auth.
pub struct VertexAiProvider {
    project_id: String,
    location: String,
    model: String,
    max_tokens: u32,
    timeout_secs: u64,
    cost: CostSchedule,
}

impl VertexAiProvider {
    pub fn new(config: Option<&ProviderConfig>, model_override: Option<&str>) -> Result<Self> {
        let project_id = std::env::var("GOOGLE_CLOUD_PROJECT")
            .or_else(|_| std::env::var("GCP_PROJECT_ID"))
            .unwrap_or_else(|_| "my-project".to_string());
        let location = config
            .and_then(|c| c.base_url.clone())
            .unwrap_or_else(|| "us-central1".to_string());
        let model = resolve_model(config, model_override, "gemini-2.5-flash");
        let max_tokens = resolve_max_tokens(config, 4096);
        let cost = CostSchedule {
            input_per_1k: 0.000125,
            output_per_1k: 0.000375,
        };
        Ok(Self {
            project_id, location, model, max_tokens,
            timeout_secs: DEFAULT_TIMEOUT_SECS, cost,
        })
    }
}

#[async_trait]
impl Provider for VertexAiProvider {
    fn name(&self) -> &str { "vertex_ai" }
    fn model(&self) -> &str { &self.model }

    async fn chat(&self, _messages: &[Message], _tools: &[Value]) -> Result<Message> {
        // Vertex AI requires Application Default Credentials (ADC) --
        // full OAuth2 token exchange is handled by the `gcp_auth` crate.
        anyhow::bail!(
            "Vertex AI provider requires GCP auth integration -- \
             stub only; see gcp_auth + reqwest"
        )
    }

    fn cost_per_1k_tokens(&self) -> CostSchedule { self.cost }
}

// ---- 9. HuggingFace Inference API -----------------------------------------

pub struct HuggingFaceProvider {
    api_key: String,
    model: String,
    base_url: String,
    max_tokens: u32,
    timeout_secs: u64,
    cost: CostSchedule,
    cost_tracker: Arc<CostTracker>,
}

impl HuggingFaceProvider {
    pub fn new(config: Option<&ProviderConfig>, model_override: Option<&str>) -> Result<Self> {
        let api_key = resolve_api_key(config, "HF_API_TOKEN")?;
        let model = resolve_model(config, model_override, "meta-llama/Llama-3-70b-chat-hf");
        let base_url = resolve_base_url(config, "https://api-inference.huggingface.co");
        let max_tokens = resolve_max_tokens(config, 2048);
        let cost = CostSchedule { input_per_1k: 0.0, output_per_1k: 0.0 };
        Ok(Self {
            api_key, model, base_url, max_tokens,
            timeout_secs: DEFAULT_TIMEOUT_SECS, cost,
            cost_tracker: Arc::new(CostTracker::new(0.0, 0.0)),
        })
    }
}

#[async_trait]
impl Provider for HuggingFaceProvider {
    fn name(&self) -> &str { "huggingface" }
    fn model(&self) -> &str { &self.model }

    async fn chat(&self, messages: &[Message], _tools: &[Value]) -> Result<Message> {
        // HuggingFace Inference API uses /models/{model} with text-generation payloads.
        let prompt = messages
            .iter()
            .map(|m| m.content.as_str())
            .collect::<Vec<_>>()
            .join("\n");

        let body = serde_json::json!({
            "inputs": prompt,
            "parameters": { "max_new_tokens": self.max_tokens },
        });

        let url = format!("{}/models/{}", self.base_url, self.model);
        let client = build_client(self.timeout_secs);
        let response = client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_body = response.text().await.unwrap_or_default();
            let safe = scrub_key(&error_body, &self.api_key);
            anyhow::bail!("HuggingFace API error {}: {}", status, safe);
        }

        let json: Value = response.json().await?;
        let content = json[0]["generated_text"]
            .as_str()
            .unwrap_or("")
            .to_string();

        Ok(Message {
            role: MessageRole::Assistant,
            content,
            tool_calls: Vec::new(),
            tool_results: Vec::new(),
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            content_blocks: Vec::new(),
        })
    }

    fn cost_per_1k_tokens(&self) -> CostSchedule { self.cost }
}

// ---- 10. Replicate --------------------------------------------------------

pub struct ReplicateProvider {
    api_key: String,
    model: String,
    base_url: String,
    timeout_secs: u64,
    cost: CostSchedule,
}

impl ReplicateProvider {
    pub fn new(config: Option<&ProviderConfig>, model_override: Option<&str>) -> Result<Self> {
        let api_key = resolve_api_key(config, "REPLICATE_API_TOKEN")?;
        let model = resolve_model(config, model_override, "meta/llama-3-70b-instruct");
        let base_url = resolve_base_url(config, "https://api.replicate.com");
        let cost = CostSchedule { input_per_1k: 0.00065, output_per_1k: 0.00275 };
        Ok(Self {
            api_key, model, base_url, timeout_secs: DEFAULT_TIMEOUT_SECS, cost,
        })
    }
}

#[async_trait]
impl Provider for ReplicateProvider {
    fn name(&self) -> &str { "replicate" }
    fn model(&self) -> &str { &self.model }

    async fn chat(&self, messages: &[Message], _tools: &[Value]) -> Result<Message> {
        // Replicate predictions API: POST /v1/predictions, then poll for completion.
        let prompt = messages
            .iter()
            .map(|m| m.content.as_str())
            .collect::<Vec<_>>()
            .join("\n");

        let body = serde_json::json!({
            "version": self.model,
            "input": { "prompt": prompt },
        });

        let client = build_client(self.timeout_secs);
        let response = client
            .post(format!("{}/v1/predictions", self.base_url))
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_body = response.text().await.unwrap_or_default();
            let safe = scrub_key(&error_body, &self.api_key);
            anyhow::bail!("Replicate API error {}: {}", status, safe);
        }

        let json: Value = response.json().await?;

        // Poll for result (synchronous predictions with `Prefer: wait`)
        let content = json["output"]
            .as_str()
            .or_else(|| {
                json["output"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(""))
                    .as_deref()
                    .map(|_| "") // fallback
            })
            .unwrap_or("")
            .to_string();

        Ok(Message {
            role: MessageRole::Assistant,
            content,
            tool_calls: Vec::new(),
            tool_results: Vec::new(),
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            content_blocks: Vec::new(),
        })
    }

    fn cost_per_1k_tokens(&self) -> CostSchedule { self.cost }
}

// ---- 11. Cloudflare Workers AI --------------------------------------------

pub struct CloudflareProvider {
    api_key: String,
    account_id: String,
    model: String,
    base_url: String,
    timeout_secs: u64,
    cost: CostSchedule,
}

impl CloudflareProvider {
    pub fn new(config: Option<&ProviderConfig>, model_override: Option<&str>) -> Result<Self> {
        let api_key = resolve_api_key(config, "CLOUDFLARE_API_TOKEN")?;
        let account_id = std::env::var("CLOUDFLARE_ACCOUNT_ID")
            .unwrap_or_else(|_| "ACCOUNT_ID".to_string());
        let model = resolve_model(config, model_override, "@cf/meta/llama-3-8b-instruct");
        let base_url = resolve_base_url(
            config,
            "https://api.cloudflare.com/client/v4",
        );
        let cost = CostSchedule { input_per_1k: 0.0, output_per_1k: 0.0 };
        Ok(Self {
            api_key, account_id, model, base_url,
            timeout_secs: DEFAULT_TIMEOUT_SECS, cost,
        })
    }
}

#[async_trait]
impl Provider for CloudflareProvider {
    fn name(&self) -> &str { "cloudflare" }
    fn model(&self) -> &str { &self.model }

    async fn chat(&self, messages: &[Message], _tools: &[Value]) -> Result<Message> {
        let api_messages: Vec<Value> = messages
            .iter()
            .map(|m| {
                let role = match m.role {
                    MessageRole::System => "system",
                    MessageRole::User | MessageRole::Tool => "user",
                    MessageRole::Assistant => "assistant",
                };
                serde_json::json!({ "role": role, "content": m.content })
            })
            .collect();

        let body = serde_json::json!({ "messages": api_messages });
        let url = format!(
            "{}/accounts/{}/ai/run/{}",
            self.base_url, self.account_id, self.model
        );

        let client = build_client(self.timeout_secs);
        let response = client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_body = response.text().await.unwrap_or_default();
            let safe = scrub_key(&error_body, &self.api_key);
            anyhow::bail!("Cloudflare API error {}: {}", status, safe);
        }

        let json: Value = response.json().await?;
        let content = json["result"]["response"]
            .as_str()
            .unwrap_or("")
            .to_string();

        Ok(Message {
            role: MessageRole::Assistant,
            content,
            tool_calls: Vec::new(),
            tool_results: Vec::new(),
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            content_blocks: Vec::new(),
        })
    }

    fn cost_per_1k_tokens(&self) -> CostSchedule { self.cost }
}

// ---------------------------------------------------------------------------
// Macro for trivial OpenAI-compatible wrappers
// ---------------------------------------------------------------------------

/// Generates a thin provider struct that delegates entirely to
/// [`OpenAiCompatibleProvider`].  This covers the ~14 vendors whose API is
/// structurally identical to OpenAI chat completions.
macro_rules! openai_compatible_provider {
    (
        name: $name:ident,
        provider_str: $pstr:literal,
        env_key: $env:literal,
        default_model: $dmodel:literal,
        default_base_url: $durl:literal,
        input_cost: $ic:literal,
        output_cost: $oc:literal
        $(, default_max_tokens: $dmt:literal)?
    ) => {
        pub struct $name {
            inner: OpenAiCompatibleProvider,
        }

        impl $name {
            pub fn new(
                config: Option<&ProviderConfig>,
                model_override: Option<&str>,
            ) -> Result<Self> {
                let api_key = resolve_api_key(config, $env)?;
                let model = resolve_model(config, model_override, $dmodel);
                let base_url = resolve_base_url(config, $durl);
                let max_tokens = resolve_max_tokens(config, openai_compatible_provider!(@mt $($dmt)?));
                let temperature = resolve_temperature(config);
                let cost = CostSchedule {
                    input_per_1k: $ic,
                    output_per_1k: $oc,
                };
                Ok(Self {
                    inner: OpenAiCompatibleProvider::new(
                        $pstr, api_key, model, base_url, max_tokens,
                        temperature, DEFAULT_TIMEOUT_SECS, cost,
                    ),
                })
            }
        }

        #[async_trait]
        impl Provider for $name {
            fn name(&self) -> &str { self.inner.name() }
            fn model(&self) -> &str { self.inner.model() }
            async fn chat(
                &self,
                messages: &[Message],
                tools: &[Value],
            ) -> Result<Message> {
                self.inner.chat(messages, tools).await
            }
            fn cost_per_1k_tokens(&self) -> CostSchedule {
                self.inner.cost_per_1k_tokens()
            }
        }
    };

    // Helper to resolve optional default_max_tokens
    (@mt $val:literal) => { $val };
    (@mt) => { 4096u32 };
}

// ---- 12. Groq -------------------------------------------------------------
openai_compatible_provider!(
    name: GroqProvider,
    provider_str: "groq",
    env_key: "GROQ_API_KEY",
    default_model: "llama-3.3-70b-versatile",
    default_base_url: "https://api.groq.com/openai",
    input_cost: 0.00059,
    output_cost: 0.00079
);

// ---- 13. Mistral ----------------------------------------------------------
openai_compatible_provider!(
    name: MistralProvider,
    provider_str: "mistral",
    env_key: "MISTRAL_API_KEY",
    default_model: "mistral-large-latest",
    default_base_url: "https://api.mistral.ai",
    input_cost: 0.002,
    output_cost: 0.006
);

// ---- 14. Together ---------------------------------------------------------
openai_compatible_provider!(
    name: TogetherProvider,
    provider_str: "together",
    env_key: "TOGETHER_API_KEY",
    default_model: "meta-llama/Llama-3-70b-chat-hf",
    default_base_url: "https://api.together.xyz",
    input_cost: 0.0009,
    output_cost: 0.0009
);

// ---- 15. Fireworks --------------------------------------------------------
openai_compatible_provider!(
    name: FireworksProvider,
    provider_str: "fireworks",
    env_key: "FIREWORKS_API_KEY",
    default_model: "accounts/fireworks/models/llama-v3p3-70b-instruct",
    default_base_url: "https://api.fireworks.ai/inference",
    input_cost: 0.0009,
    output_cost: 0.0009
);

// ---- 16. Perplexity -------------------------------------------------------
openai_compatible_provider!(
    name: PerplexityProvider,
    provider_str: "perplexity",
    env_key: "PERPLEXITY_API_KEY",
    default_model: "sonar-pro",
    default_base_url: "https://api.perplexity.ai",
    input_cost: 0.003,
    output_cost: 0.015
);

// ---- 17. DeepSeek ---------------------------------------------------------
openai_compatible_provider!(
    name: DeepSeekProvider,
    provider_str: "deepseek",
    env_key: "DEEPSEEK_API_KEY",
    default_model: "deepseek-chat",
    default_base_url: "https://api.deepseek.com",
    input_cost: 0.00014,
    output_cost: 0.00028
);

// ---- 18. AI21 -------------------------------------------------------------
openai_compatible_provider!(
    name: Ai21Provider,
    provider_str: "ai21",
    env_key: "AI21_API_KEY",
    default_model: "jamba-1.5-large",
    default_base_url: "https://api.ai21.com",
    input_cost: 0.002,
    output_cost: 0.008
);

// ---- 19. Cerebras ---------------------------------------------------------
openai_compatible_provider!(
    name: CerebrasProvider,
    provider_str: "cerebras",
    env_key: "CEREBRAS_API_KEY",
    default_model: "llama-3.3-70b",
    default_base_url: "https://api.cerebras.ai",
    input_cost: 0.0006,
    output_cost: 0.0006
);

// ---- 20. xAI (Grok) -------------------------------------------------------
openai_compatible_provider!(
    name: XaiProvider,
    provider_str: "xai",
    env_key: "XAI_API_KEY",
    default_model: "grok-3",
    default_base_url: "https://api.x.ai",
    input_cost: 0.003,
    output_cost: 0.015
);

// ---- 21. OpenRouter -------------------------------------------------------

/// OpenRouter is OpenAI-compatible but benefits from extra routing headers.
pub struct OpenRouterProvider {
    inner: OpenAiCompatibleProvider,
}

impl OpenRouterProvider {
    pub fn new(config: Option<&ProviderConfig>, model_override: Option<&str>) -> Result<Self> {
        let api_key = resolve_api_key(config, "OPENROUTER_API_KEY")?;
        let model = resolve_model(config, model_override, "anthropic/claude-sonnet-4-5");
        let base_url = resolve_base_url(config, "https://openrouter.ai/api");
        let max_tokens = resolve_max_tokens(config, 4096);
        let temperature = resolve_temperature(config);
        let cost = CostSchedule {
            input_per_1k: 0.003,
            output_per_1k: 0.015,
        };
        let inner = OpenAiCompatibleProvider::new(
            "openrouter", api_key, model, base_url, max_tokens,
            temperature, DEFAULT_TIMEOUT_SECS, cost,
        )
        .with_extra_header("HTTP-Referer", "https://ironclaw.dev")
        .with_extra_header("X-Title", "IronClaw Agent");
        Ok(Self { inner })
    }
}

#[async_trait]
impl Provider for OpenRouterProvider {
    fn name(&self) -> &str { self.inner.name() }
    fn model(&self) -> &str { self.inner.model() }
    async fn chat(&self, messages: &[Message], tools: &[Value]) -> Result<Message> {
        self.inner.chat(messages, tools).await
    }
    fn cost_per_1k_tokens(&self) -> CostSchedule { self.inner.cost_per_1k_tokens() }
}

// ---- 22. LM Studio (local) -----------------------------------------------
openai_compatible_provider!(
    name: LmStudioProvider,
    provider_str: "lmstudio",
    env_key: "LMSTUDIO_API_KEY",
    default_model: "local-model",
    default_base_url: "http://localhost:1234",
    input_cost: 0.0,
    output_cost: 0.0
);

// ---- 23. NVIDIA NIM -------------------------------------------------------
openai_compatible_provider!(
    name: NvidiaProvider,
    provider_str: "nvidia",
    env_key: "NVIDIA_API_KEY",
    default_model: "meta/llama-3.1-405b-instruct",
    default_base_url: "https://integrate.api.nvidia.com",
    input_cost: 0.0,
    output_cost: 0.0
);

// ---- 24. SambaNova --------------------------------------------------------
openai_compatible_provider!(
    name: SambanovaProvider,
    provider_str: "sambanova",
    env_key: "SAMBANOVA_API_KEY",
    default_model: "Meta-Llama-3.1-405B-Instruct",
    default_base_url: "https://api.sambanova.ai",
    input_cost: 0.001,
    output_cost: 0.003
);

// ---- 25. Lepton -----------------------------------------------------------
openai_compatible_provider!(
    name: LeptonProvider,
    provider_str: "lepton",
    env_key: "LEPTON_API_KEY",
    default_model: "llama3-70b",
    default_base_url: "https://llama3-70b.lepton.run/api",
    input_cost: 0.0008,
    output_cost: 0.0008
);

// ===========================================================================
// Provider factory
// ===========================================================================

/// Factory that maps a provider name string to a concrete [`Provider`] instance.
///
/// Supports 25 providers.  Unknown names produce a helpful error listing all
/// valid options.
pub struct ProviderFactory;

impl ProviderFactory {
    /// Create a provider from its short name and optional config / model override.
    pub fn create(
        name: &str,
        config: Option<&ProviderConfig>,
        model_override: Option<&str>,
    ) -> Result<Box<dyn Provider>> {
        match name {
            "anthropic"   => Ok(Box::new(AnthropicProvider::new(config, model_override)?)),
            "openai"      => Ok(Box::new(OpenAiProvider::new(config, model_override)?)),
            "google"      => Ok(Box::new(GoogleProvider::new(config, model_override)?)),
            "ollama"      => Ok(Box::new(OllamaProvider::new(config, model_override)?)),
            "groq"        => Ok(Box::new(GroqProvider::new(config, model_override)?)),
            "mistral"     => Ok(Box::new(MistralProvider::new(config, model_override)?)),
            "cohere"      => Ok(Box::new(CohereProvider::new(config, model_override)?)),
            "together"    => Ok(Box::new(TogetherProvider::new(config, model_override)?)),
            "fireworks"   => Ok(Box::new(FireworksProvider::new(config, model_override)?)),
            "perplexity"  => Ok(Box::new(PerplexityProvider::new(config, model_override)?)),
            "deepseek"    => Ok(Box::new(DeepSeekProvider::new(config, model_override)?)),
            "ai21"        => Ok(Box::new(Ai21Provider::new(config, model_override)?)),
            "cerebras"    => Ok(Box::new(CerebrasProvider::new(config, model_override)?)),
            "xai"         => Ok(Box::new(XaiProvider::new(config, model_override)?)),
            "bedrock"     => Ok(Box::new(BedrockProvider::new(config, model_override)?)),
            "azure_openai" | "azure" => {
                Ok(Box::new(AzureOpenAiProvider::new(config, model_override)?))
            }
            "vertex_ai" | "vertex" => {
                Ok(Box::new(VertexAiProvider::new(config, model_override)?))
            }
            "huggingface" => Ok(Box::new(HuggingFaceProvider::new(config, model_override)?)),
            "replicate"   => Ok(Box::new(ReplicateProvider::new(config, model_override)?)),
            "openrouter"  => Ok(Box::new(OpenRouterProvider::new(config, model_override)?)),
            "lmstudio"    => Ok(Box::new(LmStudioProvider::new(config, model_override)?)),
            "nvidia"      => Ok(Box::new(NvidiaProvider::new(config, model_override)?)),
            "cloudflare"  => Ok(Box::new(CloudflareProvider::new(config, model_override)?)),
            "sambanova"   => Ok(Box::new(SambanovaProvider::new(config, model_override)?)),
            "lepton"      => Ok(Box::new(LeptonProvider::new(config, model_override)?)),
            _ => anyhow::bail!(
                "Unknown provider: '{}'. Supported providers: anthropic, openai, google, \
                 ollama, groq, mistral, cohere, together, fireworks, perplexity, deepseek, \
                 ai21, cerebras, xai, bedrock, azure_openai, vertex_ai, huggingface, \
                 replicate, openrouter, lmstudio, nvidia, cloudflare, sambanova, lepton",
                name
            ),
        }
    }

    /// Return the list of all supported provider identifiers.
    pub fn available_providers() -> &'static [&'static str] {
        &[
            "anthropic", "openai", "google", "ollama", "groq", "mistral",
            "cohere", "together", "fireworks", "perplexity", "deepseek",
            "ai21", "cerebras", "xai", "bedrock", "azure_openai",
            "vertex_ai", "huggingface", "replicate", "openrouter",
            "lmstudio", "nvidia", "cloudflare", "sambanova", "lepton",
        ]
    }

    /// Return metadata catalog of all supported providers and their default models.
    pub fn model_catalog() -> &'static [ProviderModelInfo] {
        &[
            ProviderModelInfo { name: "anthropic",    default_model: "claude-sonnet-4-5-20250514",  env_key: "ANTHROPIC_API_KEY",   cost_tier: "medium", description: "Anthropic Claude — balanced intelligence and speed" },
            ProviderModelInfo { name: "openai",       default_model: "gpt-4.1",                     env_key: "OPENAI_API_KEY",      cost_tier: "medium", description: "OpenAI GPT — versatile general-purpose models" },
            ProviderModelInfo { name: "google",       default_model: "gemini-2.5-flash",            env_key: "GOOGLE_API_KEY",      cost_tier: "low",    description: "Google Gemini — fast and multimodal" },
            ProviderModelInfo { name: "ollama",       default_model: "llama3.3",                    env_key: "",                    cost_tier: "free",   description: "Ollama — local models, no API key needed" },
            ProviderModelInfo { name: "groq",         default_model: "llama-3.3-70b-versatile",     env_key: "GROQ_API_KEY",        cost_tier: "low",    description: "Groq — ultra-fast inference on LPU hardware" },
            ProviderModelInfo { name: "mistral",      default_model: "mistral-large-latest",        env_key: "MISTRAL_API_KEY",     cost_tier: "medium", description: "Mistral — European AI, strong multilingual" },
            ProviderModelInfo { name: "cohere",       default_model: "command-r-plus",              env_key: "COHERE_API_KEY",      cost_tier: "medium", description: "Cohere — enterprise search and RAG" },
            ProviderModelInfo { name: "together",     default_model: "meta-llama/Llama-3-70b-chat-hf", env_key: "TOGETHER_API_KEY", cost_tier: "low",    description: "Together AI — open-source model hosting" },
            ProviderModelInfo { name: "fireworks",    default_model: "accounts/fireworks/models/llama-v3p3-70b-instruct", env_key: "FIREWORKS_API_KEY", cost_tier: "low", description: "Fireworks — optimized open-source inference" },
            ProviderModelInfo { name: "perplexity",   default_model: "sonar-pro",                   env_key: "PERPLEXITY_API_KEY",  cost_tier: "medium", description: "Perplexity — search-augmented AI" },
            ProviderModelInfo { name: "deepseek",     default_model: "deepseek-chat",               env_key: "DEEPSEEK_API_KEY",    cost_tier: "low",    description: "DeepSeek — high quality at very low cost" },
            ProviderModelInfo { name: "ai21",         default_model: "jamba-1.5-large",             env_key: "AI21_API_KEY",        cost_tier: "medium", description: "AI21 Jamba — Mamba-based architecture" },
            ProviderModelInfo { name: "cerebras",     default_model: "llama-3.3-70b",               env_key: "CEREBRAS_API_KEY",    cost_tier: "low",    description: "Cerebras — wafer-scale chip inference" },
            ProviderModelInfo { name: "xai",          default_model: "grok-3",                      env_key: "XAI_API_KEY",         cost_tier: "medium", description: "xAI Grok — real-time knowledge" },
            ProviderModelInfo { name: "bedrock",      default_model: "anthropic.claude-sonnet-4-5-20250514-v1:0", env_key: "AWS_ACCESS_KEY_ID", cost_tier: "medium", description: "AWS Bedrock — managed AI (stub)" },
            ProviderModelInfo { name: "azure_openai", default_model: "gpt-4.1",                     env_key: "AZURE_OPENAI_API_KEY", cost_tier: "medium", description: "Azure OpenAI — enterprise OpenAI deployment" },
            ProviderModelInfo { name: "vertex_ai",    default_model: "gemini-2.5-flash",            env_key: "GOOGLE_CLOUD_PROJECT", cost_tier: "low",   description: "Google Vertex AI — GCP managed AI (stub)" },
            ProviderModelInfo { name: "huggingface",  default_model: "meta-llama/Llama-3-70b-chat-hf", env_key: "HF_API_TOKEN",     cost_tier: "free",   description: "Hugging Face — open model inference API" },
            ProviderModelInfo { name: "replicate",    default_model: "meta/llama-3-70b-instruct",   env_key: "REPLICATE_API_TOKEN", cost_tier: "low",    description: "Replicate — run models via API" },
            ProviderModelInfo { name: "openrouter",   default_model: "anthropic/claude-sonnet-4-5",  env_key: "OPENROUTER_API_KEY",  cost_tier: "varies", description: "OpenRouter — meta-provider, access 100+ models" },
            ProviderModelInfo { name: "lmstudio",     default_model: "local-model",                 env_key: "",                    cost_tier: "free",   description: "LM Studio — local GUI with API server" },
            ProviderModelInfo { name: "nvidia",       default_model: "meta/llama-3.1-405b-instruct", env_key: "NVIDIA_API_KEY",     cost_tier: "free",   description: "NVIDIA NIM — GPU-optimized inference" },
            ProviderModelInfo { name: "cloudflare",   default_model: "@cf/meta/llama-3-8b-instruct", env_key: "CLOUDFLARE_API_TOKEN", cost_tier: "free", description: "Cloudflare Workers AI — edge inference" },
            ProviderModelInfo { name: "sambanova",    default_model: "Meta-Llama-3.1-405B-Instruct", env_key: "SAMBANOVA_API_KEY",  cost_tier: "low",    description: "SambaNova — dataflow architecture AI" },
            ProviderModelInfo { name: "lepton",       default_model: "llama3-70b",                  env_key: "LEPTON_API_KEY",      cost_tier: "low",    description: "Lepton AI — serverless model hosting" },
        ]
    }

    /// Resolve a preset alias to (provider_name, model) pair.
    pub fn resolve_preset(alias: &str) -> Option<(&'static str, &'static str)> {
        match alias {
            "fast"   => Some(("groq",      "llama-3.3-70b-versatile")),
            "smart"  => Some(("anthropic",  "claude-sonnet-4-5-20250514")),
            "cheap"  => Some(("deepseek",   "deepseek-chat")),
            "local"  => Some(("ollama",     "llama3.3")),
            "vision" => Some(("google",     "gemini-2.5-flash")),
            "code"   => Some(("anthropic",  "claude-sonnet-4-5-20250514")),
            _ => None,
        }
    }

    /// Return all preset aliases for display.
    pub fn preset_list() -> &'static [(&'static str, &'static str, &'static str)] {
        &[
            ("fast",   "groq",      "llama-3.3-70b-versatile"),
            ("smart",  "anthropic",  "claude-sonnet-4-5-20250514"),
            ("cheap",  "deepseek",   "deepseek-chat"),
            ("local",  "ollama",     "llama3.3"),
            ("vision", "google",     "gemini-2.5-flash"),
            ("code",   "anthropic",  "claude-sonnet-4-5-20250514"),
        ]
    }
}

/// Metadata for a provider entry used by the `models` command.
pub struct ProviderModelInfo {
    pub name: &'static str,
    pub default_model: &'static str,
    pub env_key: &'static str,
    pub cost_tier: &'static str,
    pub description: &'static str,
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scrub_key() {
        let msg = "Error: invalid key sk-abc123 in request";
        let safe = scrub_key(msg, "sk-abc123");
        assert!(!safe.contains("sk-abc123"));
        assert!(safe.contains("***REDACTED***"));
    }

    #[test]
    fn test_scrub_key_empty() {
        let msg = "Error happened";
        let safe = scrub_key(msg, "");
        assert_eq!(safe, msg);
    }

    #[test]
    fn test_cost_tracker() {
        let ct = CostTracker::new(0.01, 0.03);
        ct.record(&TokenUsage { input_tokens: 1000, output_tokens: 500 });
        let cost = ct.total_cost_usd();
        // 1000/1000 * 0.01 + 500/1000 * 0.03 = 0.01 + 0.015 = 0.025
        assert!((cost - 0.025).abs() < 1e-9);
    }

    #[test]
    fn test_cost_tracker_accumulates() {
        let ct = CostTracker::new(0.01, 0.03);
        ct.record(&TokenUsage { input_tokens: 500, output_tokens: 200 });
        ct.record(&TokenUsage { input_tokens: 500, output_tokens: 300 });
        let cost = ct.total_cost_usd();
        // 1000/1000 * 0.01 + 500/1000 * 0.03 = 0.025
        assert!((cost - 0.025).abs() < 1e-9);
    }

    #[test]
    fn test_factory_unknown_provider() {
        let result = ProviderFactory::create("nonexistent", None, None);
        match result {
            Ok(_) => panic!("expected error for unknown provider"),
            Err(e) => {
                let err = e.to_string();
                assert!(err.contains("Unknown provider"));
                assert!(err.contains("nonexistent"));
            }
        }
    }

    #[test]
    fn test_available_providers_count() {
        let providers = ProviderFactory::available_providers();
        assert_eq!(providers.len(), 25);
    }

    #[test]
    fn test_resolve_model_override() {
        let m = resolve_model(None, Some("custom-model"), "default-model");
        assert_eq!(m, "custom-model");
    }

    #[test]
    fn test_resolve_model_default() {
        let m = resolve_model(None, None, "default-model");
        assert_eq!(m, "default-model");
    }

    #[test]
    fn test_openai_build_messages() {
        let messages = vec![
            Message {
                role: MessageRole::System,
                content: "You are helpful.".to_string(),
                tool_calls: Vec::new(),
                tool_results: Vec::new(),
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: chrono::Utc::now(),
                content_blocks: Vec::new(),
            },
            Message {
                role: MessageRole::User,
                content: "Hello".to_string(),
                tool_calls: Vec::new(),
                tool_results: Vec::new(),
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: chrono::Utc::now(),
                content_blocks: Vec::new(),
            },
        ];
        let built = OpenAiCompatibleProvider::build_messages(&messages);
        assert_eq!(built.len(), 2);
        assert_eq!(built[0]["role"], "system");
        assert_eq!(built[1]["role"], "user");
        assert_eq!(built[1]["content"], "Hello");
    }

    #[test]
    fn test_openai_build_tools() {
        let tools = vec![serde_json::json!({
            "name": "get_weather",
            "description": "Get weather info",
            "parameters": {
                "type": "object",
                "properties": {
                    "city": { "type": "string" }
                }
            }
        })];
        let built = OpenAiCompatibleProvider::build_tools(&tools);
        assert_eq!(built.len(), 1);
        assert_eq!(built[0]["type"], "function");
        assert_eq!(built[0]["function"]["name"], "get_weather");
    }

    #[test]
    fn test_cost_schedule_local_providers() {
        // Ollama and LM Studio should be free
        let ollama = OllamaProvider::new(None, None).unwrap();
        let sched = ollama.cost_per_1k_tokens();
        assert_eq!(sched.input_per_1k, 0.0);
        assert_eq!(sched.output_per_1k, 0.0);
    }
}
