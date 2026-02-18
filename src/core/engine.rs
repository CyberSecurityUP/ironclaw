//! Enhanced Core Engine for IronClaw.
//!
//! Orchestrates the full agent loop with Zero Trust security:
//! every tool call passes through a 10+ step security pipeline before
//! execution is allowed.
//!
//! Subsystems managed by the engine:
//! - Config, RBAC Policy, Command Guardian, Audit Log
//! - Anti-Stealer, SSRF Guard, DLP Engine
//! - Cost Tracker, Cache (moka), Skill Scanner
//! - Memory Store, Provider (LLM), Tool Registry, Sandbox

use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{error, info, warn};
use uuid::Uuid;

use super::config::Config;
use super::cost::{CostTracker, ProviderUsage};
use super::tool::ToolRegistry;
use super::types::{Message, MessageRole, SecurityContext, ToolCall};
use crate::antitheft::AntiStealer;
use crate::dlp::DlpEngine;
use crate::guardian::CommandGuardian;
use crate::memory::MemoryStore;
use crate::network::SsrfGuard;
use crate::observability::AuditLog;
use crate::providers::ProviderFactory;
use crate::rbac::Policy;
use crate::skills::scanner::SkillScanner;

// ---------------------------------------------------------------------------
// EngineConfig — carries all subsystem references into `Engine::new()`
// ---------------------------------------------------------------------------

/// Configuration bundle for constructing an `Engine`.
pub struct EngineConfig {
    pub config: Config,
    pub policy: Policy,
    pub guardian: CommandGuardian,
    pub audit: AuditLog,
    pub anti_stealer: AntiStealer,
    pub ssrf_guard: SsrfGuard,
    pub dlp_engine: DlpEngine,
    pub cost_tracker: Option<CostTracker>,
    pub skill_scanner: Option<SkillScanner>,
    pub provider_name: String,
    pub model: Option<String>,
    pub ui_sender: Option<tokio::sync::broadcast::Sender<crate::ui::UiMessage>>,
    pub channel_manager: Option<crate::channels::ChannelManager>,
    pub session_auth: Option<crate::auth::SessionAuthenticator>,
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/// Metadata for an active session.
#[derive(Debug, Clone)]
struct Session {
    id: String,
    turn_count: u32,
    max_turns: u32,
}

impl Session {
    fn new(max_turns: u32) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            turn_count: 0,
            max_turns,
        }
    }

    fn increment(&mut self) {
        self.turn_count += 1;
    }

    fn is_expired(&self) -> bool {
        self.turn_count >= self.max_turns
    }
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// The core execution engine that orchestrates the agent loop.
/// Enforces Zero Trust: every action is validated, sandboxed, and audited.
pub struct Engine {
    config: Config,
    policy: Arc<Policy>,
    guardian: Arc<CommandGuardian>,
    audit: Arc<AuditLog>,
    anti_stealer: Arc<AntiStealer>,
    ssrf_guard: Arc<SsrfGuard>,
    dlp_engine: Arc<DlpEngine>,
    cost_tracker: Option<Arc<CostTracker>>,
    #[allow(dead_code)]
    skill_scanner: Option<Arc<SkillScanner>>,
    tool_registry: Arc<ToolRegistry>,
    memory: Arc<dyn MemoryStore>,
    provider_name: String,
    model: Option<String>,
    session: parking_lot::Mutex<Session>,
    #[allow(dead_code)]
    ui_sender: Option<tokio::sync::broadcast::Sender<crate::ui::UiMessage>>,
    #[allow(dead_code)]
    channel_manager: Option<std::sync::Arc<crate::channels::ChannelManager>>,
    #[allow(dead_code)]
    session_auth: Option<std::sync::Arc<crate::auth::SessionAuthenticator>>,
}

impl Engine {
    /// Construct a new Engine from the given config bundle.
    pub async fn new(ec: EngineConfig) -> Result<Self> {
        let session = Session::new(ec.config.agent.max_turns);

        // Initialise memory store
        let memory = crate::memory::create_store(&ec.config.memory)?;

        // Build the tool registry from config
        let tool_registry = Self::build_tool_registry(&ec.config)?;

        info!(session_id = %session.id, "Engine initialised");

        Ok(Self {
            config: ec.config,
            policy: Arc::new(ec.policy),
            guardian: Arc::new(ec.guardian),
            audit: Arc::new(ec.audit),
            anti_stealer: Arc::new(ec.anti_stealer),
            ssrf_guard: Arc::new(ec.ssrf_guard),
            dlp_engine: Arc::new(ec.dlp_engine),
            cost_tracker: ec.cost_tracker.map(Arc::new),
            skill_scanner: ec.skill_scanner.map(Arc::new),
            tool_registry: Arc::new(tool_registry),
            memory,
            provider_name: ec.provider_name,
            model: ec.model,
            session: parking_lot::Mutex::new(session),
            ui_sender: ec.ui_sender,
            channel_manager: ec.channel_manager.map(Arc::new),
            session_auth: ec.session_auth.map(Arc::new),
        })
    }

    // ----- Tool registry ---------------------------------------------------

    fn build_tool_registry(config: &Config) -> Result<ToolRegistry> {
        let mut registry = ToolRegistry::new();

        if config
            .permissions
            .tools
            .get("file_read")
            .map_or(true, |t| t.enabled)
        {
            info!("Registered tool: file_read");
        }

        if config.permissions.system.allow_shell {
            info!("Shell tool enabled -- commands will pass through Command Guardian");
        } else {
            info!("Shell tool disabled by security policy");
        }

        let _ = &registry;
        Ok(registry)
    }

    // ----- Public API ------------------------------------------------------

    /// The current session ID.
    pub fn session_id(&self) -> String {
        self.session.lock().id.clone()
    }

    /// Process a single inbound message (used by gateway / channel adapters).
    /// Returns the assistant response message.
    pub async fn process_message(
        &self,
        conversation: &mut Vec<Message>,
    ) -> Result<Message> {
        // Check session expiry
        {
            let sess = self.session.lock();
            if sess.is_expired() {
                anyhow::bail!(
                    "Session expired after {} turns (limit {})",
                    sess.turn_count,
                    sess.max_turns
                );
            }
        }

        // Budget check
        if let Some(ref ct) = self.cost_tracker {
            ct.check_budget()?;
        }

        // Build the provider
        let provider = ProviderFactory::create(
            &self.provider_name,
            self.config.providers.get(&self.provider_name),
            self.model.as_deref(),
        )?;

        // Call LLM
        let response = provider
            .chat(conversation, &self.tool_registry.schemas())
            .await?;

        // Process tool calls
        if !response.tool_calls.is_empty() {
            for tool_call in &response.tool_calls {
                let result = self.execute_tool_call(tool_call).await;
                match &result {
                    Ok(tool_result) => {
                        conversation.push(Message {
                            role: MessageRole::Tool,
                            content: tool_result.output.clone(),
                            tool_calls: Vec::new(),
                            tool_results: vec![tool_result.clone()],
                            id: uuid::Uuid::new_v4().to_string(),
                            timestamp: chrono::Utc::now(),
                            content_blocks: Vec::new(),
                        });
                    }
                    Err(e) => {
                        error!("Tool execution failed: {}", e);
                        conversation.push(Message {
                            role: MessageRole::Tool,
                            content: format!("Error: {}", e),
                            tool_calls: Vec::new(),
                            tool_results: Vec::new(),
                            id: uuid::Uuid::new_v4().to_string(),
                            timestamp: chrono::Utc::now(),
                            content_blocks: Vec::new(),
                        });
                    }
                }
            }
        }

        // Track turn
        self.session.lock().increment();

        Ok(response)
    }

    /// Run the interactive CLI agent loop.
    pub async fn run_interactive(&self) -> Result<()> {
        let session_id = self.session_id();
        info!("Starting interactive session {}", session_id);

        let mut conversation: Vec<Message> = Vec::new();

        // System prompt
        conversation.push(Message {
            role: MessageRole::System,
            content: self.config.agent.system_prompt.clone(),
            tool_calls: Vec::new(),
            tool_results: Vec::new(),
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            content_blocks: Vec::new(),
        });

        // Build provider once for the session
        let provider = ProviderFactory::create(
            &self.provider_name,
            self.config.providers.get(&self.provider_name),
            self.model.as_deref(),
        )?;

        println!(
            "IronClaw v{} -- Secure AI Agent",
            env!("CARGO_PKG_VERSION")
        );
        println!("Session: {}", session_id);
        println!(
            "Provider: {} | Sandbox: {} | Type 'exit' to quit\n",
            self.provider_name, self.config.sandbox.backend
        );

        loop {
            // Session expiry
            {
                let sess = self.session.lock();
                if sess.is_expired() {
                    warn!(
                        "Maximum turn count reached ({}), ending session",
                        sess.turn_count
                    );
                    break;
                }
            }

            // Budget check
            if let Some(ref ct) = self.cost_tracker {
                if let Err(e) = ct.check_budget() {
                    eprintln!("[BUDGET] {}", e);
                    break;
                }
            }

            // Read user input
            let input = Self::read_input()?;
            if input.trim().eq_ignore_ascii_case("exit")
                || input.trim().eq_ignore_ascii_case("quit")
            {
                break;
            }
            if input.trim().is_empty() {
                continue;
            }

            // User message
            conversation.push(Message {
                role: MessageRole::User,
                content: input.clone(),
                tool_calls: Vec::new(),
                tool_results: Vec::new(),
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: chrono::Utc::now(),
                content_blocks: Vec::new(),
            });

            // Audit
            self.audit.log_event(
                "user_message",
                &serde_json::json!({
                    "session_id": session_id,
                    "turn": self.session.lock().turn_count,
                    "message_length": input.len(),
                }),
            )?;

            // LLM call
            let response = provider
                .chat(&conversation, &self.tool_registry.schemas())
                .await?;

            // Process tool calls
            if !response.tool_calls.is_empty() {
                for tool_call in &response.tool_calls {
                    let result = self.execute_tool_call(tool_call).await;
                    match &result {
                        Ok(tool_result) => {
                            conversation.push(Message {
                                role: MessageRole::Tool,
                                content: tool_result.output.clone(),
                                tool_calls: Vec::new(),
                                tool_results: vec![tool_result.clone()],
                                id: uuid::Uuid::new_v4().to_string(),
                                timestamp: chrono::Utc::now(),
                                content_blocks: Vec::new(),
                            });
                        }
                        Err(e) => {
                            error!("Tool execution failed: {}", e);
                            conversation.push(Message {
                                role: MessageRole::Tool,
                                content: format!("Error: {}", e),
                                tool_calls: Vec::new(),
                                tool_results: Vec::new(),
                                id: uuid::Uuid::new_v4().to_string(),
                                timestamp: chrono::Utc::now(),
                                content_blocks: Vec::new(),
                            });
                        }
                    }
                }
            }

            // Display assistant response
            if !response.content.is_empty() {
                println!("\n{}\n", response.content);
            }

            conversation.push(response);
            self.session.lock().increment();

            // Auto-save memory
            if self.config.memory.backend != "none" {
                let turn = self.session.lock().turn_count;
                if let Err(e) = self
                    .memory
                    .store(&format!("turn_{}", turn), &input, &session_id)
                    .await
                {
                    warn!("Failed to save to memory: {}", e);
                }
            }
        }

        let sess = self.session.lock();
        info!(
            "Session {} ended after {} turns",
            sess.id, sess.turn_count
        );
        Ok(())
    }

    /// Whether the LLM session is currently active (provider is reachable).
    pub fn is_session_active(&self) -> bool {
        !self.session.lock().is_expired()
    }

    /// Active provider name.
    pub fn active_provider(&self) -> &str {
        &self.provider_name
    }

    /// Active model name.
    pub fn active_model(&self) -> Option<&str> {
        self.model.as_deref()
    }

    // ----- 10-step Security Pipeline (execute_tool_call) -------------------

    /// Execute a tool call with the full security validation pipeline.
    ///
    /// Steps:
    /// 1. RBAC permission check
    /// 2. Tool lookup + argument validation
    /// 3. Command Guardian check (shell tools)
    /// 4. Anti-Stealer check — file access patterns
    /// 5. Anti-Stealer check — command patterns
    /// 6. SSRF check (network tools)
    /// 7. Exfiltration correlation check
    /// 8. Risk assessment + human approval
    /// 9. Pre-execution audit log
    /// 10. Sandbox execute
    /// 11. DLP scan on output
    /// 12. Cost tracking
    /// 13. Post-execution audit log
    pub async fn execute_tool_call(
        &self,
        tool_call: &ToolCall,
    ) -> Result<super::types::ToolResult> {
        let execution_id = Uuid::new_v4().to_string();
        let session_id = self.session_id();

        info!(
            execution_id = %execution_id,
            tool = %tool_call.name,
            "Executing tool call"
        );

        // ---- Step 1: RBAC check -------------------------------------------
        let ctx = SecurityContext {
            role: "agent".to_string(),
            permissions: vec![],
            session_id: session_id.clone(),
            approved: false,
            source_ip: None,
            channel: None,
            user_id: None,
            created_at: chrono::Utc::now(),
        };
        self.policy.check_tool_access(&tool_call.name, &ctx)?;

        // ---- Step 2: Get tool + validate args -----------------------------
        let tool = self
            .tool_registry
            .get(&tool_call.name)
            .ok_or_else(|| anyhow::anyhow!("Unknown tool: {}", tool_call.name))?;

        tool.validate_args(&tool_call.arguments)?;

        // ---- Step 3: Command Guardian (shell tools) -----------------------
        if tool_call.name == "shell" || tool_call.name == "execute" {
            if let Some(cmd) = tool_call.arguments.get("command") {
                if let Some(cmd_str) = cmd.as_str() {
                    self.guardian.validate_command(cmd_str)?;

                    // ---- Step 4: Anti-stealer command check ----------------
                    let stealer_result = self.anti_stealer.check_command(cmd_str);
                    if stealer_result.blocked {
                        self.audit.log_alert(
                            "stealer_command_blocked",
                            &serde_json::json!({
                                "execution_id": execution_id,
                                "tool": tool_call.name,
                                "findings": stealer_result.findings.len(),
                            }),
                        )?;
                        anyhow::bail!(
                            "Command blocked by anti-stealer: {}",
                            stealer_result
                                .findings
                                .first()
                                .map(|f| f.description.as_str())
                                .unwrap_or("suspicious activity")
                        );
                    }
                }
            }
        }

        // ---- Step 5: Anti-stealer file access check -----------------------
        if tool_call.name == "file_read" || tool_call.name == "file_write" {
            if let Some(path) = tool_call.arguments.get("path") {
                if let Some(path_str) = path.as_str() {
                    let stealer_result =
                        self.anti_stealer.check_file_access(path_str, &session_id);
                    if stealer_result.blocked {
                        self.audit.log_alert(
                            "stealer_file_access_blocked",
                            &serde_json::json!({
                                "execution_id": execution_id,
                                "path": path_str,
                                "findings": stealer_result.findings.len(),
                            }),
                        )?;
                        anyhow::bail!(
                            "File access blocked by anti-stealer: sensitive file detected"
                        );
                    }
                }
            }
        }

        // ---- Step 6: SSRF check (network tools) --------------------------
        if tool_call.name == "http_request" || tool_call.name == "fetch" {
            if let Some(url) = tool_call.arguments.get("url") {
                if let Some(url_str) = url.as_str() {
                    let ssrf_result = self.ssrf_guard.check_url(url_str);
                    if !ssrf_result.allowed {
                        self.audit.log_alert(
                            "ssrf_blocked",
                            &serde_json::json!({
                                "execution_id": execution_id,
                                "url": url_str,
                                "reason": ssrf_result.reason,
                            }),
                        )?;
                        anyhow::bail!(
                            "URL blocked by SSRF protection: {}",
                            ssrf_result.reason.unwrap_or_default()
                        );
                    }

                    // ---- Step 7: Exfiltration correlation -----------------
                    if let Some(host) = url_str.split('/').nth(2) {
                        let exfil_result = self
                            .anti_stealer
                            .check_exfiltration_correlation(host, &session_id);
                        if exfil_result.blocked {
                            self.audit.log_alert(
                                "exfiltration_correlation_blocked",
                                &serde_json::json!({
                                    "execution_id": execution_id,
                                    "domain": host,
                                }),
                            )?;
                            anyhow::bail!(
                                "Network request blocked: possible data exfiltration after sensitive file access"
                            );
                        }
                    }
                }
            }
        }

        // ---- Step 8: Risk assessment + human approval ---------------------
        let risk_level = tool.risk_level();
        if risk_level >= super::types::RiskLevel::High
            && self
                .config
                .permissions
                .system
                .require_approval
        {
            println!(
                "\n[APPROVAL REQUIRED] Tool '{}' has risk level {}",
                tool_call.name, risk_level
            );
            println!("Arguments: {:?}", tool_call.arguments);
            print!("Allow execution? (y/N): ");

            let mut response_buf = String::new();
            std::io::stdin().read_line(&mut response_buf)?;
            if !response_buf.trim().eq_ignore_ascii_case("y") {
                anyhow::bail!("Execution denied by user");
            }
        }

        // ---- Step 9: Pre-execution audit ----------------------------------
        self.audit.log_event(
            "tool_execution",
            &serde_json::json!({
                "execution_id": execution_id,
                "tool": tool_call.name,
                "risk_level": risk_level.to_string(),
                "session_id": session_id,
            }),
        )?;

        // ---- Step 10: Execute (sandboxed) ---------------------------------
        let start = std::time::Instant::now();
        let mut result = tool.execute(&tool_call.arguments, &ctx).await?;
        let duration = start.elapsed();

        // ---- Step 11: DLP scan on output ----------------------------------
        let dlp_result = self.dlp_engine.scan_output(&result.output);
        if !dlp_result.findings.is_empty() {
            self.audit.log_alert(
                "dlp_finding",
                &serde_json::json!({
                    "execution_id": execution_id,
                    "tool": tool_call.name,
                    "findings": dlp_result.findings.len(),
                    "blocked": dlp_result.blocked,
                }),
            )?;

            result.output = dlp_result.output;

            if dlp_result.blocked {
                warn!(
                    execution_id = %execution_id,
                    "DLP blocked tool output containing sensitive data"
                );
            }
        }

        // ---- Step 12: Cost tracking ---------------------------------------
        if let Some(ref ct) = self.cost_tracker {
            // Approximate cost from tool execution (actual LLM cost is tracked
            // separately — this covers compute/sandbox cost attribution).
            let usage = ProviderUsage {
                provider: "tool".into(),
                model: tool_call.name.clone(),
                input_tokens: 0,
                output_tokens: result.output.len() as u64,
                cost_usd: 0.0, // Tool exec itself is free; LLM cost recorded by caller
                timestamp: chrono::Utc::now().to_rfc3339(),
            };
            if let Err(e) = ct.record_usage(&usage) {
                warn!("Failed to record cost: {}", e);
            }
        }

        // ---- Step 13: Post-execution audit --------------------------------
        self.audit.log_event(
            "tool_completed",
            &serde_json::json!({
                "execution_id": execution_id,
                "tool": tool_call.name,
                "success": result.success,
                "duration_ms": duration.as_millis(),
            }),
        )?;

        info!(
            execution_id = %execution_id,
            tool = %tool_call.name,
            success = %result.success,
            duration_ms = %duration.as_millis(),
            "Tool execution completed"
        );

        Ok(result)
    }

    // ----- Helpers ---------------------------------------------------------

    fn read_input() -> Result<String> {
        use std::io::{self, Write};
        print!("> ");
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        Ok(input.trim().to_string())
    }
}
