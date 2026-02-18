//! Collaborative Specialized Agents for IronClaw.
//!
//! Provides a multi-agent orchestration system where specialized agents
//! (researcher, coder, reviewer, planner, etc.) collaborate on complex tasks.
//! Supports multiple coordination patterns: sequential pipeline, parallel fan-out,
//! debate/consensus, and hierarchical delegation.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// Agent Roles & Capabilities
// ---------------------------------------------------------------------------

/// A specialized agent role with defined capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRole {
    pub id: String,
    pub name: String,
    pub description: String,
    pub system_prompt: String,
    pub capabilities: Vec<Capability>,
    /// Preferred provider/model for this role.
    pub preferred_provider: Option<String>,
    pub preferred_model: Option<String>,
    /// Maximum tokens this agent can consume per turn.
    #[serde(default = "default_max_tokens")]
    pub max_tokens_per_turn: u32,
    /// Whether this agent can delegate to others.
    #[serde(default)]
    pub can_delegate: bool,
}

fn default_max_tokens() -> u32 {
    4096
}

/// What an agent can do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Capability {
    CodeGeneration,
    CodeReview,
    Research,
    Planning,
    Testing,
    Documentation,
    Debugging,
    Security,
    DataAnalysis,
    NaturalLanguage,
    Custom(String),
}

impl std::fmt::Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CodeGeneration => write!(f, "code_generation"),
            Self::CodeReview => write!(f, "code_review"),
            Self::Research => write!(f, "research"),
            Self::Planning => write!(f, "planning"),
            Self::Testing => write!(f, "testing"),
            Self::Documentation => write!(f, "documentation"),
            Self::Debugging => write!(f, "debugging"),
            Self::Security => write!(f, "security"),
            Self::DataAnalysis => write!(f, "data_analysis"),
            Self::NaturalLanguage => write!(f, "natural_language"),
            Self::Custom(name) => write!(f, "custom:{}", name),
        }
    }
}

// ---------------------------------------------------------------------------
// Built-in Roles
// ---------------------------------------------------------------------------

impl AgentRole {
    pub fn researcher() -> Self {
        Self {
            id: "researcher".to_string(),
            name: "Researcher".to_string(),
            description: "Gathers information, searches documentation, and synthesizes findings"
                .to_string(),
            system_prompt: "You are a research specialist. Gather information thoroughly, cite sources, and provide comprehensive summaries. Focus on accuracy and completeness.".to_string(),
            capabilities: vec![Capability::Research, Capability::NaturalLanguage],
            preferred_provider: None,
            preferred_model: None,
            max_tokens_per_turn: 4096,
            can_delegate: false,
        }
    }

    pub fn coder() -> Self {
        Self {
            id: "coder".to_string(),
            name: "Coder".to_string(),
            description: "Writes, modifies, and refactors code".to_string(),
            system_prompt: "You are a coding specialist. Write clean, efficient, well-tested code. Follow best practices and the project's existing conventions.".to_string(),
            capabilities: vec![
                Capability::CodeGeneration,
                Capability::Debugging,
            ],
            preferred_provider: None,
            preferred_model: None,
            max_tokens_per_turn: 8192,
            can_delegate: false,
        }
    }

    pub fn reviewer() -> Self {
        Self {
            id: "reviewer".to_string(),
            name: "Reviewer".to_string(),
            description: "Reviews code for bugs, security issues, and style".to_string(),
            system_prompt: "You are a code review specialist. Look for bugs, security vulnerabilities, performance issues, and style violations. Be thorough but constructive.".to_string(),
            capabilities: vec![
                Capability::CodeReview,
                Capability::Security,
            ],
            preferred_provider: None,
            preferred_model: None,
            max_tokens_per_turn: 4096,
            can_delegate: false,
        }
    }

    pub fn planner() -> Self {
        Self {
            id: "planner".to_string(),
            name: "Planner".to_string(),
            description: "Breaks down tasks, creates plans, and coordinates work".to_string(),
            system_prompt: "You are a planning specialist. Break down complex tasks into manageable steps, identify dependencies, estimate complexity, and create actionable plans.".to_string(),
            capabilities: vec![Capability::Planning, Capability::NaturalLanguage],
            preferred_provider: None,
            preferred_model: None,
            max_tokens_per_turn: 4096,
            can_delegate: true,
        }
    }

    pub fn tester() -> Self {
        Self {
            id: "tester".to_string(),
            name: "Tester".to_string(),
            description: "Writes and runs tests, validates functionality".to_string(),
            system_prompt: "You are a testing specialist. Write comprehensive tests covering edge cases, error conditions, and happy paths. Ensure code correctness through systematic testing.".to_string(),
            capabilities: vec![Capability::Testing, Capability::Debugging],
            preferred_provider: None,
            preferred_model: None,
            max_tokens_per_turn: 4096,
            can_delegate: false,
        }
    }

    pub fn security_auditor() -> Self {
        Self {
            id: "security_auditor".to_string(),
            name: "Security Auditor".to_string(),
            description: "Analyzes code and configs for security vulnerabilities".to_string(),
            system_prompt: "You are a security specialist. Identify vulnerabilities (OWASP Top 10, CWEs), suggest mitigations, and ensure secure coding practices are followed.".to_string(),
            capabilities: vec![Capability::Security, Capability::CodeReview],
            preferred_provider: None,
            preferred_model: None,
            max_tokens_per_turn: 4096,
            can_delegate: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Coordination Patterns
// ---------------------------------------------------------------------------

/// How agents collaborate on a task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CoordinationPattern {
    /// Agents work one after another in order.
    Sequential { agent_order: Vec<String> },
    /// All agents work in parallel, results are aggregated.
    Parallel { agents: Vec<String> },
    /// Agents debate and reach consensus (multiple rounds).
    Debate {
        agents: Vec<String>,
        max_rounds: u32,
        consensus_threshold: f64,
    },
    /// A lead agent delegates subtasks to specialists.
    Hierarchical {
        lead: String,
        specialists: Vec<String>,
    },
    /// Pipeline where each agent transforms the previous output.
    Pipeline { stages: Vec<PipelineStage> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineStage {
    pub agent_id: String,
    pub instruction: String,
}

// ---------------------------------------------------------------------------
// Messages & Context
// ---------------------------------------------------------------------------

/// A message in the agent collaboration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMessage {
    pub from: String,
    pub to: Option<String>,
    pub content: String,
    pub message_type: AgentMessageType,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentMessageType {
    Task,
    Response,
    Delegation,
    Feedback,
    Consensus,
    Question,
}

/// Shared context accessible to all agents in a collaboration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedContext {
    pub task_description: String,
    pub messages: Vec<AgentMessage>,
    pub artifacts: HashMap<String, String>,
    pub variables: HashMap<String, String>,
}

impl SharedContext {
    pub fn new(task: &str) -> Self {
        Self {
            task_description: task.to_string(),
            messages: Vec::new(),
            artifacts: HashMap::new(),
            variables: HashMap::new(),
        }
    }

    pub fn add_message(&mut self, msg: AgentMessage) {
        self.messages.push(msg);
    }

    pub fn add_artifact(&mut self, name: &str, content: &str) {
        self.artifacts.insert(name.to_string(), content.to_string());
    }

    pub fn get_artifact(&self, name: &str) -> Option<&String> {
        self.artifacts.get(name)
    }

    pub fn message_count(&self) -> usize {
        self.messages.len()
    }

    pub fn messages_from(&self, agent_id: &str) -> Vec<&AgentMessage> {
        self.messages
            .iter()
            .filter(|m| m.from == agent_id)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Collaboration Session
// ---------------------------------------------------------------------------

/// A collaboration session where multiple agents work on a task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollaborationSession {
    pub id: String,
    pub status: SessionStatus,
    pub pattern: CoordinationPattern,
    pub context: SharedContext,
    pub results: HashMap<String, AgentResult>,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionStatus {
    Active,
    Completed,
    Failed,
    Cancelled,
}

impl std::fmt::Display for SessionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "ACTIVE"),
            Self::Completed => write!(f, "COMPLETED"),
            Self::Failed => write!(f, "FAILED"),
            Self::Cancelled => write!(f, "CANCELLED"),
        }
    }
}

/// Result from a single agent's contribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentResult {
    pub agent_id: String,
    pub output: String,
    pub confidence: f64,
    pub duration_ms: u64,
    pub tokens_used: u32,
}

// ---------------------------------------------------------------------------
// Agent Orchestrator
// ---------------------------------------------------------------------------

/// Manages agent roles and orchestrates collaborative sessions.
pub struct AgentOrchestrator {
    roles: HashMap<String, AgentRole>,
    sessions: HashMap<String, CollaborationSession>,
    max_concurrent_sessions: usize,
}

impl AgentOrchestrator {
    pub fn new(max_concurrent: usize) -> Self {
        let mut orchestrator = Self {
            roles: HashMap::new(),
            sessions: HashMap::new(),
            max_concurrent_sessions: max_concurrent,
        };

        // Register built-in roles
        orchestrator.register_builtin_roles();

        info!(
            roles = orchestrator.roles.len(),
            max_concurrent = max_concurrent,
            "Agent orchestrator initialized"
        );

        orchestrator
    }

    fn register_builtin_roles(&mut self) {
        let builtins = vec![
            AgentRole::researcher(),
            AgentRole::coder(),
            AgentRole::reviewer(),
            AgentRole::planner(),
            AgentRole::tester(),
            AgentRole::security_auditor(),
        ];

        for role in builtins {
            self.roles.insert(role.id.clone(), role);
        }
    }

    /// Register a custom agent role.
    pub fn register_role(&mut self, role: AgentRole) {
        info!(id = %role.id, name = %role.name, "Registered agent role");
        self.roles.insert(role.id.clone(), role);
    }

    /// Get a role by ID.
    pub fn get_role(&self, id: &str) -> Option<&AgentRole> {
        self.roles.get(id)
    }

    /// List all registered roles.
    pub fn list_roles(&self) -> Vec<&AgentRole> {
        self.roles.values().collect()
    }

    /// Find roles with a specific capability.
    pub fn roles_with_capability(&self, cap: &Capability) -> Vec<&AgentRole> {
        self.roles
            .values()
            .filter(|r| r.capabilities.contains(cap))
            .collect()
    }

    /// Start a new collaboration session.
    pub fn start_session(
        &mut self,
        task: &str,
        pattern: CoordinationPattern,
    ) -> Result<String> {
        // Validate that all referenced agents exist
        let agent_ids = self.extract_agent_ids(&pattern);
        for id in &agent_ids {
            if !self.roles.contains_key(id.as_str()) {
                anyhow::bail!("Agent role '{}' not found", id);
            }
        }

        let active = self
            .sessions
            .values()
            .filter(|s| s.status == SessionStatus::Active)
            .count();

        if active >= self.max_concurrent_sessions {
            anyhow::bail!(
                "Maximum concurrent sessions reached ({})",
                self.max_concurrent_sessions
            );
        }

        let session_id = uuid::Uuid::new_v4().to_string();

        let session = CollaborationSession {
            id: session_id.clone(),
            status: SessionStatus::Active,
            pattern,
            context: SharedContext::new(task),
            results: HashMap::new(),
            started_at: chrono::Utc::now(),
            completed_at: None,
        };

        info!(
            session_id = %session_id,
            task = %truncate_str(task, 80),
            agents = agent_ids.len(),
            "Collaboration session started"
        );

        self.sessions.insert(session_id.clone(), session);
        Ok(session_id)
    }

    /// Execute a sequential collaboration round.
    ///
    /// In production this would call actual LLM providers. Here we simulate
    /// the orchestration logic.
    pub fn execute_round(&mut self, session_id: &str) -> Result<Vec<String>> {
        let session = self
            .sessions
            .get(session_id)
            .ok_or_else(|| anyhow::anyhow!("Session '{}' not found", session_id))?;

        if session.status != SessionStatus::Active {
            anyhow::bail!("Session is not active: {}", session.status);
        }

        let _agent_ids = self.extract_agent_ids(&session.pattern);
        let pattern = session.pattern.clone();
        let task = session.context.task_description.clone();
        let mut executed = Vec::new();

        match pattern {
            CoordinationPattern::Sequential { ref agent_order } => {
                for agent_id in agent_order {
                    let response = self.simulate_agent_response(agent_id, &task);
                    self.record_agent_contribution(session_id, agent_id, &response)?;
                    executed.push(agent_id.clone());
                }
            }
            CoordinationPattern::Parallel { ref agents } => {
                for agent_id in agents {
                    let response = self.simulate_agent_response(agent_id, &task);
                    self.record_agent_contribution(session_id, agent_id, &response)?;
                    executed.push(agent_id.clone());
                }
            }
            CoordinationPattern::Debate { ref agents, .. } => {
                for agent_id in agents {
                    let response = self.simulate_agent_response(agent_id, &task);
                    self.record_agent_contribution(session_id, agent_id, &response)?;
                    executed.push(agent_id.clone());
                }
            }
            CoordinationPattern::Hierarchical { ref lead, ref specialists } => {
                // Lead goes first
                let lead_response = self.simulate_agent_response(lead, &task);
                self.record_agent_contribution(session_id, lead, &lead_response)?;
                executed.push(lead.clone());

                // Then specialists
                for specialist_id in specialists {
                    let response = self.simulate_agent_response(specialist_id, &task);
                    self.record_agent_contribution(session_id, specialist_id, &response)?;
                    executed.push(specialist_id.clone());
                }
            }
            CoordinationPattern::Pipeline { ref stages } => {
                for stage in stages {
                    let prompt = format!("{}\n\nInstruction: {}", task, stage.instruction);
                    let response = self.simulate_agent_response(&stage.agent_id, &prompt);
                    self.record_agent_contribution(session_id, &stage.agent_id, &response)?;
                    executed.push(stage.agent_id.clone());
                }
            }
        }

        Ok(executed)
    }

    /// Complete a session.
    pub fn complete_session(&mut self, session_id: &str) -> Result<()> {
        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| anyhow::anyhow!("Session not found"))?;

        session.status = SessionStatus::Completed;
        session.completed_at = Some(chrono::Utc::now());
        info!(session_id = %session_id, "Collaboration session completed");
        Ok(())
    }

    /// Cancel a session.
    pub fn cancel_session(&mut self, session_id: &str) -> Result<()> {
        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| anyhow::anyhow!("Session not found"))?;

        session.status = SessionStatus::Cancelled;
        session.completed_at = Some(chrono::Utc::now());
        warn!(session_id = %session_id, "Collaboration session cancelled");
        Ok(())
    }

    /// Get a session by ID.
    pub fn get_session(&self, session_id: &str) -> Option<&CollaborationSession> {
        self.sessions.get(session_id)
    }

    /// Count active sessions.
    pub fn active_sessions(&self) -> usize {
        self.sessions
            .values()
            .filter(|s| s.status == SessionStatus::Active)
            .count()
    }

    /// Aggregate results from all agents in a session into a summary.
    pub fn aggregate_results(&self, session_id: &str) -> Result<String> {
        let session = self
            .sessions
            .get(session_id)
            .ok_or_else(|| anyhow::anyhow!("Session not found"))?;

        let mut parts = Vec::new();
        parts.push(format!("Task: {}", session.context.task_description));
        parts.push(format!("Status: {}", session.status));

        for (agent_id, result) in &session.results {
            let role_name = self
                .roles
                .get(agent_id.as_str())
                .map(|r| r.name.as_str())
                .unwrap_or(agent_id);

            parts.push(format!(
                "\n[{}] (confidence: {:.0}%, {}ms):\n{}",
                role_name,
                result.confidence * 100.0,
                result.duration_ms,
                result.output
            ));
        }

        Ok(parts.join("\n"))
    }

    // -- Internal helpers -------------------------------------------------

    fn extract_agent_ids(&self, pattern: &CoordinationPattern) -> Vec<String> {
        match pattern {
            CoordinationPattern::Sequential { agent_order } => agent_order.clone(),
            CoordinationPattern::Parallel { agents } => agents.clone(),
            CoordinationPattern::Debate { agents, .. } => agents.clone(),
            CoordinationPattern::Hierarchical { lead, specialists } => {
                let mut ids = vec![lead.clone()];
                ids.extend(specialists.clone());
                ids
            }
            CoordinationPattern::Pipeline { stages } => {
                stages.iter().map(|s| s.agent_id.clone()).collect()
            }
        }
    }

    fn simulate_agent_response(&self, agent_id: &str, task: &str) -> String {
        let role = self.roles.get(agent_id);
        let role_name = role.map(|r| r.name.as_str()).unwrap_or(agent_id);
        format!(
            "[{} analysis of: {}]",
            role_name,
            truncate_str(task, 80)
        )
    }

    fn record_agent_contribution(
        &mut self,
        session_id: &str,
        agent_id: &str,
        output: &str,
    ) -> Result<()> {
        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| anyhow::anyhow!("Session not found"))?;

        // Add message to context
        session.context.add_message(AgentMessage {
            from: agent_id.to_string(),
            to: None,
            content: output.to_string(),
            message_type: AgentMessageType::Response,
            timestamp: chrono::Utc::now(),
        });

        // Record result
        session.results.insert(
            agent_id.to_string(),
            AgentResult {
                agent_id: agent_id.to_string(),
                output: output.to_string(),
                confidence: 0.85,
                duration_ms: 100,
                tokens_used: 256,
            },
        );

        Ok(())
    }
}

fn truncate_str(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max])
    }
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Agent orchestrator configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_max_sessions")]
    pub max_concurrent_sessions: usize,
    #[serde(default)]
    pub custom_roles: Vec<AgentRole>,
}

impl Default for AgentsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_concurrent_sessions: default_max_sessions(),
            custom_roles: Vec::new(),
        }
    }
}

fn default_max_sessions() -> usize {
    4
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_roles() {
        let orchestrator = AgentOrchestrator::new(4);
        assert!(orchestrator.get_role("researcher").is_some());
        assert!(orchestrator.get_role("coder").is_some());
        assert!(orchestrator.get_role("reviewer").is_some());
        assert!(orchestrator.get_role("planner").is_some());
        assert!(orchestrator.get_role("tester").is_some());
        assert!(orchestrator.get_role("security_auditor").is_some());
        assert_eq!(orchestrator.list_roles().len(), 6);
    }

    #[test]
    fn test_register_custom_role() {
        let mut orchestrator = AgentOrchestrator::new(4);
        orchestrator.register_role(AgentRole {
            id: "custom".to_string(),
            name: "Custom Agent".to_string(),
            description: "A custom agent".to_string(),
            system_prompt: "You are custom.".to_string(),
            capabilities: vec![Capability::Custom("special".to_string())],
            preferred_provider: None,
            preferred_model: None,
            max_tokens_per_turn: 4096,
            can_delegate: false,
        });
        assert_eq!(orchestrator.list_roles().len(), 7);
        assert!(orchestrator.get_role("custom").is_some());
    }

    #[test]
    fn test_roles_with_capability() {
        let orchestrator = AgentOrchestrator::new(4);
        let security_agents = orchestrator.roles_with_capability(&Capability::Security);
        assert!(security_agents.len() >= 2); // reviewer + security_auditor

        let research_agents = orchestrator.roles_with_capability(&Capability::Research);
        assert!(research_agents.len() >= 1);
    }

    #[test]
    fn test_start_sequential_session() {
        let mut orchestrator = AgentOrchestrator::new(4);
        let session_id = orchestrator
            .start_session(
                "Write a hello world program",
                CoordinationPattern::Sequential {
                    agent_order: vec!["planner".to_string(), "coder".to_string()],
                },
            )
            .unwrap();

        assert!(!session_id.is_empty());
        assert_eq!(orchestrator.active_sessions(), 1);

        let session = orchestrator.get_session(&session_id).unwrap();
        assert_eq!(session.status, SessionStatus::Active);
    }

    #[test]
    fn test_start_session_invalid_agent_fails() {
        let mut orchestrator = AgentOrchestrator::new(4);
        let result = orchestrator.start_session(
            "task",
            CoordinationPattern::Sequential {
                agent_order: vec!["nonexistent".to_string()],
            },
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_max_concurrent_sessions() {
        let mut orchestrator = AgentOrchestrator::new(1);
        let _id1 = orchestrator
            .start_session(
                "task1",
                CoordinationPattern::Sequential {
                    agent_order: vec!["coder".to_string()],
                },
            )
            .unwrap();

        let result = orchestrator.start_session(
            "task2",
            CoordinationPattern::Sequential {
                agent_order: vec!["coder".to_string()],
            },
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_execute_sequential_round() {
        let mut orchestrator = AgentOrchestrator::new(4);
        let session_id = orchestrator
            .start_session(
                "Implement sorting",
                CoordinationPattern::Sequential {
                    agent_order: vec![
                        "planner".to_string(),
                        "coder".to_string(),
                        "reviewer".to_string(),
                    ],
                },
            )
            .unwrap();

        let executed = orchestrator.execute_round(&session_id).unwrap();
        assert_eq!(executed.len(), 3);
        assert_eq!(executed[0], "planner");
        assert_eq!(executed[1], "coder");
        assert_eq!(executed[2], "reviewer");

        let session = orchestrator.get_session(&session_id).unwrap();
        assert_eq!(session.results.len(), 3);
        assert_eq!(session.context.message_count(), 3);
    }

    #[test]
    fn test_execute_parallel_round() {
        let mut orchestrator = AgentOrchestrator::new(4);
        let session_id = orchestrator
            .start_session(
                "Review code",
                CoordinationPattern::Parallel {
                    agents: vec!["reviewer".to_string(), "security_auditor".to_string()],
                },
            )
            .unwrap();

        let executed = orchestrator.execute_round(&session_id).unwrap();
        assert_eq!(executed.len(), 2);
    }

    #[test]
    fn test_execute_pipeline() {
        let mut orchestrator = AgentOrchestrator::new(4);
        let session_id = orchestrator
            .start_session(
                "Build feature",
                CoordinationPattern::Pipeline {
                    stages: vec![
                        PipelineStage {
                            agent_id: "planner".to_string(),
                            instruction: "Create a plan".to_string(),
                        },
                        PipelineStage {
                            agent_id: "coder".to_string(),
                            instruction: "Implement the plan".to_string(),
                        },
                        PipelineStage {
                            agent_id: "tester".to_string(),
                            instruction: "Write tests".to_string(),
                        },
                    ],
                },
            )
            .unwrap();

        let executed = orchestrator.execute_round(&session_id).unwrap();
        assert_eq!(executed.len(), 3);
    }

    #[test]
    fn test_execute_hierarchical() {
        let mut orchestrator = AgentOrchestrator::new(4);
        let session_id = orchestrator
            .start_session(
                "Complex task",
                CoordinationPattern::Hierarchical {
                    lead: "planner".to_string(),
                    specialists: vec!["coder".to_string(), "tester".to_string()],
                },
            )
            .unwrap();

        let executed = orchestrator.execute_round(&session_id).unwrap();
        assert_eq!(executed.len(), 3);
        assert_eq!(executed[0], "planner"); // lead first
    }

    #[test]
    fn test_complete_session() {
        let mut orchestrator = AgentOrchestrator::new(4);
        let session_id = orchestrator
            .start_session(
                "task",
                CoordinationPattern::Sequential {
                    agent_order: vec!["coder".to_string()],
                },
            )
            .unwrap();

        orchestrator.complete_session(&session_id).unwrap();

        let session = orchestrator.get_session(&session_id).unwrap();
        assert_eq!(session.status, SessionStatus::Completed);
        assert!(session.completed_at.is_some());
    }

    #[test]
    fn test_cancel_session() {
        let mut orchestrator = AgentOrchestrator::new(4);
        let session_id = orchestrator
            .start_session(
                "task",
                CoordinationPattern::Sequential {
                    agent_order: vec!["coder".to_string()],
                },
            )
            .unwrap();

        orchestrator.cancel_session(&session_id).unwrap();

        let session = orchestrator.get_session(&session_id).unwrap();
        assert_eq!(session.status, SessionStatus::Cancelled);
    }

    #[test]
    fn test_aggregate_results() {
        let mut orchestrator = AgentOrchestrator::new(4);
        let session_id = orchestrator
            .start_session(
                "Analyze this code",
                CoordinationPattern::Sequential {
                    agent_order: vec!["reviewer".to_string(), "security_auditor".to_string()],
                },
            )
            .unwrap();

        orchestrator.execute_round(&session_id).unwrap();
        let summary = orchestrator.aggregate_results(&session_id).unwrap();

        assert!(summary.contains("Analyze this code"));
        assert!(summary.contains("Reviewer"));
        assert!(summary.contains("Security Auditor"));
    }

    #[test]
    fn test_shared_context() {
        let mut ctx = SharedContext::new("test task");
        assert_eq!(ctx.task_description, "test task");
        assert_eq!(ctx.message_count(), 0);

        ctx.add_artifact("code", "fn main() {}");
        assert_eq!(ctx.get_artifact("code"), Some(&"fn main() {}".to_string()));
        assert_eq!(ctx.get_artifact("missing"), None);

        ctx.add_message(AgentMessage {
            from: "coder".to_string(),
            to: None,
            content: "Done".to_string(),
            message_type: AgentMessageType::Response,
            timestamp: chrono::Utc::now(),
        });
        assert_eq!(ctx.message_count(), 1);
        assert_eq!(ctx.messages_from("coder").len(), 1);
        assert_eq!(ctx.messages_from("other").len(), 0);
    }

    #[test]
    fn test_capability_display() {
        assert_eq!(Capability::CodeGeneration.to_string(), "code_generation");
        assert_eq!(Capability::Security.to_string(), "security");
        assert_eq!(
            Capability::Custom("test".to_string()).to_string(),
            "custom:test"
        );
    }

    #[test]
    fn test_session_status_display() {
        assert_eq!(SessionStatus::Active.to_string(), "ACTIVE");
        assert_eq!(SessionStatus::Completed.to_string(), "COMPLETED");
        assert_eq!(SessionStatus::Failed.to_string(), "FAILED");
        assert_eq!(SessionStatus::Cancelled.to_string(), "CANCELLED");
    }

    #[test]
    fn test_execute_on_completed_session_fails() {
        let mut orchestrator = AgentOrchestrator::new(4);
        let session_id = orchestrator
            .start_session(
                "task",
                CoordinationPattern::Sequential {
                    agent_order: vec!["coder".to_string()],
                },
            )
            .unwrap();

        orchestrator.complete_session(&session_id).unwrap();
        assert!(orchestrator.execute_round(&session_id).is_err());
    }

    #[test]
    fn test_debate_pattern() {
        let mut orchestrator = AgentOrchestrator::new(4);
        let session_id = orchestrator
            .start_session(
                "Should we use async?",
                CoordinationPattern::Debate {
                    agents: vec!["planner".to_string(), "coder".to_string()],
                    max_rounds: 3,
                    consensus_threshold: 0.8,
                },
            )
            .unwrap();

        let executed = orchestrator.execute_round(&session_id).unwrap();
        assert_eq!(executed.len(), 2);
    }

    #[test]
    fn test_agent_role_serialization() {
        let role = AgentRole::coder();
        let json = serde_json::to_string(&role).unwrap();
        assert!(json.contains("coder"));

        let deser: AgentRole = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.id, "coder");
    }

    #[test]
    fn test_agents_config_default() {
        let config = AgentsConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.max_concurrent_sessions, 4);
        assert!(config.custom_roles.is_empty());
    }
}
