//! Workflow/Automation Engine for IronClaw.
//!
//! Provides a DAG-based workflow system similar to Zapier/IFTTT, allowing
//! users to define multi-step automation pipelines that chain together
//! LLM calls, tool executions, channel messages, and conditional branching.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// Workflow Definition
// ---------------------------------------------------------------------------

/// A workflow is a directed acyclic graph of steps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workflow {
    pub id: String,
    pub name: String,
    pub description: String,
    pub steps: Vec<WorkflowStep>,
    pub triggers: Vec<Trigger>,
    #[serde(default)]
    pub variables: HashMap<String, String>,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub max_retries: u32,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_timeout() -> u64 {
    300
}

/// A single step in a workflow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStep {
    pub id: String,
    pub name: String,
    pub action: StepAction,
    /// IDs of steps that must complete before this one starts.
    #[serde(default)]
    pub depends_on: Vec<String>,
    /// Condition that must be true for this step to execute.
    pub condition: Option<StepCondition>,
    /// Retry policy for this step.
    #[serde(default)]
    pub retry: RetryPolicy,
    /// Timeout for this specific step (overrides workflow default).
    pub timeout_secs: Option<u64>,
}

/// What a step does.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum StepAction {
    /// Send a prompt to an LLM and capture the response.
    LlmCall {
        prompt_template: String,
        provider: Option<String>,
        model: Option<String>,
        /// Store the response in this variable.
        output_var: String,
    },
    /// Execute a tool/command in the sandbox.
    ToolExec {
        tool_name: String,
        arguments: HashMap<String, serde_json::Value>,
        output_var: String,
    },
    /// Send a message to a channel.
    ChannelSend {
        channel: String,
        message_template: String,
    },
    /// Wait for an external event (webhook, channel message, timer).
    WaitForEvent {
        event_type: EventType,
        timeout_secs: Option<u64>,
        output_var: String,
    },
    /// Transform data using a Jinja-like template.
    Transform {
        template: String,
        output_var: String,
    },
    /// Conditional branch — evaluates condition and sets a boolean variable.
    Branch {
        condition: StepCondition,
        output_var: String,
    },
    /// Run a sub-workflow.
    SubWorkflow {
        workflow_id: String,
        input_vars: HashMap<String, String>,
        output_var: String,
    },
    /// HTTP request.
    HttpRequest {
        method: String,
        url_template: String,
        headers: HashMap<String, String>,
        body_template: Option<String>,
        output_var: String,
    },
    /// Delay execution for a duration.
    Delay {
        seconds: u64,
    },
    /// Log a message (for debugging).
    Log {
        message_template: String,
        level: String,
    },
}

/// Event types that a WaitForEvent step can listen for.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventType {
    Webhook { path: String },
    ChannelMessage { channel: String, pattern: Option<String> },
    Timer { cron: String },
    Manual,
}

/// Condition for conditional steps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepCondition {
    pub left: String,
    pub operator: ConditionOp,
    pub right: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConditionOp {
    Equals,
    NotEquals,
    Contains,
    GreaterThan,
    LessThan,
    IsEmpty,
    IsNotEmpty,
    Matches, // regex
}

/// Retry policy for a step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryPolicy {
    #[serde(default)]
    pub max_retries: u32,
    #[serde(default = "default_retry_delay")]
    pub delay_secs: u64,
    #[serde(default)]
    pub exponential_backoff: bool,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 0,
            delay_secs: default_retry_delay(),
            exponential_backoff: false,
        }
    }
}

fn default_retry_delay() -> u64 {
    5
}

// ---------------------------------------------------------------------------
// Triggers
// ---------------------------------------------------------------------------

/// What starts a workflow.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Trigger {
    /// Cron schedule.
    Schedule { cron: String },
    /// Webhook (HTTP POST to a path).
    Webhook { path: String, secret: Option<String> },
    /// Channel message matching a pattern.
    ChannelMessage { channel: String, pattern: String },
    /// Manual invocation.
    Manual,
    /// On another workflow completing.
    WorkflowComplete { workflow_id: String },
    /// On a specific event.
    Event { event_name: String },
}

// ---------------------------------------------------------------------------
// Execution State
// ---------------------------------------------------------------------------

/// Runtime state of a workflow execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowExecution {
    pub execution_id: String,
    pub workflow_id: String,
    pub status: ExecutionStatus,
    pub variables: HashMap<String, String>,
    pub step_results: HashMap<String, StepResult>,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionStatus {
    Running,
    Completed,
    Failed,
    Cancelled,
    WaitingForEvent,
    Paused,
}

impl std::fmt::Display for ExecutionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Running => write!(f, "RUNNING"),
            Self::Completed => write!(f, "COMPLETED"),
            Self::Failed => write!(f, "FAILED"),
            Self::Cancelled => write!(f, "CANCELLED"),
            Self::WaitingForEvent => write!(f, "WAITING"),
            Self::Paused => write!(f, "PAUSED"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepResult {
    pub step_id: String,
    pub status: StepStatus,
    pub output: Option<String>,
    pub error: Option<String>,
    pub duration_ms: u64,
    pub retries: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StepStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Skipped,
}

// ---------------------------------------------------------------------------
// Workflow Engine
// ---------------------------------------------------------------------------

/// The workflow engine manages workflow definitions and their execution.
pub struct WorkflowEngine {
    workflows: HashMap<String, Workflow>,
    executions: HashMap<String, WorkflowExecution>,
    max_concurrent: usize,
}

impl WorkflowEngine {
    pub fn new(max_concurrent: usize) -> Self {
        info!(max_concurrent = max_concurrent, "Workflow engine initialized");
        Self {
            workflows: HashMap::new(),
            executions: HashMap::new(),
            max_concurrent,
        }
    }

    /// Register a workflow definition.
    pub fn register(&mut self, workflow: Workflow) -> Result<()> {
        self.validate_workflow(&workflow)?;
        info!(
            id = %workflow.id,
            name = %workflow.name,
            steps = workflow.steps.len(),
            triggers = workflow.triggers.len(),
            "Workflow registered"
        );
        self.workflows.insert(workflow.id.clone(), workflow);
        Ok(())
    }

    /// Remove a workflow.
    pub fn unregister(&mut self, workflow_id: &str) -> bool {
        self.workflows.remove(workflow_id).is_some()
    }

    /// Start a workflow execution.
    pub fn start_execution(&mut self, workflow_id: &str) -> Result<String> {
        let workflow = self
            .workflows
            .get(workflow_id)
            .ok_or_else(|| anyhow::anyhow!("Workflow '{}' not found", workflow_id))?;

        if !workflow.enabled {
            anyhow::bail!("Workflow '{}' is disabled", workflow_id);
        }

        let active_count = self
            .executions
            .values()
            .filter(|e| e.status == ExecutionStatus::Running)
            .count();

        if active_count >= self.max_concurrent {
            anyhow::bail!(
                "Maximum concurrent workflows reached ({})",
                self.max_concurrent
            );
        }

        let execution_id = uuid::Uuid::new_v4().to_string();

        let execution = WorkflowExecution {
            execution_id: execution_id.clone(),
            workflow_id: workflow_id.to_string(),
            status: ExecutionStatus::Running,
            variables: workflow.variables.clone(),
            step_results: HashMap::new(),
            started_at: chrono::Utc::now(),
            completed_at: None,
            error: None,
        };

        info!(
            execution_id = %execution_id,
            workflow = %workflow_id,
            "Workflow execution started"
        );

        self.executions.insert(execution_id.clone(), execution);
        Ok(execution_id)
    }

    /// Execute the next ready step in a workflow execution.
    ///
    /// Returns the step ID that was executed, or None if no step is ready.
    pub fn execute_next_step(&mut self, execution_id: &str) -> Result<Option<String>> {
        let execution = self
            .executions
            .get(execution_id)
            .ok_or_else(|| anyhow::anyhow!("Execution '{}' not found", execution_id))?;

        if execution.status != ExecutionStatus::Running {
            return Ok(None);
        }

        let workflow = self
            .workflows
            .get(&execution.workflow_id)
            .ok_or_else(|| anyhow::anyhow!("Workflow not found"))?
            .clone();

        // Find the next step whose dependencies are all completed
        let next_step = workflow.steps.iter().find(|step| {
            // Not already executed
            !execution.step_results.contains_key(&step.id)
                // All dependencies completed
                && step.depends_on.iter().all(|dep| {
                    execution
                        .step_results
                        .get(dep)
                        .map(|r| r.status == StepStatus::Completed)
                        .unwrap_or(false)
                })
        });

        let step = match next_step {
            Some(s) => s.clone(),
            None => {
                // Check if all steps are done
                let all_done = workflow.steps.iter().all(|s| {
                    execution.step_results.contains_key(&s.id)
                });

                if all_done {
                    let exec = self.executions.get_mut(execution_id).unwrap();
                    exec.status = ExecutionStatus::Completed;
                    exec.completed_at = Some(chrono::Utc::now());
                    info!(execution_id = %execution_id, "Workflow execution completed");
                }

                return Ok(None);
            }
        };

        // Check condition
        let should_run = if let Some(ref cond) = step.condition {
            self.evaluate_condition(cond, &execution.variables)
        } else {
            true
        };

        let step_id = step.id.clone();
        let start = std::time::Instant::now();

        if should_run {
            // Execute the step action
            let result = self.execute_step_action(&step.action, &execution.variables);
            let duration_ms = start.elapsed().as_millis() as u64;

            let step_result = match result {
                Ok(output) => {
                    // Store output variable
                    if let Some(var_name) = get_output_var(&step.action) {
                        if let Some(exec) = self.executions.get_mut(execution_id) {
                            exec.variables.insert(var_name, output.clone());
                        }
                    }

                    StepResult {
                        step_id: step_id.clone(),
                        status: StepStatus::Completed,
                        output: Some(output),
                        error: None,
                        duration_ms,
                        retries: 0,
                    }
                }
                Err(e) => StepResult {
                    step_id: step_id.clone(),
                    status: StepStatus::Failed,
                    output: None,
                    error: Some(e.to_string()),
                    duration_ms,
                    retries: 0,
                },
            };

            if let Some(exec) = self.executions.get_mut(execution_id) {
                if step_result.status == StepStatus::Failed {
                    exec.status = ExecutionStatus::Failed;
                    exec.error = step_result.error.clone();
                    exec.completed_at = Some(chrono::Utc::now());
                }
                exec.step_results.insert(step_id.clone(), step_result);
            }
        } else {
            // Skip this step
            let step_result = StepResult {
                step_id: step_id.clone(),
                status: StepStatus::Skipped,
                output: None,
                error: None,
                duration_ms: 0,
                retries: 0,
            };

            if let Some(exec) = self.executions.get_mut(execution_id) {
                exec.step_results.insert(step_id.clone(), step_result);
            }
        }

        Ok(Some(step_id))
    }

    /// Run a workflow to completion (all steps).
    pub fn run_to_completion(&mut self, execution_id: &str) -> Result<ExecutionStatus> {
        loop {
            match self.execute_next_step(execution_id)? {
                Some(_) => continue,
                None => {
                    let exec = self
                        .executions
                        .get(execution_id)
                        .ok_or_else(|| anyhow::anyhow!("Execution not found"))?;
                    return Ok(exec.status.clone());
                }
            }
        }
    }

    /// Cancel a running execution.
    pub fn cancel_execution(&mut self, execution_id: &str) -> Result<()> {
        let exec = self
            .executions
            .get_mut(execution_id)
            .ok_or_else(|| anyhow::anyhow!("Execution '{}' not found", execution_id))?;

        exec.status = ExecutionStatus::Cancelled;
        exec.completed_at = Some(chrono::Utc::now());
        info!(execution_id = %execution_id, "Workflow execution cancelled");
        Ok(())
    }

    /// Get execution status.
    pub fn get_execution(&self, execution_id: &str) -> Option<&WorkflowExecution> {
        self.executions.get(execution_id)
    }

    /// List all registered workflows.
    pub fn list_workflows(&self) -> Vec<&Workflow> {
        self.workflows.values().collect()
    }

    /// Get a workflow by ID.
    pub fn get_workflow(&self, id: &str) -> Option<&Workflow> {
        self.workflows.get(id)
    }

    /// Count active executions.
    pub fn active_executions(&self) -> usize {
        self.executions
            .values()
            .filter(|e| e.status == ExecutionStatus::Running)
            .count()
    }

    // -- Internal helpers -------------------------------------------------

    fn validate_workflow(&self, workflow: &Workflow) -> Result<()> {
        if workflow.id.is_empty() {
            anyhow::bail!("Workflow ID cannot be empty");
        }
        if workflow.steps.is_empty() {
            anyhow::bail!("Workflow must have at least one step");
        }

        // Validate DAG: check for cycles and missing dependencies
        let step_ids: Vec<&str> = workflow.steps.iter().map(|s| s.id.as_str()).collect();

        for step in &workflow.steps {
            for dep in &step.depends_on {
                if !step_ids.contains(&dep.as_str()) {
                    anyhow::bail!(
                        "Step '{}' depends on '{}' which doesn't exist",
                        step.id,
                        dep
                    );
                }
                if dep == &step.id {
                    anyhow::bail!("Step '{}' depends on itself", step.id);
                }
            }
        }

        // Check for duplicate step IDs
        let mut seen = std::collections::HashSet::new();
        for step in &workflow.steps {
            if !seen.insert(&step.id) {
                anyhow::bail!("Duplicate step ID: '{}'", step.id);
            }
        }

        // Detect cycles using topological sort attempt
        if self.has_cycle(&workflow.steps) {
            anyhow::bail!("Workflow contains a dependency cycle");
        }

        Ok(())
    }

    fn has_cycle(&self, steps: &[WorkflowStep]) -> bool {
        let mut in_degree: HashMap<&str, usize> = HashMap::new();
        let mut adjacency: HashMap<&str, Vec<&str>> = HashMap::new();

        for step in steps {
            in_degree.entry(step.id.as_str()).or_insert(0);
            adjacency.entry(step.id.as_str()).or_default();
            for dep in &step.depends_on {
                *in_degree.entry(step.id.as_str()).or_insert(0) += 1;
                adjacency
                    .entry(dep.as_str())
                    .or_default()
                    .push(step.id.as_str());
            }
        }

        let mut queue: Vec<&str> = in_degree
            .iter()
            .filter(|(_, &deg)| deg == 0)
            .map(|(&id, _)| id)
            .collect();

        let mut visited = 0;

        while let Some(node) = queue.pop() {
            visited += 1;
            if let Some(neighbors) = adjacency.get(node) {
                for &neighbor in neighbors {
                    if let Some(deg) = in_degree.get_mut(neighbor) {
                        *deg -= 1;
                        if *deg == 0 {
                            queue.push(neighbor);
                        }
                    }
                }
            }
        }

        visited != steps.len()
    }

    fn evaluate_condition(&self, cond: &StepCondition, vars: &HashMap<String, String>) -> bool {
        let left = self.resolve_template(&cond.left, vars);
        let right = self.resolve_template(&cond.right, vars);

        match cond.operator {
            ConditionOp::Equals => left == right,
            ConditionOp::NotEquals => left != right,
            ConditionOp::Contains => left.contains(&right),
            ConditionOp::GreaterThan => {
                left.parse::<f64>()
                    .ok()
                    .zip(right.parse::<f64>().ok())
                    .map(|(l, r)| l > r)
                    .unwrap_or(false)
            }
            ConditionOp::LessThan => {
                left.parse::<f64>()
                    .ok()
                    .zip(right.parse::<f64>().ok())
                    .map(|(l, r)| l < r)
                    .unwrap_or(false)
            }
            ConditionOp::IsEmpty => left.is_empty(),
            ConditionOp::IsNotEmpty => !left.is_empty(),
            ConditionOp::Matches => {
                regex::Regex::new(&right)
                    .map(|re| re.is_match(&left))
                    .unwrap_or(false)
            }
        }
    }

    fn resolve_template(&self, template: &str, vars: &HashMap<String, String>) -> String {
        let mut result = template.to_string();
        for (key, value) in vars {
            result = result.replace(&format!("{{{{{}}}}}", key), value);
        }
        result
    }

    fn execute_step_action(
        &self,
        action: &StepAction,
        vars: &HashMap<String, String>,
    ) -> Result<String> {
        match action {
            StepAction::LlmCall { prompt_template, .. } => {
                let prompt = self.resolve_template(prompt_template, vars);
                // In production, this would call the actual provider
                Ok(format!("[LLM response to: {}]", truncate(&prompt, 100)))
            }
            StepAction::ToolExec { tool_name, arguments, .. } => {
                // In production, this would execute through the sandbox
                Ok(format!(
                    "[Tool '{}' executed with {} args]",
                    tool_name,
                    arguments.len()
                ))
            }
            StepAction::ChannelSend { channel, message_template } => {
                let message = self.resolve_template(message_template, vars);
                Ok(format!("[Sent to {}: {}]", channel, truncate(&message, 100)))
            }
            StepAction::WaitForEvent { event_type, .. } => {
                Ok(format!("[Waiting for event: {:?}]", event_type))
            }
            StepAction::Transform { template, .. } => {
                let result = self.resolve_template(template, vars);
                Ok(result)
            }
            StepAction::Branch { condition, .. } => {
                let result = self.evaluate_condition(condition, vars);
                Ok(result.to_string())
            }
            StepAction::SubWorkflow { workflow_id, .. } => {
                Ok(format!("[Sub-workflow '{}' would execute]", workflow_id))
            }
            StepAction::HttpRequest { method, url_template, .. } => {
                let url = self.resolve_template(url_template, vars);
                Ok(format!("[HTTP {} {}]", method, truncate(&url, 100)))
            }
            StepAction::Delay { seconds } => {
                // In production, use tokio::time::sleep
                Ok(format!("[Delayed {} seconds]", seconds))
            }
            StepAction::Log { message_template, level } => {
                let message = self.resolve_template(message_template, vars);
                info!(level = %level, "[Workflow log] {}", message);
                Ok(message)
            }
        }
    }
}

/// Extract the output_var from a step action, if any.
fn get_output_var(action: &StepAction) -> Option<String> {
    match action {
        StepAction::LlmCall { output_var, .. }
        | StepAction::ToolExec { output_var, .. }
        | StepAction::WaitForEvent { output_var, .. }
        | StepAction::Transform { output_var, .. }
        | StepAction::Branch { output_var, .. }
        | StepAction::SubWorkflow { output_var, .. }
        | StepAction::HttpRequest { output_var, .. } => Some(output_var.clone()),
        StepAction::ChannelSend { .. }
        | StepAction::Delay { .. }
        | StepAction::Log { .. } => None,
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max])
    }
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Workflow engine configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_max_concurrent_workflows")]
    pub max_concurrent: usize,
    #[serde(default)]
    pub workflows_dir: Option<String>,
    #[serde(default = "default_workflow_timeout")]
    pub default_timeout_secs: u64,
}

impl Default for WorkflowConfig {
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
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_simple_workflow() -> Workflow {
        Workflow {
            id: "test-wf".to_string(),
            name: "Test Workflow".to_string(),
            description: "A test workflow".to_string(),
            steps: vec![
                WorkflowStep {
                    id: "step1".to_string(),
                    name: "First Step".to_string(),
                    action: StepAction::Transform {
                        template: "Hello {{name}}!".to_string(),
                        output_var: "greeting".to_string(),
                    },
                    depends_on: vec![],
                    condition: None,
                    retry: RetryPolicy::default(),
                    timeout_secs: None,
                },
                WorkflowStep {
                    id: "step2".to_string(),
                    name: "Second Step".to_string(),
                    action: StepAction::Log {
                        message_template: "{{greeting}}".to_string(),
                        level: "info".to_string(),
                    },
                    depends_on: vec!["step1".to_string()],
                    condition: None,
                    retry: RetryPolicy::default(),
                    timeout_secs: None,
                },
            ],
            triggers: vec![Trigger::Manual],
            variables: {
                let mut m = HashMap::new();
                m.insert("name".to_string(), "World".to_string());
                m
            },
            enabled: true,
            max_retries: 0,
            timeout_secs: 60,
        }
    }

    #[test]
    fn test_register_workflow() {
        let mut engine = WorkflowEngine::new(4);
        let wf = make_simple_workflow();
        assert!(engine.register(wf).is_ok());
        assert_eq!(engine.list_workflows().len(), 1);
    }

    #[test]
    fn test_register_empty_workflow_fails() {
        let mut engine = WorkflowEngine::new(4);
        let wf = Workflow {
            id: "empty".to_string(),
            name: "Empty".to_string(),
            description: "".to_string(),
            steps: vec![],
            triggers: vec![],
            variables: HashMap::new(),
            enabled: true,
            max_retries: 0,
            timeout_secs: 60,
        };
        assert!(engine.register(wf).is_err());
    }

    #[test]
    fn test_register_empty_id_fails() {
        let mut engine = WorkflowEngine::new(4);
        let mut wf = make_simple_workflow();
        wf.id = "".to_string();
        assert!(engine.register(wf).is_err());
    }

    #[test]
    fn test_start_execution() {
        let mut engine = WorkflowEngine::new(4);
        engine.register(make_simple_workflow()).unwrap();

        let exec_id = engine.start_execution("test-wf").unwrap();
        assert!(!exec_id.is_empty());
        assert_eq!(engine.active_executions(), 1);
    }

    #[test]
    fn test_start_disabled_workflow_fails() {
        let mut engine = WorkflowEngine::new(4);
        let mut wf = make_simple_workflow();
        wf.enabled = false;
        engine.register(wf).unwrap();
        assert!(engine.start_execution("test-wf").is_err());
    }

    #[test]
    fn test_start_nonexistent_fails() {
        let mut engine = WorkflowEngine::new(4);
        assert!(engine.start_execution("nonexistent").is_err());
    }

    #[test]
    fn test_max_concurrent_enforced() {
        let mut engine = WorkflowEngine::new(1);
        engine.register(make_simple_workflow()).unwrap();

        let _exec1 = engine.start_execution("test-wf").unwrap();
        assert!(engine.start_execution("test-wf").is_err());
    }

    #[test]
    fn test_execute_next_step() {
        let mut engine = WorkflowEngine::new(4);
        engine.register(make_simple_workflow()).unwrap();

        let exec_id = engine.start_execution("test-wf").unwrap();

        // Execute step1
        let result = engine.execute_next_step(&exec_id).unwrap();
        assert_eq!(result, Some("step1".to_string()));

        // Check variable was set
        let exec = engine.get_execution(&exec_id).unwrap();
        assert_eq!(exec.variables.get("greeting"), Some(&"Hello World!".to_string()));

        // Execute step2
        let result = engine.execute_next_step(&exec_id).unwrap();
        assert_eq!(result, Some("step2".to_string()));

        // No more steps
        let result = engine.execute_next_step(&exec_id).unwrap();
        assert_eq!(result, None);

        // Should be completed
        let exec = engine.get_execution(&exec_id).unwrap();
        assert_eq!(exec.status, ExecutionStatus::Completed);
    }

    #[test]
    fn test_run_to_completion() {
        let mut engine = WorkflowEngine::new(4);
        engine.register(make_simple_workflow()).unwrap();

        let exec_id = engine.start_execution("test-wf").unwrap();
        let status = engine.run_to_completion(&exec_id).unwrap();
        assert_eq!(status, ExecutionStatus::Completed);
    }

    #[test]
    fn test_cancel_execution() {
        let mut engine = WorkflowEngine::new(4);
        engine.register(make_simple_workflow()).unwrap();

        let exec_id = engine.start_execution("test-wf").unwrap();
        engine.cancel_execution(&exec_id).unwrap();

        let exec = engine.get_execution(&exec_id).unwrap();
        assert_eq!(exec.status, ExecutionStatus::Cancelled);
        assert!(exec.completed_at.is_some());
    }

    #[test]
    fn test_unregister_workflow() {
        let mut engine = WorkflowEngine::new(4);
        engine.register(make_simple_workflow()).unwrap();
        assert!(engine.unregister("test-wf"));
        assert!(!engine.unregister("test-wf"));
        assert_eq!(engine.list_workflows().len(), 0);
    }

    #[test]
    fn test_conditional_step() {
        let mut engine = WorkflowEngine::new(4);
        let wf = Workflow {
            id: "cond-wf".to_string(),
            name: "Conditional".to_string(),
            description: "".to_string(),
            steps: vec![
                WorkflowStep {
                    id: "check".to_string(),
                    name: "Check".to_string(),
                    action: StepAction::Transform {
                        template: "checked".to_string(),
                        output_var: "result".to_string(),
                    },
                    depends_on: vec![],
                    condition: Some(StepCondition {
                        left: "{{flag}}".to_string(),
                        operator: ConditionOp::Equals,
                        right: "yes".to_string(),
                    }),
                    retry: RetryPolicy::default(),
                    timeout_secs: None,
                },
            ],
            triggers: vec![Trigger::Manual],
            variables: {
                let mut m = HashMap::new();
                m.insert("flag".to_string(), "no".to_string());
                m
            },
            enabled: true,
            max_retries: 0,
            timeout_secs: 60,
        };

        engine.register(wf).unwrap();
        let exec_id = engine.start_execution("cond-wf").unwrap();
        engine.execute_next_step(&exec_id).unwrap();

        let exec = engine.get_execution(&exec_id).unwrap();
        let step_result = exec.step_results.get("check").unwrap();
        assert_eq!(step_result.status, StepStatus::Skipped);
    }

    #[test]
    fn test_dependency_cycle_detection() {
        let mut engine = WorkflowEngine::new(4);
        let wf = Workflow {
            id: "cycle-wf".to_string(),
            name: "Cycle".to_string(),
            description: "".to_string(),
            steps: vec![
                WorkflowStep {
                    id: "a".to_string(),
                    name: "A".to_string(),
                    action: StepAction::Log {
                        message_template: "a".to_string(),
                        level: "info".to_string(),
                    },
                    depends_on: vec!["b".to_string()],
                    condition: None,
                    retry: RetryPolicy::default(),
                    timeout_secs: None,
                },
                WorkflowStep {
                    id: "b".to_string(),
                    name: "B".to_string(),
                    action: StepAction::Log {
                        message_template: "b".to_string(),
                        level: "info".to_string(),
                    },
                    depends_on: vec!["a".to_string()],
                    condition: None,
                    retry: RetryPolicy::default(),
                    timeout_secs: None,
                },
            ],
            triggers: vec![],
            variables: HashMap::new(),
            enabled: true,
            max_retries: 0,
            timeout_secs: 60,
        };

        assert!(engine.register(wf).is_err());
    }

    #[test]
    fn test_missing_dependency_fails() {
        let mut engine = WorkflowEngine::new(4);
        let wf = Workflow {
            id: "bad-dep".to_string(),
            name: "Bad Dep".to_string(),
            description: "".to_string(),
            steps: vec![WorkflowStep {
                id: "step1".to_string(),
                name: "Step 1".to_string(),
                action: StepAction::Log {
                    message_template: "hi".to_string(),
                    level: "info".to_string(),
                },
                depends_on: vec!["nonexistent".to_string()],
                condition: None,
                retry: RetryPolicy::default(),
                timeout_secs: None,
            }],
            triggers: vec![],
            variables: HashMap::new(),
            enabled: true,
            max_retries: 0,
            timeout_secs: 60,
        };

        assert!(engine.register(wf).is_err());
    }

    #[test]
    fn test_self_dependency_fails() {
        let mut engine = WorkflowEngine::new(4);
        let wf = Workflow {
            id: "self-dep".to_string(),
            name: "Self Dep".to_string(),
            description: "".to_string(),
            steps: vec![WorkflowStep {
                id: "step1".to_string(),
                name: "Step 1".to_string(),
                action: StepAction::Log {
                    message_template: "hi".to_string(),
                    level: "info".to_string(),
                },
                depends_on: vec!["step1".to_string()],
                condition: None,
                retry: RetryPolicy::default(),
                timeout_secs: None,
            }],
            triggers: vec![],
            variables: HashMap::new(),
            enabled: true,
            max_retries: 0,
            timeout_secs: 60,
        };

        assert!(engine.register(wf).is_err());
    }

    #[test]
    fn test_condition_operators() {
        let engine = WorkflowEngine::new(4);
        let vars: HashMap<String, String> = [
            ("a".to_string(), "hello".to_string()),
            ("b".to_string(), "10".to_string()),
            ("c".to_string(), "".to_string()),
        ]
        .into_iter()
        .collect();

        // Equals
        assert!(engine.evaluate_condition(
            &StepCondition {
                left: "{{a}}".to_string(),
                operator: ConditionOp::Equals,
                right: "hello".to_string(),
            },
            &vars
        ));

        // NotEquals
        assert!(engine.evaluate_condition(
            &StepCondition {
                left: "{{a}}".to_string(),
                operator: ConditionOp::NotEquals,
                right: "world".to_string(),
            },
            &vars
        ));

        // Contains
        assert!(engine.evaluate_condition(
            &StepCondition {
                left: "{{a}}".to_string(),
                operator: ConditionOp::Contains,
                right: "ell".to_string(),
            },
            &vars
        ));

        // GreaterThan
        assert!(engine.evaluate_condition(
            &StepCondition {
                left: "{{b}}".to_string(),
                operator: ConditionOp::GreaterThan,
                right: "5".to_string(),
            },
            &vars
        ));

        // IsEmpty
        assert!(engine.evaluate_condition(
            &StepCondition {
                left: "{{c}}".to_string(),
                operator: ConditionOp::IsEmpty,
                right: "".to_string(),
            },
            &vars
        ));

        // IsNotEmpty
        assert!(engine.evaluate_condition(
            &StepCondition {
                left: "{{a}}".to_string(),
                operator: ConditionOp::IsNotEmpty,
                right: "".to_string(),
            },
            &vars
        ));
    }

    #[test]
    fn test_template_resolution() {
        let engine = WorkflowEngine::new(4);
        let mut vars = HashMap::new();
        vars.insert("name".to_string(), "Alice".to_string());
        vars.insert("age".to_string(), "30".to_string());

        let result = engine.resolve_template("Hello {{name}}, you are {{age}}!", &vars);
        assert_eq!(result, "Hello Alice, you are 30!");
    }

    #[test]
    fn test_workflow_serialization() {
        let wf = make_simple_workflow();
        let json = serde_json::to_string(&wf).unwrap();
        assert!(json.contains("test-wf"));

        let deser: Workflow = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.id, "test-wf");
        assert_eq!(deser.steps.len(), 2);
    }

    #[test]
    fn test_execution_status_display() {
        assert_eq!(ExecutionStatus::Running.to_string(), "RUNNING");
        assert_eq!(ExecutionStatus::Completed.to_string(), "COMPLETED");
        assert_eq!(ExecutionStatus::Failed.to_string(), "FAILED");
        assert_eq!(ExecutionStatus::Cancelled.to_string(), "CANCELLED");
    }

    #[test]
    fn test_get_workflow() {
        let mut engine = WorkflowEngine::new(4);
        engine.register(make_simple_workflow()).unwrap();

        assert!(engine.get_workflow("test-wf").is_some());
        assert!(engine.get_workflow("nonexistent").is_none());
    }

    #[test]
    fn test_duplicate_step_id_fails() {
        let mut engine = WorkflowEngine::new(4);
        let wf = Workflow {
            id: "dup".to_string(),
            name: "Dup".to_string(),
            description: "".to_string(),
            steps: vec![
                WorkflowStep {
                    id: "step1".to_string(),
                    name: "A".to_string(),
                    action: StepAction::Log {
                        message_template: "a".to_string(),
                        level: "info".to_string(),
                    },
                    depends_on: vec![],
                    condition: None,
                    retry: RetryPolicy::default(),
                    timeout_secs: None,
                },
                WorkflowStep {
                    id: "step1".to_string(),
                    name: "B".to_string(),
                    action: StepAction::Log {
                        message_template: "b".to_string(),
                        level: "info".to_string(),
                    },
                    depends_on: vec![],
                    condition: None,
                    retry: RetryPolicy::default(),
                    timeout_secs: None,
                },
            ],
            triggers: vec![],
            variables: HashMap::new(),
            enabled: true,
            max_retries: 0,
            timeout_secs: 60,
        };
        assert!(engine.register(wf).is_err());
    }
}
