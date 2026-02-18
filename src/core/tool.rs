//! Enhanced Tool System for IronClaw.
//!
//! All interactions between the AI agent and the outside world pass through
//! the `Tool` trait.  Each tool declares its own risk level, required
//! permissions, parameter schema, and cacheability — the engine uses these
//! declarations to drive the security pipeline.
//!
//! Includes:
//! - `Tool` async trait with extended capabilities
//! - `ToolRegistry` for registration, lookup, and schema export
//! - `BuiltinTools` enum listing every built-in tool

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

use super::types::{RiskLevel, SecurityContext, ToolResult};

// ---------------------------------------------------------------------------
// Tool trait
// ---------------------------------------------------------------------------

/// Core trait that every tool must implement.
/// Tool execution is subject to RBAC, sandboxing, DLP, and audit logging.
#[async_trait]
pub trait Tool: Send + Sync {
    /// Unique name for this tool (used in LLM function calling).
    fn name(&self) -> &str;

    /// Human-readable description of what this tool does.
    fn description(&self) -> &str;

    /// JSON Schema describing the tool's parameters.
    fn parameters_schema(&self) -> Value;

    /// Intrinsic risk level of this tool.
    fn risk_level(&self) -> RiskLevel;

    /// Required RBAC permissions to execute this tool.
    fn required_permissions(&self) -> Vec<String>;

    /// Execute the tool with the given arguments.
    /// The security context has already been validated by the time this is
    /// called.
    async fn execute(
        &self,
        args: &HashMap<String, Value>,
        ctx: &SecurityContext,
    ) -> Result<ToolResult>;

    /// Validate arguments before execution.
    /// Called after schema validation but before security checks.
    fn validate_args(&self, args: &HashMap<String, Value>) -> Result<()> {
        let _ = args;
        Ok(())
    }

    /// Whether results from this tool can be cached (for identical inputs).
    /// Default: false (conservative).
    fn is_cacheable(&self) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// BuiltinTools
// ---------------------------------------------------------------------------

/// Enumerates all built-in tools shipped with IronClaw.
/// Each variant maps 1-to-1 to a struct that implements `Tool`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BuiltinTools {
    FileRead,
    FileWrite,
    Shell,
    HttpRequest,
    Search,
    MemoryStore,
    MemoryRetrieve,
    DirectoryList,
    Screenshot,
    Browser,
}

impl BuiltinTools {
    /// The string name used for function calling.
    pub fn tool_name(&self) -> &'static str {
        match self {
            Self::FileRead => "file_read",
            Self::FileWrite => "file_write",
            Self::Shell => "shell",
            Self::HttpRequest => "http_request",
            Self::Search => "search",
            Self::MemoryStore => "memory_store",
            Self::MemoryRetrieve => "memory_retrieve",
            Self::DirectoryList => "directory_list",
            Self::Screenshot => "screenshot",
            Self::Browser => "browser",
        }
    }

    /// Default risk level for the built-in tool.
    pub fn default_risk(&self) -> RiskLevel {
        match self {
            Self::FileRead | Self::DirectoryList | Self::Search
            | Self::MemoryRetrieve => RiskLevel::Low,
            Self::MemoryStore => RiskLevel::Medium,
            Self::FileWrite | Self::HttpRequest | Self::Browser
            | Self::Screenshot => RiskLevel::High,
            Self::Shell => RiskLevel::Critical,
        }
    }

    /// List every variant.
    pub fn all() -> &'static [BuiltinTools] {
        &[
            Self::FileRead,
            Self::FileWrite,
            Self::Shell,
            Self::HttpRequest,
            Self::Search,
            Self::MemoryStore,
            Self::MemoryRetrieve,
            Self::DirectoryList,
            Self::Screenshot,
            Self::Browser,
        ]
    }
}

impl std::fmt::Display for BuiltinTools {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.tool_name())
    }
}

// ---------------------------------------------------------------------------
// ToolRegistry
// ---------------------------------------------------------------------------

/// Registry of all available tools.
pub struct ToolRegistry {
    tools: HashMap<String, Box<dyn Tool>>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self {
            tools: HashMap::new(),
        }
    }

    /// Register a tool.  Returns an error if a tool with the same name
    /// already exists.
    pub fn register(&mut self, tool: Box<dyn Tool>) -> Result<()> {
        let name = tool.name().to_string();
        if self.tools.contains_key(&name) {
            anyhow::bail!("Tool '{}' is already registered", name);
        }
        self.tools.insert(name, tool);
        Ok(())
    }

    /// Get a tool by name.
    pub fn get(&self, name: &str) -> Option<&dyn Tool> {
        self.tools.get(name).map(|t| t.as_ref())
    }

    /// List all registered tool names.
    pub fn list(&self) -> Vec<&str> {
        self.tools.keys().map(|s| s.as_str()).collect()
    }

    /// Get tool schemas suitable for LLM function calling.
    pub fn schemas(&self) -> Vec<Value> {
        self.tools
            .values()
            .map(|tool| {
                serde_json::json!({
                    "name": tool.name(),
                    "description": tool.description(),
                    "parameters": tool.parameters_schema(),
                })
            })
            .collect()
    }
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_tools_all() {
        let all = BuiltinTools::all();
        assert_eq!(all.len(), 10);
    }

    #[test]
    fn test_builtin_names_unique() {
        let all = BuiltinTools::all();
        let names: Vec<&str> = all.iter().map(|t| t.tool_name()).collect();
        let unique: std::collections::HashSet<&str> = names.iter().copied().collect();
        assert_eq!(names.len(), unique.len(), "Duplicate tool names found");
    }

    #[test]
    fn test_builtin_risk_levels() {
        assert_eq!(BuiltinTools::FileRead.default_risk(), RiskLevel::Low);
        assert_eq!(BuiltinTools::Shell.default_risk(), RiskLevel::Critical);
        assert_eq!(BuiltinTools::FileWrite.default_risk(), RiskLevel::High);
        assert_eq!(BuiltinTools::MemoryStore.default_risk(), RiskLevel::Medium);
    }

    #[test]
    fn test_builtin_display() {
        assert_eq!(format!("{}", BuiltinTools::Shell), "shell");
        assert_eq!(format!("{}", BuiltinTools::FileRead), "file_read");
    }

    #[test]
    fn test_registry_register_and_get() {
        struct DummyTool;

        #[async_trait]
        impl Tool for DummyTool {
            fn name(&self) -> &str { "dummy" }
            fn description(&self) -> &str { "A test tool" }
            fn parameters_schema(&self) -> Value { serde_json::json!({}) }
            fn risk_level(&self) -> RiskLevel { RiskLevel::Low }
            fn required_permissions(&self) -> Vec<String> { vec![] }
            async fn execute(
                &self,
                _args: &HashMap<String, Value>,
                _ctx: &SecurityContext,
            ) -> Result<ToolResult> {
                Ok(ToolResult {
                    success: true,
                    output: "ok".into(),
                    error: None,
                    metadata: super::super::types::ToolResultMetadata {
                        tool_name: "dummy".into(),
                        duration_ms: 0,
                        sandboxed: false,
                        risk_level: RiskLevel::Low,
                        execution_id: "test".into(),
                        started_at: chrono::Utc::now(),
                        completed_at: chrono::Utc::now(),
                        exit_code: None,
                        bytes_read: 0,
                        bytes_written: 0,
                        truncated: false,
                        provider_usage: None,
                    },
                })
            }
            fn is_cacheable(&self) -> bool { true }
        }

        let mut reg = ToolRegistry::new();
        reg.register(Box::new(DummyTool)).unwrap();

        assert!(reg.get("dummy").is_some());
        assert!(reg.get("nonexistent").is_none());
        assert_eq!(reg.list().len(), 1);
    }

    #[test]
    fn test_registry_duplicate_rejected() {
        struct DummyTool;

        #[async_trait]
        impl Tool for DummyTool {
            fn name(&self) -> &str { "dup" }
            fn description(&self) -> &str { "" }
            fn parameters_schema(&self) -> Value { serde_json::json!({}) }
            fn risk_level(&self) -> RiskLevel { RiskLevel::Low }
            fn required_permissions(&self) -> Vec<String> { vec![] }
            async fn execute(
                &self,
                _: &HashMap<String, Value>,
                _: &SecurityContext,
            ) -> Result<ToolResult> {
                unreachable!()
            }
        }

        let mut reg = ToolRegistry::new();
        reg.register(Box::new(DummyTool)).unwrap();
        assert!(reg.register(Box::new(DummyTool)).is_err());
    }

    #[test]
    fn test_schemas_output() {
        struct TestTool;

        #[async_trait]
        impl Tool for TestTool {
            fn name(&self) -> &str { "test" }
            fn description(&self) -> &str { "desc" }
            fn parameters_schema(&self) -> Value {
                serde_json::json!({"type": "object"})
            }
            fn risk_level(&self) -> RiskLevel { RiskLevel::Low }
            fn required_permissions(&self) -> Vec<String> { vec![] }
            async fn execute(
                &self,
                _: &HashMap<String, Value>,
                _: &SecurityContext,
            ) -> Result<ToolResult> {
                unreachable!()
            }
        }

        let mut reg = ToolRegistry::new();
        reg.register(Box::new(TestTool)).unwrap();

        let schemas = reg.schemas();
        assert_eq!(schemas.len(), 1);
        assert_eq!(schemas[0]["name"], "test");
        assert_eq!(schemas[0]["description"], "desc");
    }
}
