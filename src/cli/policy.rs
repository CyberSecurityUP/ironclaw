//! `ironclaw policy` — Display the current security policy summary.

use anyhow::Result;

use crate::core::config::Config;
use crate::rbac::Policy;

/// Display the current security policy summary.
pub fn show(config: &Config, policy: &Policy) -> Result<()> {
    println!("IronClaw Security Policy Summary\n");

    // --- Filesystem ---
    println!("=== Filesystem ===");
    println!(
        "  Read paths:  {}",
        if config.permissions.filesystem.read.is_empty() {
            "all (except denied)".to_string()
        } else {
            config.permissions.filesystem.read.join(", ")
        }
    );
    println!(
        "  Write paths: {}",
        if config.permissions.filesystem.write.is_empty() {
            "none (secure default)".to_string()
        } else {
            config.permissions.filesystem.write.join(", ")
        }
    );
    println!(
        "  Denied:      {} path patterns",
        config.permissions.filesystem.deny.len()
    );

    // --- Network ---
    println!("\n=== Network ===");
    println!(
        "  Allowed domains:  {}",
        if config.permissions.network.allow_domains.is_empty() {
            "all (except blocked)".to_string()
        } else {
            config.permissions.network.allow_domains.join(", ")
        }
    );
    println!(
        "  Blocked domains:  {} entries",
        config.permissions.network.block_domains.len()
    );
    println!(
        "  Private network:  {}",
        if !config.permissions.network.block_private {
            "allowed"
        } else {
            "blocked"
        }
    );
    println!(
        "  Rate limit:       {}/hour",
        config.permissions.network.max_requests_per_hour
    );

    // --- System ---
    println!("\n=== System ===");
    println!(
        "  Shell execution:    {}",
        if config.permissions.system.allow_shell {
            "enabled"
        } else {
            "disabled"
        }
    );
    println!(
        "  High-risk approval: {}",
        if config.permissions.system.require_approval {
            "required"
        } else {
            "not required"
        }
    );
    println!(
        "  Max concurrent:     {}",
        config.permissions.system.max_concurrent
    );

    // --- Sandbox ---
    println!("\n=== Sandbox ===");
    println!("  Backend:    {}", config.sandbox.backend);
    println!("  Enforced:   {}", config.sandbox.enforce);
    println!("  Network:    {}", config.sandbox.network_policy);
    println!("  Memory:     {} MB", config.sandbox.memory_limit);
    println!("  CPU:        {} cores", config.sandbox.cpu_limit);

    // --- Memory ---
    println!("\n=== Memory ===");
    println!("  Backend:    {}", config.memory.backend);
    println!("  Encrypted:  {}", config.memory.encrypt_at_rest);
    println!("  Isolation:  {}", config.memory.context_isolation);

    // --- Anti-Stealer ---
    println!("\n=== Anti-Stealer ===");
    println!(
        "  Enforce:            {}",
        if config.antitheft.enforce {
            "yes (blocking mode)"
        } else {
            "no (warn-only)"
        }
    );
    println!(
        "  Correlation window: {}s",
        config.antitheft.correlation_window_secs
    );

    // --- DLP ---
    println!("\n=== Data Loss Prevention ===");
    println!(
        "  Enabled:        {}",
        if config.dlp.enabled { "yes" } else { "no" }
    );
    println!("  Default action: {}", config.dlp.default_action);
    println!(
        "  Scan outputs:   {}",
        if config.dlp.scan_tool_outputs {
            "yes"
        } else {
            "no"
        }
    );
    println!(
        "  Scan responses: {}",
        if config.dlp.scan_llm_responses {
            "yes"
        } else {
            "no"
        }
    );

    // --- SSRF ---
    println!("\n=== SSRF Protection ===");
    println!(
        "  Block private IPs: {}",
        if config.ssrf.block_private_ips {
            "yes"
        } else {
            "no"
        }
    );
    println!(
        "  Block metadata:    {}",
        if config.ssrf.block_metadata { "yes" } else { "no" }
    );

    // --- Skills ---
    println!("\n=== Skills ===");
    println!(
        "  Signatures: {}",
        if config.skills.require_signatures {
            "required"
        } else {
            "optional"
        }
    );
    println!("  Trusted keys: {}", config.skills.trusted_keys.len());

    // --- Tool Permissions ---
    println!(
        "\n=== Tool Permissions ({}) ===",
        policy.tool_count()
    );
    for (name, perms) in &config.permissions.tools {
        println!(
            "  {}: enabled={}, approval={}",
            name, perms.enabled, perms.require_approval
        );
    }

    Ok(())
}
