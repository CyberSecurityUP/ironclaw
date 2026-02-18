//! `ironclaw doctor` — Configuration and Security Diagnostics.
//!
//! Runs 20+ checks covering every security subsystem:
//! sandbox availability, enforcement, memory encryption, shell policy,
//! cloud metadata blocking, audit logging, skill signatures, PII redaction,
//! command guardian, RBAC, anti-stealer, DLP, SSRF, deny-list coverage,
//! channel configuration, channel credentials, session auth, and gateway port.

use std::time::Duration;

use anyhow::Result;

use crate::core::config::Config;
use crate::guardian::CommandGuardian;
use crate::rbac::Policy;

/// Run diagnostic checks on the IronClaw configuration and environment.
pub async fn run(config: &Config, policy: &Policy, guardian: &CommandGuardian) -> Result<()> {
    println!("IronClaw Doctor -- Configuration & Security Diagnostics\n");

    let mut warnings: u32 = 0;
    let mut errors: u32 = 0;

    // -------------------------------------------------------------------
    // Check 1: Sandbox availability
    // -------------------------------------------------------------------
    print!("  [1]  Sandbox backend ({})... ", config.sandbox.backend);
    match config.sandbox.backend.as_str() {
        "docker" => {
            let docker_available = tokio::process::Command::new("docker")
                .arg("info")
                .output()
                .await
                .map(|o| o.status.success())
                .unwrap_or(false);
            if docker_available {
                println!("OK");
            } else {
                println!("WARNING: Docker not available");
                warnings += 1;
            }
        }
        "bubblewrap" | "bwrap" => {
            let bwrap_available = tokio::process::Command::new("bwrap")
                .arg("--version")
                .output()
                .await
                .map(|o| o.status.success())
                .unwrap_or(false);
            if bwrap_available {
                println!("OK");
            } else {
                println!("WARNING: Bubblewrap (bwrap) not available");
                warnings += 1;
            }
        }
        "native" => {
            println!("WARNING: Native sandbox has reduced isolation");
            warnings += 1;
        }
        _ => {
            println!("ERROR: Unknown sandbox backend");
            errors += 1;
        }
    }

    // -------------------------------------------------------------------
    // Check 2: Sandbox enforcement
    // -------------------------------------------------------------------
    print!("  [2]  Sandbox enforcement... ");
    if config.sandbox.enforce {
        println!("OK (enforced)");
    } else {
        println!("WARNING: Sandbox enforcement disabled");
        warnings += 1;
    }

    // -------------------------------------------------------------------
    // Check 3: Memory encryption
    // -------------------------------------------------------------------
    print!("  [3]  Memory encryption... ");
    if config.memory.encrypt_at_rest {
        println!("OK (AES-256-GCM)");
    } else {
        println!("WARNING: Memory encryption disabled");
        warnings += 1;
    }

    // -------------------------------------------------------------------
    // Check 4: Shell policy
    // -------------------------------------------------------------------
    print!("  [4]  Shell execution... ");
    if config.permissions.system.allow_shell {
        println!("ENABLED (commands pass through Guardian)");
    } else {
        println!("OK (disabled)");
    }

    // -------------------------------------------------------------------
    // Check 5: Cloud metadata blocking
    // -------------------------------------------------------------------
    print!("  [5]  Cloud metadata blocking... ");
    let blocks_metadata = config
        .permissions
        .network
        .block_domains
        .iter()
        .any(|d| d.contains("169.254.169.254"));
    if blocks_metadata {
        println!("OK");
    } else {
        println!("ERROR: Cloud metadata endpoint not blocked");
        errors += 1;
    }

    // -------------------------------------------------------------------
    // Check 6: Audit logging
    // -------------------------------------------------------------------
    print!("  [6]  Audit logging... ");
    if config.audit.enabled {
        println!("OK ({})", config.audit.path);
    } else {
        println!("WARNING: Audit logging disabled");
        warnings += 1;
    }

    // -------------------------------------------------------------------
    // Check 7: Skill signatures
    // -------------------------------------------------------------------
    print!("  [7]  Skill signature verification... ");
    if config.skills.require_signatures {
        println!("OK (required)");
    } else {
        println!("WARNING: Skill signatures not required");
        warnings += 1;
    }

    // -------------------------------------------------------------------
    // Check 8: PII redaction
    // -------------------------------------------------------------------
    print!("  [8]  PII redaction in logs... ");
    if config.observability.redact_pii {
        println!("OK");
    } else {
        println!("WARNING: PII redaction disabled");
        warnings += 1;
    }

    // -------------------------------------------------------------------
    // Check 9: Command Guardian
    // -------------------------------------------------------------------
    print!("  [9]  Command Guardian... ");
    println!("OK ({} blocked patterns)", guardian.blocked_count());

    // -------------------------------------------------------------------
    // Check 10: RBAC
    // -------------------------------------------------------------------
    print!("  [10] RBAC policy... ");
    println!("OK ({} tool permissions)", policy.tool_count());

    // -------------------------------------------------------------------
    // Check 11: Anti-stealer
    // -------------------------------------------------------------------
    print!("  [11] Anti-stealer protection... ");
    if config.antitheft.enforce {
        println!("OK (enforced)");
    } else {
        println!("WARNING: Anti-stealer in warn-only mode");
        warnings += 1;
    }

    // -------------------------------------------------------------------
    // Check 12: DLP
    // -------------------------------------------------------------------
    print!("  [12] Data Loss Prevention... ");
    if config.dlp.enabled {
        println!("OK (action: {})", config.dlp.default_action);
    } else {
        println!("WARNING: DLP scanning disabled");
        warnings += 1;
    }

    // -------------------------------------------------------------------
    // Check 13: SSRF protection
    // -------------------------------------------------------------------
    print!("  [13] SSRF protection... ");
    if config.ssrf.block_private_ips {
        println!("OK (private IPs blocked)");
    } else {
        println!("WARNING: Private IP blocking disabled");
        warnings += 1;
    }

    // -------------------------------------------------------------------
    // Check 14: Filesystem deny list coverage
    // -------------------------------------------------------------------
    print!("  [14] Filesystem deny list... ");
    let deny_count = config.permissions.filesystem.deny.len();
    if deny_count >= 20 {
        println!("OK ({} paths denied)", deny_count);
    } else {
        println!(
            "WARNING: Only {} paths in deny list -- consider expanding",
            deny_count
        );
        warnings += 1;
    }

    // -------------------------------------------------------------------
    // Check 15: Network blocked domains coverage
    // -------------------------------------------------------------------
    print!("  [15] Network block list... ");
    let block_count = config.permissions.network.block_domains.len();
    if block_count >= 5 {
        println!("OK ({} domains blocked)", block_count);
    } else {
        println!(
            "WARNING: Only {} domains in block list -- consider adding known exfiltration services",
            block_count
        );
        warnings += 1;
    }

    // -------------------------------------------------------------------
    // Check 16: Correlation window
    // -------------------------------------------------------------------
    print!("  [16] Anti-stealer correlation window... ");
    if config.antitheft.correlation_window_secs > 0 {
        println!("OK ({}s)", config.antitheft.correlation_window_secs);
    } else {
        println!("WARNING: Correlation window is 0 (disabled)");
        warnings += 1;
    }

    // -------------------------------------------------------------------
    // Check 17: Channel configuration
    // -------------------------------------------------------------------
    print!("  [17] Channel configuration... ");
    let enabled_channels: Vec<&String> = config
        .channels
        .iter()
        .filter(|(_, ch)| ch.enabled)
        .map(|(name, _)| name)
        .collect();
    if !enabled_channels.is_empty() {
        println!("OK ({} channel(s) enabled)", enabled_channels.len());
    } else {
        println!("WARNING: No channels are configured and enabled");
        warnings += 1;
    }

    // -------------------------------------------------------------------
    // Check 18: Channel credentials
    // -------------------------------------------------------------------
    print!("  [18] Channel credentials... ");
    let channels_missing_creds: Vec<&String> = config
        .channels
        .iter()
        .filter(|(_, ch)| ch.enabled && ch.token.is_none() && ch.webhook_url.is_none())
        .map(|(name, _)| name)
        .collect();
    if channels_missing_creds.is_empty() && !enabled_channels.is_empty() {
        println!("OK (all enabled channels have credentials)");
    } else if enabled_channels.is_empty() {
        println!("SKIPPED (no enabled channels)");
    } else {
        println!(
            "WARNING: Missing credentials for channel(s): {}",
            channels_missing_creds
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
        warnings += 1;
    }

    // -------------------------------------------------------------------
    // Check 19: Session authentication
    // -------------------------------------------------------------------
    print!("  [19] Session authentication... ");
    if config.session_auth.enabled {
        match &config.session_auth.secret {
            Some(secret) if !secret.is_empty() => {
                println!("OK (enabled, custom secret set, TTL {}s)", config.session_auth.ttl_secs);
            }
            _ => {
                println!("WARNING: Session auth enabled but no custom secret configured");
                warnings += 1;
            }
        }
    } else {
        println!("WARNING: Session authentication is disabled");
        warnings += 1;
    }

    // -------------------------------------------------------------------
    // Check 20: Gateway port availability
    // -------------------------------------------------------------------
    print!("  [20] Gateway port availability (:{})... ", config.gateway.port);
    if config.gateway.enabled {
        let bind_addr = format!("{}:{}", config.gateway.bind_address, config.gateway.port);
        let port_check = tokio::time::timeout(
            Duration::from_secs(2),
            tokio::net::TcpListener::bind(&bind_addr),
        )
        .await;
        match port_check {
            Ok(Ok(listener)) => {
                drop(listener);
                println!("OK (port is available)");
            }
            Ok(Err(e)) => {
                println!("ERROR: Port {} is not available -- {}", config.gateway.port, e);
                errors += 1;
            }
            Err(_) => {
                println!("WARNING: Port check timed out");
                warnings += 1;
            }
        }
    } else {
        println!("SKIPPED (gateway disabled)");
    }

    // -------------------------------------------------------------------
    // Summary
    // -------------------------------------------------------------------
    println!("\n--- Summary ---");
    println!("  Errors:   {}", errors);
    println!("  Warnings: {}", warnings);

    if errors > 0 {
        println!("\nFix errors before running in production.");
    } else if warnings > 0 {
        println!("\nConfiguration is functional but review warnings for production use.");
    } else {
        println!("\nAll checks passed. Configuration is secure.");
    }

    Ok(())
}
