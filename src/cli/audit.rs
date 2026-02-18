//! `ironclaw audit` — View audit log entries.

use anyhow::Result;
use crate::observability::AuditLog;

/// Display recent audit log entries.
pub fn show(audit: &AuditLog, count: usize) -> Result<()> {
    println!("IronClaw Audit Log (last {} entries)\n", count);

    let entries = audit.read_recent(count)?;

    if entries.is_empty() {
        println!("  No audit entries found.");
        return Ok(());
    }

    for entry in &entries {
        let severity_marker = match entry.severity {
            crate::observability::AuditSeverity::Info => " ",
            crate::observability::AuditSeverity::Warning => "!",
            crate::observability::AuditSeverity::Alert => "*",
            crate::observability::AuditSeverity::Critical => "X",
        };

        println!(
            "[{}] {} {:20} {}",
            severity_marker,
            entry.timestamp,
            entry.event_type,
            serde_json::to_string(&entry.data).unwrap_or_default()
        );
    }

    println!("\n  Total entries shown: {}", entries.len());
    Ok(())
}
