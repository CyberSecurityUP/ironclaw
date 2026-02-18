//! `ironclaw skill` — List, verify, install, and scan skills.

use anyhow::Result;
use std::path::Path;

use crate::core::config::Config;
use crate::skills::SkillVerifier;

/// List installed skills.
pub async fn list(config: &Config) -> Result<()> {
    let dir = Path::new(&config.skills.directory);
    let skills = SkillVerifier::list_skills(dir)?;

    if skills.is_empty() {
        println!("No skills installed in {}", config.skills.directory);
    } else {
        println!("Installed skills ({}):", skills.len());
        for skill in &skills {
            println!("  - {}", skill);
        }
    }

    Ok(())
}

/// Verify a skill's signature and integrity.
pub async fn verify(path: &str) -> Result<()> {
    println!("Verifying skill at: {}", path);

    let content = std::fs::read(path)?;
    let hash = SkillVerifier::hash_content(&content);

    println!("  SHA-256: {}", hash);
    println!("  Size:    {} bytes", content.len());

    // Check for manifest
    let dir = Path::new(path).parent().unwrap_or(Path::new("."));
    let manifest_path = dir.join("skill.yaml");

    if manifest_path.exists() {
        println!("  Manifest: found");
    } else {
        println!("  Manifest: NOT FOUND -- skill cannot be verified");
    }

    Ok(())
}

/// Install a skill from a registry.
pub async fn install(name: &str, config: &Config) -> Result<()> {
    if let Some(ref registry) = config.skills.registry_url {
        println!("Installing skill '{}' from {}", name, registry);
        println!("Note: Skill registry support is planned for a future release.");
    } else {
        println!("No skill registry configured. Set skills.registry_url in config.");
    }

    Ok(())
}

/// Scan a skill's source code for dangerous patterns.
pub async fn scan(path: &str) -> Result<()> {
    use crate::skills::scanner::SkillScanner;

    println!("Scanning skill source at: {}\n", path);

    let scanner = SkillScanner::new()?;
    let source = std::fs::read_to_string(path)?;
    let file_name = Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");

    let report = scanner.scan_source(&source, file_name);

    if report.findings.is_empty() {
        println!("  No findings. Recommendation: {}", report.recommendation);
    } else {
        println!("  Findings ({}):", report.findings.len());
        for finding in &report.findings {
            let line_info = finding
                .line_number
                .map(|n| format!(" (line {})", n))
                .unwrap_or_default();
            println!(
                "    [{}] {}: {}{}",
                finding.severity, finding.rule_id, finding.description, line_info
            );
            if let Some(ref cwe) = finding.cwe {
                println!("           CWE: {}", cwe);
            }
        }
        println!("\n  Risk score:      {}", report.risk_score);
        println!("  Recommendation:  {}", report.recommendation);
    }

    Ok(())
}
