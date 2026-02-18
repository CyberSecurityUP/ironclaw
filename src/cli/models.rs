//! `ironclaw models` — list available providers and their default models.

use anyhow::Result;
use crate::providers::ProviderFactory;

/// Display all providers and their default models.
pub fn show(available_only: bool) -> Result<()> {
    println!("IronClaw — Available Providers & Models\n");
    println!(
        "{:<15} {:<50} {:<8} {}",
        "PROVIDER", "DEFAULT MODEL", "COST", "DESCRIPTION"
    );
    println!("{}", "-".repeat(110));

    let catalog = ProviderFactory::model_catalog();
    for entry in catalog {
        // If --available, skip providers that need an API key but don't have one set
        if available_only && !entry.env_key.is_empty() {
            if std::env::var(entry.env_key).is_err() {
                continue;
            }
        }

        println!(
            "{:<15} {:<50} {:<8} {}",
            entry.name, entry.default_model, entry.cost_tier, entry.description
        );
    }

    println!("\n\nModel Presets (use with --provider):\n");
    println!("{:<10} {:<15} {}", "PRESET", "PROVIDER", "MODEL");
    println!("{}", "-".repeat(70));

    for (alias, provider, model) in ProviderFactory::preset_list() {
        println!("{:<10} {:<15} {}", alias, provider, model);
    }

    println!("\nExamples:");
    println!("  ironclaw run --provider fast");
    println!("  ironclaw run --provider smart");
    println!("  ironclaw run --provider local");
    println!("  ironclaw run --provider openai --model gpt-4.1-mini");

    Ok(())
}
