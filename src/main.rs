use clap::{Parser, Subcommand};
use tracing::info;

mod core;
mod sandbox;
mod guardian;
mod rbac;
mod memory;
mod providers;
mod cli;
mod observability;
mod plugins;
mod skills;
mod antitheft;
mod network;
mod dlp;
mod ui;
mod channels;
mod gateway;
mod auth;
mod workflow;
mod agents;

#[derive(Parser)]
#[command(name = "ironclaw")]
#[command(about = "Secure-by-default AI agent framework with Zero Trust architecture")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Path to configuration file
    #[arg(short, long, default_value = "ironclaw.yaml")]
    config: String,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the agent in interactive mode
    Run {
        /// Provider to use (e.g., anthropic, openai, ollama) or preset (fast, smart, cheap, local)
        #[arg(short, long, default_value = "anthropic")]
        provider: String,

        /// Model identifier
        #[arg(short, long)]
        model: Option<String>,

        /// Launch the web UI alongside the interactive session
        #[arg(long)]
        ui: bool,
    },

    /// Start the web UI server
    Ui {
        /// Provider to use
        #[arg(short, long, default_value = "anthropic")]
        provider: String,

        /// Model identifier
        #[arg(short, long)]
        model: Option<String>,

        /// Port to bind (overrides config)
        #[arg(long)]
        port: Option<u16>,
    },

    /// List all available providers and models
    Models {
        /// Show only providers with available API keys
        #[arg(long)]
        available: bool,
    },

    /// Interactive onboarding wizard
    Onboard,

    /// Validate configuration and security policies
    Doctor,

    /// Manage skills
    Skill {
        #[command(subcommand)]
        action: SkillCommands,
    },

    /// Show security policy summary
    Policy,

    /// Run the audit log viewer
    Audit {
        /// Number of recent entries to show
        #[arg(short, long, default_value = "50")]
        count: usize,
    },
}

#[derive(Subcommand)]
enum SkillCommands {
    /// List installed skills
    List,
    /// Verify skill signatures
    Verify {
        /// Path to skill directory
        path: String,
    },
    /// Install a skill from a trusted registry
    Install {
        /// Skill identifier
        name: String,
    },
    /// Scan a skill's source for dangerous patterns
    Scan {
        /// Path to skill source file
        path: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli_args = Cli::parse();

    // Initialize observability
    observability::init(cli_args.verbose)?;

    info!("IronClaw v{} starting", env!("CARGO_PKG_VERSION"));

    // Models command doesn't need config or security subsystems
    if let Commands::Models { available } = cli_args.command {
        return cli::models::show(available);
    }

    // Onboard command runs its own wizard (minimal deps)
    if matches!(cli_args.command, Commands::Onboard) {
        return cli::onboard::run().await;
    }

    // Load configuration
    let config = core::config::Config::load(&cli_args.config)?;

    // Initialize security subsystems
    let policy = rbac::Policy::from_config(&config.permissions)?;
    let guardian = guardian::CommandGuardian::new(&config.guardian)?;
    let audit = observability::AuditLog::new(&config.audit)?;

    // Initialize anti-stealer module
    let anti_stealer = antitheft::AntiStealer::new(config.antitheft.enforce)?;
    info!("Anti-Stealer module initialized");

    // Initialize SSRF protection
    let ssrf_guard = network::SsrfGuard::new(
        config.permissions.network.block_private,
        config.permissions.network.block_domains.clone(),
        config.permissions.network.allow_domains.clone(),
    );
    info!("SSRF Guard initialized");

    // Initialize DLP engine
    let dlp_engine = dlp::DlpEngine::new(config.dlp.enabled, dlp::DlpAction::Redact)?;
    info!("DLP engine initialized with {} rules", dlp_engine.rule_count());

    // Initialize cost tracker
    let cost_tracker = core::cost::CostTracker::new(
        "~/.ironclaw/costs.db",
        core::cost::BudgetConfig {
            daily_limit_usd: core::cost::cents_to_usd(config.agent.max_daily_cost_cents),
            monthly_limit_usd: core::cost::cents_to_usd(config.agent.max_daily_cost_cents * 30),
            alert_threshold: 0.8,
        },
    )
    .ok();
    if cost_tracker.is_some() {
        info!("Cost tracker initialized");
    }

    // Initialize skill scanner
    let skill_scanner = skills::scanner::SkillScanner::new().ok();
    if skill_scanner.is_some() {
        info!("Skill scanner initialized");
    }

    // Initialize session authenticator
    let session_auth = auth::SessionAuthenticator::from_config(&config);
    if session_auth.is_some() {
        info!("Session authenticator initialized");
    }

    info!("Security policy loaded: {} tool permissions defined", policy.tool_count());
    info!("Command Guardian initialized with {} blocked patterns", guardian.blocked_count());

    // Initialize channel manager from config
    let channel_manager = if !config.channels.is_empty() {
        let mgr = channels::ChannelManager::from_config(
            &config.channels,
            256,
            std::time::Duration::from_millis(100),
        )
        .await;
        let registered = mgr.registered_channels().await;
        if !registered.is_empty() {
            info!("Channel manager initialized with {} channels", registered.len());
        }
        Some(mgr)
    } else {
        None
    };

    match cli_args.command {
        Commands::Run { provider, model, ui: enable_ui } => {
            // Resolve preset aliases (fast, smart, cheap, local, etc.)
            let (provider, model) = if let Some((p, m)) = providers::ProviderFactory::resolve_preset(&provider) {
                (p.to_string(), model.or_else(|| Some(m.to_string())))
            } else {
                (provider, model)
            };

            // Start Web UI if requested
            let _web_ui = if enable_ui || config.ui.enabled {
                let ui_config = ui::WebUiConfig::from(&config.ui);
                let mut web_ui = ui::WebUi::new(ui_config);
                web_ui.start().await?;
                info!("Web UI available at http://{}:{}", config.ui.bind_address, config.ui.port);
                println!("\n  Web UI: http://{}:{}\n", config.ui.bind_address, config.ui.port);
                Some(web_ui)
            } else {
                None
            };

            let ui_sender = _web_ui.as_ref().map(|w| w.sender());

            let engine = core::Engine::new(core::EngineConfig {
                config,
                policy,
                guardian,
                audit,
                anti_stealer,
                ssrf_guard,
                dlp_engine,
                cost_tracker,
                skill_scanner,
                provider_name: provider,
                model,
                ui_sender,
                channel_manager,
                session_auth,
            })
            .await?;

            engine.run_interactive().await?;
        }
        Commands::Ui { provider, model, port } => {
            // Resolve presets
            let (provider, model) = if let Some((p, m)) = providers::ProviderFactory::resolve_preset(&provider) {
                (p.to_string(), model.or_else(|| Some(m.to_string())))
            } else {
                (provider, model)
            };

            let mut ui_config = ui::WebUiConfig::from(&config.ui);
            if let Some(p) = port {
                ui_config.bind_addr.set_port(p);
            }

            let mut web_ui = ui::WebUi::new(ui_config.clone());
            web_ui.start().await?;
            let addr = ui_config.bind_addr;
            info!("Web UI available at http://{}", addr);
            println!("\n  IronClaw Web UI running at http://{}", addr);
            println!("  Press Ctrl+C to stop.\n");

            let ui_sender = web_ui.sender();

            let engine = core::Engine::new(core::EngineConfig {
                config,
                policy,
                guardian,
                audit,
                anti_stealer,
                ssrf_guard,
                dlp_engine,
                cost_tracker,
                skill_scanner,
                provider_name: provider,
                model,
                ui_sender: Some(ui_sender),
                channel_manager,
                session_auth,
            })
            .await?;

            engine.run_interactive().await?;
        }
        Commands::Models { .. } => unreachable!(), // handled above
        Commands::Onboard => unreachable!(),        // handled above
        Commands::Doctor => {
            cli::doctor::run(&config, &policy, &guardian).await?;
        }
        Commands::Skill { action } => match action {
            SkillCommands::List => cli::skills::list(&config).await?,
            SkillCommands::Verify { path } => cli::skills::verify(&path).await?,
            SkillCommands::Install { name } => cli::skills::install(&name, &config).await?,
            SkillCommands::Scan { path } => cli::skills::scan(&path).await?,
        },
        Commands::Policy => {
            cli::policy::show(&config, &policy)?;
        }
        Commands::Audit { count } => {
            cli::audit::show(&audit, count)?;
        }
    }

    Ok(())
}
