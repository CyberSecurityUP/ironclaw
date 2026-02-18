//! `ironclaw onboard` — Assistente interactivo de configuração inicial.
//!
//! Guia o utilizador por todos os passos necessários para começar a usar
//! o IronClaw: selecção de provider, canais, nível de segurança, autenticação
//! de sessão, WebUI e geração do ficheiro de configuração final.

use anyhow::Result;
use dialoguer::{theme::ColorfulTheme, Confirm, Input, MultiSelect, Select};
use std::collections::HashMap;
use std::fs;

// ---------------------------------------------------------------------------
// Constantes — listas de provedores, canais e níveis de segurança
// ---------------------------------------------------------------------------

/// Mapeamento entre nome do provedor e a variável de ambiente correspondente.
const PROVIDER_ENV_KEYS: &[(&str, &str)] = &[
    ("anthropic", "ANTHROPIC_API_KEY"),
    ("openai", "OPENAI_API_KEY"),
    ("google", "GOOGLE_API_KEY"),
    ("groq", "GROQ_API_KEY"),
    ("deepseek", "DEEPSEEK_API_KEY"),
    ("mistral", "MISTRAL_API_KEY"),
    ("openrouter", "OPENROUTER_API_KEY"),
    ("xai", "XAI_API_KEY"),
];

/// Provedores locais que não precisam de chave API.
const LOCAL_PROVIDERS: &[&str] = &[
    "ollama (local, no API key needed)",
    "lmstudio (local, no API key needed)",
];

/// Lista completa dos canais suportados.
const ALL_CHANNELS: &[&str] = &[
    "CLI",
    "Slack",
    "Discord",
    "Telegram",
    "WhatsApp",
    "Matrix",
    "IRC",
    "Teams",
    "WebUI",
    "REST API",
    "WebSocket",
    "gRPC",
    "Email",
    "LINE",
    "Signal",
    "Google Chat",
    "BlueBubbles",
    "iMessage",
    "Zalo",
    "Zalo Personal",
];

/// Canais que não exigem credenciais adicionais.
const NO_CREDENTIAL_CHANNELS: &[&str] = &["CLI", "WebUI"];

/// Descrições dos níveis de segurança apresentadas ao utilizador.
const SECURITY_LEVELS: &[&str] = &[
    "Strict  — all protections on, sandbox enforced, approval required for every action",
    "Moderate — sandbox enforced, no approval needed for medium-risk operations",
    "Permissive — native sandbox only, no approval (not recommended for production)",
];

/// Chaves internas correspondentes a cada nível de segurança.
const SECURITY_KEYS: &[&str] = &["strict", "moderate", "permissive"];

// ---------------------------------------------------------------------------
// Banner ASCII — apresentação visual da aplicação
// ---------------------------------------------------------------------------

/// Imprime o banner de boas-vindas com arte ASCII.
fn print_banner() {
    let banner = r#"
  ___                    ____ _
 |_ _|_ __ ___  _ __   / ___| | __ ___      __
  | || '__/ _ \| '_ \ | |   | |/ _` \ \ /\ / /
  | || | | (_) | | | || |___| | (_| |\ V  V /
 |___|_|  \___/|_| |_| \____|_|\__,_| \_/\_/

  Secure-by-default AI Agent Framework
  Zero Trust Architecture · Multi-Channel · Multi-Provider
"#;
    println!("{}", banner);
    println!("  Welcome to the IronClaw onboarding wizard!");
    println!("  This will guide you through initial setup.\n");
    println!("  Press Ctrl+C at any time to abort.\n");
}

// ---------------------------------------------------------------------------
// Detecção de provedores — verifica variáveis de ambiente
// ---------------------------------------------------------------------------

/// Estrutura auxiliar para representar um provedor detectado.
struct DetectedProvider {
    /// Nome legível do provedor (ex: "anthropic").
    name: String,
    /// Indica se a chave API foi encontrada no ambiente.
    available: bool,
}

/// Verifica quais provedores cloud têm chaves API definidas e devolve a lista
/// completa (cloud + local) com indicação de disponibilidade.
fn detect_providers() -> Vec<DetectedProvider> {
    let mut providers = Vec::new();

    // Verificar provedores cloud via variáveis de ambiente
    for &(name, env_var) in PROVIDER_ENV_KEYS {
        let available = std::env::var(env_var)
            .map(|v| !v.is_empty())
            .unwrap_or(false);
        providers.push(DetectedProvider {
            name: name.to_string(),
            available,
        });
    }

    // Adicionar provedores locais (sempre disponíveis)
    for &local in LOCAL_PROVIDERS {
        providers.push(DetectedProvider {
            name: local.to_string(),
            available: true,
        });
    }

    providers
}

/// Formata a lista de provedores para apresentação no selector, indicando
/// quais têm chaves disponíveis.
fn format_provider_items(providers: &[DetectedProvider]) -> Vec<String> {
    providers
        .iter()
        .map(|p| {
            if p.available {
                format!("{} (available)", p.name)
            } else {
                format!("{} (no API key found)", p.name)
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Passo 2 — Selecção do provedor por defeito
// ---------------------------------------------------------------------------

/// Pergunta ao utilizador qual provedor quer usar por defeito.
/// Devolve o nome interno do provedor seleccionado.
fn prompt_provider_selection(theme: &ColorfulTheme) -> Result<String> {
    println!("── Step 1: Provider Selection ──────────────────────────────\n");

    let providers = detect_providers();
    let items = format_provider_items(&providers);

    // Tentar pré-seleccionar o primeiro provedor disponível
    let default_idx = providers
        .iter()
        .position(|p| p.available)
        .unwrap_or(0);

    let selection = Select::with_theme(theme)
        .with_prompt("Select your default LLM provider")
        .items(&items)
        .default(default_idx)
        .interact()?;

    let chosen = &providers[selection];

    if !chosen.available {
        println!(
            "\n  Warning: No API key detected for '{}'. \
             Make sure to set the environment variable before running IronClaw.\n",
            chosen.name
        );
    } else {
        println!("\n  Selected provider: {}\n", chosen.name);
    }

    // Extrair só o nome base para provedores locais
    let provider_key = if chosen.name.contains("(local") {
        chosen.name.split_whitespace().next().unwrap_or(&chosen.name)
    } else {
        &chosen.name
    };

    Ok(provider_key.to_string())
}

// ---------------------------------------------------------------------------
// Passo 3 — Configuração dos canais de comunicação
// ---------------------------------------------------------------------------

/// Informação recolhida para cada canal activo.
struct ChannelConfig {
    /// Nome do canal.
    name: String,
    /// Credencial / token associado (vazio para CLI e WebUI).
    credential: String,
}

/// Apresenta a lista de canais e recolhe as credenciais dos seleccionados.
fn prompt_channel_setup(theme: &ColorfulTheme) -> Result<Vec<ChannelConfig>> {
    println!("── Step 2: Channel Setup ───────────────────────────────────\n");
    println!("  Select which communication channels to enable.");
    println!("  CLI is always enabled.\n");

    // CLI está sempre activo; pré-seleccionamos o índice 0
    let defaults: Vec<bool> = ALL_CHANNELS
        .iter()
        .enumerate()
        .map(|(i, _)| i == 0) // CLI pré-seleccionado
        .collect();

    let selections = MultiSelect::with_theme(theme)
        .with_prompt("Enable channels (space to toggle, enter to confirm)")
        .items(ALL_CHANNELS)
        .defaults(&defaults)
        .interact()?;

    // Garantir que CLI está sempre incluído
    let mut selected_indices = selections;
    if !selected_indices.contains(&0) {
        selected_indices.insert(0, 0);
    }

    let mut channels: Vec<ChannelConfig> = Vec::new();

    for &idx in &selected_indices {
        let name = ALL_CHANNELS[idx].to_string();

        // Canais que não precisam de credenciais
        if NO_CREDENTIAL_CHANNELS.contains(&ALL_CHANNELS[idx]) {
            channels.push(ChannelConfig {
                name,
                credential: String::new(),
            });
            continue;
        }

        // Pedir credencial para os restantes canais
        let prompt_text = format!("  Enter token/credential for {}", name);
        let credential: String = Input::with_theme(theme)
            .with_prompt(&prompt_text)
            .allow_empty(false)
            .interact_text()?;

        channels.push(ChannelConfig { name, credential });
    }

    println!(
        "\n  {} channel(s) configured.\n",
        channels.len()
    );

    Ok(channels)
}

// ---------------------------------------------------------------------------
// Passo 4 — Nível de segurança
// ---------------------------------------------------------------------------

/// Pergunta qual nível de segurança o utilizador pretende.
/// Devolve a chave interna ("strict", "moderate" ou "permissive").
fn prompt_security_level(theme: &ColorfulTheme) -> Result<String> {
    println!("── Step 3: Security Level ──────────────────────────────────\n");

    let selection = Select::with_theme(theme)
        .with_prompt("Choose a security level")
        .items(&SECURITY_LEVELS.to_vec())
        .default(0) // "Strict" por defeito
        .interact()?;

    let level = SECURITY_KEYS[selection];

    if level == "permissive" {
        println!("\n  ⚠ WARNING: Permissive mode reduces isolation significantly.");
        println!("  This is NOT recommended for production environments.\n");
    } else {
        println!("\n  Security level set to: {}\n", level);
    }

    Ok(level.to_string())
}

// ---------------------------------------------------------------------------
// Passo 5 — Autenticação de sessão LLM
// ---------------------------------------------------------------------------

/// Configuração de autenticação por sessão.
struct SessionAuthConfig {
    enabled: bool,
    ttl_seconds: u64,
}

/// Pergunta se o utilizador quer activar autenticação de sessão LLM e,
/// em caso afirmativo, qual o TTL pretendido.
fn prompt_session_auth(theme: &ColorfulTheme) -> Result<SessionAuthConfig> {
    println!("── Step 4: Session Authentication ──────────────────────────\n");
    println!("  LLM session-based auth ties each conversation to a verified");
    println!("  identity, preventing session hijacking and replay attacks.\n");

    let enabled = Confirm::with_theme(theme)
        .with_prompt("Enable LLM session-based authentication?")
        .default(true)
        .interact()?;

    let ttl_seconds = if enabled {
        let ttl: u64 = Input::with_theme(theme)
            .with_prompt("  Session TTL in seconds (e.g. 3600 for 1 hour)")
            .default(3600)
            .interact_text()?;
        ttl
    } else {
        0
    };

    if enabled {
        println!("\n  Session auth enabled (TTL: {}s).\n", ttl_seconds);
    } else {
        println!("\n  Session auth disabled.\n");
    }

    Ok(SessionAuthConfig {
        enabled,
        ttl_seconds,
    })
}

// ---------------------------------------------------------------------------
// Passo 6 — Web UI
// ---------------------------------------------------------------------------

/// Configuração da interface web.
struct WebUiConfig {
    enabled: bool,
    port: u16,
}

/// Pergunta se o utilizador quer activar o Web UI e em que porta.
fn prompt_web_ui(theme: &ColorfulTheme) -> Result<WebUiConfig> {
    println!("── Step 5: Web UI ─────────────────────────────────────────\n");
    println!("  The Web UI provides a browser-based dashboard for managing");
    println!("  IronClaw sessions, viewing audit logs, and chatting.\n");

    let enabled = Confirm::with_theme(theme)
        .with_prompt("Enable the Web UI?")
        .default(true)
        .interact()?;

    let port = if enabled {
        let p: u16 = Input::with_theme(theme)
            .with_prompt("  Web UI port")
            .default(3000)
            .interact_text()?;
        p
    } else {
        3000
    };

    if enabled {
        println!("\n  Web UI will be available at http://localhost:{}\n", port);
    } else {
        println!("\n  Web UI disabled.\n");
    }

    Ok(WebUiConfig { enabled, port })
}

// ---------------------------------------------------------------------------
// Passo 7 — Geração do ficheiro de configuração
// ---------------------------------------------------------------------------

/// Converte o nível de segurança numa secção YAML com as flags correctas.
fn security_to_yaml(level: &str) -> String {
    match level {
        "strict" => r#"security:
  level: strict
  sandbox:
    backend: docker
    enforce: true
  approval:
    required: true
    risk_threshold: low
  antitheft:
    enforce: true
    correlation_window_secs: 30"#
            .to_string(),
        "moderate" => r#"security:
  level: moderate
  sandbox:
    backend: docker
    enforce: true
  approval:
    required: true
    risk_threshold: high
  antitheft:
    enforce: true
    correlation_window_secs: 60"#
            .to_string(),
        "permissive" => r#"security:
  level: permissive
  sandbox:
    backend: native
    enforce: false
  approval:
    required: false
    risk_threshold: critical
  antitheft:
    enforce: false
    correlation_window_secs: 120"#
            .to_string(),
        _ => security_to_yaml("strict"),
    }
}

/// Gera o conteúdo YAML completo da configuração e escreve em disco.
fn generate_config(
    provider: &str,
    channels: &[ChannelConfig],
    security_level: &str,
    session_auth: &SessionAuthConfig,
    web_ui: &WebUiConfig,
) -> Result<String> {
    println!("── Step 6: Generating Configuration ───────────────────────\n");

    let mut yaml = String::with_capacity(2048);

    // Cabeçalho
    yaml.push_str("# IronClaw Configuration\n");
    yaml.push_str("# Generated by `ironclaw onboard`\n");
    yaml.push_str("# Edit as needed — see docs at https://ironclaw.dev/config\n\n");

    // Provedor
    yaml.push_str(&format!("provider:\n  default: \"{}\"\n\n", provider));

    // Canais
    yaml.push_str("channels:\n");
    for ch in channels {
        let key = ch.name.to_lowercase().replace(' ', "_");
        yaml.push_str(&format!("  {}:\n", key));
        yaml.push_str("    enabled: true\n");
        if !ch.credential.is_empty() {
            yaml.push_str(&format!("    token: \"{}\"\n", ch.credential));
        }
    }
    yaml.push('\n');

    // Segurança
    yaml.push_str(&security_to_yaml(security_level));
    yaml.push_str("\n\n");

    // Autenticação de sessão
    yaml.push_str("session_auth:\n");
    yaml.push_str(&format!("  enabled: {}\n", session_auth.enabled));
    if session_auth.enabled {
        yaml.push_str(&format!("  ttl_seconds: {}\n", session_auth.ttl_seconds));
    }
    yaml.push('\n');

    // Web UI
    yaml.push_str("web_ui:\n");
    yaml.push_str(&format!("  enabled: {}\n", web_ui.enabled));
    if web_ui.enabled {
        yaml.push_str(&format!("  port: {}\n", web_ui.port));
    }
    yaml.push('\n');

    // Secções com valores por defeito razoáveis
    yaml.push_str("audit:\n  enabled: true\n  path: \"./ironclaw_audit.log\"\n\n");
    yaml.push_str("observability:\n  redact_pii: true\n  tracing: true\n\n");
    yaml.push_str("dlp:\n  enabled: true\n  default_action: redact\n\n");
    yaml.push_str("skills:\n  require_signatures: true\n  scan_on_load: true\n");

    // Escrever ficheiro
    let config_path = "ironclaw.yaml";
    fs::write(config_path, &yaml)?;

    println!("  Configuration written to: {}\n", config_path);

    Ok(yaml)
}

// ---------------------------------------------------------------------------
// Passo 8 — Resumo final
// ---------------------------------------------------------------------------

/// Imprime um resumo de tudo o que foi configurado e sugere próximos passos.
fn print_summary(
    provider: &str,
    channels: &[ChannelConfig],
    security_level: &str,
    session_auth: &SessionAuthConfig,
    web_ui: &WebUiConfig,
) {
    println!("── Summary ─────────────────────────────────────────────────\n");
    println!("  Provider:          {}", provider);
    println!("  Security level:    {}", security_level);
    println!(
        "  Channels enabled:  {}",
        channels
            .iter()
            .map(|c| c.name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!(
        "  Session auth:      {}",
        if session_auth.enabled {
            format!("enabled (TTL {}s)", session_auth.ttl_seconds)
        } else {
            "disabled".to_string()
        }
    );
    println!(
        "  Web UI:            {}",
        if web_ui.enabled {
            format!("enabled (port {})", web_ui.port)
        } else {
            "disabled".to_string()
        }
    );

    println!("\n  Config file: ironclaw.yaml");

    println!("\n── Next Steps ──────────────────────────────────────────────\n");
    println!("  1. Review and edit ironclaw.yaml as needed");
    println!("  2. Run `ironclaw doctor` to verify your configuration");
    println!("  3. Run `ironclaw serve` to start the agent");

    if web_ui.enabled {
        println!(
            "  4. Open http://localhost:{} in your browser for the dashboard",
            web_ui.port
        );
    }

    println!("\n  Happy hacking! For docs visit https://ironclaw.dev\n");
}

// ---------------------------------------------------------------------------
// Ponto de entrada principal do wizard
// ---------------------------------------------------------------------------

/// Executa o assistente de onboarding interactivo.
///
/// Percorre todos os passos sequencialmente, recolhe as preferências do
/// utilizador e gera o ficheiro `ironclaw.yaml` no directório actual.
pub async fn run() -> Result<()> {
    let theme = ColorfulTheme::default();

    // Passo 1 — Boas-vindas
    print_banner();

    // Passo 2 — Selecção do provedor
    let provider = prompt_provider_selection(&theme)?;

    // Passo 3 — Configuração dos canais
    let channels = prompt_channel_setup(&theme)?;

    // Passo 4 — Nível de segurança
    let security_level = prompt_security_level(&theme)?;

    // Passo 5 — Autenticação de sessão
    let session_auth = prompt_session_auth(&theme)?;

    // Passo 6 — Web UI
    let web_ui = prompt_web_ui(&theme)?;

    // Passo 7 — Gerar configuração
    generate_config(
        &provider,
        &channels,
        &security_level,
        &session_auth,
        &web_ui,
    )?;

    // Passo 8 — Resumo
    print_summary(&provider, &channels, &security_level, &session_auth, &web_ui);

    Ok(())
}

// ---------------------------------------------------------------------------
// Testes unitários — cobrem lógica que não depende de interacção com o terminal
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_providers_includes_local() {
        let providers = detect_providers();
        let local_names: Vec<&str> = providers
            .iter()
            .filter(|p| p.name.contains("local"))
            .map(|p| p.name.as_str())
            .collect();
        assert_eq!(local_names.len(), 2);
        assert!(local_names.iter().any(|n| n.contains("ollama")));
        assert!(local_names.iter().any(|n| n.contains("lmstudio")));
    }

    #[test]
    fn test_detect_providers_local_always_available() {
        let providers = detect_providers();
        for p in &providers {
            if p.name.contains("local") {
                assert!(p.available, "local provider '{}' should be available", p.name);
            }
        }
    }

    #[test]
    fn test_format_provider_items_length() {
        let providers = detect_providers();
        let items = format_provider_items(&providers);
        assert_eq!(items.len(), providers.len());
    }

    #[test]
    fn test_security_to_yaml_strict() {
        let yaml = security_to_yaml("strict");
        assert!(yaml.contains("level: strict"));
        assert!(yaml.contains("enforce: true"));
        assert!(yaml.contains("required: true"));
    }

    #[test]
    fn test_security_to_yaml_moderate() {
        let yaml = security_to_yaml("moderate");
        assert!(yaml.contains("level: moderate"));
        assert!(yaml.contains("risk_threshold: high"));
    }

    #[test]
    fn test_security_to_yaml_permissive() {
        let yaml = security_to_yaml("permissive");
        assert!(yaml.contains("level: permissive"));
        assert!(yaml.contains("enforce: false"));
    }

    #[test]
    fn test_security_to_yaml_unknown_defaults_to_strict() {
        let yaml = security_to_yaml("unknown");
        assert!(yaml.contains("level: strict"));
    }

    #[test]
    fn test_all_channels_count() {
        assert_eq!(ALL_CHANNELS.len(), 20, "there should be exactly 20 channels");
    }

    #[test]
    fn test_cli_is_first_channel() {
        assert_eq!(ALL_CHANNELS[0], "CLI");
    }

    #[test]
    fn test_provider_env_keys_count() {
        assert_eq!(PROVIDER_ENV_KEYS.len(), 8, "there should be 8 cloud providers");
    }
}
