use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{watch, RwLock};
use tracing::{error, info, warn};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Tunnel configuration — which backend to use for exposing the gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelConfig {
    /// Backend: "cloudflare", "ngrok", "custom", or "none"
    #[serde(default = "default_backend")]
    pub backend: String,

    /// Local address the tunnel should forward to (default: same as gateway bind)
    #[serde(default = "default_local_addr")]
    pub local_addr: String,

    /// Path to cloudflared binary (default: "cloudflared")
    #[serde(default = "default_cloudflared")]
    pub cloudflared_bin: String,

    /// Path to ngrok binary (default: "ngrok")
    #[serde(default = "default_ngrok")]
    pub ngrok_bin: String,

    /// Ngrok auth token (optional; can also come from ngrok config)
    pub ngrok_auth_token: Option<String>,

    /// Custom tunnel command (for `backend = "custom"`)
    pub custom_command: Option<String>,

    /// Health-check interval in seconds
    #[serde(default = "default_health_interval")]
    pub health_interval_secs: u64,

    /// Maximum automatic restart attempts before giving up
    #[serde(default = "default_max_restarts")]
    pub max_restarts: u32,
}

fn default_backend() -> String {
    "none".to_string()
}
fn default_local_addr() -> String {
    "http://127.0.0.1:3000".to_string()
}
fn default_cloudflared() -> String {
    "cloudflared".to_string()
}
fn default_ngrok() -> String {
    "ngrok".to_string()
}
fn default_health_interval() -> u64 {
    15
}
fn default_max_restarts() -> u32 {
    5
}

impl Default for TunnelConfig {
    fn default() -> Self {
        Self {
            backend: default_backend(),
            local_addr: default_local_addr(),
            cloudflared_bin: default_cloudflared(),
            ngrok_bin: default_ngrok(),
            ngrok_auth_token: None,
            custom_command: None,
            health_interval_secs: default_health_interval(),
            max_restarts: default_max_restarts(),
        }
    }
}

// ---------------------------------------------------------------------------
// Tunnel trait
// ---------------------------------------------------------------------------

/// Common interface implemented by every tunnel backend.
#[async_trait::async_trait]
trait Tunnel: Send + Sync {
    /// Start the tunnel subprocess and return once the public URL is known.
    async fn start(&mut self) -> Result<String>;

    /// Gracefully stop the tunnel (SIGTERM, then SIGKILL after timeout).
    async fn stop(&mut self) -> Result<()>;

    /// Whether the underlying process is still alive.
    fn is_alive(&self) -> bool;

    /// Human-readable backend name.
    fn backend_name(&self) -> &'static str;
}

// ---------------------------------------------------------------------------
// TunnelManager
// ---------------------------------------------------------------------------

/// Manages a single tunnel process with health monitoring and auto-restart.
pub struct TunnelManager {
    config: TunnelConfig,
    /// The public URL exposed by the tunnel (empty until started).
    public_url: Arc<RwLock<Option<String>>>,
    /// Shutdown signal for the health-monitor task.
    shutdown_tx: Option<watch::Sender<bool>>,
    /// Handle for the health-monitor background task.
    monitor_handle: Option<tokio::task::JoinHandle<()>>,
    /// Whether the manager has been started.
    running: Arc<std::sync::atomic::AtomicBool>,
}

impl TunnelManager {
    pub fn new(config: TunnelConfig) -> Self {
        Self {
            config,
            public_url: Arc::new(RwLock::new(None)),
            shutdown_tx: None,
            monitor_handle: None,
            running: Arc::new(false.into()),
        }
    }

    /// Start the tunnel.  Blocks until the public URL is available or an
    /// error occurs.
    pub async fn start(&mut self) -> Result<String> {
        if self.running.load(std::sync::atomic::Ordering::SeqCst) {
            anyhow::bail!("Tunnel is already running");
        }

        let mut tunnel: Box<dyn Tunnel> = match self.config.backend.as_str() {
            "cloudflare" | "cloudflared" => Box::new(CloudflareTunnel::new(&self.config)),
            "ngrok" => Box::new(NgrokTunnel::new(&self.config)),
            "custom" => Box::new(CustomTunnel::new(&self.config)?),
            "none" => anyhow::bail!("Tunnel backend is 'none'; nothing to start"),
            other => anyhow::bail!("Unknown tunnel backend: {}", other),
        };

        info!(backend = %self.config.backend, "Starting tunnel");

        let url = tunnel
            .start()
            .await
            .with_context(|| format!("Failed to start {} tunnel", self.config.backend))?;

        info!(backend = %self.config.backend, url = %url, "Tunnel established");

        *self.public_url.write().await = Some(url.clone());
        self.running
            .store(true, std::sync::atomic::Ordering::SeqCst);

        // Spawn health-monitor task
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        self.shutdown_tx = Some(shutdown_tx);

        let health_interval = Duration::from_secs(self.config.health_interval_secs);
        let max_restarts = self.config.max_restarts;
        let running = self.running.clone();
        let public_url = self.public_url.clone();

        let handle = tokio::spawn(async move {
            health_monitor(tunnel, shutdown_rx, health_interval, max_restarts, running, public_url)
                .await;
        });
        self.monitor_handle = Some(handle);

        Ok(url)
    }

    /// Stop the tunnel and the health-monitor task.
    pub async fn stop(&mut self) -> Result<()> {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }
        if let Some(handle) = self.monitor_handle.take() {
            handle.await.ok();
        }
        self.running
            .store(false, std::sync::atomic::Ordering::SeqCst);
        *self.public_url.write().await = None;
        info!("Tunnel stopped");
        Ok(())
    }

    /// Return the currently-active public URL, if any.
    pub async fn get_url(&self) -> Option<String> {
        self.public_url.read().await.clone()
    }

    /// Whether the tunnel is running.
    pub fn is_running(&self) -> bool {
        self.running.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Background task that monitors tunnel health and restarts on crash.
async fn health_monitor(
    mut tunnel: Box<dyn Tunnel>,
    mut shutdown_rx: watch::Receiver<bool>,
    interval: Duration,
    max_restarts: u32,
    running: Arc<std::sync::atomic::AtomicBool>,
    public_url: Arc<RwLock<Option<String>>>,
) {
    let mut restart_count: u32 = 0;

    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {
                if !tunnel.is_alive() {
                    if restart_count >= max_restarts {
                        error!(
                            restarts = restart_count,
                            "Tunnel exceeded max restarts; giving up"
                        );
                        running.store(false, std::sync::atomic::Ordering::SeqCst);
                        *public_url.write().await = None;
                        break;
                    }

                    warn!(
                        backend = tunnel.backend_name(),
                        restart = restart_count + 1,
                        "Tunnel process exited; restarting"
                    );

                    match tunnel.start().await {
                        Ok(new_url) => {
                            info!(url = %new_url, "Tunnel re-established");
                            *public_url.write().await = Some(new_url);
                            restart_count += 1;
                        }
                        Err(e) => {
                            error!(error = %e, "Tunnel restart failed");
                            restart_count += 1;
                        }
                    }
                }
            }
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    info!("Health monitor received shutdown signal");
                    if let Err(e) = tunnel.stop().await {
                        warn!(error = %e, "Error stopping tunnel process");
                    }
                    break;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Cloudflare Tunnel
// ---------------------------------------------------------------------------

struct CloudflareTunnel {
    bin: String,
    local_addr: String,
    child: Option<Child>,
}

impl CloudflareTunnel {
    fn new(config: &TunnelConfig) -> Self {
        Self {
            bin: config.cloudflared_bin.clone(),
            local_addr: config.local_addr.clone(),
            child: None,
        }
    }
}

#[async_trait::async_trait]
impl Tunnel for CloudflareTunnel {
    async fn start(&mut self) -> Result<String> {
        // `cloudflared tunnel --url <local>` prints the public URL to stderr.
        let mut child = Command::new(&self.bin)
            .args(["tunnel", "--url", &self.local_addr])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("Failed to spawn {}. Is cloudflared installed?", self.bin))?;

        let stderr = child.stderr.take().context("No stderr from cloudflared")?;
        let url = parse_url_from_stream(
            BufReader::new(stderr),
            &Regex::new(r"https://[a-z0-9-]+\.trycloudflare\.com")?,
            Duration::from_secs(30),
        )
        .await
        .context("Timed out waiting for cloudflared public URL")?;

        self.child = Some(child);
        Ok(url)
    }

    async fn stop(&mut self) -> Result<()> {
        graceful_kill(&mut self.child).await
    }

    fn is_alive(&self) -> bool {
        child_is_alive(&self.child)
    }

    fn backend_name(&self) -> &'static str {
        "cloudflare"
    }
}

// ---------------------------------------------------------------------------
// Ngrok Tunnel
// ---------------------------------------------------------------------------

struct NgrokTunnel {
    bin: String,
    local_addr: String,
    auth_token: Option<String>,
    child: Option<Child>,
}

impl NgrokTunnel {
    fn new(config: &TunnelConfig) -> Self {
        Self {
            bin: config.ngrok_bin.clone(),
            local_addr: config.local_addr.clone(),
            auth_token: config.ngrok_auth_token.clone(),
            child: None,
        }
    }
}

#[async_trait::async_trait]
impl Tunnel for NgrokTunnel {
    async fn start(&mut self) -> Result<String> {
        // Optionally set auth token before starting.
        if let Some(ref token) = self.auth_token {
            let status = Command::new(&self.bin)
                .args(["config", "add-authtoken", token])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .await;

            if let Err(e) = status {
                warn!(error = %e, "Failed to set ngrok authtoken (continuing anyway)");
            }
        }

        // Extract the port from the local address for ngrok.
        let port = self
            .local_addr
            .rsplit(':')
            .next()
            .unwrap_or("3000")
            .trim_end_matches('/');

        let mut child = Command::new(&self.bin)
            .args(["http", port, "--log", "stdout", "--log-format", "term"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("Failed to spawn {}. Is ngrok installed?", self.bin))?;

        let stdout = child.stdout.take().context("No stdout from ngrok")?;
        let url = parse_url_from_stream(
            BufReader::new(stdout),
            &Regex::new(r"https://[a-z0-9-]+\.ngrok(-free)?\.app")?,
            Duration::from_secs(30),
        )
        .await
        .context("Timed out waiting for ngrok public URL")?;

        self.child = Some(child);
        Ok(url)
    }

    async fn stop(&mut self) -> Result<()> {
        graceful_kill(&mut self.child).await
    }

    fn is_alive(&self) -> bool {
        child_is_alive(&self.child)
    }

    fn backend_name(&self) -> &'static str {
        "ngrok"
    }
}

// ---------------------------------------------------------------------------
// Custom Tunnel
// ---------------------------------------------------------------------------

struct CustomTunnel {
    command: String,
    child: Option<Child>,
}

impl CustomTunnel {
    fn new(config: &TunnelConfig) -> Result<Self> {
        let command = config
            .custom_command
            .as_ref()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!(
                "Tunnel backend is 'custom' but no custom_command is set in config"
            ))?;
        Ok(Self {
            command,
            child: None,
        })
    }
}

#[async_trait::async_trait]
impl Tunnel for CustomTunnel {
    async fn start(&mut self) -> Result<String> {
        // Run the custom command through the shell.
        let mut child = Command::new("sh")
            .args(["-c", &self.command])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("Failed to spawn custom tunnel: {}", self.command))?;

        // Try to parse a URL from either stdout or stderr.
        let stdout = child.stdout.take().context("No stdout from custom tunnel")?;
        let url_re = Regex::new(r"https?://[^\s]+")?;
        let url = parse_url_from_stream(
            BufReader::new(stdout),
            &url_re,
            Duration::from_secs(30),
        )
        .await
        .context("Timed out waiting for custom tunnel URL")?;

        self.child = Some(child);
        Ok(url)
    }

    async fn stop(&mut self) -> Result<()> {
        graceful_kill(&mut self.child).await
    }

    fn is_alive(&self) -> bool {
        child_is_alive(&self.child)
    }

    fn backend_name(&self) -> &'static str {
        "custom"
    }
}

// ---------------------------------------------------------------------------
// Shared helper functions
// ---------------------------------------------------------------------------

/// Read lines from an async reader, looking for the first regex match.
/// Returns the matched string or an error if the deadline expires.
async fn parse_url_from_stream<R>(
    reader: BufReader<R>,
    pattern: &Regex,
    timeout: Duration,
) -> Result<String>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut lines = reader.lines();
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            anyhow::bail!("Timed out waiting for tunnel URL");
        }

        let line = tokio::time::timeout(remaining, lines.next_line()).await;

        match line {
            Ok(Ok(Some(text))) => {
                info!(line = %text, "tunnel output");
                if let Some(m) = pattern.find(&text) {
                    return Ok(m.as_str().to_string());
                }
            }
            Ok(Ok(None)) => {
                anyhow::bail!("Tunnel process stream ended before URL was found");
            }
            Ok(Err(e)) => {
                anyhow::bail!("IO error reading tunnel output: {}", e);
            }
            Err(_) => {
                anyhow::bail!("Timed out waiting for tunnel URL");
            }
        }
    }
}

/// Check if a child process is still running (non-blocking).
fn child_is_alive(child: &Option<Child>) -> bool {
    match child {
        Some(ref c) => c.id().is_some(),
        None => false,
    }
}

/// Send SIGTERM, wait briefly, then SIGKILL if the process is still alive.
async fn graceful_kill(child: &mut Option<Child>) -> Result<()> {
    if let Some(ref mut c) = child {
        info!("Sending SIGTERM to tunnel process");

        // On Unix, try SIGTERM first.
        #[cfg(unix)]
        {
            use nix::sys::signal::{self, Signal};
            use nix::unistd::Pid;
            if let Some(pid) = c.id() {
                let _ = signal::kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
            }
        }

        // On non-Unix, kill() is the only option.
        #[cfg(not(unix))]
        {
            let _ = c.kill().await;
        }

        // Wait up to 5 seconds for clean exit.
        match tokio::time::timeout(Duration::from_secs(5), c.wait()).await {
            Ok(Ok(status)) => {
                info!(status = %status, "Tunnel process exited");
            }
            _ => {
                warn!("Tunnel process did not exit in time; sending SIGKILL");
                let _ = c.kill().await;
            }
        }
    }
    *child = None;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let cfg = TunnelConfig::default();
        assert_eq!(cfg.backend, "none");
        assert_eq!(cfg.local_addr, "http://127.0.0.1:3000");
        assert_eq!(cfg.health_interval_secs, 15);
        assert_eq!(cfg.max_restarts, 5);
    }

    #[test]
    fn test_tunnel_manager_not_running_initially() {
        let mgr = TunnelManager::new(TunnelConfig::default());
        assert!(!mgr.is_running());
    }

    #[tokio::test]
    async fn test_tunnel_manager_get_url_initially_none() {
        let mgr = TunnelManager::new(TunnelConfig::default());
        assert!(mgr.get_url().await.is_none());
    }

    #[tokio::test]
    async fn test_tunnel_manager_start_none_backend_fails() {
        let mut mgr = TunnelManager::new(TunnelConfig::default());
        let result = mgr.start().await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("nothing to start"));
    }

    #[tokio::test]
    async fn test_custom_tunnel_requires_command() {
        let cfg = TunnelConfig {
            backend: "custom".to_string(),
            custom_command: None,
            ..Default::default()
        };
        let result = CustomTunnel::new(&cfg);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("custom_command"));
    }

    #[test]
    fn test_child_is_alive_none() {
        assert!(!child_is_alive(&None));
    }

    #[tokio::test]
    async fn test_parse_url_from_stream_finds_url() {
        let data = b"Starting tunnel...\nYour url is https://abc-123.trycloudflare.com ready\n";
        let reader = BufReader::new(&data[..]);
        let re = Regex::new(r"https://[a-z0-9-]+\.trycloudflare\.com").unwrap();

        let url = parse_url_from_stream(reader, &re, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(url, "https://abc-123.trycloudflare.com");
    }

    #[tokio::test]
    async fn test_parse_url_from_stream_no_match() {
        let data = b"No URL here\nJust some log lines\n";
        let reader = BufReader::new(&data[..]);
        let re = Regex::new(r"https://[a-z0-9-]+\.trycloudflare\.com").unwrap();

        let result = parse_url_from_stream(reader, &re, Duration::from_secs(1)).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_parse_url_from_stream_ngrok() {
        let data = b"t=2025-01-01 msg=started\nt=2025-01-01 url=https://abcd-1234.ngrok-free.app\n";
        let reader = BufReader::new(&data[..]);
        let re = Regex::new(r"https://[a-z0-9-]+\.ngrok(-free)?\.app").unwrap();

        let url = parse_url_from_stream(reader, &re, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(url, "https://abcd-1234.ngrok-free.app");
    }

    #[tokio::test]
    async fn test_graceful_kill_none() {
        let mut child: Option<Child> = None;
        let result = graceful_kill(&mut child).await;
        assert!(result.is_ok());
    }
}
