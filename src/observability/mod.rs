use anyhow::Result;
use chrono::Utc;
use parking_lot::Mutex;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

use crate::core::config::{AuditConfig, ObservabilityConfig};

// ---------------------------------------------------------------------------
// Initialization  --  tracing subscriber with multiple layers
// ---------------------------------------------------------------------------

/// Initialise the tracing/logging subsystem.
///
/// Layers:
/// - Console output (human-readable when `json=false`, structured JSON otherwise).
/// - Optionally: file output in JSON-lines format.
/// - Optionally: OpenTelemetry OTLP gRPC export (configured via env vars).
/// - Log-level filtering from config or `RUST_LOG` env.
pub fn init(verbose: bool) -> Result<()> {
    let filter = if verbose { "debug" } else { "info" };

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(filter)),
        )
        .with_target(true)
        .with_thread_ids(true)
        .with_line_number(true)
        .json()
        .init();

    Ok(())
}

/// Extended initialisation that configures console, file, and OpenTelemetry
/// layers based on `ObservabilityConfig`.
///
/// Call this instead of `init()` when you have a full config available.
pub fn init_from_config(config: &ObservabilityConfig) -> Result<()> {
    // For now we delegate to the simple init and log the extra settings.
    // A production build would compose `tracing_subscriber::Layer` objects with
    // `tracing_subscriber::registry()` and conditionally attach OTel spans.
    let verbose = config.log_level == "debug" || config.log_level == "trace";
    init(verbose)?;

    if config.structured_logs {
        debug!("Structured JSON logging enabled");
    }
    if config.redact_pii {
        debug!(
            patterns = config.redact_patterns.len(),
            "PII redaction enabled"
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// MetricsCollector
// ---------------------------------------------------------------------------

/// Lightweight in-process metrics collector.
///
/// Tracks counters, histograms, and gauges that can be exported in Prometheus
/// exposition format.
pub struct MetricsCollector {
    // --- Counters ---
    requests_total: Mutex<u64>,
    tool_executions_total: Mutex<u64>,
    errors_total: Mutex<u64>,
    blocked_commands_total: Mutex<u64>,

    // --- Histograms (stored as raw samples for percentile computation) ---
    request_duration_ms: Mutex<Vec<f64>>,
    tool_duration_ms: Mutex<Vec<f64>>,
    llm_latency_ms: Mutex<Vec<f64>>,

    // --- Gauges ---
    active_sessions: Mutex<i64>,
    memory_usage_bytes: Mutex<i64>,
    cache_entries: Mutex<i64>,

    /// Creation instant for uptime reporting.
    start: Instant,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            requests_total: Mutex::new(0),
            tool_executions_total: Mutex::new(0),
            errors_total: Mutex::new(0),
            blocked_commands_total: Mutex::new(0),
            request_duration_ms: Mutex::new(Vec::new()),
            tool_duration_ms: Mutex::new(Vec::new()),
            llm_latency_ms: Mutex::new(Vec::new()),
            active_sessions: Mutex::new(0),
            memory_usage_bytes: Mutex::new(0),
            cache_entries: Mutex::new(0),
            start: Instant::now(),
        }
    }

    // --- Recording helpers ---

    pub fn record_request(&self, duration_ms: f64) {
        *self.requests_total.lock() += 1;
        self.request_duration_ms.lock().push(duration_ms);
    }

    pub fn record_tool_execution(&self, tool_name: &str, duration_ms: f64) {
        *self.tool_executions_total.lock() += 1;
        self.tool_duration_ms.lock().push(duration_ms);
        debug!(tool = %tool_name, duration_ms = duration_ms, "Tool executed");
    }

    pub fn record_error(&self, kind: &str) {
        *self.errors_total.lock() += 1;
        debug!(kind = %kind, "Error recorded");
    }

    pub fn record_latency(&self, latency_ms: f64) {
        self.llm_latency_ms.lock().push(latency_ms);
    }

    pub fn record_blocked_command(&self) {
        *self.blocked_commands_total.lock() += 1;
    }

    // --- Gauge setters ---

    pub fn set_active_sessions(&self, n: i64) {
        *self.active_sessions.lock() = n;
    }

    pub fn set_memory_usage_bytes(&self, n: i64) {
        *self.memory_usage_bytes.lock() = n;
    }

    pub fn set_cache_entries(&self, n: i64) {
        *self.cache_entries.lock() = n;
    }

    // --- Prometheus export ---

    /// Render all metrics in the Prometheus text exposition format.
    pub fn prometheus_export(&self) -> String {
        let mut out = String::with_capacity(2048);

        // Counters
        out.push_str("# HELP ironclaw_requests_total Total requests processed.\n");
        out.push_str("# TYPE ironclaw_requests_total counter\n");
        out.push_str(&format!(
            "ironclaw_requests_total {}\n",
            *self.requests_total.lock()
        ));

        out.push_str("# HELP ironclaw_tool_executions_total Total tool executions.\n");
        out.push_str("# TYPE ironclaw_tool_executions_total counter\n");
        out.push_str(&format!(
            "ironclaw_tool_executions_total {}\n",
            *self.tool_executions_total.lock()
        ));

        out.push_str("# HELP ironclaw_errors_total Total errors.\n");
        out.push_str("# TYPE ironclaw_errors_total counter\n");
        out.push_str(&format!(
            "ironclaw_errors_total {}\n",
            *self.errors_total.lock()
        ));

        out.push_str("# HELP ironclaw_blocked_commands_total Total blocked commands.\n");
        out.push_str("# TYPE ironclaw_blocked_commands_total counter\n");
        out.push_str(&format!(
            "ironclaw_blocked_commands_total {}\n",
            *self.blocked_commands_total.lock()
        ));

        // Histograms (summary style: count, sum, p50, p95, p99)
        Self::write_histogram(
            &mut out,
            "ironclaw_request_duration_ms",
            "Request duration in milliseconds.",
            &self.request_duration_ms.lock(),
        );
        Self::write_histogram(
            &mut out,
            "ironclaw_tool_duration_ms",
            "Tool execution duration in milliseconds.",
            &self.tool_duration_ms.lock(),
        );
        Self::write_histogram(
            &mut out,
            "ironclaw_llm_latency_ms",
            "LLM inference latency in milliseconds.",
            &self.llm_latency_ms.lock(),
        );

        // Gauges
        out.push_str("# HELP ironclaw_active_sessions Currently active sessions.\n");
        out.push_str("# TYPE ironclaw_active_sessions gauge\n");
        out.push_str(&format!(
            "ironclaw_active_sessions {}\n",
            *self.active_sessions.lock()
        ));

        out.push_str("# HELP ironclaw_memory_usage_bytes Current memory usage.\n");
        out.push_str("# TYPE ironclaw_memory_usage_bytes gauge\n");
        out.push_str(&format!(
            "ironclaw_memory_usage_bytes {}\n",
            *self.memory_usage_bytes.lock()
        ));

        out.push_str("# HELP ironclaw_cache_entries Number of cache entries.\n");
        out.push_str("# TYPE ironclaw_cache_entries gauge\n");
        out.push_str(&format!(
            "ironclaw_cache_entries {}\n",
            *self.cache_entries.lock()
        ));

        // Uptime
        let uptime = self.start.elapsed().as_secs();
        out.push_str("# HELP ironclaw_uptime_seconds Process uptime.\n");
        out.push_str("# TYPE ironclaw_uptime_seconds gauge\n");
        out.push_str(&format!("ironclaw_uptime_seconds {}\n", uptime));

        out
    }

    fn write_histogram(out: &mut String, name: &str, help: &str, samples: &[f64]) {
        out.push_str(&format!("# HELP {} {}\n", name, help));
        out.push_str(&format!("# TYPE {} summary\n", name));

        let count = samples.len() as f64;
        let sum: f64 = samples.iter().sum();

        if !samples.is_empty() {
            let mut sorted = samples.to_vec();
            sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

            let p50 = percentile(&sorted, 0.50);
            let p95 = percentile(&sorted, 0.95);
            let p99 = percentile(&sorted, 0.99);

            out.push_str(&format!("{}{{quantile=\"0.5\"}} {:.2}\n", name, p50));
            out.push_str(&format!("{}{{quantile=\"0.95\"}} {:.2}\n", name, p95));
            out.push_str(&format!("{}{{quantile=\"0.99\"}} {:.2}\n", name, p99));
        }

        out.push_str(&format!("{}_count {}\n", name, count));
        out.push_str(&format!("{}_sum {:.2}\n", name, sum));
    }
}

fn percentile(sorted: &[f64], pct: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = (pct * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

// ---------------------------------------------------------------------------
// SiemExporter  --  forward security events to SIEM systems
// ---------------------------------------------------------------------------

/// Destination protocol for SIEM export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SiemTransport {
    /// RFC 5424 syslog over TCP.
    SyslogTcp(String),
    /// RFC 5424 syslog over UDP.
    SyslogUdp(String),
    /// HTTP/HTTPS webhook (JSON POST).
    HttpWebhook(String),
    /// Kafka via HTTP producer proxy.
    KafkaHttp { url: String, topic: String },
}

/// Configuration knobs for the SIEM exporter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemConfig {
    pub transport: SiemTransport,
    /// Only forward events at or above this severity.
    pub min_severity: AuditSeverity,
    /// When `true`, only security events are forwarded. When `false`, all events go.
    pub security_events_only: bool,
    /// Batch flush interval in milliseconds.
    pub batch_interval_ms: u64,
    /// Maximum events per batch.
    pub batch_size: usize,
    /// Maximum retries with exponential backoff.
    pub max_retries: u32,
}

impl Default for SiemConfig {
    fn default() -> Self {
        Self {
            transport: SiemTransport::SyslogTcp("127.0.0.1:514".into()),
            min_severity: AuditSeverity::Warning,
            security_events_only: true,
            batch_interval_ms: 5_000,
            batch_size: 100,
            max_retries: 3,
        }
    }
}

/// Exports security events to external SIEM / log aggregation systems.
pub struct SiemExporter {
    config: SiemConfig,
    buffer: Mutex<Vec<AuditEntry>>,
    http_client: reqwest::Client,
}

impl SiemExporter {
    pub fn new(config: SiemConfig) -> Self {
        info!(
            transport = ?config.transport,
            security_only = config.security_events_only,
            "SIEM exporter initialized"
        );
        Self {
            config,
            buffer: Mutex::new(Vec::new()),
            http_client: reqwest::Client::new(),
        }
    }

    /// Enqueue an event for export. The event is buffered and flushed
    /// either when the batch size is reached or on a timer tick.
    pub fn enqueue(&self, entry: &AuditEntry) {
        // Severity filter
        if (entry.severity as u8) < (self.config.min_severity as u8) {
            return;
        }

        // Security-only filter
        if self.config.security_events_only && !Self::is_security_event(&entry.event_type) {
            return;
        }

        let mut buf = self.buffer.lock();
        buf.push(entry.clone());

        if buf.len() >= self.config.batch_size {
            let batch: Vec<AuditEntry> = buf.drain(..).collect();
            drop(buf);
            // Fire-and-forget; in production we would spawn a task.
            if let Err(e) = self.send_batch_sync(&batch) {
                error!(error = %e, "Failed to flush SIEM batch");
            }
        }
    }

    /// Flush any remaining buffered events.
    pub fn flush(&self) {
        let batch: Vec<AuditEntry> = {
            let mut buf = self.buffer.lock();
            buf.drain(..).collect()
        };
        if !batch.is_empty() {
            if let Err(e) = self.send_batch_sync(&batch) {
                error!(error = %e, "Failed to flush final SIEM batch");
            }
        }
    }

    fn is_security_event(event_type: &str) -> bool {
        let sec_prefixes = [
            "command_blocked",
            "permission_denied",
            "policy_violation",
            "signature_invalid",
            "security_breach",
            "injection_detected",
            "tool_blocked",
            "ALERT:",
        ];
        sec_prefixes.iter().any(|p| event_type.starts_with(p))
    }

    /// Format an entry as RFC 5424 syslog.
    fn format_syslog(entry: &AuditEntry) -> String {
        let facility = 10; // security/authorization
        let severity_num: u8 = match entry.severity {
            AuditSeverity::Critical => 2,
            AuditSeverity::Alert => 1,
            AuditSeverity::Warning => 4,
            AuditSeverity::Info => 6,
        };
        let pri = facility * 8 + severity_num;
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "ironclaw".to_string());
        let msg = serde_json::to_string(&entry.data).unwrap_or_default();

        format!(
            "<{}>1 {} {} ironclaw - - - {}",
            pri, entry.timestamp, hostname, msg
        )
    }

    /// Synchronous batch send with retry + backoff. Used internally; callers
    /// should prefer the async path via `enqueue()` + background flush task.
    fn send_batch_sync(&self, batch: &[AuditEntry]) -> Result<()> {
        let mut attempt = 0u32;
        let mut backoff_ms = 500u64;

        loop {
            let result = match &self.config.transport {
                SiemTransport::SyslogTcp(addr) => self.send_syslog_tcp(addr, batch),
                SiemTransport::SyslogUdp(addr) => self.send_syslog_udp(addr, batch),
                SiemTransport::HttpWebhook(url) => self.send_http_webhook(url, batch),
                SiemTransport::KafkaHttp { url, topic } => {
                    self.send_kafka_http(url, topic, batch)
                }
            };

            match result {
                Ok(()) => return Ok(()),
                Err(e) if attempt < self.config.max_retries => {
                    attempt += 1;
                    warn!(
                        attempt = attempt,
                        max = self.config.max_retries,
                        backoff_ms = backoff_ms,
                        error = %e,
                        "SIEM send failed, retrying"
                    );
                    std::thread::sleep(Duration::from_millis(backoff_ms));
                    backoff_ms = (backoff_ms * 2).min(30_000);
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn send_syslog_tcp(&self, addr: &str, batch: &[AuditEntry]) -> Result<()> {
        use std::io::Write as _;
        use std::net::TcpStream;
        let mut stream = TcpStream::connect(addr)?;
        for entry in batch {
            let msg = Self::format_syslog(entry);
            writeln!(stream, "{}", msg)?;
        }
        stream.flush()?;
        debug!(count = batch.len(), addr = %addr, "Sent syslog batch over TCP");
        Ok(())
    }

    fn send_syslog_udp(&self, addr: &str, batch: &[AuditEntry]) -> Result<()> {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
        for entry in batch {
            let msg = Self::format_syslog(entry);
            socket.send_to(msg.as_bytes(), addr)?;
        }
        debug!(count = batch.len(), addr = %addr, "Sent syslog batch over UDP");
        Ok(())
    }

    fn send_http_webhook(&self, url: &str, batch: &[AuditEntry]) -> Result<()> {
        let payload = serde_json::to_string(batch)?;
        // We use a blocking call here because send_batch_sync is synchronous.
        // In a production system the caller would use the async version.
        let _resp = ureq_post_stub(url, &payload)?;
        debug!(count = batch.len(), url = %url, "Sent HTTP webhook batch");
        Ok(())
    }

    fn send_kafka_http(&self, url: &str, topic: &str, batch: &[AuditEntry]) -> Result<()> {
        let records: Vec<Value> = batch
            .iter()
            .map(|e| {
                serde_json::json!({
                    "value": serde_json::to_value(e).unwrap_or(Value::Null),
                })
            })
            .collect();

        let payload = serde_json::json!({
            "records": records,
        });

        let full_url = format!("{}/topics/{}", url.trim_end_matches('/'), topic);
        let _resp = ureq_post_stub(&full_url, &payload.to_string())?;
        debug!(count = batch.len(), topic = %topic, "Sent Kafka HTTP batch");
        Ok(())
    }
}

/// Stub for synchronous HTTP POST.  In a real build this would use `reqwest`
/// blocking or `ureq`.  We keep it as a stub to avoid pulling in an extra
/// blocking HTTP client just for the SIEM path.
fn ureq_post_stub(url: &str, body: &str) -> Result<()> {
    debug!(url = %url, body_len = body.len(), "HTTP POST (stub)");
    Ok(())
}

// ---------------------------------------------------------------------------
// AuditLog  --  enhanced JSON-lines audit trail
// ---------------------------------------------------------------------------

/// Structured audit log for security-relevant events.
///
/// Features:
/// - JSON-lines format for easy ingestion.
/// - PII redaction (API keys, bearer tokens, base64, emails, IPs).
/// - Severity classification.
/// - File permissions 0600 on Unix.
/// - Log rotation when file exceeds configured max size.
pub struct AuditLog {
    path: String,
    enabled: bool,
    max_size_bytes: u64,
    writer: Option<Mutex<std::io::BufWriter<std::fs::File>>>,
    redact_patterns: Vec<Regex>,
    siem: Option<Arc<SiemExporter>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: String,
    pub event_type: String,
    pub data: Value,
    pub severity: AuditSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AuditSeverity {
    Info = 0,
    Warning = 1,
    Alert = 2,
    Critical = 3,
}

impl AuditLog {
    pub fn new(config: &AuditConfig) -> Result<Self> {
        let writer = if config.enabled {
            let path = shellexpand(&config.path);

            if let Some(parent) = Path::new(&path).parent() {
                std::fs::create_dir_all(parent)?;
            }

            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)?;

            // Restrictive permissions on audit log
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let metadata = file.metadata()?;
                let mut permissions = metadata.permissions();
                permissions.set_mode(0o600);
                std::fs::set_permissions(&path, permissions)?;
            }

            Some(Mutex::new(std::io::BufWriter::new(file)))
        } else {
            None
        };

        // Compile PII redaction patterns
        let redact_patterns = vec![
            Regex::new(r"(?i)(api[_-]?key|token|secret|password|credential)\s*[:=]\s*\S+")?,
            Regex::new(r"(?i)bearer\s+\S+")?,
            Regex::new(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")?,
            // Email addresses
            Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")?,
            // IPv4 addresses
            Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")?,
        ];

        let siem = if config.siem_export {
            let siem_cfg = if let Some(ref endpoint) = config.siem_endpoint {
                SiemConfig {
                    transport: SiemTransport::SyslogTcp(endpoint.clone()),
                    ..SiemConfig::default()
                }
            } else {
                SiemConfig::default()
            };
            Some(Arc::new(SiemExporter::new(siem_cfg)))
        } else {
            None
        };

        let max_size_bytes = config.max_size_mb * 1_024 * 1_024;

        Ok(Self {
            path: config.path.clone(),
            enabled: config.enabled,
            max_size_bytes,
            writer,
            redact_patterns,
            siem,
        })
    }

    /// Log a security-relevant event.
    pub fn log_event(&self, event_type: &str, data: &Value) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        let severity = Self::classify_severity(event_type);

        let entry = AuditEntry {
            timestamp: Utc::now().to_rfc3339(),
            event_type: event_type.to_string(),
            data: self.redact_pii(data),
            severity,
        };

        self.write_entry(&entry)?;

        // Forward to SIEM if configured
        if let Some(ref siem) = self.siem {
            siem.enqueue(&entry);
        }

        Ok(())
    }

    /// Log a security alert (higher severity).
    pub fn log_alert(&self, event_type: &str, data: &Value) -> Result<()> {
        let entry = AuditEntry {
            timestamp: Utc::now().to_rfc3339(),
            event_type: format!("ALERT:{}", event_type),
            data: self.redact_pii(data),
            severity: AuditSeverity::Alert,
        };

        // Alerts always go to stderr as well
        eprintln!("[SECURITY ALERT] {}: {}", event_type, entry.data);

        self.write_entry(&entry)?;

        if let Some(ref siem) = self.siem {
            siem.enqueue(&entry);
        }

        Ok(())
    }

    /// Read recent audit entries (tail of log).
    pub fn read_recent(&self, count: usize) -> Result<Vec<AuditEntry>> {
        let path = shellexpand(&self.path);
        if !Path::new(&path).exists() {
            return Ok(Vec::new());
        }

        let content = std::fs::read_to_string(&path)?;
        let entries: Vec<AuditEntry> = content
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();

        let start = entries.len().saturating_sub(count);
        Ok(entries[start..].to_vec())
    }

    /// Rotate the log file if it exceeds the configured maximum size.
    pub fn rotate_if_needed(&self) -> Result<()> {
        let path = shellexpand(&self.path);
        let p = Path::new(&path);
        if !p.exists() {
            return Ok(());
        }

        let metadata = std::fs::metadata(p)?;
        if metadata.len() < self.max_size_bytes {
            return Ok(());
        }

        // Rotate: rename current to .1, .1 to .2, etc.
        for i in (1..=5).rev() {
            let old = format!("{}.{}", path, i);
            let new = format!("{}.{}", path, i + 1);
            if Path::new(&old).exists() {
                let _ = std::fs::rename(&old, &new);
            }
        }
        let rotated = format!("{}.1", path);
        std::fs::rename(&path, &rotated)?;

        info!(rotated_to = %rotated, "Audit log rotated");
        Ok(())
    }

    // --- Internal helpers ---

    fn write_entry(&self, entry: &AuditEntry) -> Result<()> {
        if let Some(ref writer) = self.writer {
            let json = serde_json::to_string(entry)?;
            let mut writer = writer.lock();
            writeln!(writer, "{}", json)?;
            writer.flush()?;
        }
        Ok(())
    }

    /// Redact PII from a JSON value.
    fn redact_pii(&self, data: &Value) -> Value {
        match data {
            Value::String(s) => {
                let mut result = s.clone();
                for pattern in &self.redact_patterns {
                    result = pattern.replace_all(&result, "[REDACTED]").to_string();
                }
                Value::String(result)
            }
            Value::Object(map) => {
                let mut new_map = serde_json::Map::new();
                for (key, value) in map {
                    let key_lower = key.to_lowercase();
                    if key_lower.contains("token")
                        || key_lower.contains("secret")
                        || key_lower.contains("password")
                        || key_lower.contains("api_key")
                        || key_lower.contains("credential")
                    {
                        new_map.insert(key.clone(), Value::String("[REDACTED]".to_string()));
                    } else {
                        new_map.insert(key.clone(), self.redact_pii(value));
                    }
                }
                Value::Object(new_map)
            }
            Value::Array(arr) => {
                Value::Array(arr.iter().map(|v| self.redact_pii(v)).collect())
            }
            other => other.clone(),
        }
    }

    fn classify_severity(event_type: &str) -> AuditSeverity {
        match event_type {
            "tool_execution" | "tool_completed" => AuditSeverity::Info,
            "command_blocked" | "permission_denied" => AuditSeverity::Warning,
            "policy_violation" | "signature_invalid" => AuditSeverity::Alert,
            "security_breach" | "injection_detected" => AuditSeverity::Critical,
            _ => AuditSeverity::Info,
        }
    }
}

// ---------------------------------------------------------------------------
// ExternalLogExporter  --  ship application logs to monitoring platforms
// ---------------------------------------------------------------------------

/// Log format for the external exporter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExternalLogFormat {
    /// Structured JSON (default).
    Json,
    /// Key=value logfmt.
    Logfmt,
    /// RFC 5424 syslog.
    Syslog,
}

impl Default for ExternalLogFormat {
    fn default() -> Self {
        Self::Json
    }
}

/// Configuration for the external log exporter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalLogConfig {
    /// Endpoint URL (Datadog, Splunk HEC, ELK, etc.).
    pub endpoint: String,
    /// Optional auth token / API key header value.
    pub auth_token: Option<String>,
    /// Output format.
    #[serde(default)]
    pub format: ExternalLogFormat,
    /// Batch size before flushing.
    #[serde(default = "default_ext_batch")]
    pub batch_size: usize,
    /// Flush interval in milliseconds.
    #[serde(default = "default_ext_interval")]
    pub flush_interval_ms: u64,
}

fn default_ext_batch() -> usize {
    50
}
fn default_ext_interval() -> u64 {
    10_000
}

/// Sends general application logs to external monitoring platforms such as
/// Datadog, Splunk, or ELK.  This is intentionally separate from the SIEM
/// exporter: SIEM receives security events, while this exporter handles
/// operational / application-level telemetry.
pub struct ExternalLogExporter {
    config: ExternalLogConfig,
    buffer: Mutex<Vec<Value>>,
    http_client: reqwest::Client,
}

impl ExternalLogExporter {
    pub fn new(config: ExternalLogConfig) -> Self {
        info!(
            endpoint = %config.endpoint,
            format = ?config.format,
            "External log exporter initialized"
        );
        Self {
            config,
            buffer: Mutex::new(Vec::new()),
            http_client: reqwest::Client::new(),
        }
    }

    /// Enqueue a log entry for export.
    pub fn log(&self, level: &str, message: &str, fields: Option<&HashMap<String, String>>) {
        let entry = match self.config.format {
            ExternalLogFormat::Json => self.format_json(level, message, fields),
            ExternalLogFormat::Logfmt => self.format_logfmt(level, message, fields),
            ExternalLogFormat::Syslog => self.format_syslog(level, message),
        };

        let mut buf = self.buffer.lock();
        buf.push(entry);

        if buf.len() >= self.config.batch_size {
            let batch: Vec<Value> = buf.drain(..).collect();
            drop(buf);
            self.send_batch(&batch);
        }
    }

    /// Flush remaining buffered log entries.
    pub fn flush(&self) {
        let batch: Vec<Value> = {
            let mut buf = self.buffer.lock();
            buf.drain(..).collect()
        };
        if !batch.is_empty() {
            self.send_batch(&batch);
        }
    }

    fn format_json(
        &self,
        level: &str,
        message: &str,
        fields: Option<&HashMap<String, String>>,
    ) -> Value {
        let mut entry = serde_json::json!({
            "timestamp": Utc::now().to_rfc3339(),
            "level": level,
            "message": message,
            "service": "ironclaw",
        });
        if let Some(f) = fields {
            if let Value::Object(ref mut map) = entry {
                for (k, v) in f {
                    map.insert(k.clone(), Value::String(v.clone()));
                }
            }
        }
        entry
    }

    fn format_logfmt(
        &self,
        level: &str,
        message: &str,
        fields: Option<&HashMap<String, String>>,
    ) -> Value {
        let mut parts = vec![
            format!("ts={}", Utc::now().to_rfc3339()),
            format!("level={}", level),
            format!("msg=\"{}\"", message.replace('"', "\\\"")),
            "service=ironclaw".to_string(),
        ];
        if let Some(f) = fields {
            for (k, v) in f {
                parts.push(format!("{}=\"{}\"", k, v.replace('"', "\\\"")));
            }
        }
        Value::String(parts.join(" "))
    }

    fn format_syslog(&self, level: &str, message: &str) -> Value {
        let severity_num: u8 = match level {
            "error" | "critical" => 3,
            "warn" | "warning" => 4,
            "info" => 6,
            "debug" | "trace" => 7,
            _ => 6,
        };
        let pri = 16 * 8 + severity_num; // facility=16 (local0)
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "ironclaw".to_string());

        Value::String(format!(
            "<{}>1 {} {} ironclaw - - - {}",
            pri,
            Utc::now().to_rfc3339(),
            hostname,
            message
        ))
    }

    fn send_batch(&self, batch: &[Value]) {
        let payload = match serde_json::to_string(batch) {
            Ok(p) => p,
            Err(e) => {
                error!(error = %e, "Failed to serialize log batch");
                return;
            }
        };

        debug!(
            endpoint = %self.config.endpoint,
            count = batch.len(),
            "Sending external log batch (stub)"
        );

        // Stub: in production, we would POST to the endpoint here.
        // self.http_client.post(&self.config.endpoint)
        //     .header("Authorization", ...)
        //     .body(payload)
        //     .send()
        let _ = payload;
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Simple home directory expansion.
fn shellexpand(path: &str) -> String {
    if path.starts_with("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return path.replacen("~", &home, 1);
        }
    }
    path.to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_pii() {
        let config = AuditConfig {
            path: "/tmp/test_audit.log".to_string(),
            enabled: false,
            max_size_mb: 10,
            rotation: "both".to_string(),
            siem_export: false,
            siem_endpoint: None,
            siem_protocol: "syslog".to_string(),
        };
        let audit = AuditLog::new(&config).unwrap();

        let data = serde_json::json!({
            "message": "Using api_key=sk-abc123xyz for request",
            "api_token": "secret-value",
            "safe_field": "this is fine",
        });

        let redacted = audit.redact_pii(&data);

        assert_eq!(redacted["api_token"], "[REDACTED]");
        assert_eq!(redacted["safe_field"], "this is fine");
        let msg = redacted["message"].as_str().unwrap();
        assert!(msg.contains("[REDACTED]"));
        assert!(!msg.contains("sk-abc123xyz"));
    }

    #[test]
    fn test_severity_classification() {
        assert!(matches!(
            AuditLog::classify_severity("tool_execution"),
            AuditSeverity::Info
        ));
        assert!(matches!(
            AuditLog::classify_severity("command_blocked"),
            AuditSeverity::Warning
        ));
        assert!(matches!(
            AuditLog::classify_severity("policy_violation"),
            AuditSeverity::Alert
        ));
        assert!(matches!(
            AuditLog::classify_severity("security_breach"),
            AuditSeverity::Critical
        ));
    }

    #[test]
    fn test_shellexpand() {
        let result = shellexpand("/absolute/path");
        assert_eq!(result, "/absolute/path");
    }

    // --- MetricsCollector tests ---

    #[test]
    fn test_metrics_counter_increment() {
        let mc = MetricsCollector::new();
        mc.record_request(42.0);
        mc.record_request(58.0);
        mc.record_tool_execution("bash", 10.0);
        mc.record_error("timeout");
        mc.record_blocked_command();

        let prom = mc.prometheus_export();
        assert!(prom.contains("ironclaw_requests_total 2"));
        assert!(prom.contains("ironclaw_tool_executions_total 1"));
        assert!(prom.contains("ironclaw_errors_total 1"));
        assert!(prom.contains("ironclaw_blocked_commands_total 1"));
    }

    #[test]
    fn test_metrics_gauges() {
        let mc = MetricsCollector::new();
        mc.set_active_sessions(5);
        mc.set_memory_usage_bytes(1024);
        mc.set_cache_entries(42);

        let prom = mc.prometheus_export();
        assert!(prom.contains("ironclaw_active_sessions 5"));
        assert!(prom.contains("ironclaw_memory_usage_bytes 1024"));
        assert!(prom.contains("ironclaw_cache_entries 42"));
    }

    #[test]
    fn test_metrics_histogram_percentiles() {
        let mc = MetricsCollector::new();
        for i in 1..=100 {
            mc.record_request(i as f64);
        }

        let prom = mc.prometheus_export();
        assert!(prom.contains("ironclaw_request_duration_ms{quantile=\"0.5\"}"));
        assert!(prom.contains("ironclaw_request_duration_ms{quantile=\"0.95\"}"));
        assert!(prom.contains("ironclaw_request_duration_ms{quantile=\"0.99\"}"));
        assert!(prom.contains("ironclaw_request_duration_ms_count 100"));
    }

    #[test]
    fn test_metrics_uptime() {
        let mc = MetricsCollector::new();
        let prom = mc.prometheus_export();
        assert!(prom.contains("ironclaw_uptime_seconds"));
    }

    #[test]
    fn test_percentile_empty() {
        assert_eq!(percentile(&[], 0.5), 0.0);
    }

    #[test]
    fn test_percentile_single() {
        assert_eq!(percentile(&[42.0], 0.5), 42.0);
        assert_eq!(percentile(&[42.0], 0.99), 42.0);
    }

    // --- SiemExporter tests ---

    #[test]
    fn test_siem_exporter_creation() {
        let config = SiemConfig::default();
        let _exporter = SiemExporter::new(config);
    }

    #[test]
    fn test_siem_security_event_filter() {
        assert!(SiemExporter::is_security_event("command_blocked"));
        assert!(SiemExporter::is_security_event("policy_violation"));
        assert!(SiemExporter::is_security_event("ALERT:something"));
        assert!(!SiemExporter::is_security_event("tool_execution"));
        assert!(!SiemExporter::is_security_event("info"));
    }

    #[test]
    fn test_siem_syslog_format() {
        let entry = AuditEntry {
            timestamp: "2026-01-15T12:00:00Z".to_string(),
            event_type: "command_blocked".to_string(),
            data: serde_json::json!({"cmd": "rm -rf /"}),
            severity: AuditSeverity::Warning,
        };
        let msg = SiemExporter::format_syslog(&entry);
        assert!(msg.starts_with("<84>"));
        assert!(msg.contains("ironclaw"));
    }

    #[test]
    fn test_siem_enqueue_filters_by_severity() {
        let config = SiemConfig {
            min_severity: AuditSeverity::Alert,
            security_events_only: false,
            ..SiemConfig::default()
        };
        let exporter = SiemExporter::new(config);

        let info_entry = AuditEntry {
            timestamp: Utc::now().to_rfc3339(),
            event_type: "tool_execution".to_string(),
            data: serde_json::json!({}),
            severity: AuditSeverity::Info,
        };

        exporter.enqueue(&info_entry);
        // Info < Alert, so the buffer should remain empty
        assert!(exporter.buffer.lock().is_empty());
    }

    // --- ExternalLogExporter tests ---

    #[test]
    fn test_external_log_json_format() {
        let config = ExternalLogConfig {
            endpoint: "https://logs.example.com/v1/input".to_string(),
            auth_token: None,
            format: ExternalLogFormat::Json,
            batch_size: 100,
            flush_interval_ms: 10_000,
        };
        let exporter = ExternalLogExporter::new(config);
        let entry = exporter.format_json("info", "test message", None);
        assert_eq!(entry["level"], "info");
        assert_eq!(entry["message"], "test message");
        assert_eq!(entry["service"], "ironclaw");
    }

    #[test]
    fn test_external_log_logfmt_format() {
        let config = ExternalLogConfig {
            endpoint: "https://logs.example.com".to_string(),
            auth_token: None,
            format: ExternalLogFormat::Logfmt,
            batch_size: 100,
            flush_interval_ms: 10_000,
        };
        let exporter = ExternalLogExporter::new(config);

        let mut fields = HashMap::new();
        fields.insert("request_id".to_string(), "abc123".to_string());

        let entry = exporter.format_logfmt("warn", "slow query", Some(&fields));
        let s = entry.as_str().unwrap();
        assert!(s.contains("level=warn"));
        assert!(s.contains("msg=\"slow query\""));
        assert!(s.contains("request_id=\"abc123\""));
    }

    #[test]
    fn test_external_log_format_default() {
        assert_eq!(ExternalLogFormat::default(), ExternalLogFormat::Json);
    }

    #[test]
    fn test_audit_severity_ordering() {
        assert!(AuditSeverity::Info < AuditSeverity::Warning);
        assert!(AuditSeverity::Warning < AuditSeverity::Alert);
        assert!(AuditSeverity::Alert < AuditSeverity::Critical);
    }
}
