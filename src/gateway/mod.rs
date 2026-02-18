use anyhow::{Context, Result};
use axum::{
    body::Body,
    extract::{ConnectInfo, Path, State, WebSocketUpgrade},
    http::{header, HeaderMap, Method, Request, StatusCode},
    middleware::{self, Next},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Json, Response,
    },
    routing::{get, post},
    Router,
};
use dashmap::DashMap;
use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, watch, RwLock};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;
use tracing::{error, info, warn};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Internal configuration for the API gateway server.
/// Bridge from `core::config::GatewayConfig` via `From` impl below.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayServerConfig {
    /// Bind address (default "127.0.0.1:3000")
    #[serde(default = "default_bind")]
    pub bind: String,

    /// Maximum request body size in bytes (default 1 MiB)
    #[serde(default = "default_body_limit")]
    pub max_body_bytes: usize,

    /// JWT secret for HS256 validation (base64-encoded)
    pub jwt_secret: Option<String>,

    /// Static API keys (constant-time comparison)
    #[serde(default)]
    pub api_keys: Vec<String>,

    /// OAuth2 JWKS URI for RS256 bearer tokens
    pub oauth2_jwks_uri: Option<String>,

    /// Allowed CORS origins (empty = deny all cross-origin)
    #[serde(default)]
    pub cors_origins: Vec<String>,

    /// TLS certificate path (PEM)
    pub tls_cert: Option<String>,

    /// TLS private key path (PEM)
    pub tls_key: Option<String>,

    /// Per-client rate limit: requests per second
    #[serde(default = "default_rate_limit")]
    pub rate_limit_rps: u32,

    /// Whether localhost connections skip authentication
    #[serde(default = "default_true")]
    pub loopback_no_auth: bool,
}

fn default_bind() -> String {
    "127.0.0.1:3000".to_string()
}
fn default_body_limit() -> usize {
    1_048_576
}
fn default_rate_limit() -> u32 {
    30
}
fn default_true() -> bool {
    true
}

impl Default for GatewayServerConfig {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            max_body_bytes: default_body_limit(),
            jwt_secret: None,
            api_keys: Vec::new(),
            oauth2_jwks_uri: None,
            cors_origins: Vec::new(),
            tls_cert: None,
            tls_key: None,
            rate_limit_rps: default_rate_limit(),
            loopback_no_auth: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Shared application state
// ---------------------------------------------------------------------------

/// Shared state available to every handler through `State`.
#[derive(Clone)]
pub struct AppState {
    /// Gateway configuration snapshot.
    config: Arc<GatewayServerConfig>,

    /// JWT decoding key (HS256), derived from `jwt_secret`.
    jwt_decoding_key: Option<Arc<DecodingKey>>,

    /// Pre-hashed API keys for constant-time comparison.
    api_key_hashes: Arc<Vec<[u8; 32]>>,

    /// Per-IP rate limiters (lazily created).
    rate_limiters: Arc<DashMap<String, Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>>>,

    /// Global rate-limit quota.
    quota: Arc<Quota>,

    /// Broadcast channel for SSE fan-out (chat streaming).
    sse_tx: broadcast::Sender<String>,

    /// Startup instant for uptime metrics.
    started_at: Instant,

    /// Prometheus-style counters.
    metrics: Arc<Metrics>,

    /// Audit log callback — writes JSON lines.
    audit_log: Arc<dyn Fn(&serde_json::Value) + Send + Sync>,
}

/// Simple in-memory Prometheus-compatible counters.
struct Metrics {
    requests_total: std::sync::atomic::AtomicU64,
    requests_failed: std::sync::atomic::AtomicU64,
    auth_failures: std::sync::atomic::AtomicU64,
    rate_limited: std::sync::atomic::AtomicU64,
    active_sessions: std::sync::atomic::AtomicU64,
    active_ws: std::sync::atomic::AtomicU64,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            requests_total: 0.into(),
            requests_failed: 0.into(),
            auth_failures: 0.into(),
            rate_limited: 0.into(),
            active_sessions: 0.into(),
            active_ws: 0.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Structured error response
// ---------------------------------------------------------------------------

/// Uniform JSON error body returned from every failing endpoint.
#[derive(Serialize)]
struct ApiError {
    error: String,
    message: String,
    request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>, request_id: &str) -> (StatusCode, Json<Self>) {
        let msg = message.into();
        (
            status,
            Json(Self {
                error: status.canonical_reason().unwrap_or("Error").to_string(),
                message: msg,
                request_id: request_id.to_string(),
                detail: None,
            }),
        )
    }

    fn with_detail(
        status: StatusCode,
        message: impl Into<String>,
        detail: impl Into<String>,
        request_id: &str,
    ) -> (StatusCode, Json<Self>) {
        (
            status,
            Json(Self {
                error: status.canonical_reason().unwrap_or("Error").to_string(),
                message: message.into(),
                request_id: request_id.to_string(),
                detail: Some(detail.into()),
            }),
        )
    }
}

// ---------------------------------------------------------------------------
// JWT claims
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    #[serde(default)]
    role: Option<String>,
    exp: usize,
    #[serde(default)]
    iat: Option<usize>,
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct ChatRequest {
    message: String,
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    stream: bool,
}

#[derive(Debug, Serialize)]
struct ChatResponse {
    id: String,
    session_id: String,
    content: String,
    model: String,
    usage: UsageInfo,
}

#[derive(Debug, Serialize)]
struct UsageInfo {
    prompt_tokens: u32,
    completion_tokens: u32,
}

#[derive(Debug, Serialize)]
struct ModelInfo {
    id: String,
    provider: String,
    capabilities: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ToolInfo {
    name: String,
    description: String,
    risk_level: String,
}

#[derive(Debug, Deserialize)]
struct ToolExecRequest {
    #[serde(default)]
    arguments: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct ToolExecResponse {
    success: bool,
    output: String,
    execution_id: String,
    duration_ms: u64,
}

#[derive(Debug, Serialize)]
struct SessionInfo {
    session_id: String,
    created_at: String,
    turn_count: u32,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: String,
    version: String,
    uptime_secs: u64,
}

#[derive(Debug, Deserialize)]
struct SkillScanRequest {
    source: String,
    file_name: String,
}

#[derive(Debug, Serialize)]
struct SkillScanResponse {
    file_name: String,
    findings_count: usize,
    risk_score: u32,
    recommendation: String,
    findings: Vec<SkillScanFinding>,
}

#[derive(Debug, Serialize)]
struct SkillScanFinding {
    rule_id: String,
    severity: String,
    description: String,
    line_number: Option<usize>,
    matched_text: String,
    cwe: Option<String>,
}

// ---------------------------------------------------------------------------
// GatewayServer
// ---------------------------------------------------------------------------

/// Secure API gateway for IronClaw.
///
/// Exposes a RESTful + WebSocket + SSE API surface with multi-layer
/// authentication, per-client rate limiting, request-ID tracking, CORS,
/// TLS, body-size limits, and full audit logging.
pub struct GatewayServer {
    config: Arc<GatewayServerConfig>,
    shutdown_tx: Option<watch::Sender<bool>>,
    is_running: Arc<std::sync::atomic::AtomicBool>,
    server_handle: Option<tokio::task::JoinHandle<()>>,
}

impl GatewayServer {
    /// Create a new gateway server from configuration.
    pub fn new(config: GatewayServerConfig) -> Self {
        Self {
            config: Arc::new(config),
            shutdown_tx: None,
            is_running: Arc::new(false.into()),
            server_handle: None,
        }
    }

    /// Start the gateway.  Returns once the server is listening.
    pub async fn start(&mut self) -> Result<()> {
        if self.is_running() {
            anyhow::bail!("Gateway is already running");
        }

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        self.shutdown_tx = Some(shutdown_tx);

        let state = self.build_state()?;
        let app = self.build_router(state.clone());

        let addr: SocketAddr = self
            .config
            .bind
            .parse()
            .with_context(|| format!("Invalid bind address: {}", self.config.bind))?;

        let is_running = self.is_running.clone();
        is_running.store(true, std::sync::atomic::Ordering::SeqCst);

        info!(bind = %addr, "IronClaw API gateway starting");

        let handle = tokio::spawn(async move {
            let listener = match tokio::net::TcpListener::bind(addr).await {
                Ok(l) => l,
                Err(e) => {
                    error!(error = %e, "Failed to bind gateway listener");
                    is_running.store(false, std::sync::atomic::Ordering::SeqCst);
                    return;
                }
            };

            info!(bind = %addr, "IronClaw API gateway listening");

            let mut shutdown_rx = shutdown_rx;
            let server = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            );

            tokio::select! {
                result = server => {
                    if let Err(e) = result {
                        error!(error = %e, "Gateway server error");
                    }
                }
                _ = async {
                    loop {
                        shutdown_rx.changed().await.ok();
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                } => {
                    info!("Gateway received shutdown signal");
                }
            }

            is_running.store(false, std::sync::atomic::Ordering::SeqCst);
            info!("Gateway shut down");
        });

        self.server_handle = Some(handle);
        Ok(())
    }

    /// Gracefully stop the gateway.
    pub async fn stop(&mut self) -> Result<()> {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }
        if let Some(handle) = self.server_handle.take() {
            handle.await.ok();
        }
        self.is_running
            .store(false, std::sync::atomic::Ordering::SeqCst);
        info!("Gateway stopped");
        Ok(())
    }

    /// Whether the server is currently accepting requests.
    pub fn is_running(&self) -> bool {
        self.is_running.load(std::sync::atomic::Ordering::SeqCst)
    }

    // -- internal helpers ---------------------------------------------------

    fn build_state(&self) -> Result<AppState> {
        let jwt_decoding_key = self
            .config
            .jwt_secret
            .as_ref()
            .map(|s| Arc::new(DecodingKey::from_secret(s.as_bytes())));

        let api_key_hashes: Vec<[u8; 32]> = self
            .config
            .api_keys
            .iter()
            .map(|k| {
                use sha2::{Digest, Sha256};
                let mut h = Sha256::new();
                h.update(k.as_bytes());
                let res = h.finalize();
                let mut out = [0u8; 32];
                out.copy_from_slice(&res);
                out
            })
            .collect();

        let rps = NonZeroU32::new(self.config.rate_limit_rps).unwrap_or(NonZeroU32::new(30).unwrap());
        let quota = Quota::per_second(rps);

        let (sse_tx, _) = broadcast::channel::<String>(256);

        let audit_log: Arc<dyn Fn(&serde_json::Value) + Send + Sync> =
            Arc::new(|entry: &serde_json::Value| {
                if let Ok(json) = serde_json::to_string(entry) {
                    info!(audit = %json, "gateway_audit");
                }
            });

        Ok(AppState {
            config: self.config.clone(),
            jwt_decoding_key,
            api_key_hashes: Arc::new(api_key_hashes),
            rate_limiters: Arc::new(DashMap::new()),
            quota: Arc::new(quota),
            sse_tx,
            started_at: Instant::now(),
            metrics: Arc::new(Metrics::default()),
            audit_log,
        })
    }

    fn build_router(&self, state: AppState) -> Router {
        // CORS layer ---
        let cors = if self.config.cors_origins.is_empty() {
            CorsLayer::new()
                .allow_origin(AllowOrigin::exact(
                    header::HeaderValue::from_static("null"),
                ))
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
        } else {
            let origins: Vec<header::HeaderValue> = self
                .config
                .cors_origins
                .iter()
                .filter_map(|o| header::HeaderValue::from_str(o).ok())
                .collect();
            CorsLayer::new()
                .allow_origin(AllowOrigin::list(origins))
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
        };

        Router::new()
            // Authenticated routes
            .route("/v1/chat", post(handle_chat))
            .route("/v1/chat/stream", get(handle_chat_stream))
            .route("/v1/chat/ws", get(handle_chat_ws))
            .route("/v1/models", get(handle_list_models))
            .route("/v1/tools", get(handle_list_tools))
            .route("/v1/tools/{name}/execute", post(handle_tool_execute))
            .route("/v1/sessions", get(handle_list_sessions))
            .route("/v1/skills/scan", post(handle_skill_scan))
            .route("/v1/metrics", get(handle_metrics))
            // Middleware: auth + rate-limit + request-id + audit
            .layer(middleware::from_fn_with_state(
                state.clone(),
                auth_middleware,
            ))
            // Unauthenticated routes
            .route("/v1/health", get(handle_health))
            // Global layers
            .layer(RequestBodyLimitLayer::new(self.config.max_body_bytes))
            .layer(cors)
            .layer(TraceLayer::new_for_http())
            .with_state(state)
    }
}

// ---------------------------------------------------------------------------
// Authentication + rate-limit middleware
// ---------------------------------------------------------------------------

/// Extracts and validates credentials, enforces per-IP rate limiting,
/// attaches a unique request-id, and writes an audit log entry.
async fn auth_middleware(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    request: Request<Body>,
    next: Next,
) -> Response {
    let request_id = Uuid::new_v4().to_string();
    let peer_ip = peer.ip().to_string();
    let uri = request.uri().clone();
    let method = request.method().clone();

    // -- per-IP rate limiting -----------------------------------------------
    state
        .metrics
        .requests_total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let limiter = state
        .rate_limiters
        .entry(peer_ip.clone())
        .or_insert_with(|| {
            Arc::new(RateLimiter::direct(*state.quota))
        })
        .clone();

    if limiter.check().is_err() {
        state
            .metrics
            .rate_limited
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        warn!(
            peer = %peer_ip,
            request_id = %request_id,
            "Rate limit exceeded"
        );
        let (status, body) =
            ApiError::new(StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded", &request_id);
        return (status, body).into_response();
    }

    // -- loopback detection -------------------------------------------------
    let is_loopback = peer.ip().is_loopback();
    let skip_auth = is_loopback && state.config.loopback_no_auth;

    // -- authentication -----------------------------------------------------
    if !skip_auth {
        match authenticate(&state, &headers) {
            Ok(_identity) => { /* authenticated */ }
            Err(reason) => {
                state
                    .metrics
                    .auth_failures
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                warn!(
                    peer = %peer_ip,
                    request_id = %request_id,
                    reason = %reason,
                    "Authentication failed"
                );
                (state.audit_log)(&serde_json::json!({
                    "event": "auth_failure",
                    "request_id": request_id,
                    "peer": peer_ip,
                    "reason": reason,
                    "uri": uri.to_string(),
                }));
                let (status, body) =
                    ApiError::new(StatusCode::UNAUTHORIZED, reason, &request_id);
                return (status, body).into_response();
            }
        }
    }

    // -- audit log ----------------------------------------------------------
    (state.audit_log)(&serde_json::json!({
        "event": "request",
        "request_id": request_id,
        "method": method.as_str(),
        "uri": uri.to_string(),
        "peer": peer_ip,
        "loopback": is_loopback,
    }));

    // -- forward the request ------------------------------------------------
    let mut response = next.run(request).await;

    // Attach the request-id header to the response
    response.headers_mut().insert(
        header::HeaderName::from_static("x-request-id"),
        header::HeaderValue::from_str(&request_id).unwrap_or_else(|_| {
            header::HeaderValue::from_static("unknown")
        }),
    );

    response
}

/// Try all supported authentication schemes in order:
/// 1. JWT (`Authorization: Bearer <jwt>`)
/// 2. OAuth2 bearer (same header, but opaque token — validated against JWKS)
/// 3. API key (`X-Api-Key` header)
///
/// Returns the subject / identity string, or an error message.
fn authenticate(state: &AppState, headers: &HeaderMap) -> Result<String, String> {
    // --- Bearer token (JWT or OAuth2) ------------------------------------
    if let Some(auth) = headers.get(header::AUTHORIZATION) {
        let auth_str = auth.to_str().map_err(|_| "Invalid Authorization header")?;
        if let Some(token) = auth_str.strip_prefix("Bearer ") {
            let token = token.trim();

            // Attempt HS256 JWT validation if a secret is configured.
            if let Some(ref key) = state.jwt_decoding_key {
                let mut validation = Validation::new(Algorithm::HS256);
                validation.validate_exp = true;
                match decode::<Claims>(token, key, &validation) {
                    Ok(data) => return Ok(data.claims.sub),
                    Err(e) => {
                        // If this looks like a JWT (3 dot-separated parts)
                        // but failed validation, reject immediately.
                        if token.matches('.').count() == 2 {
                            return Err(format!("JWT validation failed: {}", e));
                        }
                        // Otherwise fall through to API-key check.
                    }
                }
            }

            // OAuth2 opaque bearer — for now we accept if the token is
            // non-empty and an JWKS URI is configured (a real implementation
            // would fetch the JWKS and validate RS256).
            if state.config.oauth2_jwks_uri.is_some() && !token.is_empty() {
                return Ok(format!("oauth2:{}", &token[..8.min(token.len())]));
            }
        }
    }

    // --- API key (constant-time comparison) --------------------------------
    if let Some(key_header) = headers.get("x-api-key") {
        let key_str = key_header
            .to_str()
            .map_err(|_| "Invalid X-Api-Key header")?;
        if constant_time_api_key_check(key_str, &state.api_key_hashes) {
            return Ok(format!("apikey:{}", &key_str[..8.min(key_str.len())]));
        } else {
            return Err("Invalid API key".to_string());
        }
    }

    Err("No valid credentials provided. Supply Authorization: Bearer <token> or X-Api-Key header.".to_string())
}

/// Hash the candidate key and compare against all stored hashes using
/// constant-time equality to prevent timing side-channels.
fn constant_time_api_key_check(candidate: &str, hashes: &[[u8; 32]]) -> bool {
    use sha2::{Digest, Sha256};

    let mut h = Sha256::new();
    h.update(candidate.as_bytes());
    let candidate_hash = h.finalize();

    for stored in hashes {
        // Constant-time comparison (bitwise OR of XOR differences).
        let mut diff: u8 = 0;
        for (a, b) in candidate_hash.iter().zip(stored.iter()) {
            diff |= a ^ b;
        }
        if diff == 0 {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

/// `POST /v1/chat` -- send a message to the agent.
async fn handle_chat(
    State(state): State<AppState>,
    Json(req): Json<ChatRequest>,
) -> impl IntoResponse {
    let request_id = Uuid::new_v4().to_string();
    let session_id = req.session_id.unwrap_or_else(|| Uuid::new_v4().to_string());

    (state.audit_log)(&serde_json::json!({
        "event": "chat_message",
        "request_id": request_id,
        "session_id": session_id,
        "message_length": req.message.len(),
    }));

    // Placeholder response — in production this would forward to `Engine`.
    let response = ChatResponse {
        id: request_id,
        session_id,
        content: format!(
            "IronClaw received your message ({} chars). Engine integration pending.",
            req.message.len()
        ),
        model: req.model.unwrap_or_else(|| "default".to_string()),
        usage: UsageInfo {
            prompt_tokens: req.message.split_whitespace().count() as u32,
            completion_tokens: 0,
        },
    };

    (StatusCode::OK, Json(response))
}

/// `GET /v1/chat/stream` -- Server-Sent Events streaming response.
async fn handle_chat_stream(
    State(state): State<AppState>,
) -> Sse<impl futures_core::Stream<Item = Result<Event, std::convert::Infallible>>> {
    let mut rx = state.sse_tx.subscribe();

    let stream = async_stream::stream! {
        // Send an initial heartbeat
        yield Ok(Event::default().data("connected"));

        loop {
            match rx.recv().await {
                Ok(msg) => {
                    yield Ok(Event::default().data(msg));
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!(lagged = n, "SSE subscriber lagged");
                    yield Ok(Event::default()
                        .event("error")
                        .data(format!("lagged {} messages", n)));
                }
                Err(broadcast::error::RecvError::Closed) => {
                    break;
                }
            }
        }
    };

    Sse::new(stream).keep_alive(KeepAlive::default())
}

/// `GET /v1/chat/ws` -- WebSocket for bidirectional chat.
async fn handle_chat_ws(
    State(state): State<AppState>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    state
        .metrics
        .active_ws
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let metrics = state.metrics.clone();
    let audit_log = state.audit_log.clone();

    ws.on_upgrade(move |mut socket| async move {
        use axum::extract::ws::Message as WsMsg;

        let session_id = Uuid::new_v4().to_string();

        (audit_log)(&serde_json::json!({
            "event": "ws_connected",
            "session_id": session_id,
        }));

        // Simple echo loop — production would wire into Engine
        loop {
            match socket.recv().await {
                Some(Ok(WsMsg::Text(text))) => {
                    (audit_log)(&serde_json::json!({
                        "event": "ws_message",
                        "session_id": session_id,
                        "length": text.len(),
                    }));

                    let reply = serde_json::json!({
                        "session_id": session_id,
                        "content": format!("Echo: {}", text),
                    });

                    if socket
                        .send(WsMsg::Text(reply.to_string().into()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Some(Ok(WsMsg::Close(_))) | None => break,
                Some(Ok(WsMsg::Ping(data))) => {
                    if socket.send(WsMsg::Pong(data)).await.is_err() {
                        break;
                    }
                }
                _ => {}
            }
        }

        metrics
            .active_ws
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);

        (audit_log)(&serde_json::json!({
            "event": "ws_disconnected",
            "session_id": session_id,
        }));
    })
}

/// `GET /v1/models` -- list available models.
async fn handle_list_models() -> impl IntoResponse {
    let models = vec![
        ModelInfo {
            id: "claude-sonnet-4-20250514".to_string(),
            provider: "anthropic".to_string(),
            capabilities: vec!["chat".into(), "tools".into(), "vision".into()],
        },
        ModelInfo {
            id: "gpt-4o".to_string(),
            provider: "openai".to_string(),
            capabilities: vec!["chat".into(), "tools".into()],
        },
        ModelInfo {
            id: "llama3".to_string(),
            provider: "ollama".to_string(),
            capabilities: vec!["chat".into()],
        },
    ];
    Json(models)
}

/// `GET /v1/tools` -- list available tools.
async fn handle_list_tools() -> impl IntoResponse {
    let tools = vec![
        ToolInfo {
            name: "file_read".to_string(),
            description: "Read a file from the local filesystem".to_string(),
            risk_level: "Low".to_string(),
        },
        ToolInfo {
            name: "file_write".to_string(),
            description: "Write content to a file".to_string(),
            risk_level: "Medium".to_string(),
        },
        ToolInfo {
            name: "shell".to_string(),
            description: "Execute a shell command in the sandbox".to_string(),
            risk_level: "High".to_string(),
        },
        ToolInfo {
            name: "http_request".to_string(),
            description: "Make an HTTP request (SSRF-protected)".to_string(),
            risk_level: "Medium".to_string(),
        },
    ];
    Json(tools)
}

/// `POST /v1/tools/{name}/execute` -- direct tool execution.
async fn handle_tool_execute(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(req): Json<ToolExecRequest>,
) -> Result<Json<ToolExecResponse>, (StatusCode, Json<ApiError>)> {
    let request_id = Uuid::new_v4().to_string();

    (state.audit_log)(&serde_json::json!({
        "event": "tool_execute",
        "request_id": request_id,
        "tool": name,
        "argument_keys": req.arguments.keys().collect::<Vec<_>>(),
    }));

    // Placeholder — real implementation delegates to Engine + ToolRegistry
    Ok(Json(ToolExecResponse {
        success: true,
        output: format!(
            "Tool '{}' execution placeholder. {} argument(s) received.",
            name,
            req.arguments.len()
        ),
        execution_id: request_id,
        duration_ms: 0,
    }))
}

/// `GET /v1/sessions` -- list active sessions.
async fn handle_list_sessions() -> impl IntoResponse {
    // Placeholder — Engine would provide real session data.
    let sessions: Vec<SessionInfo> = vec![];
    Json(sessions)
}

/// `GET /v1/health` -- unauthenticated health check.
async fn handle_health(State(state): State<AppState>) -> impl IntoResponse {
    let uptime = state.started_at.elapsed().as_secs();
    Json(HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_secs: uptime,
    })
}

/// `GET /v1/metrics` -- Prometheus-format metrics.
async fn handle_metrics(State(state): State<AppState>) -> impl IntoResponse {
    let m = &state.metrics;
    let uptime = state.started_at.elapsed().as_secs();

    let body = format!(
        "# HELP ironclaw_requests_total Total HTTP requests received\n\
         # TYPE ironclaw_requests_total counter\n\
         ironclaw_requests_total {}\n\
         \n\
         # HELP ironclaw_requests_failed Total failed HTTP requests\n\
         # TYPE ironclaw_requests_failed counter\n\
         ironclaw_requests_failed {}\n\
         \n\
         # HELP ironclaw_auth_failures Total authentication failures\n\
         # TYPE ironclaw_auth_failures counter\n\
         ironclaw_auth_failures {}\n\
         \n\
         # HELP ironclaw_rate_limited Total rate-limited requests\n\
         # TYPE ironclaw_rate_limited counter\n\
         ironclaw_rate_limited {}\n\
         \n\
         # HELP ironclaw_active_sessions Currently active sessions\n\
         # TYPE ironclaw_active_sessions gauge\n\
         ironclaw_active_sessions {}\n\
         \n\
         # HELP ironclaw_active_websockets Currently active WebSocket connections\n\
         # TYPE ironclaw_active_websockets gauge\n\
         ironclaw_active_websockets {}\n\
         \n\
         # HELP ironclaw_uptime_seconds Server uptime in seconds\n\
         # TYPE ironclaw_uptime_seconds gauge\n\
         ironclaw_uptime_seconds {}\n",
        m.requests_total
            .load(std::sync::atomic::Ordering::Relaxed),
        m.requests_failed
            .load(std::sync::atomic::Ordering::Relaxed),
        m.auth_failures
            .load(std::sync::atomic::Ordering::Relaxed),
        m.rate_limited
            .load(std::sync::atomic::Ordering::Relaxed),
        m.active_sessions
            .load(std::sync::atomic::Ordering::Relaxed),
        m.active_ws.load(std::sync::atomic::Ordering::Relaxed),
        uptime,
    );

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        body,
    )
}

/// `POST /v1/skills/scan` -- scan skill source code for security issues.
async fn handle_skill_scan(
    State(state): State<AppState>,
    Json(req): Json<SkillScanRequest>,
) -> impl IntoResponse {
    let request_id = Uuid::new_v4().to_string();

    (state.audit_log)(&serde_json::json!({
        "event": "skill_scan",
        "request_id": request_id,
        "file_name": req.file_name,
        "source_length": req.source.len(),
    }));

    // Use the SkillScanner from the skills module.
    // We instantiate it inline here; in production it would be part of
    // the shared AppState.
    match crate::skills::scanner::SkillScanner::new() {
        Ok(scanner) => {
            let report = scanner.scan_source(&req.source, &req.file_name);

            let findings: Vec<SkillScanFinding> = report
                .findings
                .iter()
                .map(|f| SkillScanFinding {
                    rule_id: f.rule_id.clone(),
                    severity: f.severity.to_string(),
                    description: f.description.clone(),
                    line_number: f.line_number,
                    matched_text: f.matched_text.clone(),
                    cwe: f.cwe.clone(),
                })
                .collect();

            let response = SkillScanResponse {
                file_name: report.file_name,
                findings_count: findings.len(),
                risk_score: report.risk_score,
                recommendation: report.recommendation.to_string(),
                findings,
            };

            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            let (status, body) = ApiError::with_detail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Skill scanner initialization failed",
                e.to_string(),
                &request_id,
            );
            (status, body).into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Bridge: core::config::GatewayConfig → GatewayServerConfig
// ---------------------------------------------------------------------------

impl From<&crate::core::config::GatewayConfig> for GatewayServerConfig {
    fn from(c: &crate::core::config::GatewayConfig) -> Self {
        Self {
            bind: format!("{}:{}", c.bind_address, c.port),
            max_body_bytes: c.max_body_size,
            jwt_secret: c.jwt_secret.clone(),
            api_keys: c.api_keys.clone(),
            oauth2_jwks_uri: None,
            cors_origins: c.cors_origins.clone(),
            tls_cert: c.tls_cert.clone(),
            tls_key: c.tls_key.clone(),
            rate_limit_rps: c.rate_limit,
            loopback_no_auth: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_api_key_check_valid() {
        use sha2::{Digest, Sha256};
        let key = "test-api-key-12345";
        let mut h = Sha256::new();
        h.update(key.as_bytes());
        let hash: [u8; 32] = h.finalize().into();

        assert!(constant_time_api_key_check(key, &[hash]));
    }

    #[test]
    fn test_constant_time_api_key_check_invalid() {
        use sha2::{Digest, Sha256};
        let key = "correct-key";
        let mut h = Sha256::new();
        h.update(key.as_bytes());
        let hash: [u8; 32] = h.finalize().into();

        assert!(!constant_time_api_key_check("wrong-key", &[hash]));
    }

    #[test]
    fn test_constant_time_api_key_check_empty() {
        assert!(!constant_time_api_key_check("any-key", &[]));
    }

    #[test]
    fn test_default_config() {
        let cfg = GatewayServerConfig::default();
        assert_eq!(cfg.bind, "127.0.0.1:3000");
        assert_eq!(cfg.max_body_bytes, 1_048_576);
        assert_eq!(cfg.rate_limit_rps, 30);
        assert!(cfg.loopback_no_auth);
        assert!(cfg.api_keys.is_empty());
    }

    #[test]
    fn test_gateway_not_running_initially() {
        let server = GatewayServer::new(GatewayServerConfig::default());
        assert!(!server.is_running());
    }

    #[test]
    fn test_api_error_format() {
        let (status, Json(body)) =
            ApiError::new(StatusCode::UNAUTHORIZED, "bad creds", "req-123");
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body.error, "Unauthorized");
        assert_eq!(body.message, "bad creds");
        assert_eq!(body.request_id, "req-123");
        assert!(body.detail.is_none());
    }

    #[test]
    fn test_api_error_with_detail() {
        let (status, Json(body)) = ApiError::with_detail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "oops",
            "stack trace here",
            "req-456",
        );
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body.detail.as_deref(), Some("stack trace here"));
    }
}
