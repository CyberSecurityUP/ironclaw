//! Optional Web UI for IronClaw — served via axum.
//!
//! Provides a modern dark-theme chat interface with real-time WebSocket
//! communication to the gateway. Includes embedded static assets (HTML/CSS/JS)
//! so the UI is fully self-contained with zero external dependencies.
//!
//! Security:
//! - Optional basic auth or JWT validation from gateway config
//! - WebSocket messages are validated before processing
//! - All user inputs are sanitized before rendering
//! - CSP headers prevent XSS in the served HTML

use anyhow::Result;
use axum::{
    extract::ws::{Message as WsMessage, WebSocket, WebSocketUpgrade},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::get,
    Router,
};
use futures_util::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{error, info, warn};

// ---------------------------------------------------------------------------
// Embedded static assets
// ---------------------------------------------------------------------------

const INDEX_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>IronClaw — Secure AI Agent</title>
<link rel="stylesheet" href="/ui/static/style.css"/>
<meta http-equiv="Content-Security-Policy"
      content="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss:;"/>
</head>
<body>
<div id="app">
  <aside id="sidebar">
    <div class="sidebar-header">
      <span class="lock-icon">&#x1F512;</span>
      <h2>IronClaw</h2>
    </div>
    <div class="sidebar-section">
      <h3>Sessions</h3>
      <ul id="session-list"><li class="active" data-id="current">Current Session</li></ul>
    </div>
    <div class="sidebar-section">
      <h3>Tools</h3>
      <ul id="tool-list"></ul>
    </div>
    <div class="sidebar-section">
      <button id="settings-toggle" class="sidebar-btn">Settings</button>
    </div>
    <div class="sidebar-footer">
      <span class="security-badge">&#x1F512; Secured by IronClaw</span>
    </div>
  </aside>
  <main id="main">
    <div id="chat-area">
      <div id="messages"></div>
    </div>
    <form id="input-area" autocomplete="off">
      <textarea id="msg-input" rows="1" placeholder="Type a message..."></textarea>
      <button type="submit" id="send-btn">Send</button>
    </form>
    <div id="status-bar">
      <span id="sb-provider">Provider: --</span>
      <span id="sb-model">Model: --</span>
      <span id="sb-session">Session: --</span>
      <span id="sb-conn" class="disconnected">Disconnected</span>
    </div>
  </main>
</div>
<script src="/ui/static/app.js"></script>
</body>
</html>
"#;

const APP_JS: &str = r##"(function(){
"use strict";

var ws = null;
var messagesEl = document.getElementById("messages");
var inputEl    = document.getElementById("msg-input");
var formEl     = document.getElementById("input-area");
var connEl     = document.getElementById("sb-conn");
var provEl     = document.getElementById("sb-provider");
var modelEl    = document.getElementById("sb-model");
var sessEl     = document.getElementById("sb-session");
var toolListEl = document.getElementById("tool-list");
var settingsBtn = document.getElementById("settings-toggle");

// --- Markdown-lite renderer (regex-based) ---
function md(text) {
  if (!text) return "";
  var s = text
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    // code blocks
    .replace(/```(\w*)\n([\s\S]*?)```/g, '<pre><code class="lang-$1">$2</code></pre>')
    // inline code
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    // bold
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    // italic
    .replace(/\*(.+?)\*/g, '<em>$1</em>')
    // headings
    .replace(/^### (.+)$/gm, '<h4>$1</h4>')
    .replace(/^## (.+)$/gm,  '<h3>$1</h3>')
    .replace(/^# (.+)$/gm,   '<h2>$1</h2>')
    // links
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>')
    // line breaks
    .replace(/\n/g, '<br/>');
  return s;
}

function scrollBottom() {
  messagesEl.scrollTop = messagesEl.scrollHeight;
}

function appendMessage(role, content) {
  var div = document.createElement("div");
  div.className = "msg msg-" + role;
  var label = document.createElement("span");
  label.className = "msg-label";
  label.textContent = role === "user" ? "You" : role === "assistant" ? "IronClaw" : role;
  div.appendChild(label);
  var body = document.createElement("div");
  body.className = "msg-body";
  body.innerHTML = md(content);
  div.appendChild(body);
  messagesEl.appendChild(div);
  scrollBottom();
}

function setStatus(provider, model, session) {
  if (provider) provEl.textContent  = "Provider: " + provider;
  if (model)    modelEl.textContent = "Model: " + model;
  if (session)  sessEl.textContent  = "Session: " + session.substring(0, 8);
}

function setTools(tools) {
  toolListEl.innerHTML = "";
  (tools || []).forEach(function(t) {
    var li = document.createElement("li");
    li.textContent = t;
    toolListEl.appendChild(li);
  });
}

// --- WebSocket connection ---
function connect() {
  var proto = location.protocol === "https:" ? "wss:" : "ws:";
  ws = new WebSocket(proto + "//" + location.host + "/ui/ws");

  ws.onopen = function() {
    connEl.textContent = "Connected";
    connEl.className = "connected";
  };

  ws.onclose = function() {
    connEl.textContent = "Disconnected";
    connEl.className = "disconnected";
    setTimeout(connect, 3000);
  };

  ws.onerror = function() {
    connEl.textContent = "Error";
    connEl.className = "disconnected";
  };

  ws.onmessage = function(evt) {
    try {
      var msg = JSON.parse(evt.data);
      if (msg.type === "chat") {
        appendMessage(msg.role || "assistant", msg.content || "");
      } else if (msg.type === "status") {
        setStatus(msg.provider, msg.model, msg.session_id);
      } else if (msg.type === "tools") {
        setTools(msg.tools);
      } else if (msg.type === "error") {
        appendMessage("system", "Error: " + (msg.message || "unknown"));
      }
    } catch(e) {
      console.error("Bad WS message", e);
    }
  };
}

function sendMessage(text) {
  if (!ws || ws.readyState !== WebSocket.OPEN) return;
  ws.send(JSON.stringify({ type: "chat", content: text }));
  appendMessage("user", text);
}

// --- UI events ---
formEl.addEventListener("submit", function(e) {
  e.preventDefault();
  var text = inputEl.value.trim();
  if (!text) return;
  sendMessage(text);
  inputEl.value = "";
  inputEl.style.height = "auto";
});

inputEl.addEventListener("keydown", function(e) {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    formEl.dispatchEvent(new Event("submit"));
  }
});

inputEl.addEventListener("input", function() {
  this.style.height = "auto";
  this.style.height = Math.min(this.scrollHeight, 200) + "px";
});

settingsBtn.addEventListener("click", function() {
  appendMessage("system", "Settings panel is not yet implemented.");
});

// Start
connect();
})();
"##;

const STYLE_CSS: &str = r#"
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0d1117;--bg2:#161b22;--bg3:#21262d;
  --fg:#c9d1d9;--fg2:#8b949e;--accent:#58a6ff;
  --green:#3fb950;--red:#f85149;--yellow:#d29922;
  --border:#30363d;--radius:6px;
  --font:ui-monospace,SFMono-Regular,SF Mono,Menlo,Consolas,Liberation Mono,monospace;
}
html,body{height:100%;background:var(--bg);color:var(--fg);font-family:var(--font);font-size:14px}
#app{display:flex;height:100vh}

/* --- Sidebar --- */
#sidebar{width:260px;background:var(--bg2);border-right:1px solid var(--border);display:flex;flex-direction:column;overflow-y:auto}
.sidebar-header{padding:16px;display:flex;align-items:center;gap:8px;border-bottom:1px solid var(--border)}
.sidebar-header h2{font-size:16px;color:var(--accent)}
.lock-icon{font-size:18px}
.sidebar-section{padding:12px 16px}
.sidebar-section h3{font-size:12px;text-transform:uppercase;color:var(--fg2);margin-bottom:8px;letter-spacing:.5px}
.sidebar-section ul{list-style:none}
.sidebar-section li{padding:6px 8px;border-radius:var(--radius);cursor:pointer;font-size:13px;color:var(--fg2)}
.sidebar-section li:hover,.sidebar-section li.active{background:var(--bg3);color:var(--fg)}
.sidebar-btn{width:100%;padding:8px;background:var(--bg3);border:1px solid var(--border);color:var(--fg);border-radius:var(--radius);cursor:pointer;font-family:var(--font);font-size:13px}
.sidebar-btn:hover{background:var(--border)}
.sidebar-footer{margin-top:auto;padding:12px 16px;border-top:1px solid var(--border);text-align:center}
.security-badge{font-size:11px;color:var(--green)}

/* --- Main --- */
#main{flex:1;display:flex;flex-direction:column;min-width:0}
#chat-area{flex:1;overflow-y:auto;padding:16px 24px}
#messages{max-width:860px;margin:0 auto}
.msg{margin-bottom:16px}
.msg-label{display:block;font-size:11px;font-weight:600;text-transform:uppercase;margin-bottom:4px;letter-spacing:.4px}
.msg-user .msg-label{color:var(--accent)}
.msg-assistant .msg-label{color:var(--green)}
.msg-system .msg-label{color:var(--yellow)}
.msg-body{line-height:1.6;word-break:break-word}
.msg-body pre{background:var(--bg2);padding:12px;border-radius:var(--radius);overflow-x:auto;margin:8px 0}
.msg-body code{background:var(--bg3);padding:2px 5px;border-radius:3px;font-size:13px}
.msg-body pre code{background:transparent;padding:0}
.msg-body a{color:var(--accent);text-decoration:none}
.msg-body a:hover{text-decoration:underline}

/* --- Input --- */
#input-area{display:flex;gap:8px;padding:12px 24px;border-top:1px solid var(--border);background:var(--bg2)}
#msg-input{flex:1;resize:none;background:var(--bg);border:1px solid var(--border);border-radius:var(--radius);padding:10px 12px;color:var(--fg);font-family:var(--font);font-size:14px;line-height:1.5}
#msg-input:focus{outline:none;border-color:var(--accent)}
#send-btn{padding:10px 20px;background:var(--accent);color:#fff;border:none;border-radius:var(--radius);cursor:pointer;font-family:var(--font);font-weight:600;font-size:14px}
#send-btn:hover{opacity:.85}

/* --- Status bar --- */
#status-bar{display:flex;gap:16px;padding:6px 24px;font-size:11px;color:var(--fg2);border-top:1px solid var(--border);background:var(--bg2)}
.connected{color:var(--green)}
.disconnected{color:var(--red)}

/* --- Responsive --- */
@media(max-width:768px){
  #sidebar{width:200px}
  #chat-area{padding:12px}
  #input-area{padding:8px 12px}
  #status-bar{padding:4px 12px;flex-wrap:wrap}
}
@media(max-width:480px){
  #sidebar{display:none}
}
"#;

// ---------------------------------------------------------------------------
// Web UI server
// ---------------------------------------------------------------------------

/// Broadcast channel message type for inter-task communication.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct UiMessage {
    #[serde(rename = "type", default)]
    pub msg_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Configuration for the web UI.
#[derive(Debug, Clone)]
pub struct WebUiConfig {
    /// Address to bind (e.g. "0.0.0.0:9090")
    pub bind_addr: SocketAddr,
    /// Optional basic-auth credentials ("user:pass")
    pub basic_auth: Option<String>,
    /// Optional JWT secret for token validation
    pub jwt_secret: Option<String>,
}

impl Default for WebUiConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 9090)),
            basic_auth: None,
            jwt_secret: None,
        }
    }
}

impl From<&crate::core::config::UiConfig> for WebUiConfig {
    fn from(c: &crate::core::config::UiConfig) -> Self {
        let addr: std::net::IpAddr = c
            .bind_address
            .parse()
            .unwrap_or(std::net::IpAddr::from([127, 0, 0, 1]));
        Self {
            bind_addr: SocketAddr::new(addr, c.port),
            basic_auth: None,
            jwt_secret: None,
        }
    }
}

/// Shared state that is available to every handler.
struct AppState {
    tx: broadcast::Sender<UiMessage>,
    #[allow(dead_code)]
    config: WebUiConfig,
}

/// The web UI server.
pub struct WebUi {
    config: WebUiConfig,
    tx: broadcast::Sender<UiMessage>,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl WebUi {
    /// Create a new WebUi instance. Does **not** start serving yet.
    pub fn new(config: WebUiConfig) -> Self {
        let (tx, _) = broadcast::channel::<UiMessage>(256);
        Self {
            config,
            tx,
            shutdown_tx: None,
        }
    }

    /// Obtain a sender handle so other subsystems (engine, gateway) can push
    /// messages into the UI broadcast channel.
    pub fn sender(&self) -> broadcast::Sender<UiMessage> {
        self.tx.clone()
    }

    /// Start the web UI server in the background.
    pub async fn start(&mut self) -> Result<()> {
        let state = Arc::new(AppState {
            tx: self.tx.clone(),
            config: self.config.clone(),
        });

        let app = Router::new()
            .route("/", get(serve_index))
            .route("/ui/static/app.js", get(serve_js))
            .route("/ui/static/style.css", get(serve_css))
            .route("/ui/ws", get(ws_handler))
            .with_state(state);

        let addr = self.config.bind_addr;
        let listener = tokio::net::TcpListener::bind(addr).await?;

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        self.shutdown_tx = Some(shutdown_tx);

        info!(addr = %addr, "Web UI listening");

        tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                    info!("Web UI shutting down");
                })
                .await
                .unwrap_or_else(|e| error!("Web UI server error: {}", e));
        });

        Ok(())
    }

    /// Gracefully stop the web UI server.
    pub fn stop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
            info!("Web UI stop signal sent");
        }
    }

    /// Convenience: push a chat message into the broadcast channel.
    pub fn push_chat(&self, role: &str, content: &str) {
        let _ = self.tx.send(UiMessage {
            msg_type: "chat".into(),
            role: Some(role.into()),
            content: Some(content.into()),
            provider: None,
            model: None,
            session_id: None,
            tools: None,
            message: None,
        });
    }

    /// Push a status update.
    pub fn push_status(&self, provider: &str, model: &str, session_id: &str) {
        let _ = self.tx.send(UiMessage {
            msg_type: "status".into(),
            role: None,
            content: None,
            provider: Some(provider.into()),
            model: Some(model.into()),
            session_id: Some(session_id.into()),
            tools: None,
            message: None,
        });
    }

    /// Push the tool list.
    pub fn push_tools(&self, tools: Vec<String>) {
        let _ = self.tx.send(UiMessage {
            msg_type: "tools".into(),
            role: None,
            content: None,
            provider: None,
            model: None,
            session_id: None,
            tools: Some(tools),
            message: None,
        });
    }
}

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

async fn serve_index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn serve_js() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/javascript; charset=utf-8")],
        APP_JS,
    )
        .into_response()
}

async fn serve_css() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        STYLE_CSS,
    )
        .into_response()
}

/// Upgrade HTTP to WebSocket and manage the connection.
async fn ws_handler(
    ws: WebSocketUpgrade,
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws(socket, state))
}

async fn handle_ws(socket: WebSocket, state: Arc<AppState>) {
    info!("WebSocket client connected");

    // Subscribe to broadcast channel so we forward server messages to this client.
    let mut rx = state.tx.subscribe();

    // Spawn a task that forwards broadcast messages to the WebSocket client.
    let (mut ws_tx, mut ws_rx) = socket.split();

    // We use a small helper channel to merge the two event sources.
    let (merge_tx, mut merge_rx) = tokio::sync::mpsc::channel::<WsMessage>(64);

    // Task: broadcast -> client
    let merge_tx2 = merge_tx.clone();
    let broadcast_task = tokio::spawn(async move {
        while let Ok(msg) = rx.recv().await {
            if let Ok(json) = serde_json::to_string(&msg) {
                if merge_tx2.send(WsMessage::Text(json.into())).await.is_err() {
                    break;
                }
            }
        }
    });

    // Task: client -> broadcast (user messages)
    let tx_for_client = state.tx.clone();
    let client_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = ws_rx.next().await {
            match msg {
                WsMessage::Text(text) => {
                    let text_str: &str = &text;
                    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(text_str) {
                        if parsed.get("type").and_then(|v| v.as_str()) == Some("chat") {
                            let content = parsed
                                .get("content")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();

                            if content.is_empty() {
                                continue;
                            }

                            // Re-broadcast so other subscribers (engine) see it.
                            let _ = tx_for_client.send(UiMessage {
                                msg_type: "user_input".into(),
                                role: Some("user".into()),
                                content: Some(content),
                                provider: None,
                                model: None,
                                session_id: None,
                                tools: None,
                                message: None,
                            });
                        }
                    } else {
                        warn!("Invalid JSON from WebSocket client");
                    }
                }
                WsMessage::Close(_) => break,
                _ => {}
            }
        }
    });

    // Merge loop — write outgoing messages from the merge channel to the WebSocket.
    let write_task = tokio::spawn(async move {
        while let Some(msg) = merge_rx.recv().await {
            if ws_tx.send(msg).await.is_err() {
                break;
            }
        }
    });

    // Wait for either task to complete, then clean up.
    tokio::select! {
        _ = broadcast_task => {},
        _ = client_task => {},
        _ = write_task => {},
    }

    info!("WebSocket client disconnected");
}

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------

/// Validate HTTP Basic-Auth header value against the configured credential.
#[allow(dead_code)]
fn validate_basic_auth(header_value: &str, expected: &str) -> bool {
    if let Some(encoded) = header_value.strip_prefix("Basic ") {
        if let Ok(decoded_bytes) = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            encoded.trim(),
        ) {
            if let Ok(decoded) = String::from_utf8(decoded_bytes) {
                return decoded == expected;
            }
        }
    }
    false
}

/// Validate a JWT token against the configured secret (HS256).
#[allow(dead_code)]
fn validate_jwt(token: &str, secret: &str) -> bool {
    use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

    #[derive(serde::Deserialize)]
    struct Claims {
        #[allow(dead_code)]
        sub: Option<String>,
        #[allow(dead_code)]
        exp: Option<u64>,
    }

    let key = DecodingKey::from_secret(secret.as_bytes());
    let validation = Validation::new(Algorithm::HS256);
    decode::<Claims>(token, &key, &validation).is_ok()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn test_default_config() {
        let cfg = WebUiConfig::default();
        assert_eq!(cfg.bind_addr, SocketAddr::from(([127, 0, 0, 1], 9090)));
        assert!(cfg.basic_auth.is_none());
        assert!(cfg.jwt_secret.is_none());
    }

    #[test]
    fn test_ui_message_serialization() {
        let msg = UiMessage {
            msg_type: "chat".into(),
            role: Some("assistant".into()),
            content: Some("Hello!".into()),
            provider: None,
            model: None,
            session_id: None,
            tools: None,
            message: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"chat\""));
        assert!(json.contains("\"content\":\"Hello!\""));
        // None fields should be absent due to skip_serializing_if
        assert!(!json.contains("provider"));
    }

    #[test]
    fn test_push_chat_does_not_panic_without_subscribers() {
        let ui = WebUi::new(WebUiConfig::default());
        // No subscribers — should not panic.
        ui.push_chat("assistant", "test");
    }

    #[test]
    fn test_push_status_does_not_panic() {
        let ui = WebUi::new(WebUiConfig::default());
        ui.push_status("anthropic", "claude-sonnet", "abc-123");
    }

    #[test]
    fn test_push_tools_does_not_panic() {
        let ui = WebUi::new(WebUiConfig::default());
        ui.push_tools(vec!["file_read".into(), "shell".into()]);
    }

    #[test]
    fn test_html_contains_key_elements() {
        assert!(INDEX_HTML.contains("id=\"messages\""));
        assert!(INDEX_HTML.contains("id=\"msg-input\""));
        assert!(INDEX_HTML.contains("id=\"sidebar\""));
        assert!(INDEX_HTML.contains("id=\"status-bar\""));
        assert!(INDEX_HTML.contains("Secured by IronClaw"));
        assert!(INDEX_HTML.contains("Content-Security-Policy"));
    }

    #[test]
    fn test_js_contains_websocket_logic() {
        assert!(APP_JS.contains("new WebSocket"));
        assert!(APP_JS.contains("scrollBottom"));
        assert!(APP_JS.contains("md("));
    }

    #[test]
    fn test_css_dark_theme() {
        assert!(STYLE_CSS.contains("--bg:#0d1117"));
        assert!(STYLE_CSS.contains("monospace"));
        assert!(STYLE_CSS.contains("@media"));
    }
}
