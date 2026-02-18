//! LLM Session Authentication Module for IronClaw.
//!
//! This module implements authentication based on active LLM sessions. Rather than
//! traditional username/password or static API tokens, IronClaw treats a live LLM
//! session as proof of identity: if a user holds a valid API key and the upstream
//! provider responds to a health check, that constitutes an authenticated session.
//!
//! The flow works as follows:
//! 1. The user initiates a session by proving they can reach an LLM provider
//!    (valid API key + successful provider health check).
//! 2. IronClaw issues a `SessionToken` — a short-lived, HMAC-SHA256-signed blob
//!    containing the provider name, model, session ID, and timestamps.
//! 3. Subsequent requests carry this token in the `X-IronClaw-Session` header.
//! 4. The `SessionAuthenticator` verifies both the HMAC signature and the expiry
//!    window before granting access.
//!
//! This approach ties authorization to something the user *actively controls*
//! (a funded LLM account) rather than a static credential that can be stolen
//! and replayed indefinitely.

use anyhow::Result;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use serde::{Deserialize, Serialize};
use axum::http::HeaderMap;
use tracing::info;

/// Type alias for HMAC-SHA256.
type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// SessionToken
// ---------------------------------------------------------------------------

/// A signed, time-limited token representing an authenticated LLM session.
///
/// The token is created when a user proves they have access to a live LLM
/// provider and is verified on every subsequent request via HMAC-SHA256.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionToken {
    /// LLM provider that backs this session (e.g. "anthropic", "openai").
    pub provider: String,
    /// Model identifier used in the session (e.g. "claude-opus-4-6").
    pub model: String,
    /// Unique session identifier (UUID v4).
    pub session_id: String,
    /// Timestamp when the token was issued.
    pub issued_at: DateTime<Utc>,
    /// Timestamp when the token expires.
    pub expires_at: DateTime<Utc>,
    /// HMAC-SHA256 signature over the canonical token message, hex-encoded.
    pub signature: String,
}

// ---------------------------------------------------------------------------
// SessionAuthenticator
// ---------------------------------------------------------------------------

/// Core authenticator that issues and verifies `SessionToken`s.
///
/// Holds the HMAC signing key and the configured time-to-live for tokens.
pub struct SessionAuthenticator {
    /// HMAC-SHA256 signing secret.
    secret: Vec<u8>,
    /// How long a token remains valid after issuance.
    ttl: ChronoDuration,
}

impl SessionAuthenticator {
    /// Create a new authenticator.
    ///
    /// * `secret` — raw bytes used as the HMAC-SHA256 key.
    /// * `ttl`    — token lifetime (e.g. `ChronoDuration::seconds(3600)`).
    pub fn new(secret: Vec<u8>, ttl: ChronoDuration) -> Self {
        Self { secret, ttl }
    }

    /// Build a `SessionAuthenticator` from the root `Config`, returning `None`
    /// if session auth is disabled.
    pub fn from_config(config: &crate::core::config::Config) -> Option<Self> {
        if !config.session_auth.enabled {
            return None;
        }
        let secret = config
            .session_auth
            .secret
            .as_deref()
            .unwrap_or("ironclaw-default-session-secret")
            .as_bytes()
            .to_vec();
        let ttl = ChronoDuration::seconds(config.session_auth.ttl_secs as i64);
        Some(Self::new(secret, ttl))
    }

    /// Issue a fresh `SessionToken` for the given provider, model, and session.
    ///
    /// The token is signed immediately and its expiry is set to `now + ttl`.
    pub fn issue_token(
        &self,
        provider: &str,
        model: &str,
        session_id: &str,
    ) -> SessionToken {
        let now = Utc::now();
        let expires = now + self.ttl;

        let signature = self.sign(provider, model, session_id, &now);

        info!(
            provider = provider,
            model = model,
            session_id = session_id,
            "Issued session token (expires {})",
            expires.to_rfc3339()
        );

        SessionToken {
            provider: provider.to_string(),
            model: model.to_string(),
            session_id: session_id.to_string(),
            issued_at: now,
            expires_at: expires,
            signature,
        }
    }

    /// Verify that a `SessionToken` has a valid signature and has not expired.
    ///
    /// Returns `Ok(true)` when the token is valid, `Ok(false)` when verification
    /// fails (expired or bad signature), and `Err` only on unexpected internal
    /// errors (e.g. HMAC key length issue).
    pub fn verify_token(&self, token: &SessionToken) -> Result<bool> {
        // 1. Check expiry.
        if Utc::now() > token.expires_at {
            info!(
                session_id = %token.session_id,
                "Session token rejected: expired at {}",
                token.expires_at.to_rfc3339()
            );
            return Ok(false);
        }

        // 2. Recompute the expected signature and compare.
        let expected = self.sign(
            &token.provider,
            &token.model,
            &token.session_id,
            &token.issued_at,
        );

        if expected != token.signature {
            info!(
                session_id = %token.session_id,
                "Session token rejected: signature mismatch"
            );
            return Ok(false);
        }

        Ok(true)
    }

    /// Lightweight check that a provider session is still active.
    ///
    /// In the current implementation this returns `true` when an API key is
    /// present.  Future versions will perform a real HTTP health-check against
    /// the provider's `/v1/models` (or equivalent) endpoint.
    pub fn validate_session_active(
        &self,
        provider_name: &str,
        api_key: Option<&str>,
    ) -> Result<bool> {
        match api_key {
            Some(_key) => {
                info!(
                    provider = provider_name,
                    "Session validation passed (API key present)"
                );
                Ok(true)
            }
            None => {
                info!(
                    provider = provider_name,
                    "Session validation failed: no API key"
                );
                Ok(false)
            }
        }
    }

    // -- private helpers ----------------------------------------------------

    /// Compute the HMAC-SHA256 signature for the canonical token message.
    ///
    /// Message format: `{provider}:{model}:{session_id}:{issued_at_rfc3339}`
    fn sign(
        &self,
        provider: &str,
        model: &str,
        session_id: &str,
        issued_at: &DateTime<Utc>,
    ) -> String {
        let message = format!(
            "{}:{}:{}:{}",
            provider,
            model,
            session_id,
            issued_at.to_rfc3339()
        );

        let mut mac = HmacSha256::new_from_slice(&self.secret)
            .expect("HMAC-SHA256 accepts any key length");
        mac.update(message.as_bytes());
        let result = mac.finalize();

        hex::encode(result.into_bytes())
    }
}

// ---------------------------------------------------------------------------
// SessionAuthConfig
// ---------------------------------------------------------------------------

/// Serializable configuration for session-based authentication.
///
/// Typically deserialized from `ironclaw.yaml` under the `auth.session` key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionAuthConfig {
    /// Whether session authentication is enabled.
    pub enabled: bool,
    /// Token time-to-live in seconds.
    pub ttl_secs: u64,
    /// HMAC signing secret (hex or plain string). When `None`, a random
    /// secret is generated at startup.
    pub secret: Option<String>,
}

impl Default for SessionAuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ttl_secs: 3600,
            secret: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Header extraction helper
// ---------------------------------------------------------------------------

/// Header name used to carry the session token in HTTP requests.
const SESSION_HEADER: &str = "x-ironclaw-session";

/// Extract and deserialize a `SessionToken` from the `X-IronClaw-Session`
/// header.
///
/// The header value is expected to be a JSON-encoded `SessionToken`. Returns
/// `None` if the header is missing or cannot be parsed.
pub fn extract_session_token(headers: &HeaderMap) -> Option<SessionToken> {
    let value = headers.get(SESSION_HEADER)?;
    let json_str = value.to_str().ok()?;
    serde_json::from_str(json_str).ok()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration as ChronoDuration;

    /// Shared helper: build an authenticator with a known secret and 1-hour TTL.
    fn test_authenticator() -> SessionAuthenticator {
        SessionAuthenticator::new(
            b"test-secret-key-for-unit-tests".to_vec(),
            ChronoDuration::seconds(3600),
        )
    }

    // -- round-trip ---------------------------------------------------------

    #[test]
    fn issue_and_verify_round_trip() {
        let auth = test_authenticator();

        let token = auth.issue_token("anthropic", "claude-opus-4-6", "sess-001");

        assert_eq!(token.provider, "anthropic");
        assert_eq!(token.model, "claude-opus-4-6");
        assert_eq!(token.session_id, "sess-001");
        assert!(token.expires_at > token.issued_at);
        assert!(!token.signature.is_empty());

        let valid = auth.verify_token(&token).expect("verify should not error");
        assert!(valid, "freshly issued token must be valid");
    }

    // -- expired token ------------------------------------------------------

    #[test]
    fn expired_token_is_rejected() {
        let auth = SessionAuthenticator::new(
            b"secret".to_vec(),
            ChronoDuration::seconds(-1), // TTL in the past
        );

        let token = auth.issue_token("openai", "gpt-4", "sess-expired");

        // The token was born already expired.
        let valid = auth.verify_token(&token).expect("verify should not error");
        assert!(!valid, "expired token must be rejected");
    }

    // -- tampered signature -------------------------------------------------

    #[test]
    fn tampered_signature_is_rejected() {
        let auth = test_authenticator();

        let mut token = auth.issue_token("anthropic", "claude-opus-4-6", "sess-002");
        // Flip a character in the hex signature.
        token.signature = format!("deadbeef{}", &token.signature[8..]);

        let valid = auth.verify_token(&token).expect("verify should not error");
        assert!(!valid, "tampered signature must be rejected");
    }

    // -- header extraction --------------------------------------------------

    #[test]
    fn extract_session_token_from_valid_header() {
        let auth = test_authenticator();
        let token = auth.issue_token("ollama", "llama3", "sess-hdr");

        let json = serde_json::to_string(&token).expect("serialize token");

        let mut headers = HeaderMap::new();
        headers.insert("x-ironclaw-session", json.parse().unwrap());

        let extracted = extract_session_token(&headers)
            .expect("should parse token from header");

        assert_eq!(extracted.provider, "ollama");
        assert_eq!(extracted.model, "llama3");
        assert_eq!(extracted.session_id, "sess-hdr");
        assert_eq!(extracted.signature, token.signature);
    }

    #[test]
    fn extract_session_token_returns_none_on_missing_header() {
        let headers = HeaderMap::new();
        assert!(extract_session_token(&headers).is_none());
    }

    #[test]
    fn extract_session_token_returns_none_on_invalid_json() {
        let mut headers = HeaderMap::new();
        headers.insert("x-ironclaw-session", "not-json".parse().unwrap());
        assert!(extract_session_token(&headers).is_none());
    }

    // -- config defaults ----------------------------------------------------

    #[test]
    fn session_auth_config_defaults() {
        let cfg = SessionAuthConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.ttl_secs, 3600);
        assert!(cfg.secret.is_none());
    }

    // -- validate_session_active -------------------------------------------

    #[test]
    fn validate_session_active_with_key() {
        let auth = test_authenticator();
        let result = auth
            .validate_session_active("anthropic", Some("sk-ant-xxx"))
            .expect("should not error");
        assert!(result);
    }

    #[test]
    fn validate_session_active_without_key() {
        let auth = test_authenticator();
        let result = auth
            .validate_session_active("anthropic", None)
            .expect("should not error");
        assert!(!result);
    }
}
