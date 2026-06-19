//! Auth (Line A task 2 / AC-8): argon2 password hashing, login, and a session-cookie
//! middleware guarding management routes. The :53 DNS surface runs on its own runtime
//! and is never routed through axum, so it is auth-exempt by construction.

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum::extract::State;
use axum::http::{header, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::error::PanelError;
use crate::state::AppState;

/// Session cookie name.
pub const SESSION_COOKIE: &str = "panel_session";

/// Hash a plaintext password with argon2id.
///
/// # Errors
/// Returns [`PanelError::Crypto`] on hashing failure.
pub fn hash_password(password: &str) -> Result<String, PanelError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| PanelError::Crypto(e.to_string()))
}

/// Verify a plaintext password against a stored argon2 hash.
#[must_use]
pub fn verify_password(password: &str, hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// Hash an agent bearer token for at-rest storage (gap 7.6) as hex-encoded SHA-256.
///
/// Agent tokens are 122-bit-random (a v4 UUID), so a fast cryptographic hash is
/// sufficient — there is nothing to brute-force. We deliberately do NOT use argon2
/// here: verifying with argon2 on every WS `Hello` is a CPU/memory DoS amplification
/// vector on the management runtime (security MEDIUM #4). argon2 stays ONLY for
/// low-entropy `PanelUser` passwords. A DB leak still does not expose live tokens
/// (SHA-256 is preimage-resistant over a 122-bit input).
#[must_use]
pub fn hash_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    hex_encode(&digest)
}

/// Verify an agent token against its stored hex SHA-256 hash using a constant-time
/// compare (no early-exit timing leak).
#[must_use]
pub fn verify_token(token: &str, stored_hex: &str) -> bool {
    let computed = hash_token(token);
    // Constant-time over the hex strings: equal length on the happy path; a length
    // mismatch returns false without leaking via timing.
    computed.as_bytes().ct_eq(stored_hex.as_bytes()).into()
}

/// Lowercase hex-encode a byte slice (no external hex crate; keeps deps minimal).
fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Generate a fresh opaque token/session id.
#[must_use]
pub fn new_token() -> String {
    Uuid::new_v4().simple().to_string()
}

/// Extract the session cookie value from a `Cookie` header string.
#[must_use]
pub fn session_from_cookies(cookie_header: Option<&str>) -> Option<String> {
    let header = cookie_header?;
    for pair in header.split(';') {
        let pair = pair.trim();
        if let Some(val) = pair.strip_prefix(&format!("{SESSION_COOKIE}=")) {
            return Some(val.to_string());
        }
    }
    None
}

/// Axum middleware guarding management routes: requires a valid session cookie
/// resolving to a known user. Returns 401 otherwise. The DNS :53 surface is not on
/// this router, so it is exempt.
pub async fn require_session(
    State(state): State<AppState>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let cookie_header = req
        .headers()
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let token = match session_from_cookies(cookie_header.as_deref()) {
        Some(t) => t,
        None => return unauthorized(),
    };
    match crate::db::session_user(&state.db, &token).await {
        Ok(Some(_user)) => next.run(req).await,
        _ => unauthorized(),
    }
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        axum::Json(serde_json::json!({ "error": "unauthorized" })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_roundtrip() {
        let h = hash_password("s3cret").unwrap();
        assert!(verify_password("s3cret", &h));
        assert!(!verify_password("wrong", &h));
    }

    #[test]
    fn token_hash_roundtrip() {
        let t = new_token();
        let h = hash_token(&t);
        // SHA-256 hex is 64 chars; distinct from an argon2 PHC string (which the
        // password path produces) so the two hashing schemes never get confused.
        assert_eq!(h.len(), 64);
        assert!(h.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(verify_token(&t, &h));
        assert!(!verify_token("other", &h));
        // A malformed / wrong-length stored hash must not verify (constant-time false).
        assert!(!verify_token(&t, "deadbeef"));
    }

    #[test]
    fn parses_session_cookie() {
        let c = format!("foo=bar; {SESSION_COOKIE}=abc123; baz=qux");
        assert_eq!(session_from_cookies(Some(&c)), Some("abc123".to_string()));
        assert_eq!(session_from_cookies(Some("foo=bar")), None);
        assert_eq!(session_from_cookies(None), None);
    }
}
