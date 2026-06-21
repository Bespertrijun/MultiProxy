//! TOTP (RFC 6238) two-factor authentication helpers, compatible with standard
//! authenticator apps (Google/Microsoft Authenticator, Authy, …).
//!
//! Secrets are base32 strings; they are stored ENCRYPTED at rest (via the `Vault`)
//! by the callers in `api.rs`. This module only does crypto/codec, no persistence.

use totp_rs::{Algorithm, Secret, TOTP};

/// Issuer label shown in the authenticator app.
const ISSUER: &str = "multiProxy";
/// 6-digit codes (the app default).
const DIGITS: usize = 6;
/// Accept ±1 time-step (±30s) for client clock drift.
const SKEW: u8 = 1;
/// 30-second time step (the app default).
const STEP: u64 = 30;

/// Generate a fresh base32-encoded TOTP secret.
#[must_use]
pub fn generate_secret() -> String {
    Secret::generate_secret().to_encoded().to_string()
}

fn build(secret_b32: &str, account: &str) -> Result<TOTP, String> {
    let bytes = Secret::Encoded(secret_b32.to_string())
        .to_bytes()
        .map_err(|e| format!("bad totp secret: {e:?}"))?;
    TOTP::new(
        Algorithm::SHA1,
        DIGITS,
        SKEW,
        STEP,
        bytes,
        Some(ISSUER.to_string()),
        account.to_string(),
    )
    .map_err(|e| format!("totp build: {e}"))
}

/// The `otpauth://` provisioning URL for manual entry / linking.
///
/// # Errors
/// Returns a message if the secret is not valid base32.
pub fn provisioning_url(secret_b32: &str, account: &str) -> Result<String, String> {
    Ok(build(secret_b32, account)?.get_url())
}

/// A base64-encoded PNG QR code of the provisioning URL, for `<img src=data:...>`.
///
/// # Errors
/// Returns a message if the secret is invalid or QR rendering fails.
pub fn qr_base64(secret_b32: &str, account: &str) -> Result<String, String> {
    build(secret_b32, account)?
        .get_qr_base64()
        .map_err(|e| format!("totp qr: {e}"))
}

/// Verify a user-supplied code against the secret (honoring ±1 step skew).
/// Non-numeric / wrong-length input simply returns `false`.
#[must_use]
pub fn verify(secret_b32: &str, code: &str) -> bool {
    let Ok(totp) = build(secret_b32, "verify") else {
        return false;
    };
    totp.check_current(code.trim()).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_secret_verifies_its_own_current_code() {
        let secret = generate_secret();
        let totp = build(&secret, "alice").expect("build");
        let code = totp.generate_current().expect("gen");
        assert!(verify(&secret, &code));
        assert!(!verify(&secret, "000000"));
        assert!(!verify(&secret, "not-a-code"));
    }

    #[test]
    fn provisioning_outputs_are_well_formed() {
        let secret = generate_secret();
        let url = provisioning_url(&secret, "alice").expect("url");
        assert!(url.starts_with("otpauth://totp/"));
        assert!(url.contains("multiProxy"));
        assert!(!qr_base64(&secret, "alice").expect("qr").is_empty());
    }
}
