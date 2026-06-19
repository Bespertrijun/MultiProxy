//! AES-256-GCM encryption vault for sensitive settings (cf_token, etc.).
//!
//! The encryption key is stored in a separate file (`panel.key`) next to the DB,
//! so stealing the SQLite file alone does not expose secrets.
//!
//! Ciphertext format: `base64(12-byte-random-nonce || AES-256-GCM-ciphertext-with-tag)`.
//! Each encryption uses a fresh random nonce.

use std::fs;
use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Key, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

use crate::error::{PanelError, Result};

/// Setting keys whose values are always encrypted at rest.
pub const ENCRYPTED_KEYS: &[&str] = &[
    "cf_token",
    "cf_zone_id",
    "cf_domain",
    "cf_subdomain",
    "cf_ns_name",
    "cf_panel_ip",
];

/// Returns `true` if the given setting key should be encrypted at rest.
pub fn is_encrypted_key(key: &str) -> bool {
    ENCRYPTED_KEYS.contains(&key)
}

/// AES-256-GCM encryption vault.
#[derive(Clone)]
pub struct Vault {
    cipher: Aes256Gcm,
}

impl Vault {
    /// Build a vault from a raw 32-byte key.
    #[must_use]
    pub fn from_key(key: &[u8; 32]) -> Self {
        let aes_key = Key::<Aes256Gcm>::from_slice(key);
        Self {
            cipher: Aes256Gcm::new(aes_key),
        }
    }

    /// Load an existing key file or generate a new one (with `0600` permissions).
    ///
    /// On first run the key is generated and a warning is printed. On subsequent
    /// runs the key is read from disk. Returns a fatal error if the file exists
    /// but cannot be read or has the wrong length.
    pub fn load_or_create_key(path: &Path) -> Result<Self> {
        if path.exists() {
            let bytes = fs::read(path).map_err(|e| {
                PanelError::Crypto(format!("failed to read key file {}: {e}", path.display()))
            })?;
            if bytes.len() != 32 {
                return Err(PanelError::Crypto(format!(
                    "key file {} has invalid length {} (expected 32)",
                    path.display(),
                    bytes.len()
                )));
            }
            let key: [u8; 32] = bytes.try_into().unwrap();
            Ok(Self::from_key(&key))
        } else {
            // Generate a new random 256-bit key.
            use rand::RngCore;
            let mut key = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut key);

            // Ensure parent directory exists.
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|e| {
                    PanelError::Crypto(format!(
                        "failed to create directory {}: {e}",
                        parent.display()
                    ))
                })?;
            }

            fs::write(path, key).map_err(|e| {
                PanelError::Crypto(format!("failed to write key file {}: {e}", path.display()))
            })?;

            // Set file permissions to 0600 (owner read/write only).
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let perms = fs::Permissions::from_mode(0o600);
                fs::set_permissions(path, perms).map_err(|e| {
                    PanelError::Crypto(format!(
                        "failed to set permissions on {}: {e}",
                        path.display()
                    ))
                })?;
            }

            eprintln!(
                "加密密钥已生成: {} — 请妥善备份,丢失后加密数据无法恢复",
                path.display()
            );
            Ok(Self::from_key(&key))
        }
    }

    /// Encrypt plaintext into `base64(nonce || ciphertext)`.
    pub fn encrypt(&self, plaintext: &str) -> Result<String> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|e| PanelError::Crypto(format!("encryption failed: {e}")))?;
        let mut combined = nonce.to_vec();
        combined.extend_from_slice(&ciphertext);
        Ok(B64.encode(combined))
    }

    /// Decrypt `base64(nonce || ciphertext)` back to plaintext.
    pub fn decrypt(&self, encrypted: &str) -> Result<String> {
        let combined = B64
            .decode(encrypted)
            .map_err(|e| PanelError::Crypto(format!("base64 decode failed: {e}")))?;
        if combined.len() < 13 {
            return Err(PanelError::Crypto(
                "ciphertext too short (need at least nonce + 1 byte)".into(),
            ));
        }
        let (nonce_bytes, ciphertext) = combined.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = self
            .cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| PanelError::Crypto(format!("decryption failed: {e}")))?;
        String::from_utf8(plaintext)
            .map_err(|e| PanelError::Crypto(format!("decrypted data is not valid UTF-8: {e}")))
    }

    /// Try to decrypt a value. If decryption fails, assume the value is plaintext
    /// (pre-migration). Returns `(plaintext, was_already_encrypted)`.
    pub fn decrypt_or_plaintext(&self, value: &str) -> (String, bool) {
        match self.decrypt(value) {
            Ok(decrypted) => (decrypted, true),
            Err(_) => (value.to_string(), false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_vault() -> Vault {
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        Vault::from_key(&key)
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let vault = test_vault();
        let plaintext = "my-super-secret-cf-token-abc123";
        let encrypted = vault.encrypt(plaintext).unwrap();
        // Encrypted value must NOT equal the plaintext.
        assert_ne!(encrypted, plaintext);
        // Decrypting recovers the original.
        let decrypted = vault.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn each_encryption_produces_unique_ciphertext() {
        let vault = test_vault();
        let plaintext = "same-input";
        let a = vault.encrypt(plaintext).unwrap();
        let b = vault.encrypt(plaintext).unwrap();
        // Different nonces → different ciphertexts.
        assert_ne!(a, b);
        // Both decrypt to the same plaintext.
        assert_eq!(vault.decrypt(&a).unwrap(), plaintext);
        assert_eq!(vault.decrypt(&b).unwrap(), plaintext);
    }

    #[test]
    fn decrypt_or_plaintext_handles_unencrypted() {
        let vault = test_vault();
        // A raw plaintext token that is NOT valid encrypted data should be returned as-is.
        let raw = "cf-token-plaintext-value";
        let (val, was_encrypted) = vault.decrypt_or_plaintext(raw);
        assert_eq!(val, raw);
        assert!(!was_encrypted);
    }

    #[test]
    fn decrypt_or_plaintext_handles_encrypted() {
        let vault = test_vault();
        let plaintext = "cf-token-secret";
        let encrypted = vault.encrypt(plaintext).unwrap();
        let (val, was_encrypted) = vault.decrypt_or_plaintext(&encrypted);
        assert_eq!(val, plaintext);
        assert!(was_encrypted);
    }

    #[test]
    fn is_encrypted_key_check() {
        assert!(is_encrypted_key("cf_token"));
        assert!(is_encrypted_key("cf_zone_id"));
        assert!(is_encrypted_key("cf_domain"));
        assert!(is_encrypted_key("cf_subdomain"));
        assert!(is_encrypted_key("cf_ns_name"));
        assert!(is_encrypted_key("cf_panel_ip"));
        assert!(!is_encrypted_key("some_other_key"));
    }

    #[test]
    fn load_or_create_key_roundtrip() {
        let dir = std::env::temp_dir().join(format!("panel_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let key_path = dir.join("panel.key");

        // First call: creates the key.
        let v1 = Vault::load_or_create_key(&key_path).unwrap();
        assert!(key_path.exists());

        // Second call: loads the same key.
        let v2 = Vault::load_or_create_key(&key_path).unwrap();

        // Both vaults can decrypt each other's ciphertext.
        let enc = v1.encrypt("test").unwrap();
        assert_eq!(v2.decrypt(&enc).unwrap(), "test");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
