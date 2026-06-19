//! ACME DNS-01 certificate issuance using `instant-acme`.
//!
//! Orchestrates the full flow: account creation -> order -> DNS-01 challenge via
//! Cloudflare API -> validation -> finalize -> cert download -> save to disk.

use std::path::{Path, PathBuf};

use instant_acme::{
    Account, AccountCredentials, ChallengeType, Identifier, NewAccount, NewOrder, RetryPolicy,
};

use crate::cloudflare::CfClient;

/// Let's Encrypt production directory URL.
const LE_PRODUCTION: &str = "https://acme-v02.api.letsencrypt.org/directory";
/// Let's Encrypt staging directory URL.
const LE_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

/// ACME account credentials serialized to disk.
#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedCredentials {
    /// JSON-encoded account credentials from instant-acme.
    credentials_json: String,
    /// The ACME directory URL the account was registered against.
    directory: String,
}

/// Result of a successful certificate issuance.
#[derive(Debug, Clone)]
pub struct IssuedCert {
    /// Path to the certificate PEM file.
    pub cert_path: PathBuf,
    /// Path to the private key PEM file.
    pub key_path: PathBuf,
    /// Certificate PEM content.
    pub cert_pem: String,
    /// Private key PEM content.
    pub key_pem: String,
}

/// Issue (or renew) a TLS certificate for `domain` via DNS-01.
///
/// Steps:
/// 1. Load or create an ACME account (persisted to `cert_dir/account.json`).
/// 2. Create an order for the domain.
/// 3. For each DNS-01 challenge, upsert the TXT record via CF API.
/// 4. Wait for propagation, tell ACME to validate.
/// 5. Finalize (instant-acme generates key + CSR internally), download cert chain.
/// 6. Save cert + key to disk and return paths + PEM content.
pub async fn issue_cert(
    cf: &CfClient,
    domain: &str,
    cert_dir: &str,
    staging: bool,
) -> Result<IssuedCert, String> {
    let cert_dir_path = Path::new(cert_dir);
    std::fs::create_dir_all(cert_dir_path).map_err(|e| format!("create cert dir: {e}"))?;

    let directory = if staging { LE_STAGING } else { LE_PRODUCTION };

    // 1. Build the ACME account.
    let account = load_or_create_account(cert_dir_path, directory).await?;

    // 2. Create an order.
    let identifiers = vec![Identifier::Dns(domain.to_string())];
    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .map_err(|e| format!("ACME new_order: {e}"))?;

    // 3. DNS-01 challenges.
    let challenge_domain = format!("_acme-challenge.{domain}");
    {
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = result.map_err(|e| format!("ACME authorization: {e}"))?;

            if let Some(mut challenge) = authz.challenge(ChallengeType::Dns01) {
                let key_auth = challenge.key_authorization();
                let dns_value = key_auth.dns_value();

                tracing::info!(
                    domain = %challenge_domain,
                    "setting ACME DNS-01 TXT record"
                );
                cf.upsert_record("TXT", &challenge_domain, &dns_value, false, 120)
                    .await
                    .map_err(|e| format!("CF upsert TXT: {e}"))?;

                // Wait for DNS propagation.
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;

                // Tell ACME the challenge is ready.
                challenge
                    .set_ready()
                    .await
                    .map_err(|e| format!("ACME set_ready: {e}"))?;
            }
        }
    }

    // 4. Poll until the order is ready.
    let _status = order
        .poll_ready(&RetryPolicy::default())
        .await
        .map_err(|e| format!("ACME poll_ready: {e}"))?;

    // 5. Finalize -- instant-acme generates key + CSR internally via rcgen.
    let private_key_pem = order
        .finalize()
        .await
        .map_err(|e| format!("ACME finalize: {e}"))?;

    // 6. Download the certificate chain.
    let cert_pem = order
        .poll_certificate(&RetryPolicy::default())
        .await
        .map_err(|e| format!("ACME poll_certificate: {e}"))?;

    // Clean up the ACME challenge TXT record.
    if let Ok(records) = cf.list_records("TXT", &challenge_domain).await {
        for rec in records {
            let _ = cf.delete_record(&rec.id).await;
        }
    }

    // 7. Save to disk.
    let cert_path = cert_dir_path.join(format!("{domain}.crt"));
    let key_path = cert_dir_path.join(format!("{domain}.key"));
    std::fs::write(&cert_path, &cert_pem).map_err(|e| format!("write cert: {e}"))?;
    std::fs::write(&key_path, &private_key_pem).map_err(|e| format!("write key: {e}"))?;

    tracing::info!(
        cert = %cert_path.display(),
        key = %key_path.display(),
        "ACME certificate issued and saved"
    );

    Ok(IssuedCert {
        cert_path,
        key_path,
        cert_pem,
        key_pem: private_key_pem,
    })
}

/// Load existing ACME account credentials from disk, or create a new account.
async fn load_or_create_account(cert_dir: &Path, directory: &str) -> Result<Account, String> {
    let creds_path = cert_dir.join("account.json");

    // Try to load persisted credentials.
    if creds_path.exists() {
        if let Ok(data) = std::fs::read_to_string(&creds_path) {
            if let Ok(persisted) = serde_json::from_str::<PersistedCredentials>(&data) {
                if persisted.directory == directory {
                    if let Ok(creds) =
                        serde_json::from_str::<AccountCredentials>(&persisted.credentials_json)
                    {
                        let builder =
                            Account::builder().map_err(|e| format!("ACME builder: {e}"))?;
                        match builder.from_credentials(creds).await {
                            Ok(account) => {
                                tracing::info!("loaded existing ACME account");
                                return Ok(account);
                            }
                            Err(e) => {
                                tracing::warn!("failed to load ACME account, creating new: {e}");
                            }
                        }
                    }
                }
            }
        }
    }

    // Create a new account.
    let builder = Account::builder().map_err(|e| format!("ACME builder: {e}"))?;
    let (account, creds) = builder
        .create(
            &NewAccount {
                contact: &[],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            directory.to_string(),
            None,
        )
        .await
        .map_err(|e| format!("ACME create account: {e}"))?;

    // Persist credentials.
    let persisted = PersistedCredentials {
        credentials_json: serde_json::to_string(&creds)
            .map_err(|e| format!("serialize creds: {e}"))?,
        directory: directory.to_string(),
    };
    if let Ok(json) = serde_json::to_string_pretty(&persisted) {
        let _ = std::fs::write(&creds_path, json);
    }

    tracing::info!("created new ACME account");
    Ok(account)
}

/// Read a PEM certificate from disk and return its expiry (as a unix timestamp in seconds),
/// or `None` if the cert doesn't exist or can't be parsed.
pub fn cert_expiry_unix(cert_path: &Path) -> Option<i64> {
    let pem_data = std::fs::read(cert_path).ok()?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(&pem_data).ok()?;
    let (_, cert) = x509_parser::parse_x509_certificate(&pem.contents).ok()?;
    Some(cert.validity().not_after.timestamp())
}

/// Check whether the cert at the given path needs renewal (expires within 30 days,
/// or does not exist).
pub fn needs_renewal(cert_path: &Path) -> bool {
    let Some(expiry) = cert_expiry_unix(cert_path) else {
        return true; // no cert = needs issuance
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let thirty_days = 30 * 24 * 3600;
    expiry - now < thirty_days
}

/// Certificate status info for the API.
#[derive(serde::Serialize)]
pub struct CertStatus {
    pub has_cert: bool,
    pub subject: String,
    pub expires_at: String,
    pub days_remaining: i64,
}

/// Read certificate status from a PEM file on disk.
pub fn read_cert_status(cert_path: &Path) -> CertStatus {
    let default = CertStatus {
        has_cert: false,
        subject: String::new(),
        expires_at: String::new(),
        days_remaining: 0,
    };

    let Ok(pem_data) = std::fs::read(cert_path) else {
        return default;
    };
    let Ok((_, pem)) = x509_parser::pem::parse_x509_pem(&pem_data) else {
        return default;
    };
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(&pem.contents) else {
        return default;
    };

    let subject = cert.subject().to_string();
    let expiry = cert.validity().not_after.timestamp();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days_remaining = (expiry - now) / 86400;

    CertStatus {
        has_cert: true,
        subject,
        expires_at: cert.validity().not_after.to_string(),
        days_remaining,
    }
}

/// Load an existing cert+key from disk into PEM strings, if they exist.
pub fn load_cert_pair(cert_dir: &str, domain: &str) -> Option<(String, String)> {
    let cert_path = Path::new(cert_dir).join(format!("{domain}.crt"));
    let key_path = Path::new(cert_dir).join(format!("{domain}.key"));
    let cert = std::fs::read_to_string(&cert_path).ok()?;
    let key = std::fs::read_to_string(&key_path).ok()?;
    if cert.is_empty() || key.is_empty() {
        return None;
    }
    Some((cert, key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn needs_renewal_when_no_cert() {
        let path = Path::new("/tmp/nonexistent-cert-12345.crt");
        assert!(needs_renewal(path));
    }

    #[test]
    fn read_cert_status_no_file() {
        let status = read_cert_status(Path::new("/tmp/nonexistent-cert-12345.crt"));
        assert!(!status.has_cert);
        assert_eq!(status.days_remaining, 0);
    }
}
