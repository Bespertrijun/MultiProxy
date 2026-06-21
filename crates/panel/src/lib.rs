//! Panel library (Line A + Line C). Re-exports the modules so integration tests and
//! the binary share one implementation.
//!
//! Startup ordering (Line C isolation contract / pre-mortem ③): load DB → read
//! persisted `accumulated_usage_bytes` + build the initial `AvailabilitySnapshot` →
//! bind :53 on the isolated DNS runtime → start the axum management runtime.

pub mod acme;
pub mod api;
pub mod auth;
pub mod cloudflare;
pub mod configgen;
pub mod crypto;
pub mod db;
pub mod dns;
pub mod error;
pub mod scheduler;
pub mod state;
pub mod ui;
pub mod updater;
pub mod ws_server;

use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::ArcSwap;
use contract::model::DEFAULT_RESOLUTION_TTL_SECS;
use geoip::{ProviderHandle, UnknownProvider};

use crate::crypto::Vault;
use crate::dns::{spawn_dns, DnsConfig, DnsLiveness, GeoDnsHandler};
use crate::state::{AppState, CfConfig};

/// Top-level panel configuration.
#[derive(Debug, Clone)]
pub struct PanelConfig {
    /// SQLite URL (`sqlite:///path/panel.db` or `sqlite::memory:`).
    pub database_url: String,
    /// HTTP management bind address.
    pub http_bind: String,
    /// DNS bind config (port configurable so tests use a high port).
    pub dns: DnsConfig,
    /// Optional GeoCN MMDB path; when present, loaded as the geo provider.
    pub geocn_path: Option<String>,
    /// Resolution-domain TTL (Q4, default 60s).
    pub ttl_secs: u32,
    /// If true, `build()` will check for an admin user and return an error if
    /// none exists (forces the operator to run `panel init` first). Set to false
    /// in tests that seed their own admin via `db::upsert_user`.
    pub require_admin: bool,
    /// Optional Cloudflare integration config. When set, the panel auto-manages
    /// DNS records and issues ACME certificates.
    pub cf: Option<CfConfig>,
    /// Path to the encryption key file. When `None`, defaults to `panel.key`
    /// next to the SQLite DB file.
    pub key_file: Option<String>,
    /// Directory containing agent binary files served at `/dl/`.
    pub agent_bin_dir: String,
}

impl Default for PanelConfig {
    fn default() -> Self {
        Self {
            database_url: "sqlite::memory:".to_string(),
            http_bind: "0.0.0.0:8080".to_string(),
            dns: DnsConfig::default(),
            geocn_path: None,
            ttl_secs: DEFAULT_RESOLUTION_TTL_SECS,
            require_admin: false,
            cf: None,
            key_file: None,
            agent_bin_dir: "./dist".to_string(),
        }
    }
}

/// A fully-built panel: the axum app + the running DNS runtime handle + shared state.
pub struct Panel {
    pub state: AppState,
    pub router: axum::Router,
    pub dns_liveness: DnsLiveness,
    pub dns_udp_port: u16,
    pub dns_tcp_port: u16,
    /// Kept alive so the DNS runtime/thread is not dropped.
    _dns: crate::dns::runtime::DnsRuntimeHandle,
}

/// Build the panel per the startup-ordering contract. Returns the assembled
/// [`Panel`] (router not yet served — the caller binds the HTTP listener).
///
/// # Errors
/// Returns an error string on DB, provider-load, or :53 bind failure.
pub async fn build(cfg: PanelConfig) -> Result<Panel, String> {
    // 1. Load DB + migrate.
    let db = db::connect(&cfg.database_url)
        .await
        .map_err(|e| e.to_string())?;

    // Check for an admin user if required (production `serve` mode).
    if cfg.require_admin {
        let count = db::count_users(&db).await.map_err(|e| e.to_string())?;
        if count == 0 {
            return Err(
                "No admin user found. Run `panel init --admin-pass <PASSWORD>` to create one."
                    .to_string(),
            );
        }
    }

    // 1b. Load or create the encryption vault.
    let key_path = match &cfg.key_file {
        Some(p) => PathBuf::from(p),
        None => {
            // Derive from DB path: put `panel.key` next to `panel.db`.
            let db_url = &cfg.database_url;
            if db_url.contains(":memory:") {
                // In-memory DB (tests): use a deterministic test key, no file.
                // Skip file-based key; build vault directly below.
                PathBuf::new() // sentinel; handled below
            } else {
                // Strip the `sqlite://` prefix to get the file path.
                let db_path = db_url
                    .strip_prefix("sqlite://")
                    .or_else(|| db_url.strip_prefix("sqlite:"))
                    .unwrap_or(db_url);
                let db_file = PathBuf::from(db_path);
                db_file
                    .parent()
                    .unwrap_or_else(|| std::path::Path::new("."))
                    .join("panel.key")
            }
        }
    };

    let vault = if cfg.database_url.contains(":memory:") && cfg.key_file.is_none() {
        // In-memory DB without explicit key file (tests): use a fixed key.
        Arc::new(Vault::from_key(&[0x42u8; 32]))
    } else {
        Arc::new(Vault::load_or_create_key(&key_path).map_err(|e| e.to_string())?)
    };

    // 2. Geo provider (hot-reloadable). Load the GeoCN MMDB from the SAME path the
    //    online-update endpoint and `AppState` use, so a downloaded DB survives a
    //    restart (previously startup only loaded when `--geocn` was passed, silently
    //    reverting to the stub on reboot even when `./GeoCN.mmdb` existed). If the file
    //    is missing or fails to parse, fall back to the unknown stub and WARN loudly —
    //    every lookup then returns province 0 / ISP Unknown.
    let geocn_path = cfg
        .geocn_path
        .clone()
        .unwrap_or_else(|| "./GeoCN.mmdb".to_string());
    let provider = if std::path::Path::new(&geocn_path).exists() {
        match ProviderHandle::load(geoip::DbFormat::GeoCn, &geocn_path) {
            Ok(p) => {
                tracing::info!(path = %geocn_path, "GeoCN provider loaded");
                Arc::new(p)
            }
            Err(e) => {
                tracing::warn!(
                    path = %geocn_path, error = %e,
                    "GeoCN load failed; using unknown stub — every lookup returns province 0 / ISP Unknown"
                );
                Arc::new(ProviderHandle::new(Arc::new(UnknownProvider)))
            }
        }
    } else {
        tracing::warn!(
            path = %geocn_path,
            "GeoCN db not found; using unknown stub — every lookup returns province 0 / ISP Unknown. \
             Load it via the panel's online update or `panel fetch-geocn`."
        );
        Arc::new(ProviderHandle::new(Arc::new(UnknownProvider)))
    };

    // 3. Shared snapshot + groups handles (the scheduler↔resolver coupling surface).
    let snapshot = scheduler::new_snapshot_handle();
    let groups_vec = db::list_line_groups(&db).await.map_err(|e| e.to_string())?;
    let groups = Arc::new(ArcSwap::from_pointee(groups_vec));
    let zones_vec = db::list_zones(&db).await.map_err(|e| e.to_string())?;
    let zones = Arc::new(ArcSwap::from_pointee(zones_vec));

    let state = AppState::new(
        db.clone(),
        snapshot.clone(),
        provider.clone(),
        groups.clone(),
        zones.clone(),
        geocn_path,
        vault.clone(),
        cfg.agent_bin_dir.clone(),
    );

    // 3a. Seed CLI CF flags into DB (CLI wins / overwrites DB).
    let vault_ref = Some(vault.as_ref());
    if let Some(cli_cf) = &cfg.cf {
        db::set_setting(&db, "cf_token", &cli_cf.token, vault_ref)
            .await
            .map_err(|e| e.to_string())?;
        db::set_setting(&db, "cf_zone_id", &cli_cf.zone_id, vault_ref)
            .await
            .map_err(|e| e.to_string())?;
        db::set_setting(&db, "cf_domain", &cli_cf.domain, vault_ref)
            .await
            .map_err(|e| e.to_string())?;
        db::set_setting(&db, "cf_subdomain", &cli_cf.subdomain, vault_ref)
            .await
            .map_err(|e| e.to_string())?;
        db::set_setting(&db, "cf_ns_name", &cli_cf.ns_name, vault_ref)
            .await
            .map_err(|e| e.to_string())?;
        db::set_setting(&db, "cf_panel_ip", &cli_cf.panel_ip, vault_ref)
            .await
            .map_err(|e| e.to_string())?;
    }

    // 3a-1b. Auto-migrate existing plaintext secrets to encrypted form.
    for key in crypto::ENCRYPTED_KEYS {
        // Read raw value from DB (without vault decryption).
        let raw = db::get_setting(&db, key, None)
            .await
            .map_err(|e| e.to_string())?;
        if let Some(raw_val) = raw {
            if !raw_val.is_empty() {
                let (_, was_encrypted) = vault.decrypt_or_plaintext(&raw_val);
                if !was_encrypted {
                    // Plaintext detected — re-encrypt and save.
                    db::set_setting(&db, key, &raw_val, vault_ref)
                        .await
                        .map_err(|e| e.to_string())?;
                    tracing::info!(key, "migrated plaintext setting to encrypted form");
                }
            }
        }
    }

    // 3a-2. Load CF config from DB (the source of truth after seeding).
    let cf_db = db::get_cf_config(&db, vault_ref)
        .await
        .map_err(|e| e.to_string())?;
    if let Some(cf_db) = cf_db {
        // Resolve panel_ip: DB value, or auto-detect placeholder (empty means unset).
        let panel_ip = if cf_db.cf_panel_ip.is_empty() {
            // Use the CLI-provided value if we had one, otherwise leave empty
            // (the actual auto-detect happened in main.rs before building CfConfig).
            cfg.cf
                .as_ref()
                .map(|c| c.panel_ip.clone())
                .unwrap_or_default()
        } else {
            cf_db.cf_panel_ip
        };

        let cf_cfg = CfConfig {
            token: cf_db.cf_token,
            zone_id: cf_db.cf_zone_id,
            domain: cf_db.cf_domain,
            subdomain: cf_db.cf_subdomain,
            panel_ip,
            ns_name: cf_db.cf_ns_name,
            acme_staging: cfg.cf.as_ref().is_some_and(|c| c.acme_staging),
            cert_dir: cfg
                .cf
                .as_ref()
                .map_or_else(|| "./certs".to_string(), |c| c.cert_dir.clone()),
        };
        state.set_cf_config(Some(cf_cfg)).await;
    }

    // 3b. Build the initial snapshot from persisted node state (read persisted usage
    //     is implicit: classify uses node + runtime; cold-start runtimes are empty so
    //     nodes are Unhealthy until they report, which is correct fail-safe behavior).
    ws_server::rebuild_and_store_snapshot(&state).await;

    // 3c. Cloudflare DNS auto-setup + ACME cert check/issuance (optional, non-fatal).
    if let Some(cf_cfg) = state.cf_config().await {
        let cf_client = cloudflare::CfClient::new(&cf_cfg.token, &cf_cfg.zone_id);

        // Auto-setup DNS records.
        match cloudflare::auto_setup_dns(
            &cf_client,
            &cf_cfg.domain,
            &cf_cfg.subdomain,
            &cf_cfg.panel_ip,
            &cf_cfg.ns_name,
        )
        .await
        {
            Ok(records) => {
                tracing::info!(count = records.len(), "CF DNS auto-setup complete");
            }
            Err(e) => {
                tracing::warn!("CF DNS auto-setup failed (non-fatal): {e}");
            }
        }

        // Check/issue ACME cert for panel.{domain}.
        let panel_domain = format!("panel.{}", cf_cfg.domain);
        let cert_path = std::path::Path::new(&cf_cfg.cert_dir).join(format!("{panel_domain}.crt"));

        // Load existing cert into state if present.
        if let Some((cert, key)) = acme::load_cert_pair(&cf_cfg.cert_dir, &panel_domain) {
            state.set_tls_pair(cert, key).await;
            tracing::info!("loaded existing TLS cert for {panel_domain}");
        }

        if acme::needs_renewal(&cert_path) {
            tracing::info!("ACME cert for {panel_domain} needs issuance/renewal");
            match acme::issue_cert(
                &cf_client,
                &panel_domain,
                &cf_cfg.cert_dir,
                cf_cfg.acme_staging,
            )
            .await
            {
                Ok(issued) => {
                    state.set_tls_pair(issued.cert_pem, issued.key_pem).await;
                    tracing::info!("ACME cert issued for {panel_domain}");
                }
                Err(e) => {
                    tracing::warn!("ACME cert issuance failed (non-fatal): {e}");
                }
            }
        }
    }

    // 4. Bind :53 on the isolated DNS runtime.
    let handler = GeoDnsHandler::new(snapshot, provider, groups, zones, cfg.ttl_secs);
    let dns = spawn_dns(handler, cfg.dns.clone())?;
    let dns_liveness = dns.liveness.clone();
    let dns_udp_port = dns.udp_port;
    let dns_tcp_port = dns.tcp_port;

    // 5. Management router.
    let router = api::router(state.clone());

    Ok(Panel {
        state,
        router,
        dns_liveness,
        dns_udp_port,
        dns_tcp_port,
        _dns: dns,
    })
}
