//! Shared application state: DB pool, the snapshot/provider/groups handles shared
//! with the DNS runtime, and the live WS connection registry.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use arc_swap::ArcSwap;
use contract::model::{DnsZone, LineGroup};
use contract::protocol::DEFAULT_HEARTBEAT_INTERVAL_SECS;
use contract::snapshot::AvailabilitySnapshot;
use geoip::ProviderHandle;
use sqlx::SqlitePool;
use tokio::sync::{broadcast, mpsc};
use tokio::sync::{Mutex, RwLock};

use crate::crypto::Vault;
use crate::scheduler::NodeRuntime;

/// A message queued to a connected agent's writer task.
pub type AgentTx = mpsc::UnboundedSender<contract::protocol::Envelope>;

/// One live agent connection's control handle.
#[derive(Clone)]
pub struct AgentConn {
    /// Unique session id for this connection (supersede detection, gap 7.1).
    pub session: String,
    /// Channel to push frames to this agent.
    pub tx: AgentTx,
}

/// Optional Cloudflare integration config (all-or-nothing).
#[derive(Debug, Clone)]
pub struct CfConfig {
    pub token: String,
    pub zone_id: String,
    pub domain: String,
    pub subdomain: String,
    pub panel_ip: String,
    pub ns_name: String,
    pub acme_staging: bool,
    pub cert_dir: String,
}

/// Cloneable axum app state.
#[derive(Clone)]
pub struct AppState {
    pub db: SqlitePool,
    /// Scheduler↔resolver coupling surface (shared with DNS).
    pub snapshot: Arc<ArcSwap<AvailabilitySnapshot>>,
    /// Hot-reloadable geo provider (shared with DNS).
    pub provider: Arc<ProviderHandle>,
    /// Current line groups (shared with DNS; swapped on CRUD).
    pub groups: Arc<ArcSwap<Vec<LineGroup>>>,
    /// Current DNS zones (shared with DNS; swapped on CRUD).
    pub zones: Arc<ArcSwap<Vec<DnsZone>>>,
    /// Monotonic snapshot generation counter.
    pub snapshot_gen: Arc<AtomicU64>,
    /// Live WS connections by node_id.
    pub conns: Arc<Mutex<HashMap<String, AgentConn>>>,
    /// In-memory per-node health/capacity runtime (rebuilt from reports).
    pub runtimes: Arc<Mutex<HashMap<String, NodeRuntime>>>,
    /// Server-controlled heartbeat interval (gap 7.3).
    pub heartbeat_interval_secs: u32,
    /// Path where GeoCN.mmdb is stored (for online update).
    pub geocn_path: String,
    /// Optional Cloudflare integration config (reloadable from DB settings).
    pub cf: Arc<RwLock<Option<CfConfig>>>,
    /// Cached TLS cert/key PEM for distribution to agents.
    pub tls_pair: Arc<RwLock<Option<(String, String)>>>,
    /// Encryption vault for sensitive settings at rest.
    pub vault: Arc<Vault>,
    /// Directory containing agent binary files served at `/dl/`.
    pub agent_bin_dir: String,
    /// Broadcast of data-change events for the UI's SSE stream (`/api/events`).
    /// Each value is a monotonic sequence number; the UI refetches on any signal.
    pub events: broadcast::Sender<u64>,
    /// Monotonic counter backing the `events` broadcast payload.
    pub event_seq: Arc<AtomicU64>,
    /// Self-served ACME DNS-01 challenges the GeoDNS answers: normalized
    /// `_acme-challenge.<zone>` (lowercase, no trailing dot) → TXT value. Used to issue
    /// certs for NS-delegated zone domains that Cloudflare can no longer validate.
    pub acme_challenges: Arc<RwLock<HashMap<String, String>>>,
    /// Issued relay TLS certs by DNS zone `apex_domain` → (cert_pem, key_pem). Distinct
    /// from `tls_pair` (the panel's own `panel.{domain}` cert).
    pub zone_certs: Arc<RwLock<HashMap<String, (String, String)>>>,
}

impl AppState {
    /// Build state around an open DB pool and the shared DNS handles.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        db: SqlitePool,
        snapshot: Arc<ArcSwap<AvailabilitySnapshot>>,
        provider: Arc<ProviderHandle>,
        groups: Arc<ArcSwap<Vec<LineGroup>>>,
        zones: Arc<ArcSwap<Vec<DnsZone>>>,
        geocn_path: String,
        vault: Arc<Vault>,
        agent_bin_dir: String,
    ) -> Self {
        Self {
            db,
            snapshot,
            provider,
            groups,
            zones,
            snapshot_gen: Arc::new(AtomicU64::new(0)),
            conns: Arc::new(Mutex::new(HashMap::new())),
            runtimes: Arc::new(Mutex::new(HashMap::new())),
            heartbeat_interval_secs: DEFAULT_HEARTBEAT_INTERVAL_SECS,
            geocn_path,
            cf: Arc::new(RwLock::new(None)),
            tls_pair: Arc::new(RwLock::new(None)),
            vault,
            agent_bin_dir,
            // Capacity 16: a slow SSE client only needs the latest signal; on lag it
            // gets a `Lagged` and refetches once, so dropped intermediate ticks are fine.
            events: broadcast::channel(16).0,
            event_seq: Arc::new(AtomicU64::new(0)),
            acme_challenges: Arc::new(RwLock::new(HashMap::new())),
            zone_certs: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Install a self-served ACME DNS-01 TXT challenge (served by the GeoDNS).
    pub async fn set_acme_challenge(&self, fqdn: String, value: String) {
        self.acme_challenges.write().await.insert(fqdn, value);
    }

    /// Remove a self-served ACME DNS-01 TXT challenge after validation.
    pub async fn clear_acme_challenge(&self, fqdn: &str) {
        self.acme_challenges.write().await.remove(fqdn);
    }

    /// Cache an issued relay cert for a zone apex domain.
    pub async fn set_zone_cert(&self, apex: String, cert: String, key: String) {
        self.zone_certs.write().await.insert(apex, (cert, key));
    }

    /// Read the cached relay cert for a zone apex domain, if any.
    pub async fn zone_cert(&self, apex: &str) -> Option<(String, String)> {
        self.zone_certs.read().await.get(apex).cloned()
    }

    /// Signal the UI that backend data changed, so connected SSE clients refetch.
    /// Cheap and lock-free; a no-op when no clients are subscribed.
    pub fn notify_change(&self) {
        let seq = self.event_seq.fetch_add(1, Ordering::Relaxed) + 1;
        let _ = self.events.send(seq);
    }

    /// Read the cached TLS cert PEM (if any).
    pub fn tls_cert_pem(&self) -> Option<String> {
        self.tls_pair
            .try_read()
            .ok()
            .and_then(|g| g.as_ref().map(|(c, _)| c.clone()))
    }

    /// Read the cached TLS key PEM (if any).
    pub fn tls_key_pem(&self) -> Option<String> {
        self.tls_pair
            .try_read()
            .ok()
            .and_then(|g| g.as_ref().map(|(_, k)| k.clone()))
    }

    /// Store a new TLS cert/key pair (called after ACME issuance).
    pub async fn set_tls_pair(&self, cert: String, key: String) {
        let mut guard = self.tls_pair.write().await;
        *guard = Some((cert, key));
    }

    /// Read a snapshot of the current CF config.
    pub async fn cf_config(&self) -> Option<CfConfig> {
        self.cf.read().await.clone()
    }

    /// Replace the CF config (called after DB settings change or startup load).
    pub async fn set_cf_config(&self, cfg: Option<CfConfig>) {
        let mut guard = self.cf.write().await;
        *guard = cfg;
    }
}
