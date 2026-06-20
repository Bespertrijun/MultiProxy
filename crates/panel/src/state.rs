//! Shared application state: DB pool, the snapshot/provider/groups handles shared
//! with the DNS runtime, and the live WS connection registry.

use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use arc_swap::ArcSwap;
use contract::model::{DnsZone, LineGroup};
use contract::protocol::DEFAULT_HEARTBEAT_INTERVAL_SECS;
use contract::snapshot::AvailabilitySnapshot;
use geoip::ProviderHandle;
use sqlx::SqlitePool;
use tokio::sync::mpsc;
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
}

impl AppState {
    /// Build state around an open DB pool and the shared DNS handles.
    #[must_use]
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
        }
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
