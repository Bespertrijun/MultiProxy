//! Shared application state: DB pool, the snapshot/provider/groups handles shared
//! with the DNS runtime, and the live WS connection registry.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
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

/// Failover tunable parameters broadcast to agents in `HelloOk` on every (re)connect.
/// Seeded from env vars at startup; changing them requires a panel restart, after which
/// agents pick up the new values automatically on their next reconnect.
#[derive(Debug, Clone, Copy)]
pub struct FailoverParams {
    /// How often the agent probes each backend (seconds).
    pub probe_interval_secs: u32,
    /// Per-probe TCP connect timeout (milliseconds).
    pub probe_timeout_ms: u32,
    /// Consecutive probe failures before a backend is considered down.
    pub max_fails: u32,
    /// Consecutive successful probes required to consider a backend recovered.
    pub recovery_checks: u32,
    /// Minimum seconds a failover backend must remain active before reverting.
    pub min_dwell_secs: u32,
}

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
    /// Timezone offset (minutes east of UTC) for evaluating line-group active windows
    /// (晚高峰换组). Default 480 = UTC+8 (China, no DST). Shared with the DNS handler so
    /// resolution honors the same local time; persisted under settings key `tz_offset_min`.
    pub tz_offset_min: Arc<AtomicI64>,
    /// Live WS connections by node_id.
    pub conns: Arc<Mutex<HashMap<String, AgentConn>>>,
    /// In-memory per-node health/capacity runtime (rebuilt from reports).
    pub runtimes: Arc<Mutex<HashMap<String, NodeRuntime>>>,
    /// Server-controlled heartbeat interval (gap 7.3).
    pub heartbeat_interval_secs: u32,
    /// Failover tunable parameters delivered to agents in HelloOk (seeded from env).
    pub failover_params: FailoverParams,
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
    /// Failover kill-switch (must-fix #2, P0). When `true`, `push_config` short-circuits
    /// the version-split logic and pushes ONLY the legacy single-upstream render to every
    /// agent (no structured `rules`) — equivalent to pre-Phase-4 behavior. Default `false`,
    /// seeded from `PANEL_FAILOVER_KILLSWITCH=1`, hot-toggled via the API. Not a ConfigPush
    /// wire field; zero agent cooperation.
    pub failover_killswitch: Arc<AtomicBool>,
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
            tz_offset_min: Arc::new(AtomicI64::new(480)),
            conns: Arc::new(Mutex::new(HashMap::new())),
            runtimes: Arc::new(Mutex::new(HashMap::new())),
            heartbeat_interval_secs: DEFAULT_HEARTBEAT_INTERVAL_SECS,
            failover_params: failover_params_from_env(),
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
            // Default OFF; operator may seed it ON via env, hot-toggle via the API.
            failover_killswitch: Arc::new(AtomicBool::new(failover_killswitch_from_env())),
        }
    }

    /// Whether the failover kill-switch is currently engaged (legacy-only push mode).
    #[must_use]
    pub fn killswitch_on(&self) -> bool {
        self.failover_killswitch.load(Ordering::Relaxed)
    }

    /// Set the failover kill-switch (hot toggle). Returns the new value.
    pub fn set_killswitch(&self, on: bool) -> bool {
        self.failover_killswitch.store(on, Ordering::Relaxed);
        on
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

/// Read the failover kill-switch default from the environment. Engaged when
/// `PANEL_FAILOVER_KILLSWITCH` is set to `1`/`true`/`yes`/`on` (case-insensitive).
fn failover_killswitch_from_env() -> bool {
    std::env::var("PANEL_FAILOVER_KILLSWITCH")
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

/// Read failover tunable parameters from the environment. Each variable is optional;
/// missing or unparseable values fall back to the documented defaults (5/1000/3/6/60).
///
/// | Env var                          | Field                | Default |
/// |----------------------------------|----------------------|---------|
/// | `PANEL_PROBE_INTERVAL_SECS`      | `probe_interval_secs`| 5       |
/// | `PANEL_PROBE_TIMEOUT_MS`         | `probe_timeout_ms`   | 1000    |
/// | `PANEL_FAILOVER_MAX_FAILS`       | `max_fails`          | 3       |
/// | `PANEL_FAILOVER_RECOVERY_CHECKS` | `recovery_checks`    | 6       |
/// | `PANEL_MIN_DWELL_SECS`           | `min_dwell_secs`     | 60      |
fn failover_params_from_env() -> FailoverParams {
    fn parse_u32(var: &str, default: u32) -> u32 {
        std::env::var(var)
            .ok()
            .and_then(|v| v.trim().parse::<u32>().ok())
            .unwrap_or(default)
    }
    FailoverParams {
        probe_interval_secs: parse_u32("PANEL_PROBE_INTERVAL_SECS", 5),
        probe_timeout_ms: parse_u32("PANEL_PROBE_TIMEOUT_MS", 1000),
        max_fails: parse_u32("PANEL_FAILOVER_MAX_FAILS", 3),
        recovery_checks: parse_u32("PANEL_FAILOVER_RECOVERY_CHECKS", 6),
        min_dwell_secs: parse_u32("PANEL_MIN_DWELL_SECS", 60),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failover_params_defaults_when_env_absent() {
        // Ensure none of these vars are set in the test environment.
        // (They are not set in a standard CI/unit-test context.)
        let p = failover_params_from_env();
        assert_eq!(p.probe_interval_secs, 5);
        assert_eq!(p.probe_timeout_ms, 1000);
        assert_eq!(p.max_fails, 3);
        assert_eq!(p.recovery_checks, 6);
        assert_eq!(p.min_dwell_secs, 60);
    }
}
