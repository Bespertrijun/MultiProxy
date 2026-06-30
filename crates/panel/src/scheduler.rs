//! Health + capacity scheduler (Line A task 6 / 6b).
//!
//! Combines control-channel freshness (window = `2 × heartbeat + slack`) + agent
//! self-report → classifies each node into an [`ExclusionClass`] → builds an
//! [`AvailabilitySnapshot`] via the canonical [`select_available`] (two-tier
//! fallback, Rec#1) → `ArcSwap::store`. Also the capacity engine: reset-aware
//! `counter_epoch` delta accumulation (equality-only, Rec#3), persist-on-every-report
//! (Rec#2), soft(90%)/hard(100%) quota classification, saturation debounce
//! (85%/3win enter, 70%/3win exit), and `quota_reset_day` rollover.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use contract::model::{AvailabilityState, FrontNode, LineGroup, NodeStatus, SaturationState};
use contract::protocol::{ActiveBackend, BackendHealth, Capacity, StatusReport};
use contract::snapshot::{
    select_available, AvailabilitySnapshot, ExclusionClass, LineAvailability, NodeClassification,
};

use crate::db::CapacityState;

/// Freshness slack added on top of `2 × heartbeat_interval` (gap 7.3).
pub const FRESHNESS_SLACK_SECS: u64 = 5;

/// Saturation debounce defaults (rev3 §D / Q10).
pub const SAT_ENTER_PCT: u8 = 85;
pub const SAT_EXIT_PCT: u8 = 70;
pub const SAT_WINDOWS: u8 = 3;

/// Live, per-node observed state the scheduler tracks in memory between reports.
#[derive(Debug, Clone, Default)]
pub struct NodeRuntime {
    /// Last time (unix-millis) a heartbeat/report arrived (control-channel freshness).
    pub last_contact_ms: u64,
    /// Whether the agent currently reports its forwarding+backend up.
    pub forwarding_up: bool,
    pub backend_reachable: bool,
    /// Whether the control channel is currently considered connected.
    pub connected: bool,
    /// Capacity accounting state (mirrors persisted columns).
    pub capacity: CapacityState,
    pub throughput_bps: u64,
    pub saturation: SaturationState,
    /// Consecutive-window counters for saturation debounce hysteresis.
    pub sat_enter_windows: u8,
    pub sat_exit_windows: u8,
    /// Last-reported per-backend probe results (observability only — the DNS gate still
    /// reads `backend_reachable`, the any-up anchor). Overwritten on every report; a
    /// report without this field clears it (no carry-over of stale data).
    pub backend_health: Vec<BackendHealth>,
    /// Last-reported active backend per rule (observability only). Overwrite semantics
    /// identical to `backend_health`.
    pub active_backends: Vec<ActiveBackend>,
    /// Background-resolved address for a node whose `public_ip` is a DDNS *hostname*
    /// rather than an IP literal: `(hostname_it_was_resolved_from, resolved_ip)`.
    /// Populated out-of-band by the `ddns` refresh task so the hot snapshot path never
    /// blocks on a DNS lookup. `None` until the name first resolves. The hostname is kept
    /// alongside the IP so a *changed* `public_ip` can never be served a stale cache from
    /// the old name — `build_snapshot` uses it only when the cached hostname still equals
    /// the node's current `public_ip`. Not persisted — re-resolved on panel restart.
    pub resolved: Option<(String, IpAddr)>,
}

/// Compute the freshness window for a heartbeat interval: `2*interval + slack`.
#[must_use]
pub fn freshness_window_secs(heartbeat_interval_secs: u32) -> u64 {
    2 * u64::from(heartbeat_interval_secs) + FRESHNESS_SLACK_SECS
}

/// Outcome of ingesting a capacity report: the new accounting state + derived runtime.
#[derive(Debug, Clone)]
pub struct CapacityOutcome {
    pub state: CapacityState,
    pub throughput_bps: u64,
    pub saturation: SaturationState,
    /// Whether a counter-epoch reset (or non-monotonic drop) was detected this report.
    pub reset_detected: bool,
}

/// Apply one [`Capacity`] report to the prior [`CapacityState`] using reset-aware
/// delta accumulation (rev3 §A / Rec#3).
///
/// Reset detection is **equality-only** on `counter_epoch` (`epoch != last_epoch`),
/// never an ordering comparison — robust to a reinstalled agent picking a lower or
/// random epoch. A non-monotonic counter drop within the same epoch is also treated
/// as a reset (NIC wrap / counter restart). Only positive deltas accumulate; usage
/// can only ever under-count, never over-count (fail-safe toward availability).
#[must_use]
pub fn apply_capacity(
    prior: &CapacityState,
    saturation_in: SaturationState,
    sat_enter_windows: &mut u8,
    sat_exit_windows: &mut u8,
    bandwidth_cap_mbps: Option<u32>,
    cap: &Capacity,
    direction: contract::model::QuotaDirection,
) -> CapacityOutcome {
    let mut state = prior.clone();
    let mut reset_detected = false;

    let epoch_changed = !prior.has_counter_baseline || cap.counter_epoch != prior.counter_epoch;
    if epoch_changed {
        // New epoch (or first ever report): establish baseline, accumulate nothing now.
        reset_detected = prior.has_counter_baseline;
        state.counter_epoch = cap.counter_epoch;
        state.last_tx_bytes_total = cap.tx_bytes_total;
        state.last_rx_bytes_total = cap.rx_bytes_total;
        state.has_counter_baseline = true;
    } else {
        // Same epoch: accumulate positive deltas only; a drop = within-epoch reset.
        let tx_delta = cap.tx_bytes_total.checked_sub(prior.last_tx_bytes_total);
        let rx_delta = cap.rx_bytes_total.checked_sub(prior.last_rx_bytes_total);
        match (tx_delta, rx_delta) {
            (Some(tx), Some(rx)) => {
                let delta = match direction {
                    contract::model::QuotaDirection::Both => tx.saturating_add(rx),
                    contract::model::QuotaDirection::TxOnly => tx,
                    contract::model::QuotaDirection::RxOnly => rx,
                };
                state.accumulated_usage_bytes = state.accumulated_usage_bytes.saturating_add(delta);
                state.last_tx_bytes_total = cap.tx_bytes_total;
                state.last_rx_bytes_total = cap.rx_bytes_total;
            }
            _ => {
                // Non-monotonic drop → counter reset within the same epoch; re-baseline.
                reset_detected = true;
                state.last_tx_bytes_total = cap.tx_bytes_total;
                state.last_rx_bytes_total = cap.rx_bytes_total;
            }
        }
    }

    // Saturation debounce hysteresis (rev3 §D).
    let saturation = debounce_saturation(
        saturation_in,
        cap.throughput_bps,
        bandwidth_cap_mbps,
        sat_enter_windows,
        sat_exit_windows,
    );

    CapacityOutcome {
        state,
        throughput_bps: cap.throughput_bps,
        saturation,
        reset_detected,
    }
}

/// Saturation debounce state machine (rev3 §D / Scenario ⑤). Enter after
/// [`SAT_WINDOWS`] consecutive windows ≥ [`SAT_ENTER_PCT`]; exit after
/// [`SAT_WINDOWS`] consecutive windows < [`SAT_EXIT_PCT`]. Returns the new state.
#[must_use]
pub fn debounce_saturation(
    current: SaturationState,
    throughput_bps: u64,
    bandwidth_cap_mbps: Option<u32>,
    enter_windows: &mut u8,
    exit_windows: &mut u8,
) -> SaturationState {
    let Some(cap_mbps) = bandwidth_cap_mbps else {
        // No bandwidth cap configured → saturation tracking disabled.
        *enter_windows = 0;
        *exit_windows = 0;
        return SaturationState::Normal;
    };
    let cap_bps = u64::from(cap_mbps) * 1_000_000 / 8; // Mbps → bytes/sec
    if cap_bps == 0 {
        return SaturationState::Normal;
    }
    let pct = (throughput_bps.saturating_mul(100) / cap_bps).min(255) as u8;

    match current {
        SaturationState::Normal => {
            if pct >= SAT_ENTER_PCT {
                *enter_windows = enter_windows.saturating_add(1);
            } else {
                *enter_windows = 0;
            }
            *exit_windows = 0;
            if *enter_windows >= SAT_WINDOWS {
                *enter_windows = 0;
                SaturationState::Saturated
            } else {
                SaturationState::Normal
            }
        }
        SaturationState::Saturated => {
            if pct < SAT_EXIT_PCT {
                *exit_windows = exit_windows.saturating_add(1);
            } else {
                *exit_windows = 0;
            }
            *enter_windows = 0;
            if *exit_windows >= SAT_WINDOWS {
                *exit_windows = 0;
                SaturationState::Normal
            } else {
                SaturationState::Saturated
            }
        }
    }
}

/// The specific reason a node is in its current availability state (observability /
/// UI). Finer-grained than [`ExclusionClass`]: it splits the "unhealthy" bucket into
/// its sub-causes (offline / forwarding-down / backend-unreachable) so the panel can
/// show *why* a node is excluded, not merely that it is. Serialized as snake_case for
/// the health API (mapped to a human label in the frontend).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthReason {
    /// Available — included in DNS answers.
    Ok,
    /// Control channel not fresh (agent disconnected or heartbeats stale).
    Offline,
    /// Connected but the agent reports its forwarding process is not running.
    ForwardingDown,
    /// Connected and forwarding up, but the agent cannot reach its backend.
    BackendUnreachable,
    /// Traffic usage at/over the hard-quota threshold (hard exclusion).
    QuotaHard,
    /// Traffic usage at/over the soft-quota threshold (soft exclusion).
    QuotaSoft,
    /// Bandwidth saturated (soft exclusion).
    Saturated,
}

impl HealthReason {
    /// The [`ExclusionClass`] this reason maps to (the snapshot's two-tier taxonomy).
    #[must_use]
    pub fn exclusion_class(self) -> ExclusionClass {
        match self {
            HealthReason::Ok => ExclusionClass::Included,
            HealthReason::Offline
            | HealthReason::ForwardingDown
            | HealthReason::BackendUnreachable => ExclusionClass::Unhealthy,
            HealthReason::QuotaHard => ExclusionClass::HardQuota,
            HealthReason::QuotaSoft => ExclusionClass::SoftQuota,
            HealthReason::Saturated => ExclusionClass::Saturated,
        }
    }
}

/// Diagnose a single node's [`HealthReason`] from health + capacity inputs. Order of
/// precedence (highest first): offline > forwarding-down > backend-unreachable >
/// hard-quota > soft-quota > saturated > ok. This is the single source of truth that
/// [`classify_node`] derives its [`ExclusionClass`] from.
#[must_use]
pub fn health_reason(
    node: &FrontNode,
    rt: &NodeRuntime,
    now_ms: u64,
    heartbeat_interval: u32,
) -> HealthReason {
    // Health: control-channel fresh AND agent reports forwarding+backend up.
    let window_ms = freshness_window_secs(heartbeat_interval) * 1000;
    let fresh = rt.connected && now_ms.saturating_sub(rt.last_contact_ms) <= window_ms;
    if !fresh {
        return HealthReason::Offline;
    }
    if !rt.forwarding_up {
        return HealthReason::ForwardingDown;
    }
    if !rt.backend_reachable {
        return HealthReason::BackendUnreachable;
    }

    // Quota: hard exclusion at hard%, soft exclusion at soft%.
    if let (Some(quota), pct_hard, pct_soft) = (
        node.traffic_quota_bytes,
        node.hard_quota_pct,
        node.soft_quota_pct,
    ) {
        if quota > 0 {
            let used = rt.capacity.accumulated_usage_bytes;
            let hard_threshold = quota.saturating_mul(u64::from(pct_hard)) / 100;
            let soft_threshold = quota.saturating_mul(u64::from(pct_soft)) / 100;
            if used >= hard_threshold {
                return HealthReason::QuotaHard;
            }
            if used >= soft_threshold {
                return HealthReason::QuotaSoft;
            }
        }
    }

    // Saturation (soft exclusion).
    if rt.saturation == SaturationState::Saturated {
        return HealthReason::Saturated;
    }

    HealthReason::Ok
}

/// Classify a single node into its [`ExclusionClass`] from health + capacity inputs
/// (the two-tier taxonomy; Line-0 task 5). Order of precedence:
/// unhealthy/hard-quota (hard) > soft-quota/saturated (soft) > included. Thin wrapper
/// over [`health_reason`] so the policy lives in exactly one place.
#[must_use]
pub fn classify_node(
    node: &FrontNode,
    rt: &NodeRuntime,
    now_ms: u64,
    heartbeat_interval: u32,
) -> ExclusionClass {
    health_reason(node, rt, now_ms, heartbeat_interval).exclusion_class()
}

/// Map an [`ExclusionClass`] to the persisted [`AvailabilityState`] (observability).
#[must_use]
pub fn availability_state_for(class: ExclusionClass) -> AvailabilityState {
    if class.is_included() {
        AvailabilityState::Available
    } else if class.is_soft() {
        AvailabilityState::SoftExcluded
    } else {
        AvailabilityState::HardExcluded
    }
}

/// Build an [`AvailabilitySnapshot`] from the current nodes, their runtime, and the
/// line groups. Each line's `available` set is two-tier-resolved via
/// [`select_available`]; the per-node classification rides along for observability.
#[must_use]
pub fn build_snapshot(
    nodes: &HashMap<String, FrontNode>,
    runtimes: &HashMap<String, NodeRuntime>,
    groups: &[LineGroup],
    generation: u64,
    now_ms: u64,
    heartbeat_interval: u32,
) -> AvailabilitySnapshot {
    let mut lines = HashMap::new();
    for g in groups {
        let mut classified: Vec<(IpAddr, ExclusionClass)> = Vec::new();
        for node_id in &g.member_node_ids {
            let Some(node) = nodes.get(node_id) else {
                continue;
            };
            let rt = runtimes.get(node_id).cloned().unwrap_or_default();
            // An IP-literal `public_ip` is used directly. Otherwise the address is a
            // DDNS hostname: serve the IP the background `ddns` task resolved, but ONLY
            // if it was resolved from the node's *current* hostname (a changed address
            // must never be served the previous name's cache). Skip the node until it has
            // resolved at least once (fail-safe toward exclusion — a never-resolving /
            // bogus address drops the node, it never SERVFAILs).
            let resolved_ip = || {
                rt.resolved
                    .as_ref()
                    .filter(|(host, _)| *host == node.public_ip)
                    .map(|(_, ip)| *ip)
            };
            let Some(ip) = node.public_ip.parse::<IpAddr>().ok().or_else(resolved_ip) else {
                continue;
            };
            let class = classify_node(node, &rt, now_ms, heartbeat_interval);
            classified.push((ip, class));
        }
        let available = select_available(&classified);
        let line = LineAvailability {
            available,
            fallback_group: g.fallback_group.clone(),
            classified: classified
                .into_iter()
                .map(|(ip, class)| NodeClassification { ip, class })
                .collect(),
        };
        lines.insert(g.id.clone(), line);
    }
    AvailabilitySnapshot {
        generation,
        built_at: now_ms,
        lines,
    }
}

/// Whether the calendar day-of-month equals a node's `quota_reset_day` (rollover).
#[must_use]
pub fn is_quota_reset_day(quota_reset_day: Option<u8>, day_of_month: u8) -> bool {
    quota_reset_day.is_some_and(|d| d == day_of_month)
}

/// Update a node's in-memory health runtime from a fresh `StatusReport`.
pub fn apply_status_report(rt: &mut NodeRuntime, report: &StatusReport, now_ms: u64) {
    rt.last_contact_ms = now_ms;
    rt.connected = true;
    rt.forwarding_up = report.forwarding_up;
    rt.backend_reachable = report.backend_reachable;
    // Overwrite per-backend telemetry on EVERY report: `None` → clear (do not retain the
    // previous report's list). Observability only; the DNS gate still reads
    // `backend_reachable` (the any-up anchor is untouched).
    rt.backend_health = report.backend_health.clone().unwrap_or_default();
    rt.active_backends = report.active_backends.clone().unwrap_or_default();
}

/// Shared, atomically-swappable snapshot handle (the scheduler↔resolver coupling
/// surface, MAJOR-5). The scheduler stores; the DNS resolver loads lock-free.
pub type SnapshotHandle = Arc<ArcSwap<AvailabilitySnapshot>>;

/// Build a fresh snapshot handle initialized to an empty snapshot.
#[must_use]
pub fn new_snapshot_handle() -> SnapshotHandle {
    Arc::new(ArcSwap::from_pointee(AvailabilitySnapshot::default()))
}

/// Convenience: classify all nodes and persist `NodeStatus` online/offline back onto
/// the node records (used by the API/UI health view, AC-5). Pure — returns the
/// updated status, the caller persists.
// wired in M2 (AC-5): no caller in M1; kept as scaffolding for the persisted
// NodeStatus write-back path.
#[must_use]
pub fn node_status_from_runtime(
    rt: &NodeRuntime,
    now_ms: u64,
    heartbeat_interval: u32,
) -> NodeStatus {
    let window_ms = freshness_window_secs(heartbeat_interval) * 1000;
    if rt.connected && now_ms.saturating_sub(rt.last_contact_ms) <= window_ms {
        NodeStatus::Online
    } else {
        NodeStatus::Offline
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use contract::isp::Isp;
    use contract::model::{QuotaDirection, Region};
    use contract::protocol::CapacitySource;
    use std::net::Ipv4Addr;

    fn node(id: &str, ip: &str, quota: Option<u64>) -> FrontNode {
        FrontNode {
            id: id.into(),
            name: id.into(),
            public_ip: ip.into(),
            region: Region::unknown(),
            isp: Isp::Unknown,
            status: NodeStatus::Unknown,
            last_seen: 0,
            desired_config_gen: 0,
            applied_config_gen: 0,
            bandwidth_cap_mbps: Some(100),
            traffic_quota_bytes: quota,
            quota_direction: QuotaDirection::Both,
            quota_reset_day: Some(1),
            soft_quota_pct: 90,
            hard_quota_pct: 100,
            accumulated_usage_bytes: 0,
            current_throughput_bps: 0,
            saturation_state: SaturationState::Normal,
            availability_state: AvailabilityState::Available,
        }
    }

    fn healthy_rt(now: u64) -> NodeRuntime {
        NodeRuntime {
            last_contact_ms: now,
            forwarding_up: true,
            backend_reachable: true,
            connected: true,
            ..Default::default()
        }
    }

    fn cap(epoch: u64, tx: u64, rx: u64, bps: u64) -> Capacity {
        Capacity {
            counter_epoch: epoch,
            source: CapacitySource::ForwardBytes,
            tx_bytes_total: tx,
            rx_bytes_total: rx,
            throughput_bps: bps,
        }
    }

    #[test]
    fn freshness_window_math() {
        assert_eq!(freshness_window_secs(20), 45);
    }

    #[test]
    fn first_report_baselines_no_accumulation() {
        let prior = CapacityState::default();
        let (mut e, mut x) = (0, 0);
        let out = apply_capacity(
            &prior,
            SaturationState::Normal,
            &mut e,
            &mut x,
            Some(100),
            &cap(1, 1000, 2000, 0),
            QuotaDirection::Both,
        );
        assert_eq!(out.state.accumulated_usage_bytes, 0);
        assert!(out.state.has_counter_baseline);
        assert!(!out.reset_detected);
    }

    #[test]
    fn same_epoch_accumulates_positive_delta() {
        let mut prior = CapacityState::default();
        let (mut e, mut x) = (0, 0);
        prior = apply_capacity(
            &prior,
            SaturationState::Normal,
            &mut e,
            &mut x,
            Some(100),
            &cap(1, 1000, 2000, 0),
            QuotaDirection::Both,
        )
        .state;
        let out = apply_capacity(
            &prior,
            SaturationState::Normal,
            &mut e,
            &mut x,
            Some(100),
            &cap(1, 1500, 2200, 0),
            QuotaDirection::Both,
        );
        // delta tx=500 + rx=200 = 700
        assert_eq!(out.state.accumulated_usage_bytes, 700);
        assert!(!out.reset_detected);
    }

    #[test]
    fn epoch_change_to_lower_value_is_reset_no_double_count() {
        // Rec#3: a reinstalled agent picks a LOWER/random epoch — equality-only.
        let mut prior = CapacityState::default();
        let (mut e, mut x) = (0, 0);
        prior = apply_capacity(
            &prior,
            SaturationState::Normal,
            &mut e,
            &mut x,
            Some(100),
            &cap(50, 9000, 1000, 0),
            QuotaDirection::Both,
        )
        .state;
        prior = apply_capacity(
            &prior,
            SaturationState::Normal,
            &mut e,
            &mut x,
            Some(100),
            &cap(50, 9500, 1000, 0),
            QuotaDirection::Both,
        )
        .state;
        assert_eq!(prior.accumulated_usage_bytes, 500);
        // Agent reinstalled → epoch drops to 3, counters reset to small values.
        let out = apply_capacity(
            &prior,
            SaturationState::Normal,
            &mut e,
            &mut x,
            Some(100),
            &cap(3, 10, 20, 0),
            QuotaDirection::Both,
        );
        assert!(out.reset_detected);
        // No double-count, no negative: accumulation unchanged (re-baselined).
        assert_eq!(out.state.accumulated_usage_bytes, 500);
        assert_eq!(out.state.counter_epoch, 3);
    }

    #[test]
    fn within_epoch_counter_drop_is_reset() {
        let mut prior = CapacityState::default();
        let (mut e, mut x) = (0, 0);
        prior = apply_capacity(
            &prior,
            SaturationState::Normal,
            &mut e,
            &mut x,
            Some(100),
            &cap(1, 1000, 1000, 0),
            QuotaDirection::Both,
        )
        .state;
        let out = apply_capacity(
            &prior,
            SaturationState::Normal,
            &mut e,
            &mut x,
            Some(100),
            &cap(1, 10, 10, 0),
            QuotaDirection::Both,
        );
        assert!(out.reset_detected);
        assert_eq!(out.state.accumulated_usage_bytes, 0);
    }

    #[test]
    fn saturation_debounce_enter_and_exit() {
        let cap_mbps = Some(100); // 100 Mbps = 12_500_000 B/s
        let high = 11_000_000; // 88%
        let low = 7_000_000; // 56%
        let (mut e, mut x) = (0u8, 0u8);
        let mut state = SaturationState::Normal;
        // 2 windows high → still Normal (debounce).
        state = debounce_saturation(state, high, cap_mbps, &mut e, &mut x);
        state = debounce_saturation(state, high, cap_mbps, &mut e, &mut x);
        assert_eq!(state, SaturationState::Normal);
        // 3rd window high → Saturated.
        state = debounce_saturation(state, high, cap_mbps, &mut e, &mut x);
        assert_eq!(state, SaturationState::Saturated);
        // 2 windows low → still Saturated.
        state = debounce_saturation(state, low, cap_mbps, &mut e, &mut x);
        state = debounce_saturation(state, low, cap_mbps, &mut e, &mut x);
        assert_eq!(state, SaturationState::Saturated);
        // 3rd low → back to Normal.
        state = debounce_saturation(state, low, cap_mbps, &mut e, &mut x);
        assert_eq!(state, SaturationState::Normal);
    }

    #[test]
    fn brief_blip_does_not_flip() {
        let (mut e, mut x) = (0u8, 0u8);
        let mut state = SaturationState::Normal;
        state = debounce_saturation(state, 11_000_000, Some(100), &mut e, &mut x); // high
        state = debounce_saturation(state, 1_000_000, Some(100), &mut e, &mut x); // blip low resets counter
        state = debounce_saturation(state, 11_000_000, Some(100), &mut e, &mut x); // high again
        assert_eq!(state, SaturationState::Normal);
    }

    #[test]
    fn classify_unhealthy_when_stale() {
        let n = node("n1", "1.2.3.4", None);
        let mut rt = healthy_rt(0);
        rt.last_contact_ms = 0;
        // now is way past the freshness window.
        let class = classify_node(&n, &rt, 1_000_000, 20);
        assert_eq!(class, ExclusionClass::Unhealthy);
    }

    #[test]
    fn health_reason_splits_unhealthy_sub_causes() {
        let n = node("n1", "1.2.3.4", None);

        // Stale control channel → Offline (all map to Unhealthy).
        let mut stale = healthy_rt(0);
        stale.last_contact_ms = 0;
        let r = health_reason(&n, &stale, 1_000_000, 20);
        assert_eq!(r, HealthReason::Offline);
        assert_eq!(r.exclusion_class(), ExclusionClass::Unhealthy);

        // Fresh + connected, forwarding process down → ForwardingDown.
        let mut fwd_down = healthy_rt(1000);
        fwd_down.forwarding_up = false;
        assert_eq!(
            health_reason(&n, &fwd_down, 1000, 20),
            HealthReason::ForwardingDown
        );

        // Fresh + forwarding up, but backend not reachable → BackendUnreachable
        // (the bug class: node shows "online" yet is excluded).
        let mut backend_down = healthy_rt(1000);
        backend_down.backend_reachable = false;
        assert_eq!(
            health_reason(&n, &backend_down, 1000, 20),
            HealthReason::BackendUnreachable
        );

        // Fully healthy → Ok.
        assert_eq!(
            health_reason(&n, &healthy_rt(1000), 1000, 20),
            HealthReason::Ok
        );
    }

    #[test]
    fn health_reason_maps_quota_and_saturation() {
        let n = node("n1", "1.2.3.4", Some(1000));
        let mut hard = healthy_rt(1000);
        hard.capacity.accumulated_usage_bytes = 1000; // 100% → hard
        assert_eq!(health_reason(&n, &hard, 1000, 20), HealthReason::QuotaHard);
        // Quota-over-limit is NOT an "error" — it is a deliberate policy exclusion.
        assert!(hard.forwarding_up && hard.backend_reachable);

        let mut sat = healthy_rt(1000);
        sat.saturation = SaturationState::Saturated;
        assert_eq!(health_reason(&n, &sat, 1000, 20), HealthReason::Saturated);
    }

    #[test]
    fn classify_hard_quota() {
        let n = node("n1", "1.2.3.4", Some(1000));
        let mut rt = healthy_rt(1000);
        rt.capacity.accumulated_usage_bytes = 1000; // 100% → hard
        let class = classify_node(&n, &rt, 1000, 20);
        assert_eq!(class, ExclusionClass::HardQuota);
    }

    #[test]
    fn classify_soft_quota() {
        let n = node("n1", "1.2.3.4", Some(1000));
        let mut rt = healthy_rt(1000);
        rt.capacity.accumulated_usage_bytes = 950; // 95% ≥ 90% soft, < 100% hard
        let class = classify_node(&n, &rt, 1000, 20);
        assert_eq!(class, ExclusionClass::SoftQuota);
    }

    #[test]
    fn status_report_ingest_overwrites_and_clears_telemetry() {
        use contract::protocol::{ActiveBackend, BackendHealth};

        let mut rt = NodeRuntime::default();
        let report_with = StatusReport {
            forwarding_up: true,
            backend_reachable: true,
            applied_config_gen: 1,
            metrics: None,
            capacity: None,
            backend_health: Some(vec![BackendHealth {
                host: "10.0.0.1".into(),
                port: 8096,
                reachable: true,
            }]),
            active_backends: Some(vec![ActiveBackend {
                rule_id: "r1".into(),
                host: "10.0.0.1".into(),
                port: 8096,
            }]),
        };
        apply_status_report(&mut rt, &report_with, 1000);
        assert_eq!(rt.backend_health.len(), 1);
        assert_eq!(rt.active_backends.len(), 1);

        // A subsequent report WITHOUT the fields must CLEAR them (no carry-over).
        let report_without = StatusReport {
            forwarding_up: true,
            backend_reachable: true,
            applied_config_gen: 1,
            metrics: None,
            capacity: None,
            backend_health: None,
            active_backends: None,
        };
        apply_status_report(&mut rt, &report_without, 2000);
        assert!(
            rt.backend_health.is_empty(),
            "backend_health must be cleared"
        );
        assert!(
            rt.active_backends.is_empty(),
            "active_backends must be cleared"
        );
        // The DNS-gate anchor is untouched (still reads backend_reachable).
        assert!(rt.backend_reachable);
    }

    #[test]
    fn health_reason_ignores_backend_telemetry_partial_failure() {
        use contract::protocol::BackendHealth;

        // Multiple replicas, some down, but the agent's any-up `backend_reachable` is
        // true → health_reason stays Ok (we must NOT drop the node from DNS).
        let n = node("n1", "1.2.3.4", None);
        let mut rt = healthy_rt(1000);
        rt.backend_health = vec![
            BackendHealth {
                host: "10.0.0.1".into(),
                port: 8096,
                reachable: false,
            },
            BackendHealth {
                host: "10.0.0.2".into(),
                port: 8096,
                reachable: true,
            },
        ];
        assert_eq!(health_reason(&n, &rt, 1000, 20), HealthReason::Ok);
    }

    #[test]
    fn snapshot_promotes_soft_over_blackout() {
        // Scenario ⑥: one saturated node, rest unhealthy → saturated promoted.
        let mut nodes = HashMap::new();
        nodes.insert("n1".into(), node("n1", "10.0.0.1", None));
        nodes.insert("n2".into(), node("n2", "10.0.0.2", None));
        let mut rts = HashMap::new();
        let mut rt1 = healthy_rt(1000);
        rt1.saturation = SaturationState::Saturated;
        rts.insert("n1".to_string(), rt1);
        // n2 unhealthy (no runtime → default, not connected).
        rts.insert("n2".to_string(), NodeRuntime::default());

        let group = LineGroup {
            id: "g1".into(),
            name: "g1".into(),
            zone_id: None,
            match_region: None,
            match_isp: None,
            member_node_ids: vec!["n1".into(), "n2".into()],
            priority: 0,
            fallback_group: None,
            active_window: None,
        };
        let snap = build_snapshot(&nodes, &rts, &[group], 1, 1000, 20);
        let avail = snap.available_for("g1");
        assert_eq!(avail, &[IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))]);
    }

    fn solo_group(member: &str) -> LineGroup {
        LineGroup {
            id: "g1".into(),
            name: "g1".into(),
            zone_id: None,
            match_region: None,
            match_isp: None,
            member_node_ids: vec![member.into()],
            priority: 0,
            fallback_group: None,
            active_window: None,
        }
    }

    #[test]
    fn ddns_node_uses_resolved_ip_and_skips_until_resolved() {
        // A node whose `public_ip` is a hostname is excluded while unresolved...
        let mut nodes = HashMap::new();
        nodes.insert("n1".into(), node("n1", "relay.example.com", None));
        let mut rts = HashMap::new();
        rts.insert("n1".to_string(), healthy_rt(1000)); // resolved_ip = None
        let group = solo_group("n1");

        let snap = build_snapshot(&nodes, &rts, std::slice::from_ref(&group), 1, 1000, 20);
        assert!(
            snap.available_for("g1").is_empty(),
            "hostname node must be excluded until the ddns task resolves it (no SERVFAIL bypass)"
        );

        // ...and served once the background ddns task has cached an IP for it.
        let mut rt = healthy_rt(1000);
        rt.resolved = Some((
            "relay.example.com".into(),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
        ));
        rts.insert("n1".to_string(), rt);
        let snap = build_snapshot(&nodes, &rts, &[group], 2, 1000, 20);
        assert_eq!(
            snap.available_for("g1"),
            &[IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))]
        );
    }

    #[test]
    fn ip_literal_node_ignores_stale_resolved_ip() {
        // An IP-literal address always wins; a stale resolved cache never overrides it.
        let mut nodes = HashMap::new();
        nodes.insert("n1".into(), node("n1", "10.0.0.5", None));
        let mut rts = HashMap::new();
        let mut rt = healthy_rt(1000);
        rt.resolved = Some((
            "old.example.com".into(),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
        ));
        rts.insert("n1".to_string(), rt);

        let snap = build_snapshot(&nodes, &rts, &[solo_group("n1")], 1, 1000, 20);
        assert_eq!(
            snap.available_for("g1"),
            &[IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))]
        );
    }

    #[test]
    fn changed_hostname_does_not_serve_stale_cache() {
        // Codex BLOCK #1: address changed old.example.com → new.example.com. The cache
        // is still bound to the OLD name, so the node must be EXCLUDED (not served the
        // old name's IP) until the new name resolves.
        let mut nodes = HashMap::new();
        nodes.insert("n1".into(), node("n1", "new.example.com", None));
        let mut rts = HashMap::new();
        let mut rt = healthy_rt(1000);
        rt.resolved = Some((
            "old.example.com".into(),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
        ));
        rts.insert("n1".to_string(), rt);

        let snap = build_snapshot(&nodes, &rts, &[solo_group("n1")], 1, 1000, 20);
        assert!(
            snap.available_for("g1").is_empty(),
            "a changed hostname must not be served the previous name's cached IP"
        );

        // Once the new name resolves, it is served.
        let mut rt = healthy_rt(1000);
        rt.resolved = Some((
            "new.example.com".into(),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
        ));
        rts.insert("n1".to_string(), rt);
        let snap = build_snapshot(&nodes, &rts, &[solo_group("n1")], 2, 1000, 20);
        assert_eq!(
            snap.available_for("g1"),
            &[IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9))]
        );
    }
}
