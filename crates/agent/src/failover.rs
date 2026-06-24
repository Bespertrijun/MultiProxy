//! Agent-side failover engine (Phase 4a).
//!
//! The panel pushes structured per-rule specs (`ConfigPush.rules`) where each
//! rule carries an **ordered** backend list `[primary, ...standby]`. The agent
//! probes each replica on the `probe_interval_secs` cadence and runs a small
//! per-rule state machine to pick the **current active backend** for every rule:
//!
//!   * **fast-fail** — a backend is only abandoned after `failover_max_fails`
//!     consecutive probe failures;
//!   * **slow-recovery** — a higher-priority backend is only reverted to after
//!     `failover_recovery_checks` consecutive successes;
//!   * **min-dwell** — after a switch, the engine will not *revert to a
//!     higher-priority* backend for `min_dwell_secs` (escaping a dead active is
//!     always allowed — dwell never pins the node to a dead backend).
//!
//! When the set of active backends changes the engine re-renders the **whole
//! node's** single-upstream config (one upstream per rule = its active replica)
//! via [`relaycfg`] and asks the supervisor to restart **once** — all rule
//! changes in a probe cycle are batched into a single re-render + restart.
//!
//! **P6**: switching the local active backend NEVER touches `applied_gen` and
//! NEVER emits a `ConfigAck`. The active replica is surfaced only through the
//! next `StatusReport.active_backends`.
//!
//! **OQ-8**: when a rule has *no* healthy replica the engine keeps the last
//! known config (the active backend cannot change → no restart), so a fully-dead
//! rule never drives a kill+spawn crash-loop. The rule is flagged down in the
//! report instead.

use std::collections::HashMap;
use std::time::Duration;

use contract::model::{ForwardRule, Tool as ModelTool};
use contract::protocol::{ActiveBackend, BackendEndpoint, BackendHealth, RuleSpec};
use relaycfg::TlsPaths;

use crate::config::ConfigPaths;
use crate::selfheal::BackendProbe;

/// Tunables governing the per-rule state machine. Sourced from `HelloOk` at
/// handshake time (Phase 3 fields, with serde defaults for older panels).
#[derive(Debug, Clone, Copy)]
pub struct FailoverTunables {
    pub probe_interval: Duration,
    pub probe_timeout: Duration,
    pub max_fails: u32,
    pub recovery_checks: u32,
    pub min_dwell: Duration,
}

impl FailoverTunables {
    /// Build from the `HelloOk` failover fields (all seconds/millis on the wire).
    #[must_use]
    pub fn from_hello_ok(ok: &contract::protocol::HelloOk) -> Self {
        Self {
            probe_interval: Duration::from_secs(ok.probe_interval_secs.max(1) as u64),
            probe_timeout: Duration::from_millis(ok.probe_timeout_ms.max(1) as u64),
            max_fails: ok.failover_max_fails.max(1),
            recovery_checks: ok.failover_recovery_checks.max(1),
            min_dwell: Duration::from_secs(ok.min_dwell_secs as u64),
        }
    }
}

/// Hysteresis state for one backend endpoint within a rule.
#[derive(Debug, Clone)]
struct EndpointState {
    /// Stable up/down classification (drives selection).
    up: bool,
    consecutive_fails: u32,
    consecutive_successes: u32,
}

impl EndpointState {
    fn new() -> Self {
        // Optimistic: a freshly-pushed backend starts UP so a single-replica rule
        // (and the primary on a healthy node) is active immediately, matching
        // today's behavior before the first probe completes.
        Self {
            up: true,
            consecutive_fails: 0,
            consecutive_successes: 0,
        }
    }

    /// Fold one probe result into the streaks and update the up/down state with
    /// fast-fail / slow-recovery hysteresis.
    fn observe(&mut self, reachable: bool, max_fails: u32, recovery_checks: u32) {
        if reachable {
            self.consecutive_successes = self.consecutive_successes.saturating_add(1);
            self.consecutive_fails = 0;
            if !self.up && self.consecutive_successes >= recovery_checks {
                self.up = true;
            }
        } else {
            self.consecutive_fails = self.consecutive_fails.saturating_add(1);
            self.consecutive_successes = 0;
            if self.up && self.consecutive_fails >= max_fails {
                self.up = false;
            }
        }
    }
}

/// Per-rule failover state: a copy of the rule's ordered backends plus the
/// per-endpoint hysteresis state and the currently-selected active index.
#[derive(Debug, Clone)]
struct RuleState {
    spec: RuleSpec,
    endpoints: Vec<EndpointState>,
    /// Index into `spec.backends` of the active backend, or `None` when no
    /// replica is healthy (OQ-8: keep last-known config, report down).
    active_idx: Option<usize>,
    /// Probe ticks since the last switch (proxy for dwell using the probe cadence).
    ticks_since_switch: u64,
}

impl RuleState {
    fn new(spec: RuleSpec) -> Self {
        let endpoints = spec.backends.iter().map(|_| EndpointState::new()).collect();
        // Active starts at the primary (index 0) if the rule has any backend.
        let active_idx = if spec.backends.is_empty() {
            None
        } else {
            Some(0)
        };
        Self {
            spec,
            endpoints,
            active_idx,
            ticks_since_switch: u64::MAX / 2, // "long ago" so the first revert isn't dwell-blocked
        }
    }

    /// The endpoint currently selected as active, if any.
    fn active_endpoint(&self) -> Option<&BackendEndpoint> {
        self.active_idx.and_then(|i| self.spec.backends.get(i))
    }
}

/// The failover engine: owns one [`RuleState`] per pushed rule and the agent's
/// config paths (for rendering). Lives in the session so state persists across
/// probe ticks.
pub struct FailoverEngine {
    rules: Vec<RuleState>,
    /// Lookup from rule_id → index in `rules` (rebuilt on each push).
    by_id: HashMap<String, usize>,
    tls: TlsPaths,
    /// Whether a usable relay cert is currently available (the last `ConfigPush`
    /// carried `tls_cert_pem`+`tls_key_pem`). Mirrors the panel's rule: a
    /// `tls_mode=terminate` listener is rendered with TLS ONLY when a cert exists;
    /// otherwise it renders plain TCP (else the relay references a missing/stale
    /// cert file and fails to start). Persists across probe-tick re-renders until
    /// the next push updates it.
    tls_available: bool,
}

/// The outcome of one probe-cycle decision: whether a restart is needed and the
/// freshly-rendered single-upstream config to apply.
#[derive(Debug, Default)]
pub struct FailoverDecision {
    /// `true` when the active-backend set changed and the node must be re-rendered
    /// + restarted (batched: at most one restart per probe cycle).
    pub changed: bool,
    pub gost_config: Option<String>,
    pub realm_config: Option<String>,
}

impl FailoverEngine {
    /// Build an engine for a config directory's TLS paths.
    #[must_use]
    pub fn new(paths: &ConfigPaths) -> Self {
        Self {
            rules: Vec::new(),
            by_id: HashMap::new(),
            tls: TlsPaths {
                cert: paths.tls_cert.to_string_lossy().into_owned(),
                key: paths.tls_key.to_string_lossy().into_owned(),
            },
            tls_available: false,
        }
    }

    /// Record whether a relay cert is currently available (set from each
    /// `ConfigPush`'s `tls_cert_pem`+`tls_key_pem` presence). Gates TLS rendering
    /// so the engine never emits a TLS listener pointing at a missing cert.
    pub fn set_tls_available(&mut self, available: bool) {
        self.tls_available = available;
    }

    /// Whether the engine has rules to manage (i.e. the panel pushed structured
    /// rules). When empty, the caller stays on the legacy single-upstream path.
    #[must_use]
    pub fn is_active(&self) -> bool {
        !self.rules.is_empty()
    }

    /// Adopt a new set of rules from a `ConfigPush`. Reuses existing per-endpoint
    /// hysteresis state for rules/backends that persist across the push so a
    /// re-push does not reset failover progress; rules/backends that disappear are
    /// dropped and new ones start fresh.
    pub fn set_rules(&mut self, rules: &[RuleSpec]) {
        let mut prev: HashMap<String, RuleState> = self
            .rules
            .drain(..)
            .map(|rs| (rs.spec.rule_id.clone(), rs))
            .collect();

        let mut next = Vec::with_capacity(rules.len());
        for spec in rules {
            let state = match prev.remove(&spec.rule_id) {
                Some(mut old) if old.spec.backends == spec.backends => {
                    // Identical backend list → keep streaks + active selection.
                    old.spec = spec.clone();
                    old
                }
                _ => RuleState::new(spec.clone()),
            };
            next.push(state);
        }

        self.by_id = next
            .iter()
            .enumerate()
            .map(|(i, rs)| (rs.spec.rule_id.clone(), i))
            .collect();
        self.rules = next;
    }

    /// All distinct backend endpoints across every rule, deduped — used to fill
    /// the legacy flat `deps.backends` so the any-up `backend.reachable` path does
    /// not regress when rules are present.
    #[must_use]
    pub fn flat_backends(&self) -> Vec<BackendEndpoint> {
        let mut out: Vec<BackendEndpoint> = Vec::new();
        for rs in &self.rules {
            for ep in &rs.spec.backends {
                if !out.contains(ep) {
                    out.push(ep.clone());
                }
            }
        }
        out
    }

    /// Run one probe cycle: probe every replica of every rule, fold results into
    /// the per-rule state machines, and (if the active set changed) re-render the
    /// node's single-upstream config. Returns the per-replica health (for the
    /// report) alongside the decision.
    pub async fn probe_and_decide<P: BackendProbe>(
        &mut self,
        probe: &P,
        tunables: &FailoverTunables,
    ) -> (FailoverDecision, Vec<BackendHealth>) {
        let mut all_health: Vec<BackendHealth> = Vec::new();
        let mut changed = false;

        for rs in &mut self.rules {
            rs.ticks_since_switch = rs.ticks_since_switch.saturating_add(1);

            let health = probe.reachable_each(&rs.spec.backends).await;
            for (i, h) in health.iter().enumerate() {
                if let Some(st) = rs.endpoints.get_mut(i) {
                    st.observe(h.reachable, tunables.max_fails, tunables.recovery_checks);
                }
            }
            all_health.extend(health);

            if Self::reselect(rs, tunables) {
                changed = true;
            }
        }

        let decision = if changed {
            let (gost_config, realm_config) = self.render_active();
            FailoverDecision {
                changed: true,
                gost_config,
                realm_config,
            }
        } else {
            FailoverDecision::default()
        };
        (decision, all_health)
    }

    /// Recompute the active backend for one rule. Returns `true` if it changed.
    ///
    /// Selection = lowest-index (highest-priority) endpoint that is currently
    /// `up`. Dwell gates only *reverting to a higher priority* than the current
    /// active; escaping a now-down active is always allowed (OQ-8 safety: if no
    /// endpoint is up the active is cleared but stays pointing at the last index
    /// for restart purposes — see below).
    fn reselect(rs: &mut RuleState, tunables: &FailoverTunables) -> bool {
        let best_up = rs.endpoints.iter().position(|e| e.up);
        let prev = rs.active_idx;

        let new_idx = match (prev, best_up) {
            // No healthy replica at all → OQ-8: keep last-known active (do NOT
            // clear → the active endpoint is unchanged → no restart, no crash-loop).
            (_, None) => prev,
            // Nothing active yet (e.g. empty at push) → take the best available.
            (None, Some(b)) => Some(b),
            (Some(cur), Some(b)) => {
                if !rs.endpoints[cur].up {
                    // Current active went down → must escape to best available now
                    // (dwell never pins us to a dead backend).
                    Some(b)
                } else if b < cur {
                    // A higher-priority backend recovered. Only revert after the
                    // min-dwell window has elapsed (slow, hysteretic recovery).
                    let dwell_ticks = dwell_ticks(tunables);
                    if rs.ticks_since_switch >= dwell_ticks {
                        Some(b)
                    } else {
                        Some(cur)
                    }
                } else {
                    // Current active is still up and is the best/peer → stay put.
                    Some(cur)
                }
            }
        };

        if new_idx != prev {
            rs.active_idx = new_idx;
            rs.ticks_since_switch = 0;
            true
        } else {
            false
        }
    }

    /// Public wrapper over [`Self::render_active`]: render the node's
    /// single-upstream config from the engine's **current active selection** per
    /// rule. Used by the inbound ConfigPush handler so the bytes written to disk
    /// reflect the engine's active replica (not the panel's primary-only string),
    /// which keeps a failed-over node from being shoved back to its primary on an
    /// unrelated re-push (e.g. cert renewal).
    #[must_use]
    pub fn render_active_config(&self) -> (Option<String>, Option<String>) {
        self.render_active()
    }

    /// Render the whole node's single-upstream config from each rule's active
    /// backend. Mirrors the panel's `configgen::render_node_with_tls` (gost/realm
    /// split, sorted by listen port, TLS paths) so the bytes match the panel path.
    fn render_active(&self) -> (Option<String>, Option<String>) {
        // Build a `ForwardRule` view per rule whose backend = the active replica.
        let views: Vec<ForwardRule> = self
            .rules
            .iter()
            .filter_map(|rs| {
                let active = rs.active_endpoint()?;
                Some(ForwardRule {
                    id: rs.spec.rule_id.clone(),
                    node_id: String::new(),
                    listen_port: rs.spec.listen_port,
                    protocol: rs.spec.protocol,
                    backend_host: active.host.clone(),
                    backend_port: active.port,
                    tool: rs.spec.tool,
                    tls_mode: rs.spec.tls_mode,
                    extra_backends: Vec::new(),
                })
            })
            .collect();

        let mut gost_rules: Vec<&ForwardRule> =
            views.iter().filter(|r| r.tool == ModelTool::Gost).collect();
        let mut realm_rules: Vec<&ForwardRule> = views
            .iter()
            .filter(|r| r.tool == ModelTool::Realm)
            .collect();
        gost_rules.sort_by_key(|r| r.listen_port);
        realm_rules.sort_by_key(|r| r.listen_port);

        // Inject TLS only when a cert is actually available — matches the panel's
        // `render_node_with_tls` (cert present ⇒ TLS listener; absent ⇒ plain TCP).
        let tls = if self.tls_available {
            Some(&self.tls)
        } else {
            None
        };
        let gost_config = if gost_rules.is_empty() {
            None
        } else {
            Some(relaycfg::render_gost(&gost_rules, tls))
        };
        let realm_config = if realm_rules.is_empty() {
            None
        } else {
            Some(relaycfg::render_realm(&realm_rules, tls))
        };
        (gost_config, realm_config)
    }

    /// The current active backend per rule, for `StatusReport.active_backends`.
    /// A rule with no healthy replica still reports its last-known active (so the
    /// panel sees which backend the node is *trying* to serve); whether that rule
    /// is "up" is reflected in `backend_reachable` / `backend_health`.
    #[must_use]
    pub fn active_backends(&self) -> Vec<ActiveBackend> {
        self.rules
            .iter()
            .filter_map(|rs| {
                let ep = rs.active_endpoint()?;
                Some(ActiveBackend {
                    rule_id: rs.spec.rule_id.clone(),
                    host: ep.host.clone(),
                    port: ep.port,
                })
            })
            .collect()
    }

    /// Whether **every** rule currently has at least one healthy replica
    /// (all-rules-have-a-healthy-replica). Drives `backend_reachable` when rules
    /// are present. An engine with no rules returns `true` only vacuously — the
    /// caller handles the no-rules case via the legacy any-up path instead.
    #[must_use]
    pub fn all_rules_have_healthy_replica(&self) -> bool {
        self.rules
            .iter()
            .all(|rs| rs.endpoints.iter().any(|e| e.up))
    }
}

/// Number of probe ticks that approximate the `min_dwell` window. The dwell is
/// expressed in seconds but the engine advances per probe cycle, so convert via
/// the probe interval (round up; at least one tick so a zero/short dwell still
/// lets the very next cycle revert).
fn dwell_ticks(t: &FailoverTunables) -> u64 {
    let dwell = t.min_dwell.as_secs();
    let interval = t.probe_interval.as_secs().max(1);
    if dwell == 0 {
        0
    } else {
        dwell.div_ceil(interval).max(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use contract::model::{Protocol, TlsMode};

    fn ep(host: &str, port: u16) -> BackendEndpoint {
        BackendEndpoint {
            host: host.into(),
            port,
        }
    }

    fn spec(id: &str, port: u16, backends: Vec<BackendEndpoint>) -> RuleSpec {
        RuleSpec {
            rule_id: id.into(),
            listen_port: port,
            protocol: Protocol::Tcp,
            tls_mode: TlsMode::Passthrough,
            tool: ModelTool::Gost,
            backends,
        }
    }

    fn tunables(
        max_fails: u32,
        recovery: u32,
        dwell_secs: u32,
        interval_secs: u32,
    ) -> FailoverTunables {
        FailoverTunables {
            probe_interval: Duration::from_secs(interval_secs as u64),
            probe_timeout: Duration::from_millis(100),
            max_fails,
            recovery_checks: recovery,
            min_dwell: Duration::from_secs(dwell_secs as u64),
        }
    }

    fn engine_with(rules: Vec<RuleSpec>) -> FailoverEngine {
        let mut e = FailoverEngine::new(&ConfigPaths::under("/tmp/fo-test"));
        e.set_rules(&rules);
        e
    }

    #[test]
    fn render_gates_tls_on_cert_availability() {
        // A terminate rule must render a TLS listener ONLY when a cert is available,
        // else plain TCP — mirroring the panel's render_node_with_tls. Otherwise the
        // engine would emit a TLS listener pointing at a missing/stale local cert and
        // the relay would fail to start (Codex review regression).
        let rule = RuleSpec {
            rule_id: "r1".into(),
            listen_port: 443,
            protocol: Protocol::Tcp,
            tls_mode: TlsMode::Terminate,
            tool: ModelTool::Gost,
            backends: vec![ep("10.0.0.1", 8096)],
        };
        let mut e = engine_with(vec![rule]);

        // No cert → plain TCP (no TLS listener referencing a missing cert file).
        e.set_tls_available(false);
        let (gost_no_tls, _) = e.render_active_config();
        let g = gost_no_tls.expect("gost config");
        assert!(
            !g.contains("certFile"),
            "no cert ⇒ must not render a TLS listener: {g}"
        );

        // Cert available → TLS listener rendered.
        e.set_tls_available(true);
        let (gost_tls, _) = e.render_active_config();
        let g = gost_tls.expect("gost config");
        assert!(g.contains("certFile"), "cert present ⇒ TLS listener: {g}");
    }

    // Drive a rule's single endpoint through a sequence of probe results without a
    // real probe, to test the state machine deterministically.
    fn observe(rs: &mut RuleState, results: &[bool], t: &FailoverTunables) -> bool {
        let mut changed = false;
        for &r in results {
            rs.ticks_since_switch = rs.ticks_since_switch.saturating_add(1);
            for st in &mut rs.endpoints {
                st.observe(r, t.max_fails, t.recovery_checks);
            }
            if FailoverEngine::reselect(rs, t) {
                changed = true;
            }
        }
        changed
    }

    fn observe_each(rs: &mut RuleState, per_ep: &[bool], t: &FailoverTunables) -> bool {
        rs.ticks_since_switch = rs.ticks_since_switch.saturating_add(1);
        for (i, &r) in per_ep.iter().enumerate() {
            rs.endpoints[i].observe(r, t.max_fails, t.recovery_checks);
        }
        FailoverEngine::reselect(rs, t)
    }

    #[test]
    fn three_consecutive_fails_switch_to_standby() {
        let t = tunables(3, 2, 0, 5);
        let mut e = engine_with(vec![spec(
            "r1",
            8080,
            vec![ep("10.0.0.1", 8096), ep("10.0.0.2", 8096)],
        )]);
        let rs = &mut e.rules[0];
        observe_each(rs, &[false, true], &t);
        observe_each(rs, &[false, true], &t);
        assert_eq!(rs.active_idx, Some(0), "2 fails < max_fails(3): stay");
        let changed = observe_each(rs, &[false, true], &t);
        assert!(changed, "3rd consecutive fail must switch");
        assert_eq!(rs.active_idx, Some(1), "now serving the standby");
    }

    #[test]
    fn slow_recovery_reverts_only_after_recovery_checks_and_dwell() {
        // dwell 0 so only recovery_checks gates the revert.
        let t = tunables(2, 3, 0, 5);
        let mut e = engine_with(vec![spec(
            "r1",
            8080,
            vec![ep("10.0.0.1", 8096), ep("10.0.0.2", 8096)],
        )]);
        let rs = &mut e.rules[0];
        // Kill primary (2 fails) → switch to standby.
        observe_each(rs, &[false, true], &t);
        observe_each(rs, &[false, true], &t);
        assert_eq!(rs.active_idx, Some(1));

        // Primary recovers: 2 successes (< recovery_checks=3) → still on standby.
        observe_each(rs, &[true, true], &t);
        observe_each(rs, &[true, true], &t);
        assert_eq!(
            rs.active_idx,
            Some(1),
            "must not revert before recovery_checks"
        );

        // 3rd success → primary marked up → revert to higher priority.
        let changed = observe_each(rs, &[true, true], &t);
        assert!(changed);
        assert_eq!(rs.active_idx, Some(0), "reverted to recovered primary");
    }

    #[test]
    fn min_dwell_blocks_revert_within_window() {
        // recovery_checks=1 (instant up) but dwell=30s, interval=5s → 6 ticks dwell.
        let t = tunables(2, 1, 30, 5);
        let mut e = engine_with(vec![spec(
            "r1",
            8080,
            vec![ep("10.0.0.1", 8096), ep("10.0.0.2", 8096)],
        )]);
        let rs = &mut e.rules[0];
        // Switch to standby (2 primary fails).
        observe_each(rs, &[false, true], &t);
        observe_each(rs, &[false, true], &t);
        assert_eq!(rs.active_idx, Some(1));
        // ticks_since_switch reset to 0 on the switch.

        // Primary healthy again immediately, but we are within the dwell window:
        // ticks 1..5 (< 6) must NOT revert.
        for _ in 0..5 {
            observe_each(rs, &[true, true], &t);
            assert_eq!(rs.active_idx, Some(1), "dwell must block early revert");
        }
        // 6th tick reaches the dwell threshold → revert allowed.
        observe_each(rs, &[true, true], &t);
        assert_eq!(rs.active_idx, Some(0), "revert after dwell elapses");
    }

    #[test]
    fn single_replica_rule_never_switches() {
        // A rule with only the primary must behave exactly as today: it stays
        // active=0 and never "switches" no matter the probe results (OQ-8: a dead
        // single replica keeps last-known, no crash-loop).
        let t = tunables(2, 2, 0, 5);
        let mut e = engine_with(vec![spec("r1", 8080, vec![ep("10.0.0.1", 8096)])]);
        let rs = &mut e.rules[0];
        assert_eq!(rs.active_idx, Some(0));
        // Many failures: endpoint goes down but active stays 0 (no alternative).
        let changed = observe(rs, &[false, false, false, false, false], &t);
        assert!(!changed, "single-replica rule never switches active");
        assert_eq!(rs.active_idx, Some(0), "keeps last-known on death (OQ-8)");
        // And it recovers in place.
        observe(rs, &[true, true, true], &t);
        assert_eq!(rs.active_idx, Some(0));
    }

    #[test]
    fn all_replicas_dead_keeps_last_known_no_change() {
        // Two replicas; switch to standby, then standby also dies → no further
        // change (active stays on the standby = last-known), so no restart fires.
        let t = tunables(2, 2, 0, 5);
        let mut e = engine_with(vec![spec(
            "r1",
            8080,
            vec![ep("10.0.0.1", 8096), ep("10.0.0.2", 8096)],
        )]);
        let rs = &mut e.rules[0];
        // Primary dies → switch to standby (idx 1).
        observe_each(rs, &[false, true], &t);
        observe_each(rs, &[false, true], &t);
        assert_eq!(rs.active_idx, Some(1));
        // Now BOTH dead repeatedly → must keep last-known (idx 1), never clear,
        // never report a change (no restart → no crash-loop).
        for _ in 0..5 {
            let changed = observe_each(rs, &[false, false], &t);
            assert!(!changed, "all-dead must not produce a switch/restart");
            assert_eq!(rs.active_idx, Some(1), "keep last-known active on all-dead");
        }
        // all_rules_have_healthy_replica is false now.
        assert!(!e.all_rules_have_healthy_replica());
    }

    #[test]
    fn set_rules_preserves_state_for_identical_backends() {
        let t = tunables(2, 5, 0, 5);
        let mut e = engine_with(vec![spec(
            "r1",
            8080,
            vec![ep("10.0.0.1", 8096), ep("10.0.0.2", 8096)],
        )]);
        // Move to standby.
        {
            let rs = &mut e.rules[0];
            observe_each(rs, &[false, true], &t);
            observe_each(rs, &[false, true], &t);
            assert_eq!(rs.active_idx, Some(1));
        }
        // Re-push the SAME rule (identical backends) → state preserved.
        e.set_rules(&[spec(
            "r1",
            8080,
            vec![ep("10.0.0.1", 8096), ep("10.0.0.2", 8096)],
        )]);
        assert_eq!(
            e.rules[0].active_idx,
            Some(1),
            "state preserved across re-push"
        );

        // Re-push with DIFFERENT backends → reset to primary.
        e.set_rules(&[spec(
            "r1",
            8080,
            vec![ep("10.0.0.3", 8096), ep("10.0.0.4", 8096)],
        )]);
        assert_eq!(
            e.rules[0].active_idx,
            Some(0),
            "changed backends reset state"
        );
    }

    #[test]
    fn flat_backends_dedupes_across_rules() {
        let e = engine_with(vec![
            spec("r1", 8080, vec![ep("10.0.0.1", 8096), ep("10.0.0.2", 8096)]),
            spec("r2", 9090, vec![ep("10.0.0.2", 8096), ep("10.0.0.3", 8096)]),
        ]);
        let flat = e.flat_backends();
        assert_eq!(flat.len(), 3, "deduped union of all rule backends");
        assert!(flat.contains(&ep("10.0.0.1", 8096)));
        assert!(flat.contains(&ep("10.0.0.2", 8096)));
        assert!(flat.contains(&ep("10.0.0.3", 8096)));
    }

    #[test]
    fn render_active_emits_single_upstream_for_active_backend() {
        let mut e = engine_with(vec![spec(
            "r1",
            8080,
            vec![ep("10.0.0.1", 8096), ep("10.0.0.2", 8096)],
        )]);
        // Default active = primary.
        let (gost, realm) = e.render_active();
        assert!(realm.is_none());
        let g = gost.expect("gost rendered");
        assert!(
            g.contains("10.0.0.1:8096"),
            "renders the active (primary) backend"
        );
        assert!(
            !g.contains("10.0.0.2"),
            "standby is NOT in the single-upstream config"
        );

        // Switch to standby, re-render.
        {
            let t = tunables(1, 1, 0, 5);
            let rs = &mut e.rules[0];
            observe_each(rs, &[false, true], &t);
            assert_eq!(rs.active_idx, Some(1));
        }
        let (gost, _) = e.render_active();
        let g = gost.expect("gost rendered");
        assert!(
            g.contains("10.0.0.2:8096"),
            "now renders the standby as the upstream"
        );
        assert!(!g.contains("10.0.0.1"));
    }

    /// A probe whose per-endpoint answer is keyed by "host:port" and controllable
    /// at runtime, so a test can fail/heal specific replicas across multiple rules
    /// within one `probe_and_decide` cycle.
    #[derive(Clone, Default)]
    struct MapProbe {
        down: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
    }
    impl MapProbe {
        fn key(ep: &BackendEndpoint) -> String {
            format!("{}:{}", ep.host, ep.port)
        }
        fn set_down(&self, ep: &BackendEndpoint, down: bool) {
            let mut g = self.down.lock().unwrap();
            if down {
                g.insert(Self::key(ep));
            } else {
                g.remove(&Self::key(ep));
            }
        }
    }
    impl BackendProbe for MapProbe {
        async fn reachable_each(&self, targets: &[BackendEndpoint]) -> Vec<BackendHealth> {
            let g = self.down.lock().unwrap();
            targets
                .iter()
                .map(|t| BackendHealth {
                    host: t.host.clone(),
                    port: t.port,
                    reachable: !g.contains(&Self::key(t)),
                })
                .collect()
        }
    }

    #[tokio::test]
    async fn probe_and_decide_batches_multi_rule_change_into_one_decision() {
        // Two rules, each [primary, standby]. Fail BOTH primaries within one cycle:
        // probe_and_decide must return a SINGLE decision (one re-render) covering
        // both switches — so conn.rs restarts the relay ONCE, not per rule.
        let t = tunables(1, 1, 0, 5); // max_fails=1 so a single failure switches
        let mut e = engine_with(vec![
            spec("r1", 8080, vec![ep("10.0.0.1", 8096), ep("10.0.0.2", 8096)]),
            spec("r2", 9090, vec![ep("10.0.1.1", 8096), ep("10.0.1.2", 8096)]),
        ]);
        let probe = MapProbe::default();
        probe.set_down(&ep("10.0.0.1", 8096), true);
        probe.set_down(&ep("10.0.1.1", 8096), true);

        let (decision, health) = e.probe_and_decide(&probe, &t).await;
        assert!(decision.changed, "both primaries down → one batched change");
        // One re-rendered gost config covering BOTH rules' new active backends.
        let g = decision.gost_config.expect("gost rendered");
        assert!(
            g.contains("10.0.0.2:8096"),
            "rule r1 switched to its standby"
        );
        assert!(
            g.contains("10.0.1.2:8096"),
            "rule r2 switched to its standby"
        );
        assert!(!g.contains("10.0.0.1"), "r1 dead primary not in upstream");
        assert!(!g.contains("10.0.1.1"), "r2 dead primary not in upstream");
        // Health covers every replica of every rule (4 total).
        assert_eq!(health.len(), 4);
    }

    #[tokio::test]
    async fn probe_and_decide_all_dead_rule_never_changes_no_restart() {
        // A rule whose every replica is dead must keep last-known active and report
        // `changed=false` every cycle → conn.rs never restarts → no crash-loop (OQ-8).
        let t = tunables(1, 1, 0, 5);
        let mut e = engine_with(vec![spec(
            "r1",
            8080,
            vec![ep("10.0.0.1", 8096), ep("10.0.0.2", 8096)],
        )]);
        let probe = MapProbe::default();
        probe.set_down(&ep("10.0.0.1", 8096), true);
        probe.set_down(&ep("10.0.0.2", 8096), true);

        // First cycle: primary dead but standby is... also dead, so the only
        // possible move is none → active stays on primary (last-known), no change.
        for cycle in 0..5 {
            let (decision, _h) = e.probe_and_decide(&probe, &t).await;
            assert!(
                !decision.changed,
                "all-dead rule must not produce a restart (cycle {cycle})"
            );
        }
        // Active is still the last-known primary; rule is reported down.
        assert_eq!(e.active_backends()[0].host, "10.0.0.1");
        assert!(!e.all_rules_have_healthy_replica());
    }

    #[tokio::test]
    async fn probe_and_decide_single_replica_never_restarts() {
        // Single-replica rule = today's behavior: failing it never switches/restarts.
        let t = tunables(1, 1, 0, 5);
        let mut e = engine_with(vec![spec("r1", 8080, vec![ep("10.0.0.1", 8096)])]);
        let probe = MapProbe::default();
        probe.set_down(&ep("10.0.0.1", 8096), true);
        for _ in 0..4 {
            let (decision, _h) = e.probe_and_decide(&probe, &t).await;
            assert!(!decision.changed, "single replica never triggers a switch");
        }
        assert_eq!(e.active_backends()[0].host, "10.0.0.1");
    }

    #[tokio::test]
    async fn probe_reads_rule_backends_not_a_flat_list() {
        // The engine must probe each rule's OWN ordered backends (rules[].backends),
        // independently — failing r1's primary must NOT affect r2.
        let t = tunables(1, 1, 0, 5);
        let mut e = engine_with(vec![
            spec("r1", 8080, vec![ep("10.0.0.1", 8096), ep("10.0.0.2", 8096)]),
            spec("r2", 9090, vec![ep("10.0.1.1", 8096), ep("10.0.1.2", 8096)]),
        ]);
        let probe = MapProbe::default();
        probe.set_down(&ep("10.0.0.1", 8096), true); // only r1's primary
        let (decision, _h) = e.probe_and_decide(&probe, &t).await;
        assert!(decision.changed);
        let ab = e.active_backends();
        assert_eq!(ab[0].host, "10.0.0.2", "r1 failed over to its standby");
        assert_eq!(ab[1].host, "10.0.1.1", "r2 untouched, still on its primary");
    }

    #[test]
    fn active_backends_reports_each_rule() {
        let e = engine_with(vec![
            spec("r1", 8080, vec![ep("10.0.0.1", 8096)]),
            spec("r2", 9090, vec![ep("10.0.0.2", 8096), ep("10.0.0.3", 8096)]),
        ]);
        let ab = e.active_backends();
        assert_eq!(ab.len(), 2);
        assert_eq!(ab[0].rule_id, "r1");
        assert_eq!(ab[0].host, "10.0.0.1");
        assert_eq!(ab[1].rule_id, "r2");
        assert_eq!(ab[1].host, "10.0.0.2", "primary active by default");
    }
}
