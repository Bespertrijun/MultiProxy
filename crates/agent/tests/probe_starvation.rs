//! Integration regression proof for the v0.10.4 incident: a **blocked/slow
//! failover probe must NOT starve the heartbeat** (NAT nodes going Offline).
//!
//! Root cause (see `.omc/plans/v0.10.4-probe-starvation-fix.md`): the failover
//! probe cycle used a hardcoded 3s connect timeout, probed serially, and was
//! `await`ed **inline** in the biased session `select!`. On a NAT node whose
//! standby backend is unreachable, one cycle cost Σ(unreachable × 3s), which
//! suspended the heartbeat tick past the panel's freshness window → the node was
//! marked Offline even though it was healthy and reachable.
//!
//! These tests drive the **real session path** (`run_session` over a plain-ws
//! mock panel — acceptable for tests per the brief) with a `ConfigPush` carrying
//! structured `rules` = a reachable primary + an **unreachable standby**, and
//! assert the panel keeps receiving `Heartbeat` frames at ~the configured cadence
//! for ≥5s. Before the fix the heartbeats would stall while the probe blocked;
//! after it (A1 concurrent probing + A2 honoring the panel `probe_timeout` +
//! A3 outer cycle-budget) they flow.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use agent::capacity::CapacityCollector;
use agent::config::ConfigPaths;
use agent::conn::{run_session, AgentConfig, SessionDeps};
use agent::selfheal::{BackendProbe, TcpBackendProbe};
use agent::supervisor::Supervisor;
use agent::testutil::{DummySpawner, SteppingCounterSource};

use contract::model::{Protocol, TlsMode, Tool};
use contract::protocol::{
    BackendEndpoint, BackendHealth, ConfigPush, Envelope, HelloOk, Message, RuleSpec,
};
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message as WsMessage;

/// Spin up a plain-ws mock panel that speaks the failover-arming handshake:
///   1. accepts one connection,
///   2. expects a `Hello`, forwards it, replies with the supplied `HelloOk`
///      (tight cadences so the test is quick),
///   3. pushes the supplied `ConfigPush` (carrying structured `rules` → arms the
///      agent's failover engine),
///   4. drains every inbound frame (`Heartbeat` / `StatusReport` / `ConfigAck`)
///      and forwards it to the test over `saw_tx` so the test can observe the
///      heartbeat cadence.
async fn start_failover_mock_panel(
    hello_ok: HelloOk,
    push: ConfigPush,
    saw_tx: tokio::sync::mpsc::UnboundedSender<Message>,
) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("ws://{addr}/agent");

    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();

        // 1. Hello.
        let hello = next_msg(&mut ws).await.expect("hello");
        saw_tx.send(hello).ok();

        // 2. HelloOk with the tight failover cadences.
        send_msg(&mut ws, Message::HelloOk(hello_ok)).await;

        // 3. ConfigPush with structured rules → arms the failover engine so the
        //    probe/decide cadence runs and can (pre-fix) starve the heartbeat.
        send_msg(&mut ws, Message::ConfigPush(push)).await;

        // 4. Drain inbound frames until the socket closes / the test is done.
        while let Some(m) = next_msg(&mut ws).await {
            if saw_tx.send(m).is_err() {
                break;
            }
        }
    });

    url
}

async fn next_msg<S>(ws: &mut S) -> Option<Message>
where
    S: futures_util::Stream<Item = Result<WsMessage, tokio_tungstenite::tungstenite::Error>>
        + Unpin,
{
    while let Some(item) = ws.next().await {
        match item {
            Ok(WsMessage::Text(t)) => {
                if let Ok(env) = serde_json::from_str::<Envelope>(&t) {
                    return Some(env.message);
                }
            }
            Ok(WsMessage::Close(_)) | Err(_) => return None,
            _ => continue,
        }
    }
    None
}

async fn send_msg<S>(ws: &mut S, message: Message)
where
    S: futures_util::Sink<WsMessage, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    let env = Envelope::new("mock", message);
    ws.send(WsMessage::Text(serde_json::to_string(&env).unwrap().into()))
        .await
        .unwrap();
}

fn ep(host: &str, port: u16) -> BackendEndpoint {
    BackendEndpoint {
        host: host.into(),
        port,
    }
}

/// A `HelloOk` with tight failover cadences (fast heartbeat + probe) so the test
/// exercises many probe cycles in a few seconds.
fn tight_hello_ok(probe_timeout_ms: u32) -> HelloOk {
    HelloOk {
        session: "s-fo".into(),
        heartbeat_interval_secs: 1,
        probe_interval_secs: 1,
        probe_timeout_ms,
        failover_max_fails: 3,
        failover_recovery_checks: 6,
        min_dwell_secs: 60,
    }
}

/// One gost rule `[primary, standby]`.
fn one_rule(primary: BackendEndpoint, standby: BackendEndpoint) -> RuleSpec {
    RuleSpec {
        rule_id: "r1".into(),
        listen_port: 8080,
        protocol: Protocol::Tcp,
        tls_mode: TlsMode::Passthrough,
        tool: Tool::Gost,
        backends: vec![primary, standby],
    }
}

/// Collect heartbeat arrival instants + every StatusReport the panel saw for a
/// fixed wall-clock `window`, then return them. Runs concurrently with the driven
/// `run_session` (via the caller's `select!`).
async fn collect_for(
    window: Duration,
    saw_rx: &mut tokio::sync::mpsc::UnboundedReceiver<Message>,
) -> (Vec<Instant>, Vec<contract::protocol::StatusReport>) {
    let mut hb_times = Vec::new();
    let mut reports = Vec::new();
    let deadline = tokio::time::sleep(window);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => break,
            m = saw_rx.recv() => match m {
                Some(Message::Heartbeat(_)) => hb_times.push(Instant::now()),
                Some(Message::StatusReport(r)) => reports.push(r),
                Some(_) => {}
                None => break,
            },
        }
    }
    (hb_times, reports)
}

/// Assert heartbeats arrived promptly and continuously across the whole window:
/// no gap between session start, any two consecutive heartbeats, or the last
/// heartbeat and the window end exceeds `max_gap`. This is the starvation guard —
/// a blocked probe that suspended the heartbeat would open a gap wider than the
/// configured heartbeat interval.
fn assert_no_heartbeat_starvation(
    start: Instant,
    hb_times: &[Instant],
    window_end: Instant,
    min_heartbeats: usize,
    max_gap: Duration,
) {
    assert!(
        hb_times.len() >= min_heartbeats,
        "heartbeats starved: got {} in the window, want >= {min_heartbeats}",
        hb_times.len()
    );
    let mut points = Vec::with_capacity(hb_times.len() + 2);
    points.push(start);
    points.extend_from_slice(hb_times);
    points.push(window_end);
    for pair in points.windows(2) {
        let gap = pair[1].duration_since(pair[0]);
        assert!(
            gap < max_gap,
            "heartbeat gap {gap:?} exceeded {max_gap:?} — the probe starved the heartbeat"
        );
    }
}

/// WU-4 — the incident's regression proof.
///
/// A NAT node whose rule has a **reachable primary** (a live local listener) and
/// an **unreachable standby** (`192.0.2.1`, RFC5737 TEST-NET-1 — a connect there
/// blocks until the deadline). The agent is handed a real [`TcpBackendProbe`] with
/// the *old production* 3s connect timeout; the fix makes the engine honor the
/// panel's `probe_timeout` (300ms) and probe concurrently, so a whole cycle costs
/// ~one 300ms deadline instead of blocking multiple seconds. The heartbeat must
/// keep flowing at ~its 1s cadence for ≥5s.
///
/// Pre-fix this test would fail: the standby connect would block ~3s inline in the
/// session `select!`, opening multi-second heartbeat gaps.
#[tokio::test]
async fn blocked_standby_probe_does_not_starve_heartbeats() {
    // A live local listener = the reachable primary. Never `accept()`ed, but the
    // OS completes the TCP handshake into the backlog so a connect succeeds. Held
    // alive for the whole test.
    let primary_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let primary_port = primary_listener.local_addr().unwrap().port();
    let primary = ep("127.0.0.1", primary_port);
    // RFC5737 TEST-NET-1 — guaranteed non-routable; a connect here hangs to the
    // per-probe deadline (verified ~300ms in-sandbox), the exact NAT condition.
    let standby = ep("192.0.2.1", 80);

    let (saw_tx, mut saw_rx) = tokio::sync::mpsc::unbounded_channel();
    let push = ConfigPush {
        desired_gen: 1,
        gost_config: None, // engine renders the single-upstream config from the active backend
        realm_config: None,
        tls_cert_pem: None,
        tls_key_pem: None,
        backends: vec![primary.clone(), standby.clone()],
        rules: vec![one_rule(primary.clone(), standby.clone())],
    };
    let url = start_failover_mock_panel(tight_hello_ok(300), push, saw_tx).await;

    let tmp = std::env::temp_dir().join(format!("agent-probestarve-{}", std::process::id()));
    let cfg = AgentConfig {
        panel_url: url.clone(),
        node_id: "node-fo".into(),
        token: "tok".into(),
        agent_version: "0.1.0-test".into(),
        platform: agent::platform::detect(),
        config_paths: ConfigPaths::under(&tmp),
    };

    let (spawner, _control) = DummySpawner::new();
    // A real TCP probe carrying the *old* hardcoded 3s timeout: the fix must make
    // the engine honor the panel's 300ms `probe_timeout` instead, so this 3s value
    // never actually stalls the cycle.
    let mut deps = SessionDeps {
        supervisor: Supervisor::new(spawner),
        capacity: CapacityCollector::new(
            SteppingCounterSource::new(1000),
            7,
            Duration::from_secs(60),
        ),
        backend: TcpBackendProbe::new(Duration::from_secs(3)),
        backends: vec![],
        applied_gen: 0,
    };

    let (_sd_tx, mut sd_rx) = tokio::sync::watch::channel(false);
    let (mut client_ws, _resp) = tokio_tungstenite::connect_async(&url).await.unwrap();

    let start = Instant::now();
    let agent_fut = run_session(&mut client_ws, &cfg, &mut deps, &mut sd_rx);
    let (hb_times, reports) = tokio::select! {
        _ = agent_fut => unreachable!("session must not end before the window closes"),
        v = collect_for(Duration::from_millis(6000), &mut saw_rx) => v,
    };
    let window_end = Instant::now();

    // The heartbeat flowed at ~1s cadence for the whole ~6s window despite the
    // unreachable standby — no multi-second starvation gap anywhere.
    assert_no_heartbeat_starvation(start, &hb_times, window_end, 4, Duration::from_millis(2500));

    // And the probe cycle still completed (concurrently, within budget): a report
    // for the applied config carries populated per-replica `backend_health` and
    // stays active on the reachable primary — no false failover to the dead standby.
    let applied = reports
        .iter()
        .find(|r| r.applied_config_gen == 1 && r.backend_health.is_some());
    let applied = applied.expect("a StatusReport for the applied config with backend_health");
    let health = applied.backend_health.as_ref().unwrap();
    assert_eq!(health.len(), 2, "both replicas probed");
    assert!(
        health.iter().any(|h| h.host == "127.0.0.1" && h.reachable),
        "the reachable primary is healthy: {health:?}"
    );
    assert!(
        health.iter().any(|h| h.host == "192.0.2.1" && !h.reachable),
        "the unreachable standby is down: {health:?}"
    );
    let active = applied
        .active_backends
        .as_ref()
        .expect("active_backends present");
    assert_eq!(active[0].rule_id, "r1");
    assert_eq!(
        active[0].host, "127.0.0.1",
        "stayed active on the healthy primary (no false switch)"
    );

    drop(primary_listener);
    std::fs::remove_dir_all(&tmp).ok();
}

/// A `BackendProbe` whose FIRST failover cycle answers fast, then every subsequent
/// cycle **hangs forever** — a probe that blocks past its per-endpoint deadline.
/// This forces conn.rs's outer cycle-budget (`< heartbeat`) to be the thing that
/// (a) keeps heartbeats flowing and (b) preserves the `last_health` captured on
/// the fast cycle. The legacy `reachable` (pre-ConfigPush any-up path) is answered
/// without consuming a cycle so the counter tracks only failover probe cycles.
#[derive(Clone, Default)]
struct FastThenHangProbe {
    cycles: Arc<AtomicU32>,
}

impl BackendProbe for FastThenHangProbe {
    async fn reachable(&self, _targets: &[BackendEndpoint]) -> bool {
        false
    }

    async fn reachable_each(&self, targets: &[BackendEndpoint]) -> Vec<BackendHealth> {
        let n = self.cycles.fetch_add(1, Ordering::SeqCst);
        if n == 0 {
            targets
                .iter()
                .map(|t| BackendHealth {
                    host: t.host.clone(),
                    port: t.port,
                    reachable: t.host == "10.0.0.1", // primary up, standby down
                })
                .collect()
        } else {
            // Block forever: the outer cycle-budget must elapse each cycle, keep
            // the last-known health, take no switch, and let heartbeats proceed.
            std::future::pending().await
        }
    }
}

/// conn.rs cycle-budget / `last_health` guarantee (plan test 6), proven end-to-end
/// through the real session path.
///
/// `last_health` is a local in `run_session`, observable only via
/// `StatusReport.backend_health`. We arm the engine, let the FIRST probe cycle
/// populate `last_health`, then make every later cycle exceed the cycle-budget
/// (the probe hangs). The budget must:
///   * keep heartbeats flowing (no starvation), and
///   * preserve `last_health` — every later report still carries the *same*
///     populated `backend_health` (never `None`, never changed) and the active
///     backend never switches.
#[tokio::test]
async fn budget_exceeding_probe_preserves_last_health_and_heartbeats() {
    let primary = ep("10.0.0.1", 8096);
    let standby = ep("10.0.0.2", 8096);

    let (saw_tx, mut saw_rx) = tokio::sync::mpsc::unbounded_channel();
    let push = ConfigPush {
        desired_gen: 1,
        gost_config: None,
        realm_config: None,
        tls_cert_pem: None,
        tls_key_pem: None,
        backends: vec![primary.clone(), standby.clone()],
        rules: vec![one_rule(primary.clone(), standby.clone())],
    };
    // probe_timeout 100ms, heartbeat 1s → cycle_budget = 500ms (< heartbeat).
    let url = start_failover_mock_panel(tight_hello_ok(100), push, saw_tx).await;

    let tmp = std::env::temp_dir().join(format!("agent-budget-{}", std::process::id()));
    let cfg = AgentConfig {
        panel_url: url.clone(),
        node_id: "node-budget".into(),
        token: "tok".into(),
        agent_version: "0.1.0-test".into(),
        platform: agent::platform::detect(),
        config_paths: ConfigPaths::under(&tmp),
    };

    let (spawner, _control) = DummySpawner::new();
    let mut deps = SessionDeps {
        supervisor: Supervisor::new(spawner),
        capacity: CapacityCollector::new(
            SteppingCounterSource::new(1000),
            7,
            Duration::from_secs(60),
        ),
        backend: FastThenHangProbe::default(),
        backends: vec![],
        applied_gen: 0,
    };

    let (_sd_tx, mut sd_rx) = tokio::sync::watch::channel(false);
    let (mut client_ws, _resp) = tokio_tungstenite::connect_async(&url).await.unwrap();

    let start = Instant::now();
    let agent_fut = run_session(&mut client_ws, &cfg, &mut deps, &mut sd_rx);
    let (hb_times, reports) = tokio::select! {
        _ = agent_fut => unreachable!("session must not end before the window closes"),
        v = collect_for(Duration::from_millis(6000), &mut saw_rx) => v,
    };
    let window_end = Instant::now();

    // The permanently-hanging probe never starves the heartbeat: the cycle-budget
    // caps each blocked cycle at 500ms < the 1s heartbeat interval.
    assert_no_heartbeat_starvation(start, &hb_times, window_end, 4, Duration::from_millis(2500));

    // `last_health` set on the fast first cycle is preserved across every later
    // budget-exceeding cycle: all reports that carry it are identical, it never
    // reverts to `None`, and the active backend never switches.
    let populated: Vec<_> = reports
        .iter()
        .filter(|r| r.backend_health.is_some())
        .collect();
    assert!(
        populated.len() >= 2,
        "expected the fast cycle's health to persist across >=1 budget-exceeding cycle, \
         saw {} populated reports",
        populated.len()
    );
    let first = populated[0].backend_health.clone();
    for r in &populated {
        assert_eq!(
            r.backend_health, first,
            "last_health must be preserved unchanged across budget-exceeding cycles"
        );
        let active = r.active_backends.as_ref().expect("active_backends present");
        assert_eq!(active[0].rule_id, "r1");
        assert_eq!(
            active[0].host, "10.0.0.1",
            "no false switch off the healthy primary when the probe cycle elapses"
        );
    }
    let h0 = first.expect("populated health is Some");
    assert_eq!(h0.len(), 2, "both replicas captured on the fast cycle");
    assert!(
        h0.iter().any(|h| h.host == "10.0.0.1" && h.reachable),
        "primary healthy on the fast cycle: {h0:?}"
    );

    std::fs::remove_dir_all(&tmp).ok();
}
