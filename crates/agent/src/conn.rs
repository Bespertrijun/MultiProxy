//! wss reverse-connect client (Line B tasks 1–3).
//!
//! Reverse-connects to the panel over WebSocket-over-TLS (rustls + the **ring**
//! crypto provider — installed at startup, see [`crate::install_crypto_provider`]),
//! sends [`Hello`] with the per-node token, adopts the server-controlled
//! heartbeat interval from [`HelloOk`], then runs a session loop that:
//!   * sends an app-level [`Heartbeat`] + a [`StatusReport`] (with capacity
//!     telemetry) every interval;
//!   * applies a [`ConfigPush`] (write config → (re)start the supervised tool →
//!     reply [`ConfigAck`]);
//!   * self-heals a crashed forwarding child on the same tick;
//!   * honours server [`Ping`] / [`Close`].
//!
//! On any disconnect it reconnects with exponential backoff (capped, jittered).
//!
//! The session loop ([`run_session`]) is generic over the WebSocket stream so
//! tests drive it with a plain-ws stream from a mock panel (no TLS), while
//! production uses the TLS stream that [`connect`] establishes for `wss://`.

use std::time::Duration;

use contract::protocol::{
    AuthRejectReason, BackendEndpoint, Capacity, CloseReason, ConfigAck, ConfigPush, Envelope,
    Heartbeat, Hello, Message,
};
use contract::version::PROTOCOL_VERSION;
use futures_util::{SinkExt, StreamExt};
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::Message as WsMessage;

use crate::capacity::{CapacityCollector, CounterSource};
use crate::config::{self, ConfigPaths};
use crate::failover::{FailoverEngine, FailoverTunables};
use crate::report::{self, ReportInputs};
use crate::selfheal::BackendProbe;
use crate::supervisor::{ProcessSpawner, Supervisor, Tool};

/// Static identity + endpoint config for the agent.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// `wss://panel.example.com/agent` in production; `ws://127.0.0.1:port/...`
    /// for the mock-panel tests.
    pub panel_url: String,
    pub node_id: String,
    pub token: String,
    pub agent_version: String,
    /// Detected platform triple (see [`crate::platform::detect`]).
    pub platform: String,
    /// Where tool config files are written.
    pub config_paths: ConfigPaths,
}

/// Exponential-backoff schedule for the reconnect loop.
#[derive(Debug, Clone)]
pub struct Backoff {
    pub initial: Duration,
    pub max: Duration,
    current: Duration,
}

impl Backoff {
    #[must_use]
    pub fn new(initial: Duration, max: Duration) -> Self {
        Self {
            initial,
            max,
            current: initial,
        }
    }

    /// Reset after a successful connection so the next outage starts small again.
    pub fn reset(&mut self) {
        self.current = self.initial;
    }

    /// Current delay, then double (capped at `max`) for next time. A small
    /// deterministic jitter (±12.5%) avoids thundering-herd reconnects without
    /// pulling a rng dependency.
    pub fn next_delay(&mut self) -> Duration {
        let base = self.current;
        let doubled = base.saturating_mul(2).min(self.max);
        self.current = doubled;
        let nanos = base.as_nanos() as u64;
        // jitter source: low bits of the monotonic clock.
        let j = (Instant::now().elapsed().subsec_nanos() as u64) % (nanos / 8 + 1);
        base.saturating_add(Duration::from_nanos(j))
    }
}

impl Default for Backoff {
    fn default() -> Self {
        Self::new(Duration::from_secs(1), Duration::from_secs(30))
    }
}

/// Why a single session ended. The reconnect loop reacts to this. The
/// `established` flag records whether the handshake (`HelloOk`) completed before
/// the session ended, so the loop can reset backoff after a genuinely-connected
/// session (a flapping panel grows the delay; a long healthy session that later
/// drops starts the next retry small again).
#[derive(Debug)]
pub enum SessionEnd {
    /// Transport closed / errored — reconnect with backoff.
    Disconnected { established: bool, why: String },
    /// Panel rejected the handshake (bad token / protocol). Reconnecting won't
    /// help for `ProtocolVersion`; the loop still backs off (operator fixes it).
    AuthRejected(AuthRejectReason),
    /// Server asked us to close for a reason (supersede / token-rotate /
    /// shutdown). Reconnect unless it's a token rotation that needs a new token.
    ServerClose(CloseReason),
    /// Local shutdown signal.
    Shutdown,
}

impl SessionEnd {
    /// Whether the handshake completed before this session ended.
    #[must_use]
    pub fn was_established(&self) -> bool {
        match self {
            SessionEnd::Disconnected { established, .. } => *established,
            // A server-initiated close or shutdown can only happen after the
            // handshake; an auth rejection happens before it.
            SessionEnd::ServerClose(_) | SessionEnd::Shutdown => true,
            SessionEnd::AuthRejected(_) => false,
        }
    }
}

/// Build the agent's `Hello` envelope.
fn hello_envelope(cfg: &AgentConfig) -> Envelope {
    Envelope::new(
        new_msg_id(),
        Message::Hello(Hello {
            node_id: cfg.node_id.clone(),
            token: cfg.token.clone(),
            agent_version: cfg.agent_version.clone(),
            platform: cfg.platform.clone(),
        }),
    )
}

/// A lightweight unique-ish message id without an rng/uuid dependency: process
/// id + a monotonic-ish nanosecond stamp.
fn new_msg_id() -> String {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{}-{}", std::process::id(), n)
}

/// Unix-millis now, for `Heartbeat.ts`.
fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Trait alias for the WebSocket stream the session loop runs over: a
/// Sink+Stream of tungstenite messages. Satisfied by both the TLS stream
/// (`wss`) and the plain-ws test stream.
pub trait WsStream:
    futures_util::Sink<WsMessage, Error = tokio_tungstenite::tungstenite::Error>
    + futures_util::Stream<Item = Result<WsMessage, tokio_tungstenite::tungstenite::Error>>
    + Unpin
{
}

impl<T> WsStream for T where
    T: futures_util::Sink<WsMessage, Error = tokio_tungstenite::tungstenite::Error>
        + futures_util::Stream<Item = Result<WsMessage, tokio_tungstenite::tungstenite::Error>>
        + Unpin
{
}

/// Runtime dependencies the session needs (supervisor + capacity + backend
/// probe). Bundled so [`run_session`] has one parameter for them.
pub struct SessionDeps<S, C, P>
where
    S: ProcessSpawner,
    C: CounterSource,
    P: BackendProbe,
{
    pub supervisor: Supervisor<S>,
    pub capacity: CapacityCollector<C>,
    pub backend: P,
    /// Backend endpoints to probe, from the latest `ConfigPush.backends`. Empty
    /// until the panel pushes the node's rules → probe reports backend-down (correct:
    /// a node with no forwarding backend is not backend-up).
    pub backends: Vec<BackendEndpoint>,
    /// Last applied config generation (0 before any push).
    pub applied_gen: u64,
}

/// Encode an envelope as a tungstenite text frame.
fn encode(env: &Envelope) -> WsMessage {
    WsMessage::Text(serde_json::to_string(env).unwrap_or_default().into())
}

/// Apply a failover switch decision: write the re-rendered single-upstream config
/// to disk and restart the supervised tool **once**.
///
/// P6 invariant: this NEVER mutates `deps.applied_gen` and NEVER sends a
/// `ConfigAck` — a local active-backend switch is not a new config generation. We
/// reuse [`config::apply`] only for its write-file + tool-selection logic by
/// handing it a synthetic push tagged with the *current* applied gen (so even if
/// some future code path read the returned gen it would be a no-op change).
fn apply_failover_switch<S, C, P>(
    decision: &crate::failover::FailoverDecision,
    deps: &mut SessionDeps<S, C, P>,
    paths: &ConfigPaths,
) where
    S: ProcessSpawner,
    C: CounterSource,
    P: BackendProbe,
{
    let synthetic = ConfigPush {
        desired_gen: deps.applied_gen,
        gost_config: decision.gost_config.clone(),
        realm_config: decision.realm_config.clone(),
        tls_cert_pem: None,
        tls_key_pem: None,
        backends: Vec::new(),
        rules: Vec::new(),
    };
    match config::apply(&synthetic, paths) {
        Ok(result) => {
            // The decision carries a config ONLY for the tool(s) whose active
            // backend changed this cycle (a gost-rule failover does not re-render
            // realm). Restart exactly those — and deliberately do NOT stop the
            // absent tool: its absence here means "unchanged", not "removed", so a
            // gost failover never bounces a healthy realm relay.
            for applied in &result.starts {
                if let Err(e) = deps.supervisor.start(applied.tool, &applied.config_path) {
                    eprintln!(
                        "failover: restart {:?} after backend switch failed: {e}",
                        applied.tool
                    );
                } else {
                    eprintln!(
                        "failover: {:?} active backend changed → re-rendered + restarted relay",
                        applied.tool
                    );
                }
            }
            // P6: deliberately DO NOT touch deps.applied_gen here.
        }
        Err(e) => eprintln!("failover: writing re-rendered config failed: {e}"),
    }
}

/// Decide, for an inbound [`ConfigPush`], which config bytes the agent writes to
/// disk + supervises, and which flat backend list it should probe next. Pure
/// (modulo mutating the engine's rule set): no I/O, so it is directly unit-testable.
///
/// Adopting the rules first is load-bearing: an EMPTY `push.rules` clears the engine
/// → [`FailoverEngine::is_active`] flips to `false` → the caller's `probe_tick` arm
/// stops switching locally → a panel kill-switch (or an older panel that never sends
/// rules) genuinely halts local failover. A NON-EMPTY `push.rules` arms/refreshes the
/// engine (reusing per-replica hysteresis for unchanged rules).
///
/// Returns `(apply_push, flat_backends)` where `flat_backends` is the NEW flat probe
/// target, or `None` to mean "keep the prior list" (caller leaves `deps.backends`
/// untouched):
///   * **engine ACTIVE** (rules non-empty) → `apply_push` is rendered from the engine's
///     CURRENT active selection (NOT the panel's primary-only string), so a node that
///     has already failed over to a standby is not shoved back to its primary by an
///     unrelated re-push (e.g. a cert renewal); the push's cert + `desired_gen` are
///     carried through, `rules`/`backends` cleared. On the very first push the engine's
///     active is the primary (index 0, optimistically up) → bytes match today's
///     first-push behavior. `flat_backends` = `Some(`deduped union of all rule backends`)`.
///   * **engine INACTIVE** (rules empty) → legacy single-upstream path: `apply_push` is
///     the panel's main-upstream string verbatim (kill-switch / older-agent route);
///     `flat_backends` tracks `push.backends`, or clears when there is genuinely no
///     config, or `None` (keep prior seed) for a pre-this-version panel that can't send
///     backends but does send a config.
fn select_apply_push(
    failover: &mut FailoverEngine,
    push: &ConfigPush,
) -> (ConfigPush, Option<Vec<BackendEndpoint>>) {
    failover.set_rules(&push.rules);
    // Gate TLS rendering on actual cert availability (mirrors the panel's
    // render_node_with_tls): a terminate rule with no cert must render plain TCP,
    // not a TLS listener pointing at a missing/stale local cert file.
    failover.set_tls_available(push.tls_cert_pem.is_some() && push.tls_key_pem.is_some());

    if failover.is_active() {
        let (gost_config, realm_config) = failover.render_active_config();
        let apply_push = ConfigPush {
            desired_gen: push.desired_gen,
            gost_config,
            realm_config,
            tls_cert_pem: push.tls_cert_pem.clone(),
            tls_key_pem: push.tls_key_pem.clone(),
            backends: Vec::new(),
            rules: Vec::new(),
        };
        (apply_push, Some(failover.flat_backends()))
    } else {
        // A new panel always sends a non-empty `backends` when there are rules (empty
        // config ⟺ no rules), so for the flat probe target:
        //   * non-empty           → adopt the pushed backends;
        //   * empty + no config   → genuinely no rules → clear;
        //   * empty + has config  → a pre-this-version panel that can't send backends
        //     → keep the prior seed (don't blank health).
        let flat = if !push.backends.is_empty() {
            Some(push.backends.clone())
        } else if push.gost_config.is_none() && push.realm_config.is_none() {
            Some(Vec::new())
        } else {
            None
        };
        (push.clone(), flat)
    }
}

/// Run one connected session until it ends. The handshake (`Hello` → wait for
/// `HelloOk`/`AuthReject`) happens here, then the heartbeat/report/config loop.
///
/// Generic over the stream so tests inject a plain-ws stream.
pub async fn run_session<W, S, C, P>(
    stream: &mut W,
    cfg: &AgentConfig,
    deps: &mut SessionDeps<S, C, P>,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> SessionEnd
where
    W: WsStream,
    S: ProcessSpawner,
    C: CounterSource,
    P: BackendProbe,
{
    // ---- handshake ----
    if stream.send(encode(&hello_envelope(cfg))).await.is_err() {
        return SessionEnd::Disconnected {
            established: false,
            why: "send Hello failed".into(),
        };
    }

    let mut heartbeat_interval =
        Duration::from_secs(contract::protocol::DEFAULT_HEARTBEAT_INTERVAL_SECS as u64);
    // The HelloOk that ends the handshake; carries the failover tunables (Phase 3
    // fields, serde-defaulted for older panels). HelloOk is the only non-`return`
    // way out of the loop, so it is always `Some` after the loop.
    let hello_ok;

    // Wait for HelloOk / AuthReject (or a transport failure).
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() { return SessionEnd::Shutdown; }
            }
            msg = stream.next() => {
                match decode_next(msg) {
                    DecodeResult::Message(Message::HelloOk(ok)) => {
                        if ok.heartbeat_interval_secs > 0 {
                            heartbeat_interval =
                                Duration::from_secs(ok.heartbeat_interval_secs as u64);
                        }
                        hello_ok = ok;
                        break;
                    }
                    DecodeResult::Message(Message::AuthReject(rej)) => {
                        return SessionEnd::AuthRejected(rej.reason);
                    }
                    DecodeResult::Message(Message::Close(c)) => {
                        return SessionEnd::ServerClose(c.reason);
                    }
                    DecodeResult::Message(_) => { /* ignore pre-handshake noise */ }
                    DecodeResult::Closed => {
                        return SessionEnd::Disconnected {
                            established: false,
                            why: "closed during handshake".into(),
                        };
                    }
                    DecodeResult::TransportError(e) => {
                        return SessionEnd::Disconnected { established: false, why: e };
                    }
                    DecodeResult::NonProtocol => { /* ignore ping/pong/binary */ }
                }
            }
        }
    }

    let tunables = FailoverTunables::from_hello_ok(&hello_ok);

    // ---- session loop ----
    let mut tick = tokio::time::interval(heartbeat_interval);
    // Fire (almost) immediately so the first report doesn't wait a full interval.
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // Independent probe/failover cadence (decoupled from the heartbeat). The
    // failover engine drives active-backend selection per `probe_interval_secs`;
    // the heartbeat arm merely *reports* the latest state on its slower cadence.
    let mut probe_tick = tokio::time::interval(tunables.probe_interval);
    probe_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // Per-session failover engine, built from the agent's config dir (for TLS
    // paths). Empty until a ConfigPush carries structured `rules`; while empty the
    // agent stays on the legacy single-upstream path (no failover, no regression).
    let mut failover = FailoverEngine::new(&cfg.config_paths);
    // Latest per-replica probe results (refreshed by the probe arm), reported on
    // the heartbeat cadence so it lags by ≤ one heartbeat — decoupled from the
    // faster failover decision cadence.
    let mut last_health: Option<Vec<contract::protocol::BackendHealth>> = None;

    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() { return SessionEnd::Shutdown; }
            }

            _ = tick.tick() => {
                // Self-heal a crashed child before reporting so the report is fresh.
                let _ = deps.supervisor.heal_if_crashed();

                // Heartbeat.
                let hb = Envelope::new(new_msg_id(), Message::Heartbeat(Heartbeat { ts: now_millis() }));
                if stream.send(encode(&hb)).await.is_err() {
                    return SessionEnd::Disconnected {
                        established: true,
                        why: "heartbeat send failed".into(),
                    };
                }

                // StatusReport (incl. capacity telemetry). Probe the REAL backends
                // pushed by the panel (not a fixed address) for `backend_reachable`.
                let capacity: Option<Capacity> = deps.capacity.sample();
                let forwarding_up = deps.supervisor.forwarding_up();
                // With structured rules: backend_reachable = every rule has a healthy
                // replica (all-rules-have-a-healthy-replica), and we attach the latest
                // per-replica health + the current active backend per rule. Without
                // rules: the legacy any-up probe, health fields omitted (no regression).
                let (backend_reachable, backend_health, active_backends) = if failover.is_active() {
                    (
                        failover.all_rules_have_healthy_replica(),
                        last_health.clone(),
                        Some(failover.active_backends()),
                    )
                } else {
                    (deps.backend.reachable(&deps.backends).await, None, None)
                };
                let report = report::build(ReportInputs {
                    forwarding_up,
                    backend_reachable,
                    applied_config_gen: deps.applied_gen,
                    restart_count: deps.supervisor.restart_count(),
                    pids: deps.supervisor.pids(),
                    capacity,
                    backend_health,
                    active_backends,
                });
                let env = Envelope::new(new_msg_id(), Message::StatusReport(report));
                if stream.send(encode(&env)).await.is_err() {
                    return SessionEnd::Disconnected {
                        established: true,
                        why: "status send failed".into(),
                    };
                }
            }

            // Independent failover cadence: probe every replica of every rule and
            // let the engine pick each rule's active backend. Only runs once the
            // panel has pushed structured rules; otherwise it is a cheap no-op so
            // the legacy single-upstream path is unaffected.
            _ = probe_tick.tick() => {
                if failover.is_active() {
                    let (decision, health) =
                        failover.probe_and_decide(&deps.backend, &tunables).await;
                    last_health = Some(health);

                    // Only an ACTUAL active-backend change triggers a re-render +
                    // a SINGLE restart (all rule changes this cycle are batched).
                    // OQ-8: an all-dead rule keeps last-known → no change → no
                    // restart → never a crash-loop. P6: a local switch NEVER touches
                    // applied_gen and NEVER emits a ConfigAck — the new active is
                    // surfaced only via the next StatusReport.active_backends.
                    if decision.changed {
                        apply_failover_switch(&decision, deps, &cfg.config_paths);
                    }
                }
            }

            msg = stream.next() => {
                match decode_next(msg) {
                    DecodeResult::Message(Message::ConfigPush(push)) => {
                        // Select the bytes that actually hit disk + supervisor (pure decision,
                        // see `select_apply_push`), then reset the stale per-replica health
                        // snapshot so the next probe cycle re-populates it.
                        let (apply_push, new_backends) =
                            select_apply_push(&mut failover, &push);
                        if let Some(backends) = new_backends {
                            deps.backends = backends;
                        }
                        last_health = None;
                        eprintln!(
                            "config: gen={} backend probe target(s)=[{}]",
                            push.desired_gen,
                            deps.backends
                                .iter()
                                .map(|b| format!("{}:{}", b.host, b.port))
                                .collect::<Vec<_>>()
                                .join(", ")
                        );
                        let ack = match config::apply(&apply_push, &cfg.config_paths) {
                            Ok(result) => {
                                // A full-node render: start every tool the push carried
                                // (gost AND realm for a mixed node) and STOP any tool no
                                // longer present (e.g. all of a node's realm rules were
                                // deleted) so a removed tool doesn't linger holding a port.
                                let want_gost =
                                    result.starts.iter().any(|s| s.tool == Tool::Gost);
                                let want_realm =
                                    result.starts.iter().any(|s| s.tool == Tool::Realm);
                                // STOP absent tools BEFORE starting present ones: a rule
                                // that moves to a different tool on the SAME listen port
                                // must free the port before the new tool binds it, else the
                                // new spawn hits EADDRINUSE.
                                if !want_gost {
                                    deps.supervisor.stop_tool(Tool::Gost);
                                }
                                if !want_realm {
                                    deps.supervisor.stop_tool(Tool::Realm);
                                }
                                let mut spawn_errs: Vec<String> = Vec::new();
                                for applied in &result.starts {
                                    if let Err(e) =
                                        deps.supervisor.start(applied.tool, &applied.config_path)
                                    {
                                        spawn_errs.push(format!("{:?}: {e}", applied.tool));
                                    }
                                }
                                if spawn_errs.is_empty() {
                                    deps.applied_gen = result.applied_gen;
                                    ConfigAck { applied_gen: result.applied_gen, ok: true, err: None }
                                } else {
                                    // Keep applied_gen at the LAST good gen (NOT desired): the
                                    // panel ignores `ok` and re-pushes only while
                                    // applied != desired, so acking desired on failure would
                                    // look converged and the broken node would never be
                                    // re-pushed (the failed tool stays down forever).
                                    ConfigAck {
                                        applied_gen: deps.applied_gen,
                                        ok: false,
                                        err: Some(format!("spawn failed: {}", spawn_errs.join("; "))),
                                    }
                                }
                            }
                            Err(e) => ConfigAck {
                                applied_gen: deps.applied_gen,
                                ok: false,
                                err: Some(format!("write failed: {e}")),
                            },
                        };
                        let env = Envelope::new(new_msg_id(), Message::ConfigAck(ack));
                        if stream.send(encode(&env)).await.is_err() {
                            return SessionEnd::Disconnected {
                                established: true,
                                why: "ack send failed".into(),
                            };
                        }
                    }
                    DecodeResult::Message(Message::Ping) => {
                        // Reply at the app level isn't required (heartbeat covers
                        // liveness); ignore. A ws-level Ping is handled below.
                    }
                    DecodeResult::Message(Message::Close(c)) => {
                        return SessionEnd::ServerClose(c.reason);
                    }
                    DecodeResult::Message(Message::UpdateAgent) => {
                        // Panel asked us to upgrade: pull the new binary from the
                        // panel's /dl/, replace this executable, and restart. On
                        // success self_update never returns (it exits/exec's).
                        eprintln!("received UpdateAgent; self-updating from panel");
                        match crate::updater::self_update(&cfg.panel_url).await {
                            Ok(false) => eprintln!("self-update: already up to date"),
                            Ok(true) => {}
                            Err(e) => eprintln!("self-update failed: {e}"),
                        }
                    }
                    DecodeResult::Message(_) => { /* ignore unexpected agent-bound kinds */ }
                    DecodeResult::Closed => {
                        return SessionEnd::Disconnected {
                            established: true,
                            why: "peer closed".into(),
                        };
                    }
                    DecodeResult::TransportError(e) => {
                        return SessionEnd::Disconnected { established: true, why: e };
                    }
                    DecodeResult::NonProtocol => { /* ws ping/pong/binary: ignore */ }
                }
            }
        }
    }
}

/// Classification of the next inbound ws item.
enum DecodeResult {
    Message(Message),
    /// A non-protocol ws frame (ping/pong/binary/empty) — ignore.
    NonProtocol,
    /// Peer closed the stream cleanly.
    Closed,
    /// Transport-level error.
    TransportError(String),
}

fn decode_next(
    item: Option<Result<WsMessage, tokio_tungstenite::tungstenite::Error>>,
) -> DecodeResult {
    match item {
        None => DecodeResult::Closed,
        Some(Err(e)) => DecodeResult::TransportError(e.to_string()),
        Some(Ok(WsMessage::Text(txt))) => match serde_json::from_str::<Envelope>(&txt) {
            Ok(env) => DecodeResult::Message(env.message),
            // A malformed/unknown frame is not fatal — ignore it (forward-compat).
            Err(_) => DecodeResult::NonProtocol,
        },
        Some(Ok(WsMessage::Close(_))) => DecodeResult::Closed,
        Some(Ok(_)) => DecodeResult::NonProtocol, // ping/pong/binary/frame
    }
}

/// Whether the protocol version we speak is the one this build advertises. The
/// panel does the authoritative gate (gap 7.4); this is a local sanity assert.
#[must_use]
pub fn protocol_version() -> u32 {
    PROTOCOL_VERSION
}

/// Establish a real WebSocket connection (TLS for `wss://`, plain for `ws://`)
/// and run a single session over it. tokio-tungstenite drives the TLS handshake
/// with the rustls **ring** provider (installed in [`crate::install_crypto_provider`])
/// and validates the panel cert against the webpki root store (task 1).
///
/// Returns how the session ended so the reconnect loop can react.
pub async fn connect_and_run<S, C, P>(
    cfg: &AgentConfig,
    deps: &mut SessionDeps<S, C, P>,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> SessionEnd
where
    S: ProcessSpawner,
    C: CounterSource,
    P: BackendProbe,
{
    match tokio_tungstenite::connect_async(&cfg.panel_url).await {
        Ok((mut ws, _resp)) => run_session(&mut ws, cfg, deps, shutdown).await,
        Err(e) => SessionEnd::Disconnected {
            established: false,
            why: format!("connect failed: {e}"),
        },
    }
}

/// Top-level reconnect-with-backoff loop (task 1). Connects, runs a session,
/// and on any disconnect waits a backoff delay and retries — until a local
/// shutdown is signalled. A clean `Shutdown`/token-rotation end stops the loop.
pub async fn run_reconnect_loop<S, C, P>(
    cfg: &AgentConfig,
    mut deps: SessionDeps<S, C, P>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    mut backoff: Backoff,
) where
    S: ProcessSpawner,
    C: CounterSource,
    P: BackendProbe,
{
    loop {
        if *shutdown.borrow() {
            break;
        }

        let end = connect_and_run(cfg, &mut deps, &mut shutdown).await;
        match &end {
            SessionEnd::Shutdown => break,
            SessionEnd::ServerClose(CloseReason::TokenRotated) => {
                // The operator must distribute a new token; reconnecting with the
                // stale one will just be rejected. Stop the loop (a real deploy
                // would reload config here). Documented behavior.
                break;
            }
            // Everything else (transport drop, supersede, shutdown-close, auth
            // reject) → back off and retry.
            _ => {}
        }

        // A session that actually established before dropping resets the backoff
        // so the next outage starts small; repeated pre-handshake failures keep
        // growing the delay.
        if end.was_established() {
            backoff.reset();
        }

        let delay = backoff.next_delay();
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
            _ = tokio::time::sleep(delay) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_and_caps() {
        let mut b = Backoff::new(Duration::from_millis(100), Duration::from_millis(800));
        let d0 = b.next_delay();
        assert!(d0 >= Duration::from_millis(100) && d0 < Duration::from_millis(120));
        // current is now 200, 400, 800, then capped at 800.
        b.next_delay();
        b.next_delay();
        let d3 = b.next_delay(); // base = 800 (capped)
        assert!(d3 >= Duration::from_millis(800));
        let d4 = b.next_delay();
        assert!(d4 >= Duration::from_millis(800) && d4 < Duration::from_millis(1000));
    }

    #[test]
    fn backoff_reset_returns_to_initial() {
        let mut b = Backoff::new(Duration::from_millis(50), Duration::from_secs(5));
        b.next_delay();
        b.next_delay();
        b.reset();
        let d = b.next_delay();
        assert!(d >= Duration::from_millis(50) && d < Duration::from_millis(60));
    }

    #[test]
    fn msg_ids_are_distinct() {
        let a = new_msg_id();
        let b = new_msg_id();
        assert_ne!(a, b);
    }

    fn ep(host: &str, port: u16) -> BackendEndpoint {
        BackendEndpoint {
            host: host.into(),
            port,
        }
    }

    fn rule_spec(
        id: &str,
        port: u16,
        backends: Vec<BackendEndpoint>,
    ) -> contract::protocol::RuleSpec {
        contract::protocol::RuleSpec {
            rule_id: id.into(),
            listen_port: port,
            protocol: contract::model::Protocol::Tcp,
            tls_mode: contract::model::TlsMode::Passthrough,
            tool: contract::model::Tool::Gost,
            backends,
        }
    }

    /// Per-endpoint controllable probe (host:port keyed) so a test can fail a
    /// specific replica and drive the engine to a standby deterministically — with
    /// no timer (we call `probe_and_decide` directly).
    #[derive(Clone, Default)]
    struct MapProbe {
        down: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
    }
    impl MapProbe {
        fn key(e: &BackendEndpoint) -> String {
            format!("{}:{}", e.host, e.port)
        }
        fn set_down(&self, e: &BackendEndpoint, down: bool) {
            let mut g = self.down.lock().unwrap();
            if down {
                g.insert(Self::key(e));
            } else {
                g.remove(&Self::key(e));
            }
        }
    }
    impl crate::selfheal::BackendProbe for MapProbe {
        async fn reachable_each(
            &self,
            targets: &[BackendEndpoint],
        ) -> Vec<contract::protocol::BackendHealth> {
            let g = self.down.lock().unwrap();
            targets
                .iter()
                .map(|t| contract::protocol::BackendHealth {
                    host: t.host.clone(),
                    port: t.port,
                    reachable: !g.contains(&Self::key(t)),
                })
                .collect()
        }
    }

    fn tunables_max_fails_1() -> FailoverTunables {
        FailoverTunables {
            probe_interval: Duration::from_secs(5),
            probe_timeout: Duration::from_millis(100),
            max_fails: 1,
            recovery_checks: 1,
            min_dwell: Duration::from_secs(0),
        }
    }

    fn push_with_rules(
        desired_gen: u64,
        gost_config: Option<String>,
        backends: Vec<BackendEndpoint>,
        rules: Vec<contract::protocol::RuleSpec>,
    ) -> ConfigPush {
        ConfigPush {
            desired_gen,
            gost_config,
            realm_config: None,
            tls_cert_pem: None,
            tls_key_pem: None,
            backends,
            rules,
        }
    }

    // Kill-switch / empty-rules push: the engine clears (is_active=false) and the
    // panel's main-upstream string is what hits disk verbatim (local failover off).
    #[test]
    fn select_apply_push_empty_rules_is_killswitch_and_applies_panel_string() {
        let paths = ConfigPaths::under("/tmp/conn-killswitch-test");
        let mut failover = FailoverEngine::new(&paths);

        // First arm the engine with a rule so it is active...
        let armed = push_with_rules(
            1,
            Some("{\"services\":[{\"name\":\"engine-rendered\"}]}".into()),
            vec![ep("10.0.0.1", 8096)],
            vec![rule_spec("r1", 8080, vec![ep("10.0.0.1", 8096)])],
        );
        let _ = select_apply_push(&mut failover, &armed);
        assert!(failover.is_active(), "engine armed by the first push");

        // ...then a kill-switch push with rules=[] but a panel main-upstream string.
        let panel_string = "{\"services\":[{\"name\":\"PANEL-KILLSWITCH-VERBATIM\"}]}".to_string();
        let killswitch = push_with_rules(
            2,
            Some(panel_string.clone()),
            vec![ep("10.0.0.1", 8096)],
            vec![],
        );
        let (apply_push, flat) = select_apply_push(&mut failover, &killswitch);

        assert!(
            !failover.is_active(),
            "empty rules clear the engine → local failover halted (kill-switch works)"
        );
        assert_eq!(
            apply_push.gost_config.as_deref(),
            Some(panel_string.as_str()),
            "kill-switch applies the panel's main-upstream string verbatim, not an engine render"
        );
        // Legacy path tracks the pushed flat backends for the any-up probe.
        assert_eq!(flat, Some(vec![ep("10.0.0.1", 8096)]));
    }

    // After a failover to the standby, an IDENTICAL re-push (e.g. cert renewal) must
    // write the engine's CURRENT active (standby) to disk — never shove it back to the
    // primary.
    #[tokio::test]
    async fn select_apply_push_repush_reflects_current_active_not_primary() {
        let paths = ConfigPaths::under("/tmp/conn-repush-test");
        let mut failover = FailoverEngine::new(&paths);
        let rules = vec![rule_spec(
            "r1",
            8080,
            vec![ep("10.0.0.1", 8096), ep("10.0.0.2", 8096)],
        )];

        // First push arms the engine; active = primary (index 0).
        let first = push_with_rules(
            1,
            Some("panel-primary-string".into()),
            vec![ep("10.0.0.1", 8096), ep("10.0.0.2", 8096)],
            rules.clone(),
        );
        let (apply_first, _) = select_apply_push(&mut failover, &first);
        let g0 = apply_first
            .gost_config
            .expect("gost rendered on first push");
        assert!(
            g0.contains("10.0.0.1:8096"),
            "first push serves the primary"
        );
        assert!(!g0.contains("10.0.0.2"), "standby not yet active");

        // Drive a real failover to the standby (primary down) via the engine — no timer.
        let t = tunables_max_fails_1();
        let probe = MapProbe::default();
        probe.set_down(&ep("10.0.0.1", 8096), true);
        let (decision, _h) = failover.probe_and_decide(&probe, &t).await;
        assert!(decision.changed, "primary down → switched to standby");

        // An IDENTICAL re-push (same rules) — simulates a cert-renewal / unrelated push.
        let repush = push_with_rules(
            2,
            Some("panel-primary-string".into()),
            vec![ep("10.0.0.1", 8096), ep("10.0.0.2", 8096)],
            rules.clone(),
        );
        let (apply_repush, _) = select_apply_push(&mut failover, &repush);
        let g1 = apply_repush
            .gost_config
            .clone()
            .expect("gost rendered on re-push");
        assert!(
            g1.contains("10.0.0.2:8096"),
            "re-push must reflect the engine's CURRENT active (standby), not the primary"
        );
        assert!(
            !g1.contains("10.0.0.1"),
            "the failed-over primary must NOT be shoved back as the upstream"
        );
        assert_ne!(
            apply_repush.gost_config.as_deref(),
            Some("panel-primary-string"),
            "the panel's primary-only string is NOT what gets written while active"
        );
    }

    #[test]
    fn hello_envelope_carries_identity() {
        let cfg = AgentConfig {
            panel_url: "ws://x".into(),
            node_id: "n1".into(),
            token: "tok".into(),
            agent_version: "0.1.0".into(),
            platform: "x86_64-linux".into(),
            config_paths: ConfigPaths::under("/tmp"),
        };
        match hello_envelope(&cfg).message {
            Message::Hello(h) => {
                assert_eq!(h.node_id, "n1");
                assert_eq!(h.token, "tok");
                assert_eq!(h.platform, "x86_64-linux");
            }
            _ => panic!("not a hello"),
        }
    }
}
