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
    AuthRejectReason, BackendEndpoint, Capacity, CloseReason, ConfigAck, Envelope, Heartbeat,
    Hello, Message,
};
use contract::version::PROTOCOL_VERSION;
use futures_util::{SinkExt, StreamExt};
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::Message as WsMessage;

use crate::capacity::{CapacityCollector, CounterSource};
use crate::config::{self, ApplyOutcome, ConfigPaths};
use crate::report::{self, ReportInputs};
use crate::selfheal::BackendProbe;
use crate::supervisor::{ProcessSpawner, Supervisor};

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

    // ---- session loop ----
    let mut tick = tokio::time::interval(heartbeat_interval);
    // Fire (almost) immediately so the first report doesn't wait a full interval.
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

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
                let backend_reachable = deps.backend.reachable(&deps.backends).await;
                let report = report::build(ReportInputs {
                    forwarding_up,
                    backend_reachable,
                    applied_config_gen: deps.applied_gen,
                    restart_count: deps.supervisor.restart_count(),
                    pid: deps.supervisor.pid(),
                    capacity,
                });
                let env = Envelope::new(new_msg_id(), Message::StatusReport(report));
                if stream.send(encode(&env)).await.is_err() {
                    return SessionEnd::Disconnected {
                        established: true,
                        why: "status send failed".into(),
                    };
                }
            }

            msg = stream.next() => {
                match decode_next(msg) {
                    DecodeResult::Message(Message::ConfigPush(push)) => {
                        // Track the real backends so the next health probe targets them.
                        // A new panel always sends a non-empty `backends` when there are
                        // rules (empty config ⟺ no rules), so:
                        //   * non-empty           → adopt the pushed backends;
                        //   * empty + no config   → genuinely no rules → clear;
                        //   * empty + has config  → a pre-this-version panel that can't
                        //     send backends → keep the fallback seed (don't blank health).
                        if !push.backends.is_empty() {
                            deps.backends = push.backends.clone();
                        } else if push.gost_config.is_none() && push.realm_config.is_none() {
                            deps.backends.clear();
                        }
                        eprintln!(
                            "config: gen={} backend probe target(s)=[{}]",
                            push.desired_gen,
                            deps.backends
                                .iter()
                                .map(|b| format!("{}:{}", b.host, b.port))
                                .collect::<Vec<_>>()
                                .join(", ")
                        );
                        let ack = match config::apply(&push, &cfg.config_paths) {
                            Ok(ApplyOutcome::Start(applied)) => {
                                let start = deps.supervisor.start(applied.tool, applied.config_path);
                                match start {
                                    Ok(()) => {
                                        deps.applied_gen = applied.applied_gen;
                                        ConfigAck { applied_gen: applied.applied_gen, ok: true, err: None }
                                    }
                                    Err(e) => ConfigAck {
                                        applied_gen: push.desired_gen,
                                        ok: false,
                                        err: Some(format!("spawn failed: {e}")),
                                    },
                                }
                            }
                            Ok(ApplyOutcome::NoTool { applied_gen }) => {
                                deps.applied_gen = applied_gen;
                                ConfigAck { applied_gen, ok: true, err: None }
                            }
                            Err(e) => ConfigAck {
                                applied_gen: push.desired_gen,
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
