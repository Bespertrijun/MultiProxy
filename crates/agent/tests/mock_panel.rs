//! Integration test (Line B M1 independent verifiable output):
//! the agent connects to a **mock ws panel** (plain ws — acceptable for M1 per
//! the brief), applies a sample `ConfigPush`, supervises a **dummy** process,
//! acks the config, and emits a `StatusReport` carrying capacity telemetry.
//!
//! This exercises AC-4 (connect + apply + ack) and AC-5 (self-report) end-to-end
//! against a real WebSocket transport, without a real TLS panel or a real
//! gost/realm binary (both unavailable in the sandbox — see the dummy spawner).

use std::time::Duration;

use agent::capacity::CapacityCollector;
use agent::config::ConfigPaths;
use agent::conn::{run_session, AgentConfig, SessionDeps};
use agent::supervisor::Supervisor;
use agent::testutil::{DummySpawner, RecordingBackendProbe, SteppingCounterSource};

use contract::protocol::{BackendEndpoint, ConfigPush, Envelope, HelloOk, Message};
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message as WsMessage;

/// Spin up a plain-ws mock panel on an ephemeral port. Returns the bound
/// `ws://` URL and the `JoinHandle` running the accept+drive logic. The mock:
///   1. accepts one connection,
///   2. expects a `Hello`, replies `HelloOk` (1s heartbeat),
///   3. pushes a `ConfigPush` with a gost config,
///   4. collects inbound messages and reports back what it saw via a channel.
async fn start_mock_panel(
    desired_gen: u64,
    saw_tx: tokio::sync::mpsc::UnboundedSender<Message>,
) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("ws://{addr}/agent");

    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();

        // 1. Expect Hello.
        let hello = next_msg(&mut ws).await.expect("hello");
        saw_tx.send(hello).ok();

        // 2. HelloOk with a fast 1s heartbeat so the test is quick.
        send_msg(
            &mut ws,
            Message::HelloOk(HelloOk {
                session: "s-1".into(),
                heartbeat_interval_secs: 1,
                probe_interval_secs: 5,
                probe_timeout_ms: 1000,
                failover_max_fails: 3,
                failover_recovery_checks: 6,
                min_dwell_secs: 60,
            }),
        )
        .await;

        // 3. Push a gost config carrying the node's real backend endpoint(s) so the
        //    agent probes those (not a hardcoded address) for backend reachability.
        send_msg(
            &mut ws,
            Message::ConfigPush(ConfigPush {
                desired_gen,
                gost_config: Some("{\"services\":[{\"name\":\"relay\"}]}".into()),
                realm_config: None,
                tls_cert_pem: None,
                tls_key_pem: None,
                backends: vec![BackendEndpoint {
                    host: "10.9.9.9".into(),
                    port: 8096,
                }],
                rules: vec![],
            }),
        )
        .await;

        // 4. Drain inbound messages and forward them to the test until the
        //    socket closes or the test has what it needs.
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

#[tokio::test]
async fn agent_connects_applies_config_and_self_reports() {
    let (saw_tx, mut saw_rx) = tokio::sync::mpsc::unbounded_channel();
    let url = start_mock_panel(42, saw_tx).await;

    // Build the agent session against injected doubles (no real proc/backend).
    let tmp = std::env::temp_dir().join(format!("agent-it-{}", std::process::id()));
    let cfg = AgentConfig {
        panel_url: url.clone(),
        node_id: "node-it".into(),
        token: "secret-token".into(),
        agent_version: "0.1.0-test".into(),
        platform: agent::platform::detect(),
        config_paths: ConfigPaths::under(&tmp),
    };

    let (spawner, control) = DummySpawner::new();
    let backend = RecordingBackendProbe::new(true);
    let mut deps = SessionDeps {
        supervisor: Supervisor::new(spawner),
        capacity: CapacityCollector::new(
            SteppingCounterSource::new(1000),
            7,
            Duration::from_secs(60),
        ),
        backend: backend.clone(),
        backends: vec![],
        applied_gen: 0,
    };

    let (_sd_tx, mut sd_rx) = tokio::sync::watch::channel(false);

    // Drive the agent's client side over a real ws connection to the mock panel.
    let (mut client_ws, _resp) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let agent_fut = run_session(&mut client_ws, &cfg, &mut deps, &mut sd_rx);

    // Run the agent session with a hard timeout; collect what the panel saw.
    let collector = async {
        let mut saw_hello = false;
        let mut saw_ack = false;
        let mut saw_report = false;
        while let Some(m) = saw_rx.recv().await {
            match m {
                Message::Hello(h) => {
                    assert_eq!(h.node_id, "node-it");
                    assert_eq!(h.token, "secret-token");
                    assert!(h.platform.ends_with("-linux"));
                    saw_hello = true;
                }
                Message::ConfigAck(a) => {
                    assert_eq!(a.applied_gen, 42, "ack echoes the pushed desired_gen");
                    assert!(a.ok, "config apply must succeed");
                    saw_ack = true;
                }
                Message::StatusReport(r) => {
                    // Early reports may arrive before the ConfigPush is applied
                    // (the heartbeat tick can fire first) — those legitimately
                    // show forwarding down with gen 0. We assert on the report
                    // that reflects the applied config (gen 42).
                    if r.applied_config_gen == 42 {
                        assert!(
                            r.forwarding_up,
                            "supervised dummy child is up after config applied"
                        );
                        assert!(r.backend_reachable);
                        let cap = r.capacity.expect("capacity telemetry present");
                        assert_eq!(cap.counter_epoch, 7);
                        saw_report = true;
                    }
                }
                Message::Heartbeat(_) => {}
                _ => {}
            }
            if saw_hello && saw_ack && saw_report {
                return (saw_hello, saw_ack, saw_report);
            }
        }
        (saw_hello, saw_ack, saw_report)
    };

    let result = tokio::select! {
        _ = agent_fut => unreachable!("session should not end before the panel closes"),
        r = tokio::time::timeout(Duration::from_secs(10), collector) => r,
    };

    let (hello, ack, report) = result.expect("timed out waiting for agent traffic");
    assert!(hello, "panel must have received Hello");
    assert!(ack, "panel must have received ConfigAck for gen 42");
    assert!(
        report,
        "panel must have received a StatusReport with capacity"
    );

    // The agent probed the backend endpoint(s) carried in the ConfigPush — i.e. the
    // real rule backend, not a hardcoded address (the bug this fix closes).
    assert_eq!(
        backend.last_targets(),
        vec![BackendEndpoint {
            host: "10.9.9.9".into(),
            port: 8096,
        }],
        "agent must probe the backends from ConfigPush.backends"
    );

    // The config file was actually written to disk by the agent.
    let written = std::fs::read_to_string(tmp.join("gost.json")).expect("gost.json written");
    assert!(written.contains("relay"), "pushed config text persisted");

    // The dummy forwarding process was started exactly once.
    assert_eq!(control.spawn_count(), 1, "config push starts the tool once");
    assert!(control.current_alive());

    std::fs::remove_dir_all(&tmp).ok();
}
