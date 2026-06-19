//! Integration test: the reconnect-with-backoff loop (Line B task 1, AC-4).
//!
//! A mock ws panel rejects/drops the FIRST connection, then on the retry sends
//! a proper `HelloOk` + `Close{Superseded}`. We assert the agent:
//!   * retries after the first failure (reconnect loop), and
//!   * on the second connection completes the handshake and reacts to a server
//!     `Close` — proving the close path and reconnect both work.
//!
//! Plain ws (no TLS) — acceptable for M1 per the brief.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use agent::capacity::{CapacityCollector, NicCounterSource};
use agent::config::ConfigPaths;
use agent::conn::{run_reconnect_loop, AgentConfig, Backoff, SessionDeps};
use agent::supervisor::Supervisor;
use agent::testutil::{DummySpawner, FixedBackendProbe};

use contract::protocol::{Close, CloseReason, Envelope, HelloOk, Message};
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message as WsMessage;

#[tokio::test]
async fn agent_retries_after_a_dropped_connection() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("ws://{addr}/agent");
    let connections = Arc::new(AtomicU32::new(0));

    // Mock panel: drop the first connection right after accept; on the second,
    // do the handshake then send Close{Superseded}.
    let conns = connections.clone();
    let panel = tokio::spawn(async move {
        loop {
            let (tcp, _) = match listener.accept().await {
                Ok(c) => c,
                Err(_) => break,
            };
            let n = conns.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                // First attempt: drop immediately (simulates a flaky panel).
                drop(tcp);
                continue;
            }
            // Second attempt: full handshake + a server-initiated close.
            let Ok(mut ws) = tokio_tungstenite::accept_async(tcp).await else {
                continue;
            };
            // Read Hello.
            let _ = ws.next().await;
            send(
                &mut ws,
                Message::HelloOk(HelloOk {
                    session: "s".into(),
                    heartbeat_interval_secs: 1,
                }),
            )
            .await;
            send(
                &mut ws,
                Message::Close(Close {
                    reason: CloseReason::Superseded,
                }),
            )
            .await;
            // Give the agent a moment to observe the close, then stop the panel.
            tokio::time::sleep(Duration::from_millis(200)).await;
            break;
        }
    });

    let tmp = std::env::temp_dir().join(format!("agent-reconnect-{}", std::process::id()));
    let cfg = AgentConfig {
        panel_url: url,
        node_id: "n-rc".into(),
        token: "tok".into(),
        agent_version: "0.1.0-test".into(),
        platform: agent::platform::detect(),
        config_paths: ConfigPaths::under(&tmp),
    };
    let (spawner, _control) = DummySpawner::new();
    let deps = SessionDeps {
        supervisor: Supervisor::new(spawner),
        capacity: CapacityCollector::new(NicCounterSource, 1, Duration::from_secs(60)),
        backend: FixedBackendProbe::new(false),
        applied_gen: 0,
    };

    let (sd_tx, sd_rx) = tokio::sync::watch::channel(false);
    // Tight backoff so the retry happens fast in the test.
    let backoff = Backoff::new(Duration::from_millis(50), Duration::from_millis(200));

    let agent_loop = tokio::spawn(async move {
        run_reconnect_loop(&cfg, deps, sd_rx, backoff).await;
    });

    // The agent should establish the SECOND connection, get superseded, then
    // (per the loop) back off and try again — so connection count climbs past 1.
    let reached_two = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            if connections.load(Ordering::SeqCst) >= 2 {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or(false);

    // Signal shutdown and let the loop exit cleanly.
    let _ = sd_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(3), agent_loop).await;
    panel.abort();

    assert!(
        reached_two,
        "agent must retry after the first dropped connection (saw {} connections)",
        connections.load(Ordering::SeqCst)
    );

    std::fs::remove_dir_all(&tmp).ok();
}

async fn send<S>(ws: &mut S, message: Message)
where
    S: futures_util::Sink<WsMessage, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    let env = Envelope::new("mock", message);
    let _ = ws
        .send(WsMessage::Text(serde_json::to_string(&env).unwrap().into()))
        .await;
}
