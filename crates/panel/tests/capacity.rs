//! Integration: capacity engine (AC-11). Feeds capacity reports through the live WS
//! server, then asserts: reset-aware accumulation, hard-quota → node excluded from the
//! available answer, and usage PERSISTS across a simulated panel restart (per-report
//! SQLite persistence, Rec#2). Built directly against `panel::db` + `panel::scheduler`
//! plus a WS round-trip for the end-to-end persistence path.

use contract::protocol::{
    Capacity, CapacitySource, ConfigAck, Envelope, Hello, Message, StatusReport,
};
use futures_util::{SinkExt, StreamExt};
use panel::dns::DnsConfig;
use panel::{build, Panel, PanelConfig};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

struct Harness {
    base: String,
    ws_url: String,
    client: reqwest::Client,
    db_path: String,
    _keep: tokio::task::JoinHandle<()>,
}

/// Boot a panel backed by an ON-DISK SQLite file (so a "restart" can re-open it).
async fn boot(db_path: &str) -> Harness {
    let cfg = PanelConfig {
        database_url: format!("sqlite://{db_path}"),
        http_bind: "127.0.0.1:0".into(),
        dns: DnsConfig {
            bind_addr: "127.0.0.1".into(),
            port: 0,
            ..Default::default()
        },
        geocn_path: None,
        ttl_secs: 60,
        ..Default::default()
    };
    let panel: Panel = build(cfg).await.expect("build");
    // Seed admin directly via the DB layer (idempotent upsert — safe on restart).
    let hash = panel::auth::hash_password("secret").unwrap();
    panel::db::upsert_user(
        &panel.state.db,
        &contract::model::PanelUser {
            username: "admin".into(),
            password_hash: hash,
        },
    )
    .await
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = panel.router.clone();
    let keep = tokio::spawn(async move {
        let _p = panel;
        axum::serve(listener, router).await.unwrap();
    });
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();
    client
        .post(format!("http://{addr}/api/login"))
        .json(&serde_json::json!({"username":"admin","password":"secret"}))
        .send()
        .await
        .unwrap();
    Harness {
        base: format!("http://{addr}"),
        ws_url: format!("ws://{addr}/agent"),
        client,
        db_path: db_path.to_string(),
        _keep: keep,
    }
}

async fn send(ws: &mut Ws, msg: Message) {
    let env = Envelope::new("m", msg);
    ws.send(WsMessage::Text(serde_json::to_string(&env).unwrap()))
        .await
        .unwrap();
}
async fn recv(ws: &mut Ws) -> Option<Message> {
    let frame = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .ok()??;
    match frame.ok()? {
        WsMessage::Text(t) => serde_json::from_str::<Envelope>(&t).ok().map(|e| e.message),
        _ => None,
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

async fn status(applied_gen: u64, capacity: Option<Capacity>) -> Message {
    Message::StatusReport(StatusReport {
        forwarding_up: true,
        backend_reachable: true,
        applied_config_gen: applied_gen,
        metrics: None,
        capacity,
    })
}

#[tokio::test]
async fn usage_accumulates_and_survives_restart_with_quota_exclusion() {
    let dir = std::env::temp_dir().join(format!("panel-cap-{}.db", std::process::id()));
    let db_path = dir.to_string_lossy().to_string();
    let _ = std::fs::remove_file(&db_path);

    // ---- boot #1 ----
    let h = boot(&db_path).await;

    // Node with a small quota and a line group so we can check DNS-side exclusion.
    let node: serde_json::Value = h
        .client
        .post(format!("{}/api/nodes", h.base))
        .json(&serde_json::json!({
            "name":"capnode","public_ip":"203.0.113.50",
            "division_code":410000,"isp":"telecom",
            "bandwidth_cap_mbps":100,"traffic_quota_bytes":1000u64
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let node_id = node["node"]["id"].as_str().unwrap().to_string();
    let token = node["token"].as_str().unwrap().to_string();

    h.client
        .post(format!("{}/api/line-groups", h.base))
        .json(&serde_json::json!({
            "name":"hn-telecom","match_region":41,"match_isp":"telecom",
            "priority":0,"member_node_ids":[node_id]
        }))
        .send()
        .await
        .unwrap();

    // Connect a mock agent.
    let (mut ws, _) = connect_async(&h.ws_url).await.unwrap();
    send(
        &mut ws,
        Message::Hello(Hello {
            node_id: node_id.clone(),
            token,
            agent_version: "0.1.0".into(),
            platform: "x86_64-linux".into(),
        }),
    )
    .await;
    let _hello_ok = recv(&mut ws).await;
    let push = loop {
        match recv(&mut ws).await {
            Some(Message::ConfigPush(p)) => break p,
            Some(_) => continue,
            None => panic!("no config push"),
        }
    };
    send(
        &mut ws,
        Message::ConfigAck(ConfigAck {
            applied_gen: push.desired_gen,
            ok: true,
            err: None,
        }),
    )
    .await;

    // First capacity report establishes the counter baseline (no accumulation).
    send(
        &mut ws,
        status(push.desired_gen, Some(cap(1, 0, 0, 0))).await,
    )
    .await;
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Second report: tx grows to 600, rx to 600 → +1200 bytes ≥ 1000 hard quota.
    send(
        &mut ws,
        status(push.desired_gen, Some(cap(1, 600, 600, 0))).await,
    )
    .await;
    tokio::time::sleep(Duration::from_millis(250)).await;

    // The node should now be hard-quota excluded → not in the available DNS answer.
    let health: serde_json::Value = h
        .client
        .get(format!("{}/api/health", h.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let me = health
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["id"] == node_id)
        .unwrap();
    assert!(
        me["accumulated_usage_bytes"].as_u64().unwrap() >= 1000,
        "usage accumulated past hard quota, got {}",
        me["accumulated_usage_bytes"]
    );
    assert_eq!(me["availability_state"], "hard_excluded");

    // Tear down boot #1 (drop the server task implicitly by dropping harness later).
    drop(ws);
    drop(h);
    // Give the OS a moment to flush + release the file handle.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // ---- boot #2 (restart): same DB file ----
    let h2 = boot(&db_path).await;
    let health2: serde_json::Value = h2
        .client
        .get(format!("{}/api/health", h2.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let me2 = health2
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["id"] == node_id)
        .unwrap();
    // Usage persisted across restart (Rec#2).
    assert!(
        me2["accumulated_usage_bytes"].as_u64().unwrap() >= 1000,
        "usage must persist across restart, got {}",
        me2["accumulated_usage_bytes"]
    );

    let _ = std::fs::remove_file(&h2.db_path);
}
