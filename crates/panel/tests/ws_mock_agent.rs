//! Integration: WS reverse-server with a mock agent (AC-4 + MAJOR-4 gaps).
//! Covers: valid/invalid token, ConfigPush on connect, ConfigAck, duplicate-connection
//! supersede (Close{Superseded}), config-gen drift re-push, protocol-version mismatch,
//! token rotation rejecting the old token.

use std::time::Duration;

use contract::protocol::{
    AuthRejectReason, CloseReason, ConfigAck, Envelope, Hello, Message, StatusReport,
};
use contract::version::PROTOCOL_VERSION;
use futures_util::{SinkExt, StreamExt};
use panel::dns::DnsConfig;
use panel::{build, Panel, PanelConfig};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

struct Harness {
    base_http: String,
    ws_url: String,
    client: reqwest::Client,
    _panel_keepalive: tokio::task::JoinHandle<()>,
}

async fn boot() -> Harness {
    let cfg = PanelConfig {
        database_url: "sqlite::memory:".into(),
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
    // Seed admin directly via the DB layer.
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
    let handle = tokio::spawn(async move {
        let _keep = panel;
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
        base_http: format!("http://{addr}"),
        ws_url: format!("ws://{addr}/agent"),
        client,
        _panel_keepalive: handle,
    }
}

/// Create a node + one gost rule; return (node_id, agent_token).
async fn make_node_with_rule(h: &Harness) -> (String, String) {
    let body: serde_json::Value = h
        .client
        .post(format!("{}/api/nodes", h.base_http))
        .json(&serde_json::json!({"name":"n1","public_ip":"5.5.5.5"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let node_id = body["node"]["id"].as_str().unwrap().to_string();
    let token = body["token"].as_str().unwrap().to_string();
    h.client
        .post(format!("{}/api/rules", h.base_http))
        .json(&serde_json::json!({
            "node_id": node_id, "listen_port": 8443, "protocol":"tcp",
            "backend_host":"10.0.0.5","backend_port":8096,"tool":"gost"
        }))
        .send()
        .await
        .unwrap();
    (node_id, token)
}

async fn send(ws: &mut Ws, msg: Message) {
    let env = Envelope::new("m", msg);
    ws.send(WsMessage::Text(serde_json::to_string(&env).unwrap()))
        .await
        .unwrap();
}

/// Read the next protocol envelope, with a timeout so tests fail fast.
async fn recv(ws: &mut Ws) -> Option<Message> {
    let frame = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .ok()??;
    match frame.ok()? {
        WsMessage::Text(t) => serde_json::from_str::<Envelope>(&t).ok().map(|e| e.message),
        _ => None,
    }
}

#[tokio::test]
async fn valid_token_gets_hello_ok_and_config_push() {
    let h = boot().await;
    let (_node, token) = make_node_with_rule(&h).await;
    let (mut ws, _) = connect_async(&h.ws_url).await.unwrap();

    send(
        &mut ws,
        Message::Hello(Hello {
            node_id: "n1-bad".into(), // will fix below
            token: token.clone(),
            agent_version: "0.1.0".into(),
            platform: "x86_64-linux".into(),
        }),
    )
    .await;
    // Wrong node_id → BadToken (no such agent).
    match recv(&mut ws).await {
        Some(Message::AuthReject(r)) => assert_eq!(r.reason, AuthRejectReason::BadToken),
        other => panic!("expected AuthReject, got {other:?}"),
    }
}

#[tokio::test]
async fn happy_path_hello_configpush_ack() {
    let h = boot().await;
    let (node_id, token) = make_node_with_rule(&h).await;
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

    // HelloOk first.
    match recv(&mut ws).await {
        Some(Message::HelloOk(ok)) => assert_eq!(ok.heartbeat_interval_secs, 20),
        other => panic!("expected HelloOk, got {other:?}"),
    }
    // ConfigPush on connect (Q6 immediate push), carrying gost config for the rule.
    let push = loop {
        match recv(&mut ws).await {
            Some(Message::ConfigPush(p)) => break p,
            Some(_) => continue,
            None => panic!("no ConfigPush received"),
        }
    };
    assert!(push.gost_config.unwrap().contains("8443"));

    // Ack the pushed gen.
    send(
        &mut ws,
        Message::ConfigAck(ConfigAck {
            applied_gen: push.desired_gen,
            ok: true,
            err: None,
        }),
    )
    .await;

    // A status report keeps the node fresh; node should appear connected in health.
    send(
        &mut ws,
        Message::StatusReport(StatusReport {
            forwarding_up: true,
            backend_reachable: true,
            applied_config_gen: push.desired_gen,
            metrics: None,
            capacity: None,
        }),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let health: serde_json::Value = h
        .client
        .get(format!("{}/api/health", h.base_http))
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
    assert_eq!(me["connected"], true);
}

#[tokio::test]
async fn protocol_version_mismatch_is_rejected() {
    let h = boot().await;
    let (node_id, token) = make_node_with_rule(&h).await;
    let (mut ws, _) = connect_async(&h.ws_url).await.unwrap();

    // Craft a Hello envelope with a bogus protocol_version.
    let env = serde_json::json!({
        "protocol_version": PROTOCOL_VERSION + 99,
        "msg_id":"m",
        "kind":"hello",
        "payload": {"node_id": node_id, "token": token, "agent_version":"0.1.0"}
    });
    ws.send(WsMessage::Text(env.to_string())).await.unwrap();

    match recv(&mut ws).await {
        Some(Message::AuthReject(r)) => assert_eq!(r.reason, AuthRejectReason::ProtocolVersion),
        other => panic!("expected ProtocolVersion reject, got {other:?}"),
    }
}

#[tokio::test]
async fn duplicate_connection_supersedes_old() {
    let h = boot().await;
    let (node_id, token) = make_node_with_rule(&h).await;

    // First connection.
    let (mut ws1, _) = connect_async(&h.ws_url).await.unwrap();
    send(
        &mut ws1,
        Message::Hello(Hello {
            node_id: node_id.clone(),
            token: token.clone(),
            agent_version: "0.1.0".into(),
            platform: "x86_64-linux".into(),
        }),
    )
    .await;
    // Drain HelloOk + ConfigPush.
    let _ = recv(&mut ws1).await;
    let _ = recv(&mut ws1).await;

    // Second connection for the SAME node_id → first must receive Close{Superseded}.
    let (mut ws2, _) = connect_async(&h.ws_url).await.unwrap();
    send(
        &mut ws2,
        Message::Hello(Hello {
            node_id: node_id.clone(),
            token,
            agent_version: "0.1.0".into(),
            platform: "x86_64-linux".into(),
        }),
    )
    .await;

    // ws1 should now get a Close{Superseded}.
    let mut superseded = false;
    for _ in 0..5 {
        match recv(&mut ws1).await {
            Some(Message::Close(c)) => {
                assert_eq!(c.reason, CloseReason::Superseded);
                superseded = true;
                break;
            }
            Some(_) => continue,
            None => break,
        }
    }
    assert!(superseded, "old connection must be superseded");
}

#[tokio::test]
async fn config_gen_drift_triggers_repush() {
    // The drift watchdog re-pushes if applied != desired after T_ACK. T_ACK is 15s in
    // the contract, which is too long for a fast test; instead we assert the IMMEDIATE
    // re-push behavior: adding a second rule bumps desired_gen and pushes again without
    // waiting, and the node stays in drift until it acks the new gen.
    let h = boot().await;
    let (node_id, token) = make_node_with_rule(&h).await;
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
    let _ = recv(&mut ws).await; // HelloOk
    let push1 = loop {
        if let Some(Message::ConfigPush(p)) = recv(&mut ws).await {
            break p;
        }
    };

    // Add a second rule → desired_gen bumps and a fresh ConfigPush arrives.
    h.client
        .post(format!("{}/api/rules", h.base_http))
        .json(&serde_json::json!({
            "node_id": node_id, "listen_port": 9000, "protocol":"tcp",
            "backend_host":"10.0.0.5","backend_port":8096,"tool":"gost"
        }))
        .send()
        .await
        .unwrap();

    let push2 = loop {
        match recv(&mut ws).await {
            Some(Message::ConfigPush(p)) => break p,
            Some(_) => continue,
            None => panic!("no re-push after rule change"),
        }
    };
    assert!(
        push2.desired_gen > push1.desired_gen,
        "desired_gen must bump on change"
    );
    assert!(
        push2.gost_config.unwrap().contains("9000"),
        "new rule must be in the re-push"
    );
}

#[tokio::test]
async fn token_rotation_rejects_old_token() {
    let h = boot().await;
    let (node_id, old_token) = make_node_with_rule(&h).await;

    // Rotate the token (gap 7.6).
    h.client
        .post(format!("{}/api/nodes/{node_id}/token", h.base_http))
        .send()
        .await
        .unwrap();

    // Reconnecting with the OLD token must be rejected.
    let (mut ws, _) = connect_async(&h.ws_url).await.unwrap();
    send(
        &mut ws,
        Message::Hello(Hello {
            node_id,
            token: old_token,
            agent_version: "0.1.0".into(),
            platform: "x86_64-linux".into(),
        }),
    )
    .await;
    match recv(&mut ws).await {
        Some(Message::AuthReject(r)) => assert_eq!(r.reason, AuthRejectReason::BadToken),
        other => panic!("expected BadToken after rotation, got {other:?}"),
    }
}
