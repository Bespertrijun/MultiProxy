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
            totp_secret: None,
            totp_enabled: false,
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

/// agent_version for a "new" (Phase-4-failover-capable) agent (>= v0.10.0).
const NEW_AGENT_VERSION: &str = "0.10.0";
/// agent_version for an "old" agent (< v0.10.0).
const OLD_AGENT_VERSION: &str = "0.9.6";

/// Connect, handshake with the given agent version, drain HelloOk, return (ws, first push).
async fn connect_and_handshake(
    h: &Harness,
    node_id: &str,
    token: &str,
    agent_version: &str,
) -> (Ws, contract::protocol::ConfigPush) {
    let (mut ws, _) = connect_async(&h.ws_url).await.unwrap();
    send(
        &mut ws,
        Message::Hello(Hello {
            node_id: node_id.to_string(),
            token: token.to_string(),
            agent_version: agent_version.to_string(),
            platform: "x86_64-linux".into(),
        }),
    )
    .await;
    // HelloOk first.
    match recv(&mut ws).await {
        Some(Message::HelloOk(_)) => {}
        other => panic!("expected HelloOk, got {other:?}"),
    }
    let push = loop {
        match recv(&mut ws).await {
            Some(Message::ConfigPush(p)) => break p,
            Some(_) => continue,
            None => panic!("no ConfigPush on connect"),
        }
    };
    (ws, push)
}

/// Create a line group containing `node_id` (no zone). Re-pushes to its members via
/// `push_config_to` WITHOUT bumping desired_gen — the leg-b "unrelated re-push" path.
async fn create_group_with_node(h: &Harness, node_id: &str) {
    h.client
        .post(format!("{}/api/line-groups", h.base_http))
        .json(&serde_json::json!({
            "name": "g1",
            "member_node_ids": [node_id],
        }))
        .send()
        .await
        .unwrap();
}

async fn set_killswitch(h: &Harness, enabled: bool) {
    h.client
        .put(format!("{}/api/settings/failover-killswitch", h.base_http))
        .json(&serde_json::json!({ "enabled": enabled }))
        .send()
        .await
        .unwrap();
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
            backend_health: None,
            active_backends: None,
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

#[tokio::test]
async fn new_agent_gets_rules_old_agent_does_not() {
    // Version split (must-fix #4): a NEW agent's push carries structured `rules`
    // (a full replica list) PLUS the legacy render; an OLD agent gets the legacy render
    // only (no rules), byte-for-byte the pre-Phase-4 push.
    let h = boot().await;
    let (node_id, token) = make_node_with_rule(&h).await;

    let (_ws_new, push_new) = connect_and_handshake(&h, &node_id, &token, NEW_AGENT_VERSION).await;
    assert!(
        !push_new.rules.is_empty(),
        "new agent must receive structured rules"
    );
    assert_eq!(push_new.rules[0].listen_port, 8443);
    // Legacy render is still present as a fallback.
    assert!(
        push_new.gost_config.as_deref().unwrap().contains("8443"),
        "legacy gost_config must still be sent as fallback"
    );

    let (_ws_old, push_old) = connect_and_handshake(&h, &node_id, &token, OLD_AGENT_VERSION).await;
    assert!(
        push_old.rules.is_empty(),
        "old agent must NOT receive structured rules"
    );
    assert!(push_old.gost_config.as_deref().unwrap().contains("8443"));
}

#[tokio::test]
async fn leg_b_unrelated_repush_to_new_agent_still_carries_rules() {
    // BLOCKING (must-fix #1): an unrelated re-push (here: group CRUD via push_config_to,
    // the same path as cert renewal certs.rs:94, which does NOT bump desired_gen) to a
    // NEW agent must STILL carry the full structured `rules` — never a "main upstream
    // only" push that would knock the agent back onto a dead primary.
    let h = boot().await;
    let (node_id, token) = make_node_with_rule(&h).await;
    let (mut ws, push1) = connect_and_handshake(&h, &node_id, &token, NEW_AGENT_VERSION).await;
    assert!(!push1.rules.is_empty(), "connect push carries rules");

    // Trigger an unrelated re-push (group membership) — does NOT bump desired_gen.
    create_group_with_node(&h, &node_id).await;

    let push2 = loop {
        match recv(&mut ws).await {
            Some(Message::ConfigPush(p)) => break p,
            Some(_) => continue,
            None => panic!("no re-push after group create"),
        }
    };
    assert!(
        !push2.rules.is_empty(),
        "unrelated re-push to a new agent MUST still carry structured rules (leg-b)"
    );
    assert_eq!(push2.rules[0].listen_port, 8443);
    // gen unchanged (group CRUD does not bump desired_gen).
    assert_eq!(
        push2.desired_gen, push1.desired_gen,
        "group CRUD must not bump desired_gen"
    );
}

#[tokio::test]
async fn killswitch_forces_legacy_only_push_for_new_agent() {
    // BLOCKING (must-fix #2): with the kill-switch ENGAGED, a NEW agent receives ONLY the
    // legacy single-upstream render and NO structured rules (== pre-Phase-4). Disengaging
    // restores rules + legacy fallback.
    let h = boot().await;
    let (node_id, token) = make_node_with_rule(&h).await;

    // Kill-switch ON.
    set_killswitch(&h, true).await;
    let (mut ws, push_on) = connect_and_handshake(&h, &node_id, &token, NEW_AGENT_VERSION).await;
    assert!(
        push_on.rules.is_empty(),
        "kill-switch ON: new agent must NOT receive structured rules"
    );
    assert!(
        push_on.gost_config.as_deref().unwrap().contains("8443"),
        "legacy render still present under kill-switch"
    );

    // Kill-switch OFF → re-push (via group CRUD) now carries rules again.
    set_killswitch(&h, false).await;
    create_group_with_node(&h, &node_id).await;
    let push_off = loop {
        match recv(&mut ws).await {
            Some(Message::ConfigPush(p)) => break p,
            Some(_) => continue,
            None => panic!("no re-push after disengaging kill-switch"),
        }
    };
    assert!(
        !push_off.rules.is_empty(),
        "kill-switch OFF: new agent receives structured rules again"
    );
}

#[tokio::test]
async fn killswitch_push_matches_old_agent_push_byte_for_byte() {
    // The kill-switch push to a new agent must equal the legacy push an old agent gets:
    // same gost_config / realm_config / backends, and rules empty in both.
    let h = boot().await;
    let (node_id, token) = make_node_with_rule(&h).await;

    set_killswitch(&h, true).await;
    let (_ws_new, push_new) = connect_and_handshake(&h, &node_id, &token, NEW_AGENT_VERSION).await;
    let (_ws_old, push_old) = connect_and_handshake(&h, &node_id, &token, OLD_AGENT_VERSION).await;

    assert!(push_new.rules.is_empty());
    assert!(push_old.rules.is_empty());
    assert_eq!(push_new.gost_config, push_old.gost_config);
    assert_eq!(push_new.realm_config, push_old.realm_config);
    assert_eq!(push_new.backends, push_old.backends);
}

#[tokio::test]
async fn new_agent_active_backend_report_does_not_trigger_repush() {
    // drift-no-fight: a NEW agent reports active_backends but keeps applied_config_gen ==
    // desired_config_gen → panel sees desired == applied → NO re-push within T_ACK.
    let h = boot().await;
    let (node_id, token) = make_node_with_rule(&h).await;
    let (mut ws, push) = connect_and_handshake(&h, &node_id, &token, NEW_AGENT_VERSION).await;

    // Ack the desired gen so applied == desired (no drift).
    send(
        &mut ws,
        Message::ConfigAck(ConfigAck {
            applied_gen: push.desired_gen,
            ok: true,
            err: None,
        }),
    )
    .await;

    // Report active_backends while keeping applied_config_gen == desired.
    send(
        &mut ws,
        Message::StatusReport(StatusReport {
            forwarding_up: true,
            backend_reachable: true,
            applied_config_gen: push.desired_gen,
            metrics: None,
            capacity: None,
            backend_health: None,
            active_backends: Some(vec![contract::protocol::ActiveBackend {
                rule_id: push.rules[0].rule_id.clone(),
                host: "10.0.0.5".into(),
                port: 8096,
            }]),
        }),
    )
    .await;

    // No ConfigPush should arrive in a short window (we are not waiting the full T_ACK,
    // but any spurious immediate re-push would show up here).
    let spurious = tokio::time::timeout(Duration::from_millis(500), async {
        loop {
            match recv(&mut ws).await {
                Some(Message::ConfigPush(_)) => break true,
                Some(_) => continue,
                None => break false,
            }
        }
    })
    .await;
    assert!(
        spurious.is_err() || spurious == Ok(false),
        "no re-push expected when applied == desired (drift must not fight failover)"
    );
}
