//! WS reverse-server (Line A task 5 / AC-4). Accepts agent WebSocket connections,
//! validates the per-node token on `Hello`, tracks conn_state, pushes `ConfigPush`
//! on connect + on change, receives `StatusReport`/`ConfigAck`, supersedes a
//! duplicate connection (`Close{Superseded}`, gap 7.1), and re-pushes config on
//! config-gen drift after `T_ACK_SECS` (gap 7.2). Reports feed the scheduler.
//!
//! M1 uses plain ws (TLS termination is a deploy concern, M3); the framing/logic is
//! transport-agnostic.

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::time::Duration;

use axum::extract::ws::{Message as WsMessage, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::Response;
use contract::protocol::{
    AuthReject, AuthRejectReason, Close, CloseReason, ConfigPush, Envelope, HelloOk, Message,
    StatusReport, T_ACK_SECS,
};
use contract::version::is_accepted;
use tokio::sync::mpsc;

use crate::auth::{new_token, verify_token};
use crate::scheduler;
use crate::state::{AgentConn, AppState};
use crate::{configgen, db};

/// axum handler: upgrade an incoming `/agent` request to a WebSocket.
pub async fn agent_ws(State(state): State<AppState>, ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

/// Drive one agent connection through its lifecycle.
async fn handle_socket(socket: WebSocket, state: AppState) {
    let (sink, mut stream) = futures_split(socket);

    // Per-connection outbound queue: a writer task drains it to the socket.
    let (tx, rx) = mpsc::unbounded_channel::<Envelope>();
    let writer = tokio::spawn(writer_task(sink, rx));

    // --- handshake: first frame must be Hello ---
    let node_id = match handshake(&mut stream, &tx, &state).await {
        Some(id) => id,
        None => {
            // Close the channel so the writer flushes the queued AuthReject, then drains.
            drop(tx);
            let _ = writer.await;
            return;
        }
    };

    // Register this connection, superseding any prior one (gap 7.1).
    let session = supersede_register(&state, &node_id, tx.clone()).await;

    // Mark connected + push current config immediately (Q6 immediate push).
    on_connect(&state, &node_id).await;

    // Spawn the drift watchdog (gap 7.2): re-push after T_ACK if applied != desired.
    let drift = tokio::spawn(drift_watchdog(state.clone(), node_id.clone()));

    // --- main receive loop ---
    while let Some(frame) = next_text(&mut stream).await {
        let Ok(env) = serde_json::from_str::<Envelope>(&frame) else {
            continue; // ignore malformed frames (forward-compat / noise)
        };
        match env.message {
            Message::Heartbeat(_) => {
                touch_runtime(&state, &node_id).await;
            }
            Message::StatusReport(report) => {
                handle_status_report(&state, &node_id, &report).await;
            }
            Message::ConfigAck(ack) => {
                handle_config_ack(&state, &node_id, ack.applied_gen).await;
            }
            Message::Hello(_) => { /* duplicate hello on live socket: ignore */ }
            _ => { /* panel→agent kinds are not expected inbound */ }
        }
    }

    // --- teardown ---
    drift.abort();
    disconnect(&state, &node_id, &session).await;
    writer.abort();
}

/// Validate the `Hello` handshake. On success returns the node_id; on failure sends
/// an `AuthReject`/`Close` and returns `None`.
async fn handshake(
    stream: &mut futures_util::stream::SplitStream<WebSocket>,
    tx: &mpsc::UnboundedSender<Envelope>,
    state: &AppState,
) -> Option<String> {
    let frame = next_text(stream).await?;
    let env: Envelope = serde_json::from_str(&frame).ok()?;

    // Protocol-version gate (gap 7.4, hard-reject default).
    if !is_accepted(env.protocol_version) {
        let _ = tx.send(Envelope::new(
            new_token(),
            Message::AuthReject(AuthReject {
                reason: AuthRejectReason::ProtocolVersion,
            }),
        ));
        return None;
    }

    let Message::Hello(hello) = env.message else {
        // First frame must be Hello.
        let _ = tx.send(Envelope::new(
            new_token(),
            Message::AuthReject(AuthReject {
                reason: AuthRejectReason::Other("expected_hello".into()),
            }),
        ));
        return None;
    };

    // Validate the token against the stored hash (gap 7.6 token rotation: only the
    // current hash verifies; an old token after rotation fails here).
    let agent = match db::get_agent(&state.db, &hello.node_id).await {
        Ok(a) => a,
        Err(_) => {
            let _ = tx.send(Envelope::new(
                new_token(),
                Message::AuthReject(AuthReject {
                    reason: AuthRejectReason::BadToken,
                }),
            ));
            return None;
        }
    };
    if !verify_token(&hello.token, &agent.token_hash) {
        let _ = tx.send(Envelope::new(
            new_token(),
            Message::AuthReject(AuthReject {
                reason: AuthRejectReason::BadToken,
            }),
        ));
        return None;
    }

    // Record agent version + platform on the node/agent record.
    let mut updated = agent.clone();
    updated.agent_version = hello.agent_version.clone();
    updated.conn_state = contract::model::ConnState::Connected;
    let _ = db::upsert_agent(&state.db, &updated).await;

    // HelloOk carries the server-controlled heartbeat interval (gap 7.3).
    let session = new_token();
    let _ = tx.send(Envelope::new(
        new_token(),
        Message::HelloOk(HelloOk {
            session: session.clone(),
            heartbeat_interval_secs: state.heartbeat_interval_secs,
        }),
    ));
    Some(hello.node_id)
}

/// Register the new connection, closing any prior live socket for this node (gap 7.1).
async fn supersede_register(
    state: &AppState,
    node_id: &str,
    tx: mpsc::UnboundedSender<Envelope>,
) -> String {
    let session = new_token();
    let mut conns = state.conns.lock().await;
    if let Some(prev) = conns.remove(node_id) {
        // Force-close the prior socket with Superseded.
        let _ = prev.tx.send(Envelope::new(
            new_token(),
            Message::Close(Close {
                reason: CloseReason::Superseded,
            }),
        ));
    }
    conns.insert(
        node_id.to_string(),
        AgentConn {
            session: session.clone(),
            tx,
        },
    );
    session
}

/// Mark the node connected, build + push its current config, refresh the snapshot.
async fn on_connect(state: &AppState, node_id: &str) {
    touch_runtime(state, node_id).await;
    push_config(state, node_id).await;
    rebuild_and_store_snapshot(state).await;
}

/// Render + push the node's current desired config (ConfigPush, AC-4).
async fn push_config(state: &AppState, node_id: &str) {
    let Ok(rules) = db::list_rules_for_node(&state.db, node_id).await else {
        return;
    };
    // Pick the cert matching the domain(s) this node serves (zone → cert), NOT the
    // panel's own cert. A relay listener can present only one cert; if a node serves
    // multiple zones we use the first with an issued cert and warn.
    let domains = domains_for_node(state, node_id);
    let mut chosen: Option<(String, (String, String))> = None;
    for d in &domains {
        if let Some(pair) = state.zone_cert(d).await {
            chosen = Some((d.clone(), pair));
            break;
        }
    }
    if domains.len() > 1 {
        tracing::warn!(
            node_id, ?domains, chosen = ?chosen.as_ref().map(|(d, _)| d),
            "node serves multiple zones but a listener presents one cert; using the first issued one"
        );
    }
    let (cert, key) = match chosen {
        Some((_, (c, k))) => (Some(c), Some(k)),
        None => (None, None),
    };
    // Render TLS-terminate listeners ONLY when a matching cert is available — otherwise
    // a Terminate rule renders plain TCP and the client's HTTPS handshake fails
    // (ERR_SSL_PROTOCOL_ERROR). The rendered cert paths must match where the agent
    // writes the PEMs below (configgen::PROD_TLS_*).
    let tls = if cert.is_some() && key.is_some() {
        Some(configgen::TlsPaths::prod())
    } else {
        None
    };
    let rendered = configgen::render_node_with_tls(&rules, tls.as_ref());
    let Ok(node) = db::get_node(&state.db, node_id).await else {
        return;
    };
    let push = ConfigPush {
        desired_gen: node.desired_config_gen,
        gost_config: rendered.gost_config,
        realm_config: rendered.realm_config,
        tls_cert_pem: cert,
        tls_key_pem: key,
        backends: rendered.backends,
    };
    let conns = state.conns.lock().await;
    if let Some(conn) = conns.get(node_id) {
        let _ = conn
            .tx
            .send(Envelope::new(new_token(), Message::ConfigPush(push)));
    }
}

/// The DNS zone apex domains a node serves: line groups that list it as a member →
/// their `zone_id` → that zone's `apex_domain`. Mirrors the resolver's
/// zone→group→node join (see `dns::answer::resolve`) in reverse, so we hand a relay
/// the cert for the domain clients actually reach it by.
#[must_use]
pub fn domains_for_node(state: &AppState, node_id: &str) -> Vec<String> {
    let groups = state.groups.load();
    let zones = state.zones.load();
    domains_for_node_in(&groups, &zones, node_id)
}

/// Pure core of [`domains_for_node`] (testable without an `AppState`).
fn domains_for_node_in(
    groups: &[contract::model::LineGroup],
    zones: &[contract::model::DnsZone],
    node_id: &str,
) -> Vec<String> {
    let mut zone_ids: Vec<&str> = groups
        .iter()
        .filter(|g| g.member_node_ids.iter().any(|m| m == node_id))
        .filter_map(|g| g.zone_id.as_deref())
        .collect();
    zone_ids.sort_unstable();
    zone_ids.dedup();
    zone_ids
        .iter()
        .filter_map(|zid| {
            zones
                .iter()
                .find(|z| z.id == *zid)
                .map(|z| z.apex_domain.clone())
        })
        .collect()
}

/// Re-push the desired config to a single connected node (no-op if it is not
/// currently connected). Used by the API on CRUD mutations that affect that node.
pub async fn push_config_to(state: &AppState, node_id: &str) {
    push_config(state, node_id).await;
}

/// Send a message to every currently-connected agent. Returns how many were
/// notified (offline nodes are skipped; they get nothing until they reconnect).
pub async fn broadcast_to_agents(state: &AppState, msg: Message) -> usize {
    let conns = state.conns.lock().await;
    let mut sent = 0;
    for conn in conns.values() {
        if conn
            .tx
            .send(Envelope::new(new_token(), msg.clone()))
            .is_ok()
        {
            sent += 1;
        }
    }
    sent
}

async fn touch_runtime(state: &AppState, node_id: &str) {
    let now = now_ms();
    let mut rts = state.runtimes.lock().await;
    let rt = rts.entry(node_id.to_string()).or_default();
    rt.last_contact_ms = now;
    rt.connected = true;
}

/// Apply a StatusReport: update health runtime + run the capacity engine + persist on
/// every report (Rec#2) + refresh the snapshot.
async fn handle_status_report(state: &AppState, node_id: &str, report: &StatusReport) {
    let now = now_ms();

    // Pull node config for quota/bandwidth thresholds.
    let Ok(node) = db::get_node(&state.db, node_id).await else {
        return;
    };

    let mut rts = state.runtimes.lock().await;
    let rt = rts.entry(node_id.to_string()).or_default();
    scheduler::apply_status_report(rt, report, now);

    // Capacity engine (rev3 §A/§B).
    if let Some(cap) = &report.capacity {
        let prior = if rt.capacity.has_counter_baseline {
            rt.capacity.clone()
        } else {
            // Cold start: load persisted baseline so usage survives a panel restart.
            db::get_capacity_state(&state.db, node_id)
                .await
                .unwrap_or_default()
        };
        let mut enter = rt.sat_enter_windows;
        let mut exit = rt.sat_exit_windows;
        let outcome = scheduler::apply_capacity(
            &prior,
            rt.saturation,
            &mut enter,
            &mut exit,
            node.bandwidth_cap_mbps,
            cap,
            node.quota_direction,
        );
        rt.sat_enter_windows = enter;
        rt.sat_exit_windows = exit;
        rt.capacity = outcome.state.clone();
        rt.throughput_bps = outcome.throughput_bps;
        rt.saturation = outcome.saturation;

        if outcome.reset_detected {
            tracing::info!(node_id, "capacity counter_epoch reset detected");
        }

        // Classify for the persisted availability_state (observability).
        let class = scheduler::classify_node(&node, rt, now, state.heartbeat_interval_secs);
        let avail = scheduler::availability_state_for(class);

        // Persist on EVERY accepted report (Rec#2).
        let _ = db::persist_capacity(
            &state.db,
            node_id,
            &outcome.state,
            outcome.throughput_bps,
            outcome.saturation,
            avail,
            now,
        )
        .await;
    }
    drop(rts);

    // Record applied config gen from the report (corroborates ConfigAck).
    let _ = db::set_applied_gen(&state.db, node_id, report.applied_config_gen).await;

    rebuild_and_store_snapshot(state).await;
}

/// Handle a ConfigAck: record applied gen; a stale-gen ack is harmless (the drift
/// watchdog only clears when applied == desired). Gap 7.2.
async fn handle_config_ack(state: &AppState, node_id: &str, applied_gen: u64) {
    let _ = db::set_applied_gen(&state.db, node_id, applied_gen).await;
    // applied_config_gen drives the drift indicator in the UI.
    state.notify_change();
}

/// Drift watchdog (gap 7.2): every `T_ACK_SECS`, if the node is still connected and
/// `applied_config_gen != desired_config_gen`, re-push the current desired config.
async fn drift_watchdog(state: AppState, node_id: String) {
    let interval = Duration::from_secs(u64::from(T_ACK_SECS));
    loop {
        tokio::time::sleep(interval).await;
        // Still connected?
        {
            let conns = state.conns.lock().await;
            if !conns.contains_key(&node_id) {
                return;
            }
        }
        if let Ok(node) = db::get_node(&state.db, &node_id).await {
            if node.applied_config_gen != node.desired_config_gen {
                tracing::warn!(
                    node_id = %node_id,
                    desired = node.desired_config_gen,
                    applied = node.applied_config_gen,
                    "config-gen drift; re-pushing"
                );
                push_config(&state, &node_id).await;
            }
        }
    }
}

/// Connection teardown: only clear the registry/state if WE are still the registered
/// session (a superseding connection must not be evicted by the old socket's exit).
async fn disconnect(state: &AppState, node_id: &str, session: &str) {
    let mut conns = state.conns.lock().await;
    if let Some(conn) = conns.get(node_id) {
        if conn.session == session {
            conns.remove(node_id);
            drop(conns);
            let mut rts = state.runtimes.lock().await;
            if let Some(rt) = rts.get_mut(node_id) {
                rt.connected = false;
            }
            drop(rts);
            let _ = db::set_agent_conn_disconnected(&state.db, node_id).await;
            rebuild_and_store_snapshot(state).await;
        }
    }
}

/// Recompute the availability snapshot from the current nodes + runtimes + groups and
/// atomically store it (the scheduler→resolver swap).
pub async fn rebuild_and_store_snapshot(state: &AppState) {
    let Ok(nodes_vec) = db::list_nodes(&state.db).await else {
        return;
    };
    let groups = state.groups.load_full();
    let nodes: HashMap<String, contract::model::FrontNode> =
        nodes_vec.into_iter().map(|n| (n.id.clone(), n)).collect();
    let rts = state.runtimes.lock().await.clone();
    let now = now_ms();
    let gen = state.snapshot_gen.fetch_add(1, Ordering::Relaxed) + 1;
    let snap = scheduler::build_snapshot(
        &nodes,
        &rts,
        groups.as_ref(),
        gen,
        now,
        state.heartbeat_interval_secs,
    );
    state.snapshot.store(std::sync::Arc::new(snap));
    // Central choke point for node/group/zone/health changes → push to the UI.
    state.notify_change();
}

/// Unix-millis now.
pub fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Read the next text frame from the socket, ignoring pings/binary; `None` on close.
async fn next_text(stream: &mut futures_util::stream::SplitStream<WebSocket>) -> Option<String> {
    use futures_util::StreamExt;
    while let Some(msg) = stream.next().await {
        match msg {
            Ok(WsMessage::Text(t)) => return Some(t.to_string()),
            Ok(WsMessage::Binary(b)) => {
                if let Ok(s) = String::from_utf8(b.to_vec()) {
                    return Some(s);
                }
            }
            Ok(WsMessage::Close(_)) | Err(_) => return None,
            _ => continue,
        }
    }
    None
}

/// Split a WebSocket into sink + stream.
fn futures_split(
    socket: WebSocket,
) -> (
    futures_util::stream::SplitSink<WebSocket, WsMessage>,
    futures_util::stream::SplitStream<WebSocket>,
) {
    use futures_util::StreamExt;
    socket.split()
}

/// Writer task: serialize queued envelopes and send them; a `Close` envelope also
/// closes the socket.
async fn writer_task(
    mut sink: futures_util::stream::SplitSink<WebSocket, WsMessage>,
    mut rx: mpsc::UnboundedReceiver<Envelope>,
) {
    use futures_util::SinkExt;
    while let Some(env) = rx.recv().await {
        let is_close = matches!(env.message, Message::Close(_));
        let Ok(json) = serde_json::to_string(&env) else {
            continue;
        };
        if sink.send(WsMessage::Text(json.into())).await.is_err() {
            return;
        }
        if is_close {
            let _ = sink.send(WsMessage::Close(None)).await;
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::domains_for_node_in;
    use contract::model::{DnsZone, LineGroup};

    fn zone(id: &str, apex: &str) -> DnsZone {
        DnsZone {
            id: id.into(),
            apex_domain: apex.into(),
            soa: String::new(),
            ns: vec![],
            default_ttl: 60,
        }
    }

    fn group(id: &str, zone_id: Option<&str>, members: &[&str]) -> LineGroup {
        LineGroup {
            id: id.into(),
            name: id.into(),
            zone_id: zone_id.map(Into::into),
            match_region: None,
            match_isp: None,
            member_node_ids: members.iter().map(|s| (*s).to_string()).collect(),
            priority: 0,
            fallback_group: None,
            active_window: None,
        }
    }

    #[test]
    fn maps_node_to_its_zone_domains() {
        let zones = vec![zone("z1", "a.example.com"), zone("z2", "b.example.com")];
        let groups = vec![
            group("g1", Some("z1"), &["node-1", "node-2"]),
            group("g2", Some("z2"), &["node-2"]),
            group("g3", None, &["node-1"]), // zone_id=None contributes no domain
        ];
        // node-1 is in z1 (and a zoneless group) → only a.example.com.
        assert_eq!(
            domains_for_node_in(&groups, &zones, "node-1"),
            vec!["a.example.com".to_string()]
        );
        // node-2 spans both zones.
        let mut d2 = domains_for_node_in(&groups, &zones, "node-2");
        d2.sort();
        assert_eq!(
            d2,
            vec!["a.example.com".to_string(), "b.example.com".to_string()]
        );
        // unknown node → none.
        assert!(domains_for_node_in(&groups, &zones, "node-x").is_empty());
    }
}
