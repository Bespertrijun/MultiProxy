//! Transport-agnostic wire protocol (Line-0 tasks 1–3, 7).
//!
//! The envelope is JSON (D1 wire-format decision: self-describing, forward-
//! compatible with additive/optional fields, debuggable; paired with strict
//! version negotiation in [`crate::version`]). It is transport-agnostic — carried
//! over WebSocket-over-TLS today, swappable to QUIC/gRPC later without protocol
//! churn.
//!
//! Wire shape: `{ "protocol_version": u32, "msg_id": "...", "kind": "...", "payload": { .. } }`.

use serde::{Deserialize, Serialize};

use crate::model::{Protocol, TlsMode, Tool};
use crate::version::PROTOCOL_VERSION;

/// Server-controlled heartbeat interval default (gap 7.3). Delivered to the agent
/// in [`HelloOk::heartbeat_interval_secs`] so it is tunable without redeploying agents.
pub const DEFAULT_HEARTBEAT_INTERVAL_SECS: u32 = 20;

/// ConfigAck timeout (gap 7.2). If the panel sees no ack within this window it
/// flags config-gen drift and re-pushes the current desired config.
pub const T_ACK_SECS: u32 = 15;

/// One framed protocol message. `protocol_version` + `msg_id` are envelope-level;
/// `message` flattens to `{kind, payload}` so the on-wire object is exactly
/// `{protocol_version, msg_id, kind, payload}`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Envelope {
    pub protocol_version: u32,
    pub msg_id: String,
    #[serde(flatten)]
    pub message: Message,
}

impl Envelope {
    /// Wrap a message with the current protocol version and a caller-supplied id.
    #[must_use]
    pub fn new(msg_id: impl Into<String>, message: Message) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            msg_id: msg_id.into(),
            message,
        }
    }
}

/// All message kinds, both directions. Serialized as `{"kind": "...", "payload": {..}}`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", content = "payload", rename_all = "snake_case")]
pub enum Message {
    // ---- agent → panel ----
    Hello(Hello),
    Heartbeat(Heartbeat),
    StatusReport(StatusReport),
    ConfigAck(ConfigAck),
    // ---- panel → agent ----
    HelloOk(HelloOk),
    AuthReject(AuthReject),
    ConfigPush(ConfigPush),
    Ping,
    /// Server-initiated close notice (gap 7.1 supersede / 7.6 token rotation / shutdown).
    Close(Close),
    /// Tell the agent to self-update its binary from the panel's `/dl/` and restart.
    /// Unknown to older agents (they ignore the frame), so it is forward-compatible.
    UpdateAgent,
}

/// agent→panel handshake. Per-node bearer `token` validated over TLS (task 3),
/// hashed at rest on the panel side.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Hello {
    pub node_id: String,
    pub token: String,
    pub agent_version: String,
    /// Node CPU arch / OS triple (rev4 Q1), e.g. `x86_64-linux` / `aarch64-linux`.
    /// Additive field: older agents omit it → defaults to `x86_64-linux` (the panel
    /// surfaces an upgrade warning). NOT a new coupling surface.
    #[serde(default = "default_platform")]
    pub platform: String,
}

fn default_platform() -> String {
    "x86_64-linux".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Heartbeat {
    /// Agent-local unix-millis timestamp; freshness is judged by the panel against
    /// arrival time, not this value.
    pub ts: u64,
}

/// Periodic agent self-report (D3 hybrid health + rev3 capacity telemetry).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StatusReport {
    pub forwarding_up: bool,
    pub backend_reachable: bool,
    pub applied_config_gen: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics: Option<Metrics>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capacity: Option<Capacity>,
    /// Per-backend probe results, keyed by (host, port). Additive field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_health: Option<Vec<BackendHealth>>,
    /// Which backend is currently active for each rule. Additive field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_backends: Option<Vec<ActiveBackend>>,
}

/// Probe result for one backend endpoint, as seen from the agent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BackendHealth {
    pub host: String,
    pub port: u16,
    pub reachable: bool,
}

/// Currently active backend for one forwarding rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ActiveBackend {
    pub rule_id: String,
    pub host: String,
    pub port: u16,
}

/// Optional, extensible observability metrics (gap 7.5). All fields optional;
/// unknown fields are ignored by the panel.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Metrics {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gost_realm_pids: Option<Vec<u32>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_backend_rtt_ms: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restart_count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_pct: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mem_mb: Option<u32>,
}

/// Capacity telemetry sub-object (rev3 §A — frozen at M0).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Capacity {
    /// Boot/counter-generation id. Compared by INEQUALITY only (Architect Rec#3):
    /// any change means "counter reset" — never an ordering comparison. Opaque `u64`,
    /// no monotonicity promised.
    pub counter_epoch: u64,
    /// Attribution tier so the panel knows the confidence of the numbers.
    pub source: CapacitySource,
    pub tx_bytes_total: u64,
    pub rx_bytes_total: u64,
    /// Agent-computed sliding-window rate (not a raw cumulative).
    pub throughput_bps: u64,
}

/// Traffic attribution tier (rev3 §A / Q9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapacitySource {
    /// Per-rule/per-port byte counters from gost/realm — accurate (relayed traffic only).
    ForwardBytes,
    /// NIC counter deltas — coarse (includes all host traffic); lower confidence.
    NicDelta,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConfigAck {
    pub applied_gen: u64,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub err: Option<String>,
}

/// panel→agent handshake success. Carries the server-controlled heartbeat interval
/// (gap 7.3) and failover tunables so all cadences are adjustable from the panel.
/// Failover tunable values are server-controlled via panel env vars
/// (`PANEL_PROBE_INTERVAL_SECS`, `PANEL_PROBE_TIMEOUT_MS`, `PANEL_FAILOVER_MAX_FAILS`,
/// `PANEL_FAILOVER_RECOVERY_CHECKS`, `PANEL_MIN_DWELL_SECS`), applied on agent reconnect.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HelloOk {
    pub session: String,
    pub heartbeat_interval_secs: u32,
    /// How often the agent probes each backend (seconds).
    #[serde(default = "default_probe_interval_secs")]
    pub probe_interval_secs: u32,
    /// Per-probe TCP connect timeout (milliseconds).
    #[serde(default = "default_probe_timeout_ms")]
    pub probe_timeout_ms: u32,
    /// Consecutive probe failures before a backend is considered down.
    #[serde(default = "default_failover_max_fails")]
    pub failover_max_fails: u32,
    /// Consecutive successful probes required to consider a backend recovered.
    #[serde(default = "default_failover_recovery_checks")]
    pub failover_recovery_checks: u32,
    /// Minimum seconds a failover backend must remain active before reverting.
    #[serde(default = "default_min_dwell_secs")]
    pub min_dwell_secs: u32,
}

fn default_probe_interval_secs() -> u32 {
    5
}
fn default_probe_timeout_ms() -> u32 {
    1000
}
fn default_failover_max_fails() -> u32 {
    3
}
fn default_failover_recovery_checks() -> u32 {
    6
}
fn default_min_dwell_secs() -> u32 {
    60
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthReject {
    pub reason: AuthRejectReason,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthRejectReason {
    BadToken,
    /// Protocol version outside the accepted set (gap 7.4, hard-reject default).
    ProtocolVersion,
    Other(String),
}

/// One forwarding backend (e.g. Emby) endpoint a node relays traffic to. Carried in
/// [`ConfigPush::backends`] so the agent can probe the **real** backend for
/// `StatusReport.backend_reachable` instead of a hardcoded/CLI address (the relay
/// node is the only vantage point that can see the backend behind its NAT).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackendEndpoint {
    pub host: String,
    pub port: u16,
}

/// Per-rule structured spec carried in [`ConfigPush::rules`]. Backends are ordered
/// `[main, ...extra]` matching `ForwardRule.backend_host/backend_port` then
/// `ForwardRule.extra_backends`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuleSpec {
    pub rule_id: String,
    pub listen_port: u16,
    pub protocol: Protocol,
    pub tls_mode: TlsMode,
    pub tool: Tool,
    /// Ordered backend list: index 0 is the primary, rest are standby replicas.
    pub backends: Vec<BackendEndpoint>,
}

/// Versioned full-config snapshot push (D2). Idempotent; agent echoes `desired_gen`
/// back in [`ConfigAck`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConfigPush {
    pub desired_gen: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gost_config: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_config: Option<String>,
    /// Optional TLS certificate (PEM) for gost/realm TLS termination on the front node.
    /// Additive field: older agents ignore it (D1 forward-compat).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_cert_pem: Option<String>,
    /// Optional TLS private key (PEM) paired with `tls_cert_pem`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_key_pem: Option<String>,
    /// Distinct backend endpoints this node's forwarding rules target. The agent
    /// probes these for `StatusReport.backend_reachable`. Additive: older panels
    /// omit it (defaults empty) and older agents ignore it (D1 forward-compat).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub backends: Vec<BackendEndpoint>,
    /// Structured per-rule specs (ordered backends per rule). Additive field:
    /// older agents omit/ignore it (D1 forward-compat). The legacy
    /// `gost_config`/`realm_config`/`backends` fields are retained and still populated.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<RuleSpec>,
}

/// Server-initiated close notice.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Close {
    pub reason: CloseReason,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloseReason {
    /// A newer authenticated connection for the same node_id superseded this one (gap 7.1).
    Superseded,
    /// The node's token was rotated; this session is now invalid (gap 7.6).
    TokenRotated,
    /// Panel shutting down.
    Shutdown,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(message: Message) {
        let env = Envelope::new("m-1", message);
        let json = serde_json::to_string(&env).expect("serialize");
        let back: Envelope = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(env, back, "round-trip mismatch for {json}");
        assert!(json.contains("\"kind\""));
        assert!(json.contains("\"protocol_version\""));
    }

    #[test]
    fn every_message_kind_round_trips() {
        roundtrip(Message::Hello(Hello {
            node_id: "n1".into(),
            token: "t".into(),
            agent_version: "0.1.0".into(),
            platform: "aarch64-linux".into(),
        }));
        roundtrip(Message::Heartbeat(Heartbeat { ts: 1 }));
        roundtrip(Message::StatusReport(StatusReport {
            forwarding_up: true,
            backend_reachable: true,
            applied_config_gen: 3,
            metrics: Some(Metrics {
                restart_count: Some(2),
                ..Default::default()
            }),
            capacity: Some(Capacity {
                counter_epoch: 7,
                source: CapacitySource::ForwardBytes,
                tx_bytes_total: 100,
                rx_bytes_total: 200,
                throughput_bps: 50,
            }),
            backend_health: None,
            active_backends: None,
        }));
        roundtrip(Message::ConfigAck(ConfigAck {
            applied_gen: 3,
            ok: true,
            err: None,
        }));
        roundtrip(Message::HelloOk(HelloOk {
            session: "s".into(),
            heartbeat_interval_secs: 20,
            probe_interval_secs: 5,
            probe_timeout_ms: 1000,
            failover_max_fails: 3,
            failover_recovery_checks: 6,
            min_dwell_secs: 60,
        }));
        roundtrip(Message::AuthReject(AuthReject {
            reason: AuthRejectReason::ProtocolVersion,
        }));
        roundtrip(Message::ConfigPush(ConfigPush {
            desired_gen: 4,
            gost_config: Some("...".into()),
            realm_config: None,
            tls_cert_pem: None,
            tls_key_pem: None,
            backends: vec![
                BackendEndpoint {
                    host: "10.0.0.5".into(),
                    port: 8096,
                },
                BackendEndpoint {
                    host: "emby.example.com".into(),
                    port: 443,
                },
            ],
            rules: vec![],
        }));
        // ConfigPush with TLS cert fields populated.
        roundtrip(Message::ConfigPush(ConfigPush {
            desired_gen: 5,
            gost_config: Some("g".into()),
            realm_config: None,
            tls_cert_pem: Some(
                "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n".into(),
            ),
            tls_key_pem: Some(
                "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----\n".into(),
            ),
            backends: vec![],
            rules: vec![],
        }));
        roundtrip(Message::Ping);
        roundtrip(Message::Close(Close {
            reason: CloseReason::Superseded,
        }));
    }

    #[test]
    fn platform_defaults_for_older_agents() {
        // An older agent omits `platform` entirely; it must default, not fail.
        let json = r#"{"protocol_version":1,"msg_id":"x","kind":"hello","payload":{"node_id":"n","token":"t","agent_version":"0.0.1"}}"#;
        let env: Envelope = serde_json::from_str(json).expect("legacy hello");
        match env.message {
            Message::Hello(h) => assert_eq!(h.platform, "x86_64-linux"),
            other => panic!("expected hello, got {other:?}"),
        }
    }

    #[test]
    fn config_push_tls_fields_are_optional() {
        // An older panel omits `tls_cert_pem`/`tls_key_pem` entirely; they must default to None.
        let json = r#"{"protocol_version":1,"msg_id":"x","kind":"config_push","payload":{"desired_gen":1,"gost_config":"g"}}"#;
        let env: Envelope = serde_json::from_str(json).expect("legacy config_push");
        match env.message {
            Message::ConfigPush(cp) => {
                assert_eq!(cp.desired_gen, 1);
                assert_eq!(cp.gost_config.as_deref(), Some("g"));
                assert!(cp.tls_cert_pem.is_none());
                assert!(cp.tls_key_pem.is_none());
            }
            other => panic!("expected config_push, got {other:?}"),
        }
    }

    #[test]
    fn unknown_metric_fields_are_ignored() {
        let json = r#"{"gost_realm_pids":[1,2],"some_future_field":99}"#;
        let m: Metrics = serde_json::from_str(json).expect("forward-compat metrics");
        assert_eq!(m.gost_realm_pids, Some(vec![1, 2]));
    }

    #[test]
    fn protocol_version_is_one() {
        assert_eq!(PROTOCOL_VERSION, 1, "PROTOCOL_VERSION must not be bumped");
    }

    #[test]
    fn legacy_config_push_missing_rules_defaults_empty() {
        // A panel that predates the `rules` field omits it entirely; the agent
        // must deserialize successfully with rules = [].
        let json = r#"{"protocol_version":1,"msg_id":"x","kind":"config_push","payload":{"desired_gen":2,"gost_config":"g"}}"#;
        let env: Envelope = serde_json::from_str(json).expect("legacy config_push");
        match env.message {
            Message::ConfigPush(cp) => {
                assert_eq!(cp.desired_gen, 2);
                assert!(cp.rules.is_empty(), "rules must default to []");
            }
            other => panic!("expected config_push, got {other:?}"),
        }
    }

    #[test]
    fn legacy_status_report_missing_health_fields_defaults_none() {
        // An older agent omits backend_health / active_backends; they must default to None.
        let json = r#"{"forwarding_up":true,"backend_reachable":false,"applied_config_gen":0}"#;
        let sr: StatusReport = serde_json::from_str(json).expect("legacy status_report");
        assert!(sr.backend_health.is_none());
        assert!(sr.active_backends.is_none());
    }

    #[test]
    fn legacy_hello_ok_missing_failover_fields_defaults() {
        // An older panel omits the new failover tunables; they must default correctly.
        let json = r#"{"session":"s","heartbeat_interval_secs":20}"#;
        let h: HelloOk = serde_json::from_str(json).expect("legacy hello_ok");
        assert_eq!(h.probe_interval_secs, 5);
        assert_eq!(h.probe_timeout_ms, 1000);
        assert_eq!(h.failover_max_fails, 3);
        assert_eq!(h.failover_recovery_checks, 6);
        assert_eq!(h.min_dwell_secs, 60);
    }

    #[test]
    fn config_push_with_rules_field_is_ignored_by_older_schema() {
        // A new panel sends rules=[...]; an older agent ignores unknown fields
        // (no deny_unknown_fields). We verify the field round-trips present.
        use crate::model::{Protocol, TlsMode, Tool};
        let push = ConfigPush {
            desired_gen: 1,
            gost_config: None,
            realm_config: None,
            tls_cert_pem: None,
            tls_key_pem: None,
            backends: vec![],
            rules: vec![RuleSpec {
                rule_id: "r1".into(),
                listen_port: 8080,
                protocol: Protocol::Tcp,
                tls_mode: TlsMode::Passthrough,
                tool: Tool::Gost,
                backends: vec![BackendEndpoint {
                    host: "10.0.0.1".into(),
                    port: 8096,
                }],
            }],
        };
        let json = serde_json::to_string(&push).expect("serialize");
        // rules field is present in JSON (not skipped since non-empty)
        assert!(
            json.contains("\"rules\""),
            "rules field must appear in JSON"
        );
        let back: ConfigPush = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, push);
    }

    #[test]
    fn new_types_round_trip() {
        // BackendHealth and ActiveBackend roundtrip
        let bh = BackendHealth {
            host: "10.0.0.1".into(),
            port: 8096,
            reachable: true,
        };
        let json = serde_json::to_string(&bh).unwrap();
        let back: BackendHealth = serde_json::from_str(&json).unwrap();
        assert_eq!(back, bh);

        let ab = ActiveBackend {
            rule_id: "r1".into(),
            host: "10.0.0.1".into(),
            port: 8096,
        };
        let json = serde_json::to_string(&ab).unwrap();
        let back: ActiveBackend = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ab);
    }

    #[test]
    fn status_report_with_health_fields_round_trips() {
        let sr = StatusReport {
            forwarding_up: true,
            backend_reachable: true,
            applied_config_gen: 1,
            metrics: None,
            capacity: None,
            backend_health: Some(vec![BackendHealth {
                host: "10.0.0.1".into(),
                port: 8096,
                reachable: true,
            }]),
            active_backends: Some(vec![ActiveBackend {
                rule_id: "r1".into(),
                host: "10.0.0.1".into(),
                port: 8096,
            }]),
        };
        let env = Envelope::new("m-health", Message::StatusReport(sr.clone()));
        let json = serde_json::to_string(&env).expect("serialize");
        let back: Envelope = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(env, back);
    }
}
