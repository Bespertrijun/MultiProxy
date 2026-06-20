//! Data model DTOs (Line-0 task 4). Maps the spec Ontology with the analyst-found
//! gaps filled (`tool` selector on rules, `priority` on line groups, the `DnsZone`
//! entity, capacity config + runtime fields on the node).

use serde::{Deserialize, Serialize};

use crate::isp::Isp;

pub type NodeId = String;
pub type RuleId = String;
pub type LineGroupId = String;
pub type ZoneId = String;

/// A front NAT node. Holds operator-set capacity config and panel-maintained
/// capacity runtime (rev3 §B).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FrontNode {
    pub id: NodeId,
    pub name: String,
    pub public_ip: String,
    /// Decoded region (province/city/district from `division_code`). See [`crate::isp`].
    pub region: Region,
    pub isp: Isp,
    pub status: NodeStatus,
    /// Unix-millis of last successful contact.
    pub last_seen: u64,
    pub desired_config_gen: u64,
    pub applied_config_gen: u64,

    // ---- capacity config (operator-set, rev3 §B) ----
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bandwidth_cap_mbps: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traffic_quota_bytes: Option<u64>,
    #[serde(default)]
    pub quota_direction: QuotaDirection,
    /// Billing-cycle reset day-of-month (1–28). `None` = no quota tracking.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota_reset_day: Option<u8>,
    #[serde(default = "default_soft_quota_pct")]
    pub soft_quota_pct: u8,
    #[serde(default = "default_hard_quota_pct")]
    pub hard_quota_pct: u8,

    // ---- capacity runtime (panel-maintained, persisted; rev3 §B) ----
    #[serde(default)]
    pub accumulated_usage_bytes: u64,
    #[serde(default)]
    pub current_throughput_bps: u64,
    #[serde(default)]
    pub saturation_state: SaturationState,
    #[serde(default)]
    pub availability_state: AvailabilityState,
}

const fn default_soft_quota_pct() -> u8 {
    90
}
const fn default_hard_quota_pct() -> u8 {
    100
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum QuotaDirection {
    #[default]
    Both,
    TxOnly,
    RxOnly,
}

/// Administrative region decoded from GeoCN's integer `division_code` (D5/CRITICAL-2).
/// Variant *values* are confirmed against a real `GeoCN.mmdb` at M0; the *shape* is
/// frozen here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Region {
    /// Raw GeoCN division code, e.g. `410105`. `0` = unknown.
    pub division_code: u32,
    /// High-order province code derived from `division_code` (e.g. `41` = 河南).
    pub province_code: u16,
}

impl Region {
    #[must_use]
    pub fn unknown() -> Self {
        Self {
            division_code: 0,
            province_code: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeStatus {
    Online,
    Offline,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SaturationState {
    #[default]
    Normal,
    Saturated,
}

/// The node's current availability classification (drives the two-tier snapshot
/// build; see [`crate::snapshot`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AvailabilityState {
    #[default]
    Available,
    /// Soft exclusion (soft-quota or saturated) — promotable under pressure.
    SoftExcluded,
    /// Hard exclusion (hard-quota or unhealthy) — never promoted.
    HardExcluded,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Agent {
    pub node_id: NodeId,
    pub token_hash: String,
    pub agent_version: String,
    pub conn_state: ConnState,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnState {
    Connected,
    #[default]
    Disconnected,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ForwardRule {
    pub id: RuleId,
    pub node_id: NodeId,
    pub listen_port: u16,
    pub protocol: Protocol,
    pub backend_host: String,
    pub backend_port: u16,
    /// Which forwarding tool renders/runs this rule (AC-2 gap).
    pub tool: Tool,
    /// TLS handling mode for this rule's listener.
    #[serde(default)]
    pub tls_mode: TlsMode,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsMode {
    /// TCP passthrough -- just forward bytes, no TLS handling by the front node.
    /// Use when the Emby backend already has HTTPS. Zero cert config needed.
    #[default]
    Passthrough,
    /// TLS termination -- front node terminates HTTPS using the panel-issued cert,
    /// then forwards to the backend as plain HTTP (or re-encrypts if backend is HTTPS).
    Terminate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tool {
    Gost,
    Realm,
}

/// Maps a (region, ISP) match to a set of front nodes. `priority` resolves overlap
/// when multiple groups match (AC-3 gap). Lower number = higher priority.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LineGroup {
    pub id: LineGroupId,
    pub name: String,
    /// Which DNS zone this line group belongs to. `None` = applies to all zones.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone_id: Option<String>,
    /// `None` = matches any region.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_region: Option<u16>,
    /// `None` = matches any ISP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_isp: Option<Isp>,
    pub member_node_ids: Vec<NodeId>,
    pub priority: i32,
    /// Q3 empty-set policy: try this group when this one resolves empty; if it too
    /// is empty → SERVFAIL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_group: Option<LineGroupId>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EmbyBackend {
    pub host: String,
    pub port: u16,
}

/// Authoritative DNS zone served by the embedded GeoDNS (resolution domain ①).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DnsZone {
    pub id: ZoneId,
    pub apex_domain: String,
    pub soa: String,
    pub ns: Vec<String>,
    /// Resolution-domain A-record TTL (Q4 = 60s). Distinct from the ≤30s
    /// authoritative-removal SLO.
    pub default_ttl: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HealthCheck {
    pub node_id: NodeId,
    pub check_type: HealthCheckType,
    pub interval_secs: u32,
    pub last_result: bool,
    pub last_change_ts: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthCheckType {
    /// Control-channel heartbeat freshness (panel vantage).
    ChannelFreshness,
    /// Agent self-reported forwarding + backend reachability (agent vantage).
    AgentReport,
    /// Optional panel→public-forwarding-port TCP probe (corroborates user path).
    PublicPortProbe,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PanelUser {
    pub username: String,
    pub password_hash: String,
}

/// Q4 resolution-domain TTL default (seconds). User-adjudicated.
pub const DEFAULT_RESOLUTION_TTL_SECS: u32 = 60;

/// Q5 authoritative-layer failover SLO: max seconds from detection to :53 removal.
pub const AUTHORITATIVE_FAILOVER_SLO_SECS: u32 = 30;
