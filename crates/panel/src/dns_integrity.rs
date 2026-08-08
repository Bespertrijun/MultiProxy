//! Conservative DNS integrity inspection and repair.
//!
//! This service deliberately keeps provider mutation narrow: it validates the zone
//! identity and panel IPv4 first, then creates only exact records that are absent.
//! Existing records, conflicts, and duplicates are reported without update/delete.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use contract::model::{DnsZone, LineGroup};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::cloudflare::{self, CfApiError, CfClient, EnsureRecord};
use crate::db;
use crate::error::Result;
use crate::state::{AppState, CfConfig};

const LOOPBACK_TIMEOUT: Duration = Duration::from_secs(1);
const ENDPOINT_DEADLINE: Duration = Duration::from_secs(15);
const PROVIDER_DEADLINE: Duration = Duration::from_secs(12);
const FALLBACK_PROBE_NAME: &str = "dns-integrity.invalid";
const DEFAULT_ZONE_TTL: u32 = 60;

/// UI-stable check item states.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Ok,
    Repaired,
    Attention,
    Failed,
    Skipped,
}

impl CheckStatus {
    fn summary_bucket(self) -> SummaryBucket {
        match self {
            Self::Ok => SummaryBucket::Ok,
            Self::Repaired => SummaryBucket::Repaired,
            Self::Attention | Self::Skipped => SummaryBucket::Attention,
            Self::Failed => SummaryBucket::Failed,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum SummaryBucket {
    Ok,
    Repaired,
    Attention,
    Failed,
}

/// One user-facing integrity check.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CheckItem {
    pub id: String,
    pub scope: String,
    pub status: CheckStatus,
    pub message: String,
}

/// Stable item counts used by the settings UI.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct IntegritySummary {
    pub ok: usize,
    pub repaired: usize,
    pub attention: usize,
    pub failed: usize,
}

/// Overall report state.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum IntegrityStatus {
    Ok,
    Repaired,
    Attention,
    Failed,
}

/// Complete endpoint response.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct IntegrityReport {
    pub status: IntegrityStatus,
    pub checked_at: u64,
    pub summary: IntegritySummary,
    pub checks: Vec<CheckItem>,
}

/// Normalized provider/local desired state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredState {
    pub parent: String,
    pub configured_child: String,
    pub ns_host: String,
    pub panel_ip: Ipv4Addr,
    /// Configured child plus strict descendant local zones, deduplicated.
    pub managed_children: Vec<String>,
}

/// Build normalized desired state from active settings and local zones.
pub fn derive_desired_state(
    cf: &CfConfig,
    zones: &[DnsZone],
) -> std::result::Result<DesiredState, String> {
    let parent = cloudflare::normalize_dns_name(&cf.domain);
    if parent.is_empty() {
        return Err("Cloudflare parent domain is empty".into());
    }
    let configured_child = qualify_label(&cf.subdomain, &parent)?;
    let ns_host = qualify_label(&cf.ns_name, &parent)?;
    let panel_ip = cloudflare::parse_panel_ipv4(&cf.panel_ip)?;

    let mut children = BTreeSet::new();
    children.insert(configured_child.clone());
    for zone in zones {
        let apex = cloudflare::normalize_dns_name(&zone.apex_domain);
        if is_strict_descendant(&apex, &parent) {
            children.insert(apex);
        }
    }

    Ok(DesiredState {
        parent,
        configured_child,
        ns_host,
        panel_ip,
        managed_children: children.into_iter().collect(),
    })
}

fn qualify_label(label: &str, parent: &str) -> std::result::Result<String, String> {
    let label = cloudflare::normalize_dns_name(label);
    if label.is_empty() {
        return Err("DNS label is empty".into());
    }
    let full = format!("{label}.{parent}");
    if full.split('.').any(|part| part.is_empty()) {
        return Err(format!("invalid DNS name `{full}`"));
    }
    Ok(full)
}

fn is_strict_descendant(name: &str, parent: &str) -> bool {
    name != parent && name.ends_with(&format!(".{parent}"))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn now_local_minute(state: &AppState) -> u16 {
    let utc_min = (now_ms() / 60_000) % 1440;
    let offset = state.tz_offset_min.load(Ordering::Relaxed).rem_euclid(1440) as u64;
    ((utc_min + offset) % 1440) as u16
}

struct ReportBuilder {
    checks: Vec<CheckItem>,
}

impl ReportBuilder {
    fn new() -> Self {
        Self { checks: Vec::new() }
    }

    fn push(
        &mut self,
        id: impl Into<String>,
        scope: impl Into<String>,
        status: CheckStatus,
        message: impl Into<String>,
    ) {
        self.checks.push(CheckItem {
            id: id.into(),
            scope: scope.into(),
            status,
            message: message.into(),
        });
    }

    fn finish(self) -> IntegrityReport {
        let mut summary = IntegritySummary::default();
        let mut has_repaired = false;
        let mut has_attention = false;
        let mut has_failed = false;
        for item in &self.checks {
            match item.status.summary_bucket() {
                SummaryBucket::Ok => summary.ok += 1,
                SummaryBucket::Repaired => {
                    summary.repaired += 1;
                    has_repaired = true;
                }
                SummaryBucket::Attention => {
                    summary.attention += 1;
                    has_attention = true;
                }
                SummaryBucket::Failed => {
                    summary.failed += 1;
                    has_failed = true;
                }
            }
            if item.status == CheckStatus::Failed {
                has_failed = true;
            }
            if matches!(item.status, CheckStatus::Attention | CheckStatus::Skipped) {
                has_attention = true;
            }
        }
        let status = if has_failed {
            IntegrityStatus::Failed
        } else if has_attention {
            IntegrityStatus::Attention
        } else if has_repaired {
            IntegrityStatus::Repaired
        } else {
            IntegrityStatus::Ok
        };
        IntegrityReport {
            status,
            checked_at: now_ms(),
            summary,
            checks: self.checks,
        }
    }
}

/// Inspect and optionally repair current DNS/local integrity.
pub async fn inspect_and_repair(state: &AppState, repair: bool) -> Result<IntegrityReport> {
    let provider_deadline = Instant::now() + PROVIDER_DEADLINE;
    let snapshot = state.snapshot.load_full();
    let groups = state.groups.load_full();
    let zones = state.zones.load_full();
    let mut cf = state.cf_config().await;
    let mut out = ReportBuilder::new();

    let format = state.provider.current().format();
    if format == "unknown-stub" {
        out.push(
            "geocn",
            "panel",
            CheckStatus::Failed,
            "GeoCN 未加载，当前使用 unknown-stub，地理线路匹配不可用",
        );
    } else {
        out.push(
            "geocn",
            "panel",
            CheckStatus::Ok,
            format!("GeoCN 已加载 ({format})"),
        );
    }

    // An empty panel IP is an auto-detection placeholder. Only a repair run may
    // resolve it; a read-only check reports the incomplete configuration without
    // attempting a network call or mutating the runtime/DB.
    let mut cf_ready = true;
    if let Some(cf_cfg) = cf.as_mut() {
        if cf_cfg.panel_ip.trim().is_empty() {
            if repair {
                match crate::api::detect_public_ip().await {
                    Some(panel_ip) => {
                        if let Err(error) = db::set_setting(
                            &state.db,
                            "cf_panel_ip",
                            &panel_ip,
                            Some(state.vault.as_ref()),
                        )
                        .await
                        {
                            cf_ready = false;
                            out.push(
                                "cf_config",
                                "cloudflare",
                                CheckStatus::Failed,
                                format!(
                                    "已自动检测到面板公网 IPv4 {panel_ip}，但持久化失败: {error}；未执行 Cloudflare 写入"
                                ),
                            );
                        } else {
                            cf_cfg.panel_ip = panel_ip;
                            state.set_cf_config(Some(cf_cfg.clone())).await;
                            out.push(
                                "cf_config",
                                "cloudflare",
                                CheckStatus::Repaired,
                                format!("已自动检测并保存面板公网 IPv4: {}", cf_cfg.panel_ip),
                            );
                        }
                    }
                    None => {
                        cf_ready = false;
                        out.push(
                            "cf_config",
                            "cloudflare",
                            CheckStatus::Failed,
                            "面板公网 IP 为空，自动检测 IPv4 失败；未执行 Cloudflare 检查或写入",
                        );
                    }
                }
            } else {
                cf_ready = false;
                out.push(
                    "cf_config",
                    "cloudflare",
                    CheckStatus::Failed,
                    "面板公网 IP 为空；点击修复以自动检测 IPv4，当前未执行 Cloudflare 写入",
                );
            }
        }
    }

    let desired = if cf_ready {
        if let Some(cf_cfg) = &cf {
            match derive_desired_state(cf_cfg, zones.as_ref()) {
                Ok(desired) => Some(desired),
                Err(error) => {
                    out.push("cf_config", "cloudflare", CheckStatus::Failed, error);
                    None
                }
            }
        } else {
            out.push(
                "cf_config",
                "cloudflare",
                CheckStatus::Skipped,
                "未配置 Cloudflare，跳过公共 DNS 检查",
            );
            None
        }
    } else {
        None
    };

    if let (Some(cf_cfg), Some(desired)) = (cf.as_ref(), desired.as_ref()) {
        let client = CfClient::new(&cf_cfg.token, &cf_cfg.zone_id);
        let zone_ok = match with_provider_deadline(
            provider_deadline,
            client.validate_zone_name(&desired.parent),
        )
        .await
        {
            Ok(_) => {
                out.push(
                    "cf_zone",
                    &desired.parent,
                    CheckStatus::Ok,
                    format!("Cloudflare Zone ID 与父域名 {} 一致", desired.parent),
                );
                true
            }
            Err(error) => {
                out.push(
                    "cf_zone",
                    &desired.parent,
                    CheckStatus::Failed,
                    format_provider_error(&error),
                );
                false
            }
        };

        if zone_ok {
            repair_cloudflare_records(&client, desired, repair, provider_deadline, &mut out).await;
        } else {
            out.push(
                "cf_records",
                &desired.parent,
                CheckStatus::Skipped,
                "Zone 校验失败，未执行任何 Cloudflare 记录写入",
            );
        }
    }

    let zones_after = inspect_local_zones(state, desired.as_ref(), repair, &mut out).await?;
    inspect_groups(
        state,
        &zones_after,
        groups.as_ref(),
        snapshot.as_ref(),
        &mut out,
    );

    let probe_name = select_probe_name(desired.as_ref(), zones_after.as_ref());
    let route_policy = route_policy_for_probe(
        state,
        &probe_name,
        &zones_after,
        groups.as_ref(),
        snapshot.as_ref(),
    );
    inspect_dns_runtime(state, &probe_name, route_policy, &mut out).await;

    Ok(out.finish())
}

fn select_probe_name(desired: Option<&DesiredState>, zones: &[DnsZone]) -> String {
    desired
        .map(|state| state.configured_child.clone())
        .or_else(|| {
            zones.iter().find_map(|zone| {
                let apex = cloudflare::normalize_dns_name(&zone.apex_domain);
                (!apex.is_empty()).then_some(apex)
            })
        })
        .unwrap_or_else(|| FALLBACK_PROBE_NAME.to_string())
}

async fn repair_cloudflare_records(
    client: &CfClient,
    desired: &DesiredState,
    repair: bool,
    provider_deadline: Instant,
    out: &mut ReportBuilder,
) {
    let records = std::iter::once((
        "cf_ns_host_a".to_string(),
        desired.ns_host.clone(),
        "A",
        desired.panel_ip.to_string(),
    ))
    .chain(desired.managed_children.iter().map(|child| {
        (
            "cf_child_ns".to_string(),
            child.clone(),
            "NS",
            desired.ns_host.clone(),
        )
    }))
    .collect::<Vec<_>>();

    for (id, name, record_type, content) in records {
        let result = if repair {
            with_provider_deadline(
                provider_deadline,
                client.ensure_missing_record(record_type, &name, &content, false, 300),
            )
            .await
            .map(|r| match r {
                EnsureRecord::AlreadyOk(_) => CheckStatus::Ok,
                EnsureRecord::Created(_) => CheckStatus::Repaired,
            })
        } else {
            with_provider_deadline(
                provider_deadline,
                client.classify_record(record_type, &name, &content, false),
            )
            .await
            .map(|state| match state {
                cloudflare::RecordState::Ok => CheckStatus::Ok,
                cloudflare::RecordState::Missing | cloudflare::RecordState::Conflict => {
                    CheckStatus::Attention
                }
            })
        };
        match result {
            Ok(status) => {
                let message = match status {
                    CheckStatus::Ok => format!("已存在且匹配: {record_type} {name} -> {content}"),
                    CheckStatus::Repaired => format!("已补齐: {record_type} {name} -> {content}"),
                    CheckStatus::Attention => {
                        format!("记录缺失或冲突，未修改: {record_type} {name} -> {content}")
                    }
                    _ => String::new(),
                };
                out.push(id, name, status, message);
            }
            Err(error) => {
                let status = if is_conflict_error(&error) {
                    CheckStatus::Attention
                } else {
                    CheckStatus::Failed
                };
                out.push(id, name, status, format_provider_error(&error));
            }
        }
    }
}

async fn with_provider_deadline<T, F>(deadline: Instant, future: F) -> cloudflare::CfResult<T>
where
    F: std::future::Future<Output = cloudflare::CfResult<T>>,
{
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(CfApiError::Api(
            "DNS integrity provider deadline exceeded".into(),
        ));
    }
    tokio::time::timeout(remaining, future)
        .await
        .map_err(|_| CfApiError::Api("DNS integrity provider deadline exceeded".into()))?
}

fn format_provider_error(error: &CfApiError) -> String {
    format!("Cloudflare: {error}")
}

fn is_conflict_error(error: &CfApiError) -> bool {
    error.to_string().to_ascii_lowercase().contains("conflict")
}

async fn inspect_local_zones(
    state: &AppState,
    desired: Option<&DesiredState>,
    repair: bool,
    out: &mut ReportBuilder,
) -> Result<Vec<DnsZone>> {
    let Some(desired) = desired else {
        return Ok(state.zones.load_full().as_ref().clone());
    };
    let mut zones = db::list_zones(&state.db).await?;
    let expected_ns = desired.ns_host.clone();
    for child in &desired.managed_children {
        let Some(index) = zones
            .iter()
            .position(|zone| cloudflare::normalize_dns_name(&zone.apex_domain) == *child)
        else {
            if child != &desired.configured_child {
                continue;
            }
            if !repair {
                out.push(
                    "local_child_zone",
                    child,
                    CheckStatus::Attention,
                    format!("本地缺少配置子域名 {child}，未重建"),
                );
                continue;
            }
            let zone = DnsZone {
                id: uuid::Uuid::new_v4().to_string(),
                apex_domain: child.clone(),
                soa: String::new(),
                ns: vec![expected_ns.clone()],
                default_ttl: DEFAULT_ZONE_TTL,
            };
            db::upsert_zone(&state.db, &zone).await?;
            zones.push(zone);
            out.push(
                "local_child_zone",
                child,
                CheckStatus::Repaired,
                format!("已重建本地配置子域名 {child}"),
            );
            continue;
        };

        let zone = &mut zones[index];
        let normalized_ns: Vec<String> = zone
            .ns
            .iter()
            .map(|ns| cloudflare::normalize_dns_name(ns))
            .collect();
        if normalized_ns.is_empty() {
            if repair {
                zone.ns = vec![expected_ns.clone()];
                db::upsert_zone(&state.db, zone).await?;
                out.push(
                    "local_zone_ns",
                    child,
                    CheckStatus::Repaired,
                    format!("已补齐本地 NS: {child} -> {expected_ns}"),
                );
            } else {
                out.push(
                    "local_zone_ns",
                    child,
                    CheckStatus::Attention,
                    format!("本地 NS 为空: {child}，未修改"),
                );
            }
        } else if normalized_ns.len() == 1 && normalized_ns[0] == expected_ns {
            out.push(
                "local_zone_ns",
                child,
                CheckStatus::Ok,
                format!("本地 NS 正常: {child} -> {expected_ns}"),
            );
        } else {
            out.push(
                "local_zone_ns",
                child,
                CheckStatus::Attention,
                format!("本地 NS 自定义或重复，未修改: {child} -> {:?}", zone.ns),
            );
        }
    }

    state.zones.store(std::sync::Arc::new(zones.clone()));
    state.notify_change();
    Ok(zones)
}

fn inspect_groups(
    state: &AppState,
    zones: &[DnsZone],
    groups: &[LineGroup],
    snapshot: &contract::snapshot::AvailabilitySnapshot,
    out: &mut ReportBuilder,
) {
    let now = now_local_minute(state);
    for zone in zones {
        let scope = cloudflare::normalize_dns_name(&zone.apex_domain);
        let applicable: Vec<&LineGroup> = groups
            .iter()
            .filter(|group| group.zone_id.as_deref().is_none_or(|id| id == zone.id))
            .collect();
        if applicable.is_empty() {
            out.push(
                "line_group",
                &scope,
                CheckStatus::Attention,
                "没有适用于该域名的线路组",
            );
            continue;
        }
        out.push(
            "line_group",
            &scope,
            CheckStatus::Ok,
            format!("找到 {} 个适用线路组", applicable.len()),
        );

        let active: Vec<&LineGroup> = applicable
            .iter()
            .copied()
            .filter(|group| {
                group
                    .active_window
                    .is_none_or(|window| window.contains(now))
            })
            .collect();
        if active.is_empty() {
            out.push(
                "line_group_active",
                &scope,
                CheckStatus::Attention,
                "适用线路组当前均不在生效时段",
            );
        } else {
            out.push(
                "line_group_active",
                &scope,
                CheckStatus::Ok,
                format!("当前有 {} 个线路组生效", active.len()),
            );
        }

        let available = active.iter().any(|group| {
            let primary = snapshot
                .available_for(&group.id)
                .iter()
                .any(|ip| matches!(ip, IpAddr::V4(_)));
            let fallback = snapshot.fallback_for(&group.id).is_some_and(|fallback_id| {
                snapshot
                    .available_for(fallback_id)
                    .iter()
                    .any(|ip| matches!(ip, IpAddr::V4(_)))
            });
            primary || fallback
        });
        out.push(
            "line_group_ipv4",
            &scope,
            if available {
                CheckStatus::Ok
            } else {
                CheckStatus::Attention
            },
            if available {
                "当前快照存在可用 IPv4 节点"
            } else {
                "当前生效线路组没有可用 IPv4 节点"
            },
        );

        let catch_all = active
            .iter()
            .any(|group| group.match_region.is_none() && group.match_isp.is_none());
        out.push(
            "line_group_catch_all",
            &scope,
            CheckStatus::Ok,
            if catch_all {
                "存在始终适用的 catch-all 线路组"
            } else {
                "未配置 catch-all，未匹配客户端按策略 SERVFAIL"
            },
        );
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct RoutePolicy {
    catch_all: bool,
    available_ipv4: bool,
}

fn route_policy_for_probe(
    state: &AppState,
    child: &str,
    zones: &[DnsZone],
    groups: &[LineGroup],
    snapshot: &contract::snapshot::AvailabilitySnapshot,
) -> RoutePolicy {
    let now = now_local_minute(state);
    let zone_id = zones
        .iter()
        .find(|zone| cloudflare::normalize_dns_name(&zone.apex_domain) == child)
        .map(|zone| zone.id.as_str());
    let active: Vec<&LineGroup> = groups
        .iter()
        .filter(|group| match (group.zone_id.as_deref(), zone_id) {
            (Some(group_zone), Some(query_zone)) => group_zone == query_zone,
            (None, _) => true,
            (Some(_), None) => false,
        })
        .filter(|group| {
            group
                .active_window
                .is_none_or(|window| window.contains(now))
        })
        .collect();
    RoutePolicy {
        catch_all: active
            .iter()
            .any(|group| group.match_region.is_none() && group.match_isp.is_none()),
        available_ipv4: active.iter().any(|group| {
            let primary = snapshot
                .available_for(&group.id)
                .iter()
                .any(|ip| matches!(ip, IpAddr::V4(_)));
            let fallback = snapshot.fallback_for(&group.id).is_some_and(|fallback_id| {
                snapshot
                    .available_for(fallback_id)
                    .iter()
                    .any(|ip| matches!(ip, IpAddr::V4(_)))
            });
            primary || fallback
        }),
    }
}

#[derive(Debug)]
struct ProbeResult {
    response_code: Option<ResponseCode>,
    answers: Vec<Ipv4Addr>,
    error: Option<String>,
}

fn route_self_test_status(
    udp: &ProbeResult,
    tcp: &ProbeResult,
    route_policy: RoutePolicy,
) -> CheckStatus {
    let route_ok = [udp, tcp].iter().all(|probe| {
        probe.response_code == Some(ResponseCode::NoError) && !probe.answers.is_empty()
    });
    let expected_servfail = !route_policy.catch_all
        && route_policy.available_ipv4
        && udp.response_code == Some(ResponseCode::ServFail)
        && tcp.response_code == Some(ResponseCode::ServFail);
    if route_ok || expected_servfail {
        CheckStatus::Ok
    } else if udp.response_code.is_some() && tcp.response_code.is_some() {
        CheckStatus::Attention
    } else {
        CheckStatus::Failed
    }
}

async fn inspect_dns_runtime(
    state: &AppState,
    child: &str,
    route_policy: RoutePolicy,
    out: &mut ReportBuilder,
) {
    let Some((liveness, udp_port, tcp_port)) = state.dns_runtime().await else {
        out.push(
            "dns_udp",
            child,
            CheckStatus::Failed,
            "DNS runtime 尚未发布实际监听端口",
        );
        out.push(
            "dns_tcp",
            child,
            CheckStatus::Failed,
            "DNS runtime 尚未发布实际监听端口",
        );
        out.push(
            "route_self_test",
            child,
            CheckStatus::Failed,
            "无法执行 DNS 自测",
        );
        return;
    };

    let query_name = format!("{child}.");
    let (udp, tcp) = tokio::time::timeout(ENDPOINT_DEADLINE, async {
        tokio::join!(
            probe_udp(udp_port, &query_name),
            probe_tcp(tcp_port, &query_name)
        )
    })
    .await
    .unwrap_or_else(|_| {
        (
            ProbeResult {
                response_code: None,
                answers: Vec::new(),
                error: Some("DNS probe deadline exceeded".into()),
            },
            ProbeResult {
                response_code: None,
                answers: Vec::new(),
                error: Some("DNS probe deadline exceeded".into()),
            },
        )
    });

    let runtime_live = liveness.is_live();
    push_probe_item(out, "dns_udp", child, &udp, runtime_live);
    push_probe_item(out, "dns_tcp", child, &tcp, runtime_live);

    let route_ok = [&udp, &tcp].iter().all(|probe| {
        probe.response_code == Some(ResponseCode::NoError) && !probe.answers.is_empty()
    });
    let expected_servfail = !route_policy.catch_all
        && route_policy.available_ipv4
        && udp.response_code == Some(ResponseCode::ServFail)
        && tcp.response_code == Some(ResponseCode::ServFail);
    let transport_live = udp.response_code.is_some() && tcp.response_code.is_some();
    let message = format!(
        "UDP: code={:?}, A={:?}; TCP: code={:?}, A={:?}",
        udp.response_code, udp.answers, tcp.response_code, tcp.answers
    );
    let route_status = route_self_test_status(&udp, &tcp, route_policy);
    out.push(
        "route_self_test",
        child,
        route_status,
        if route_ok {
            message
        } else if expected_servfail {
            format!(
                "未配置 catch-all，当前自测不带 ECS，未匹配客户端按策略返回 SERVFAIL: {message}"
            )
        } else if transport_live {
            format!("DNS 传输正常但路由自测未就绪: {message}")
        } else {
            format!("DNS 路由自测失败: {message}")
        },
    );
}

fn push_probe_item(
    out: &mut ReportBuilder,
    id: &str,
    scope: &str,
    probe: &ProbeResult,
    runtime_live: bool,
) {
    let status = if probe.response_code.is_some() {
        CheckStatus::Ok
    } else {
        CheckStatus::Failed
    };
    let message = match (&probe.error, probe.response_code) {
        (Some(error), _) => format!(
            "DNS {} 探测失败{}: {error}",
            id,
            if runtime_live {
                ""
            } else {
                "，runtime 未标记 live"
            }
        ),
        (None, Some(code)) => format!("DNS {} 已响应: {:?}", id, code),
        (None, None) => format!("DNS {} 未返回有效响应", id),
    };
    out.push(id, scope, status, message);
}

fn build_query(name: &str) -> std::result::Result<Vec<u8>, String> {
    let mut message = Message::new(
        (now_ms() as u16).wrapping_add(1),
        MessageType::Query,
        OpCode::Query,
    );
    let mut query = Query::new();
    query
        .set_name(Name::from_ascii(name).map_err(|e| e.to_string())?)
        .set_query_type(RecordType::A);
    message.add_query(query);
    message.to_vec().map_err(|e| e.to_string())
}

async fn probe_udp(port: u16, name: &str) -> ProbeResult {
    let result = async {
        let packet = build_query(name)?;
        let socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .map_err(|e| e.to_string())?;
        let target = SocketAddr::from(([127, 0, 0, 1], port));
        socket
            .send_to(&packet, target)
            .await
            .map_err(|e| e.to_string())?;
        let mut buf = [0_u8; 4096];
        let size = tokio::time::timeout(LOOPBACK_TIMEOUT, socket.recv(&mut buf))
            .await
            .map_err(|_| "timeout after 1s".to_string())?
            .map_err(|e| e.to_string())?;
        parse_response(&buf[..size])
    }
    .await;
    result.unwrap_or_else(|error| ProbeResult {
        response_code: None,
        answers: Vec::new(),
        error: Some(error),
    })
}

async fn probe_tcp(port: u16, name: &str) -> ProbeResult {
    let result = async {
        let packet = build_query(name)?;
        let target = SocketAddr::from(([127, 0, 0, 1], port));
        let mut stream = tokio::time::timeout(LOOPBACK_TIMEOUT, TcpStream::connect(target))
            .await
            .map_err(|_| "connect timeout after 1s".to_string())?
            .map_err(|e| e.to_string())?;
        let length = u16::try_from(packet.len())
            .map_err(|_| "DNS query packet exceeds TCP frame size".to_string())?;
        stream
            .write_all(&length.to_be_bytes())
            .await
            .map_err(|e| e.to_string())?;
        stream.write_all(&packet).await.map_err(|e| e.to_string())?;
        let mut length_buf = [0_u8; 2];
        tokio::time::timeout(LOOPBACK_TIMEOUT, stream.read_exact(&mut length_buf))
            .await
            .map_err(|_| "read timeout after 1s".to_string())?
            .map_err(|e| e.to_string())?;
        let frame_len = usize::from(u16::from_be_bytes(length_buf));
        let mut response = vec![0_u8; frame_len];
        tokio::time::timeout(LOOPBACK_TIMEOUT, stream.read_exact(&mut response))
            .await
            .map_err(|_| "read body timeout after 1s".to_string())?
            .map_err(|e| e.to_string())?;
        parse_response(&response)
    }
    .await;
    result.unwrap_or_else(|error| ProbeResult {
        response_code: None,
        answers: Vec::new(),
        error: Some(error),
    })
}

fn parse_response(bytes: &[u8]) -> std::result::Result<ProbeResult, String> {
    let message = Message::from_vec(bytes).map_err(|e| format!("malformed DNS packet: {e}"))?;
    let answers = message
        .answers
        .iter()
        .filter_map(|record| match record.data.ip_addr() {
            Some(IpAddr::V4(ip)) => Some(ip),
            _ => None,
        })
        .collect();
    Ok(ProbeResult {
        response_code: Some(message.metadata.response_code),
        answers,
        error: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use contract::model::DnsZone;

    fn cf() -> CfConfig {
        CfConfig {
            token: "token".into(),
            zone_id: "zone".into(),
            domain: "HWII.DE.".into(),
            subdomain: "Dingjian".into(),
            panel_ip: "1.2.3.4".into(),
            ns_name: "NS1".into(),
            acme_staging: false,
            cert_dir: "./certs".into(),
        }
    }

    #[test]
    fn desired_state_normalizes_and_filters_strict_descendants() {
        let zones = vec![
            DnsZone {
                id: "z1".into(),
                apex_domain: "foo.HWII.DE.".into(),
                soa: String::new(),
                ns: vec![],
                default_ttl: 60,
            },
            DnsZone {
                id: "z2".into(),
                apex_domain: "hwii.de".into(),
                soa: String::new(),
                ns: vec![],
                default_ttl: 60,
            },
            DnsZone {
                id: "z3".into(),
                apex_domain: "nothwii.de".into(),
                soa: String::new(),
                ns: vec![],
                default_ttl: 60,
            },
        ];
        let state = derive_desired_state(&cf(), &zones).unwrap();
        assert_eq!(state.parent, "hwii.de");
        assert_eq!(state.configured_child, "dingjian.hwii.de");
        assert_eq!(state.ns_host, "ns1.hwii.de");
        assert_eq!(
            state.managed_children,
            vec!["dingjian.hwii.de", "foo.hwii.de"]
        );
    }

    #[test]
    fn invalid_panel_ip_blocks_desired_state() {
        let mut config = cf();
        config.panel_ip = "2001:db8::1".into();
        assert!(derive_desired_state(&config, &[]).is_err());
    }

    #[test]
    fn probe_name_falls_back_when_cloudflare_is_unavailable() {
        let zones = vec![DnsZone {
            id: "z1".into(),
            apex_domain: "Local.Example.".into(),
            soa: String::new(),
            ns: vec![],
            default_ttl: 60,
        }];
        assert_eq!(select_probe_name(None, &zones), "local.example".to_string());
        assert_eq!(select_probe_name(None, &[]), FALLBACK_PROBE_NAME);
        let desired = derive_desired_state(&cf(), &zones).unwrap();
        assert_eq!(
            select_probe_name(Some(&desired), &zones),
            "dingjian.hwii.de".to_string()
        );
    }

    #[test]
    fn report_aggregation_is_deterministic() {
        let mut out = ReportBuilder::new();
        out.push("ok", "x", CheckStatus::Ok, "ok");
        out.push("repair", "x", CheckStatus::Repaired, "repair");
        let report = out.finish();
        assert_eq!(report.status, IntegrityStatus::Repaired);
        assert_eq!(report.summary.ok, 1);
        assert_eq!(report.summary.repaired, 1);
    }

    #[test]
    fn provider_deadline_leaves_endpoint_budget_for_local_work() {
        assert!(PROVIDER_DEADLINE < ENDPOINT_DEADLINE);
        assert!(PROVIDER_DEADLINE + Duration::from_secs(2) <= ENDPOINT_DEADLINE);
    }

    fn probe(code: ResponseCode, answers: &[&str]) -> ProbeResult {
        ProbeResult {
            response_code: Some(code),
            answers: answers
                .iter()
                .map(|answer| answer.parse().unwrap())
                .collect(),
            error: None,
        }
    }

    #[test]
    fn no_catch_all_servfail_without_ecs_is_expected_when_ipv4_is_available() {
        let udp = probe(ResponseCode::ServFail, &[]);
        let tcp = probe(ResponseCode::ServFail, &[]);
        let policy = RoutePolicy {
            catch_all: false,
            available_ipv4: true,
        };
        assert_eq!(route_self_test_status(&udp, &tcp, policy), CheckStatus::Ok);
    }

    #[test]
    fn catch_all_servfail_remains_an_attention_condition() {
        let udp = probe(ResponseCode::ServFail, &[]);
        let tcp = probe(ResponseCode::ServFail, &[]);
        let policy = RoutePolicy {
            catch_all: true,
            available_ipv4: true,
        };
        assert_eq!(
            route_self_test_status(&udp, &tcp, policy),
            CheckStatus::Attention
        );
    }
}
