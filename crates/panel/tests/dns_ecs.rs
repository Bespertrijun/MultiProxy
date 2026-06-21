//! Integration: embedded GeoDNS via DIRECT non-caching UDP queries to the bound :53
//! (here a high port). Covers AC-6 (ECS-driven per-line A set + scope echo) and AC-7
//! (flip a node's health in the snapshot → answer changes within one query).
//!
//! Queries are crafted raw with hickory-proto and sent over a UDP socket — the most
//! faithful "direct non-caching resolver query against :53" (MAJOR-3 / §11).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use contract::isp::Isp;
use contract::model::{LineGroup, Region};
use contract::snapshot::{AvailabilitySnapshot, LineAvailability};
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsCode, EdnsOption};
use hickory_proto::rr::{Name, RecordType};
use panel::dns::{spawn_dns, DnsConfig, GeoDnsHandler};
use tokio::net::UdpSocket;

use arc_swap::ArcSwap;
use geoip::{GeoIpProvider, ProviderHandle};

/// A test provider returning a fixed (province, ISP) for any IP — lets us drive the
/// answer path deterministically without a real MMDB.
struct FixedProvider {
    region: Region,
    isp: Isp,
}
impl GeoIpProvider for FixedProvider {
    fn lookup(&self, _ip: IpAddr) -> (Region, Isp) {
        (self.region.clone(), self.isp)
    }
    fn format(&self) -> &'static str {
        "fixed-test"
    }
}

fn region(p: u16) -> Region {
    Region {
        division_code: u32::from(p) * 10000,
        province_code: p,
    }
}

/// Build a snapshot with one line's available set.
fn snapshot_with(line: &str, ips: Vec<Ipv4Addr>) -> AvailabilitySnapshot {
    let mut lines = std::collections::HashMap::new();
    lines.insert(
        line.to_string(),
        LineAvailability {
            available: ips.into_iter().map(IpAddr::V4).collect(),
            fallback_group: None,
            classified: vec![],
        },
    );
    AvailabilitySnapshot {
        generation: 1,
        built_at: 0,
        lines,
    }
}

/// Spin up the DNS runtime with given handles; return (udp_port, handles).
fn spawn(
    provider: Arc<ProviderHandle>,
    groups: Arc<ArcSwap<Vec<LineGroup>>>,
    snapshot: Arc<ArcSwap<AvailabilitySnapshot>>,
) -> (u16, panel::dns::runtime::DnsRuntimeHandle) {
    let zones = Arc::new(ArcSwap::from_pointee(Vec::<contract::model::DnsZone>::new()));
    let challenges = Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new()));
    let tz_offset = Arc::new(std::sync::atomic::AtomicI64::new(480));
    let handler = GeoDnsHandler::new(snapshot, provider, groups, zones, 60, tz_offset, challenges);
    let cfg = DnsConfig {
        bind_addr: "127.0.0.1".into(),
        port: 0,
        tcp_timeout: Duration::from_secs(5),
    };
    let h = spawn_dns(handler, cfg).expect("spawn dns");
    (h.udp_port, h)
}

/// Send a raw A query (optionally with ECS) to the DNS port; return the parsed response.
async fn query(port: u16, name: &str, ecs: Option<ClientSubnet>) -> Message {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    let mut msg = Message::new(0x1234, MessageType::Query, OpCode::Query);
    let mut q = Query::new();
    q.set_name(Name::from_ascii(name).unwrap());
    q.set_query_type(RecordType::A);
    msg.add_query(q);
    if let Some(cs) = ecs {
        let mut edns = Edns::new();
        edns.set_max_payload(4096);
        edns.options_mut().insert(EdnsOption::Subnet(cs));
        msg.set_edns(edns);
    }
    let bytes = msg.to_vec().unwrap();
    sock.send_to(&bytes, target).await.unwrap();

    let mut buf = [0u8; 1500];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
        .await
        .expect("dns response timed out")
        .unwrap();
    Message::from_vec(&buf[..n]).unwrap()
}

fn answer_ips(resp: &Message) -> Vec<Ipv4Addr> {
    resp.answers
        .iter()
        .filter_map(|r| match r.data.ip_addr() {
            Some(IpAddr::V4(v4)) => Some(v4),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn ecs_query_returns_line_a_set_and_echoes_scope() {
    // 河南电信 → group g_hncc with one node.
    let provider = Arc::new(ProviderHandle::new(Arc::new(FixedProvider {
        region: region(41),
        isp: Isp::Telecom,
    })));
    let group = LineGroup {
        id: "g_hncc".into(),
        name: "henan-telecom".into(),
        zone_id: None,
        match_region: Some(41),
        match_isp: Some(Isp::Telecom),
        member_node_ids: vec!["n1".into()],
        priority: 0,
        fallback_group: None,
        active_window: None,
    };
    let groups = Arc::new(ArcSwap::from_pointee(vec![group]));
    let snapshot = Arc::new(ArcSwap::from_pointee(snapshot_with(
        "g_hncc",
        vec![Ipv4Addr::new(203, 0, 113, 7)],
    )));
    let (port, _h) = spawn(provider, groups, snapshot);

    let ecs = ClientSubnet::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 0)), 24, 0);
    let resp = query(port, "emby.example.com.", Some(ecs)).await;

    assert_eq!(answer_ips(&resp), vec![Ipv4Addr::new(203, 0, 113, 7)]);
    // ECS scope must be echoed = source prefix (24).
    let echoed = resp
        .edns
        .as_ref()
        .and_then(|e| e.option(EdnsCode::Subnet))
        .and_then(|o| match o {
            EdnsOption::Subnet(cs) => Some(*cs),
            _ => None,
        })
        .expect("response must echo ECS");
    assert_eq!(echoed.scope_prefix(), 24);
    assert_eq!(echoed.source_prefix(), 24);
}

#[tokio::test]
async fn flipping_health_changes_answer_within_one_query() {
    // AC-7 authoritative layer: store an empty snapshot → SERVFAIL; store a healthy
    // snapshot → answer. The resolver reads the live ArcSwap each query (no caching).
    let provider = Arc::new(ProviderHandle::new(Arc::new(FixedProvider {
        region: region(31),
        isp: Isp::Mobile,
    })));
    let group = LineGroup {
        id: "g_shmobile".into(),
        name: "shanghai-mobile".into(),
        zone_id: None,
        match_region: Some(31),
        match_isp: Some(Isp::Mobile),
        member_node_ids: vec!["n2".into()],
        priority: 0,
        fallback_group: None,
        active_window: None,
    };
    let groups = Arc::new(ArcSwap::from_pointee(vec![group]));
    // Start empty → SERVFAIL.
    let snapshot = Arc::new(ArcSwap::from_pointee(AvailabilitySnapshot::default()));
    let (port, _h) = spawn(provider, groups, snapshot.clone());

    let resp = query(port, "emby.example.com.", None).await;
    assert_eq!(
        resp.metadata.response_code,
        hickory_proto::op::ResponseCode::ServFail
    );

    // Node recovers: store a snapshot with an available IP.
    snapshot.store(Arc::new(snapshot_with(
        "g_shmobile",
        vec![Ipv4Addr::new(198, 51, 100, 9)],
    )));

    let resp2 = query(port, "emby.example.com.", None).await;
    assert_eq!(
        resp2.metadata.response_code,
        hickory_proto::op::ResponseCode::NoError
    );
    assert_eq!(answer_ips(&resp2), vec![Ipv4Addr::new(198, 51, 100, 9)]);

    // Node dies again: empty snapshot → SERVFAIL within one query (no fallback group).
    snapshot.store(Arc::new(AvailabilitySnapshot::default()));
    let resp3 = query(port, "emby.example.com.", None).await;
    assert_eq!(
        resp3.metadata.response_code,
        hickory_proto::op::ResponseCode::ServFail
    );
}

#[tokio::test]
async fn no_ecs_uses_source_ip_fallback() {
    // Without ECS the resolver geolocates the recursor source IP. The FixedProvider
    // returns 广东电信 regardless, so the matching group resolves.
    let provider = Arc::new(ProviderHandle::new(Arc::new(FixedProvider {
        region: region(44),
        isp: Isp::Telecom,
    })));
    let group = LineGroup {
        id: "g_gd".into(),
        name: "gd-telecom".into(),
        zone_id: None,
        match_region: Some(44),
        match_isp: Some(Isp::Telecom),
        member_node_ids: vec!["n3".into()],
        priority: 0,
        fallback_group: None,
        active_window: None,
    };
    let groups = Arc::new(ArcSwap::from_pointee(vec![group]));
    let snapshot = Arc::new(ArcSwap::from_pointee(snapshot_with(
        "g_gd",
        vec![Ipv4Addr::new(192, 0, 2, 5)],
    )));
    let (port, _h) = spawn(provider, groups, snapshot);

    let resp = query(port, "emby.example.com.", None).await;
    assert_eq!(answer_ips(&resp), vec![Ipv4Addr::new(192, 0, 2, 5)]);
    // No ECS in → no ECS echoed.
    let has_ecs = resp
        .edns
        .as_ref()
        .and_then(|e| e.option(EdnsCode::Subnet))
        .is_some();
    assert!(!has_ecs, "no ECS echoed when query had none");
}
