//! Wire-level regression tests for the authoritative DNS response contract.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use contract::isp::Isp;
use contract::model::{DnsZone, LineGroup, Region};
use contract::snapshot::{AvailabilitySnapshot, LineAvailability};
use geoip::{GeoIpProvider, ProviderHandle};
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::opt::EdnsCode;
use hickory_proto::rr::{Name, RData, RecordType};
use panel::dns::{spawn_dns, DnsConfig, GeoDnsHandler};
use tokio::net::UdpSocket;

struct FixedProvider;

impl GeoIpProvider for FixedProvider {
    fn lookup(&self, _ip: IpAddr) -> (Region, Isp) {
        (
            Region {
                division_code: 44010000,
                province_code: 44,
            },
            Isp::Telecom,
        )
    }

    fn format(&self) -> &'static str {
        "fixed-test"
    }
}

struct Fixture {
    provider: Arc<ProviderHandle>,
    groups: Arc<ArcSwap<Vec<LineGroup>>>,
    snapshot: Arc<ArcSwap<AvailabilitySnapshot>>,
    zones: Arc<ArcSwap<Vec<DnsZone>>>,
}

fn healthy_fixture() -> Fixture {
    let provider = Arc::new(ProviderHandle::new(Arc::new(FixedProvider)));
    let groups = Arc::new(ArcSwap::from_pointee(vec![LineGroup {
        id: "g1".into(),
        name: "test-line".into(),
        zone_id: Some("z1".into()),
        match_region: Some(44),
        match_isp: Some(Isp::Telecom),
        member_node_ids: vec!["node-1".into()],
        priority: 0,
        fallback_group: None,
        active_window: None,
    }]));
    let mut lines = std::collections::HashMap::new();
    lines.insert(
        "g1".to_string(),
        LineAvailability {
            available: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))],
            fallback_group: None,
            classified: vec![],
        },
    );
    let snapshot = Arc::new(ArcSwap::from_pointee(AvailabilitySnapshot {
        generation: 1,
        built_at: 0,
        lines,
    }));
    let zones = Arc::new(ArcSwap::from_pointee(vec![DnsZone {
        id: "z1".into(),
        apex_domain: "example.com".into(),
        soa: String::new(),
        ns: vec!["ns1.example.com".into(), "ns2.example.com".into()],
        default_ttl: 60,
    }]));
    Fixture {
        provider,
        groups,
        snapshot,
        zones,
    }
}

fn spawn_fixture(
    provider: Arc<ProviderHandle>,
    groups: Arc<ArcSwap<Vec<LineGroup>>>,
    snapshot: Arc<ArcSwap<AvailabilitySnapshot>>,
    zones: Arc<ArcSwap<Vec<DnsZone>>>,
) -> (u16, panel::dns::runtime::DnsRuntimeHandle) {
    let challenges = Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new()));
    let handler = GeoDnsHandler::new(
        snapshot,
        provider,
        groups,
        zones,
        60,
        Arc::new(std::sync::atomic::AtomicI64::new(480)),
        challenges,
    );
    let handle = spawn_dns(
        handler,
        DnsConfig {
            bind_addr: "127.0.0.1".into(),
            port: 0,
            tcp_timeout: Duration::from_secs(5),
        },
    )
    .expect("spawn DNS");
    (handle.udp_port, handle)
}

async fn query(port: u16, name: &str, qtype: RecordType, edns: Option<(u16, bool)>) -> Message {
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind client socket");
    let target: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let mut message = Message::new(0x7a11, MessageType::Query, OpCode::Query);
    let mut query = Query::new();
    query.set_name(Name::from_ascii(name).unwrap());
    query.set_query_type(qtype);
    message.add_query(query);
    if let Some((payload, do_bit)) = edns {
        let mut options = Edns::new();
        options.set_max_payload(payload);
        options.set_dnssec_ok(do_bit);
        message.set_edns(options);
    }
    socket
        .send_to(&message.to_vec().unwrap(), target)
        .await
        .expect("send DNS query");
    let mut buffer = [0_u8; 2048];
    let (len, _) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buffer))
        .await
        .expect("DNS response timeout")
        .expect("receive DNS response");
    Message::from_vec(&buffer[..len]).expect("decode DNS response")
}

#[tokio::test]
async fn no_edns_query_does_not_receive_an_opt_record() {
    let Fixture {
        provider,
        groups,
        snapshot,
        zones,
    } = healthy_fixture();
    let (port, _server) = spawn_fixture(provider, groups, snapshot, zones);

    let response = query(port, "app.example.com.", RecordType::A, None).await;

    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert_eq!(response.edns, None);
    assert!(response.answers.iter().any(|record| {
        matches!(record.data, RData::A(ref address) if address.0 == Ipv4Addr::new(192, 0, 2, 10))
    }));
}

#[tokio::test]
async fn response_preserves_the_dnssec_ok_bit_when_edns_is_present() {
    let Fixture {
        provider,
        groups,
        snapshot,
        zones,
    } = healthy_fixture();
    let (port, _server) = spawn_fixture(provider, groups, snapshot, zones);

    let response = query(port, "app.example.com.", RecordType::A, Some((1232, true))).await;

    let edns = response.edns.as_ref().expect("EDNS response");
    assert!(edns.flags().dnssec_ok);
    assert_eq!(edns.max_payload(), 1232);
}

#[tokio::test]
async fn apex_ns_and_soa_are_served_from_the_zone() {
    let Fixture {
        provider,
        groups,
        snapshot,
        zones,
    } = healthy_fixture();
    let (port, _server) = spawn_fixture(provider, groups, snapshot, zones);

    let ns_response = query(port, "example.com.", RecordType::NS, None).await;
    let ns_names: Vec<String> = ns_response
        .answers
        .iter()
        .filter_map(|record| match &record.data {
            RData::NS(ns) => Some(ns.0.to_ascii()),
            _ => None,
        })
        .collect();
    assert_eq!(ns_names, vec!["ns1.example.com.", "ns2.example.com."]);

    let soa_response = query(port, "example.com.", RecordType::SOA, None).await;
    let soa = soa_response
        .answers
        .iter()
        .find_map(|record| match &record.data {
            RData::SOA(soa) => Some(soa),
            _ => None,
        })
        .expect("SOA answer");
    assert_eq!(soa.mname.to_ascii(), "ns1.example.com.");
    assert_eq!(soa.rname.to_ascii(), "hostmaster.example.com.");
    assert_eq!(soa.minimum, 60);
}

#[tokio::test]
async fn served_zone_nodata_carries_soa_authority() {
    let Fixture {
        provider,
        groups,
        snapshot,
        zones,
    } = healthy_fixture();
    let (port, _server) = spawn_fixture(provider, groups, snapshot, zones);

    let response = query(port, "missing.example.com.", RecordType::AAAA, None).await;

    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert!(response.answers.is_empty());
    assert!(response
        .authorities
        .iter()
        .any(|record| matches!(record.data, RData::SOA(_))));
}

#[tokio::test]
async fn servfail_preserves_negotiated_edns() {
    let Fixture {
        provider,
        groups,
        snapshot: _,
        zones,
    } = healthy_fixture();
    let empty_snapshot = Arc::new(ArcSwap::from_pointee(AvailabilitySnapshot::default()));
    let (port, _server) = spawn_fixture(provider, groups, empty_snapshot, zones);

    let response = query(port, "app.example.com.", RecordType::A, Some((1232, true))).await;

    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    let edns = response.edns.as_ref().expect("EDNS on SERVFAIL response");
    assert_eq!(edns.max_payload(), 1232);
    assert!(edns.flags().dnssec_ok);
    assert!(edns.option(EdnsCode::Subnet).is_none());
}

#[tokio::test]
async fn negative_answers_use_closest_zone_and_configured_soa_minimum() {
    let Fixture {
        provider,
        groups,
        snapshot,
        zones,
    } = healthy_fixture();
    let mut configured = zones.load().as_ref().clone();
    configured.push(DnsZone {
        id: "child".into(),
        apex_domain: "Child.Example.COM.".into(),
        soa: "ns.example.com. hostmaster.example.com. 42 7200 900 1209600 10".into(),
        ns: vec!["ns.example.com.".into()],
        default_ttl: 60,
    });
    zones.store(Arc::new(configured));
    let (port, _server) = spawn_fixture(provider, groups, snapshot, zones);
    for kind in [RecordType::AAAA, RecordType::TXT] {
        let response = query(port, "app.child.example.com.", kind, Some((512, true))).await;
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert!(response.metadata.authoritative);
        assert!(response.answers.is_empty());
        assert_eq!(response.authorities.len(), 1);
        let record = &response.authorities[0];
        assert_eq!(record.name.to_ascii(), "child.example.com.");
        assert_eq!(record.ttl, 10);
        let RData::SOA(soa) = &record.data else {
            panic!("expected negative SOA")
        };
        assert_eq!(soa.serial, 42);
        assert_eq!(soa.minimum, 10);
    }
    let unrelated = query(port, "badexample.com.", RecordType::AAAA, None).await;
    assert!(
        unrelated.authorities.is_empty(),
        "must not attach another zone's SOA"
    );
}

#[tokio::test]
async fn zero_ttl_is_preserved_for_negative_answers() {
    let Fixture {
        provider,
        groups,
        snapshot,
        zones,
    } = healthy_fixture();
    let mut configured = zones.load().as_ref().clone();
    configured[0].default_ttl = 0;
    zones.store(Arc::new(configured));
    let (port, _server) = spawn_fixture(provider, groups, snapshot, zones);
    let response = query(port, "example.com.", RecordType::AAAA, None).await;
    assert_eq!(response.authorities.len(), 1);
    assert_eq!(response.authorities[0].ttl, 0);
}

#[tokio::test]
async fn tcp_supports_a_and_negative_aaaa_on_one_connection() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let Fixture {
        provider,
        groups,
        snapshot,
        zones,
    } = healthy_fixture();
    let (_, server) = spawn_fixture(provider, groups, snapshot, zones);
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", server.tcp_port))
            .await
            .unwrap();
        for kind in [RecordType::A, RecordType::AAAA] {
            let mut request = Message::new(42, MessageType::Query, OpCode::Query);
            let mut question = Query::new();
            question
                .set_name(Name::from_ascii("app.example.com.").unwrap())
                .set_query_type(kind);
            request.add_query(question);
            let mut edns = Edns::new();
            edns.set_dnssec_ok(true);
            request.set_edns(edns);
            let packet = request.to_vec().unwrap();
            stream.write_u16(packet.len() as u16).await.unwrap();
            stream.write_all(&packet).await.unwrap();
            let length = stream.read_u16().await.unwrap();
            let mut bytes = vec![0; usize::from(length)];
            stream.read_exact(&mut bytes).await.unwrap();
            let response = Message::from_vec(&bytes).unwrap();
            assert_eq!(response.metadata.id, 42);
            assert_eq!(response.metadata.response_code, ResponseCode::NoError);
            assert!(response.edns.as_ref().unwrap().flags().dnssec_ok);
            if kind == RecordType::A {
                assert_eq!(response.answers.len(), 1);
            } else {
                assert!(response.answers.is_empty());
                assert!(matches!(response.authorities[0].data, RData::SOA(_)));
            }
        }
    })
    .await
    .expect("TCP DNS test timed out");
}
