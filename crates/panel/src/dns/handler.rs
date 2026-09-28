//! The custom hickory `RequestHandler` (Line C task 2/3). Verified against
//! hickory-server 0.26.1: `handle_request<R: ResponseHandler, T: Time>`, ECS via
//! `request.edns`, answers built with `MessageResponseBuilder`.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;

use arc_swap::ArcSwap;
use contract::model::{DnsZone, LineGroup};
use contract::snapshot::AvailabilitySnapshot;
use geoip::ProviderHandle;
use hickory_proto::op::{Edns, Header, HeaderCounts, MessageType, Metadata, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, NS, SOA, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_server::net::runtime::Time;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponseBuilder;
use tokio::sync::RwLock;

use crate::dns::answer::{self, Resolution};
use crate::dns::ecs;

/// Shared, lock-free read inputs the resolver needs. All hot-path reads are
/// `ArcSwap::load` / `Arc` clones — no locks held across `.await`.
#[derive(Clone)]
pub struct GeoDnsHandler {
    /// The sole scheduler↔resolver coupling surface (MAJOR-5).
    pub snapshot: Arc<ArcSwap<AvailabilitySnapshot>>,
    /// Hot-reloadable geo/ISP provider (AC-10).
    pub provider: Arc<ProviderHandle>,
    /// Current line groups (swapped by the panel when CRUD changes them).
    pub groups: Arc<ArcSwap<Vec<LineGroup>>>,
    /// DNS zones for domain→zone matching.
    pub zones: Arc<ArcSwap<Vec<DnsZone>>>,
    /// Resolution-domain A-record TTL (Q4, default 60s).
    pub ttl: Arc<AtomicU64>,
    /// Timezone offset (minutes east of UTC) for evaluating line-group active windows
    /// (晚高峰换组). Shared with `AppState` so live changes apply without a restart.
    pub tz_offset_min: Arc<AtomicI64>,
    /// Observability counters (ECS hit/miss), for the metrics surface (§12).
    pub ecs_hits: Arc<AtomicU64>,
    pub ecs_misses: Arc<AtomicU64>,
    /// Self-served ACME DNS-01 challenges: normalized `_acme-challenge.<zone>` → TXT
    /// value. Lets the panel validate certs for zones delegated to its own GeoDNS.
    pub challenges: Arc<RwLock<HashMap<String, String>>>,
}

impl GeoDnsHandler {
    /// Build a handler from its shared inputs.
    #[must_use]
    pub fn new(
        snapshot: Arc<ArcSwap<AvailabilitySnapshot>>,
        provider: Arc<ProviderHandle>,
        groups: Arc<ArcSwap<Vec<LineGroup>>>,
        zones: Arc<ArcSwap<Vec<DnsZone>>>,
        ttl_secs: u32,
        tz_offset_min: Arc<AtomicI64>,
        challenges: Arc<RwLock<HashMap<String, String>>>,
    ) -> Self {
        Self {
            snapshot,
            provider,
            groups,
            zones,
            ttl: Arc::new(AtomicU64::new(u64::from(ttl_secs))),
            tz_offset_min,
            ecs_hits: Arc::new(AtomicU64::new(0)),
            ecs_misses: Arc::new(AtomicU64::new(0)),
            challenges,
        }
    }
}

fn servfail_info(meta: &Metadata) -> ResponseInfo {
    let mut m = Metadata::response_from_request(meta);
    m.response_code = ResponseCode::ServFail;
    ResponseInfo::from(Header {
        metadata: m,
        counts: HeaderCounts::default(),
    })
}

#[async_trait::async_trait]
impl RequestHandler for GeoDnsHandler {
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let request_meta = request.metadata;

        // Exactly one query expected.
        let queries = request.queries.queries();
        let Some(query) = queries.first() else {
            let resp_edns = response_edns(request, None);
            return send_servfail(
                &mut response_handle,
                request,
                &request_meta,
                resp_edns.as_ref(),
            )
            .await;
        };
        let name: Name = query.name().into();
        let qtype = query.query_type();
        let query_name_str = name.to_ascii().trim_end_matches('.').to_lowercase();
        let zones = self.zones.load();

        // A queries are routed through the line scheduler. Other types are served from
        // the authoritative zone data or returned as NODATA.
        // ECS extraction + scope echo.
        let ecs_opt = ecs::ecs_from_edns(request.edns.as_ref());
        if ecs_opt.is_some() {
            self.ecs_hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.ecs_misses.fetch_add(1, Ordering::Relaxed);
        }
        let src_ip: IpAddr = request.src().ip();
        let client = ecs::client_network(ecs_opt.as_ref(), src_ip);

        // Build EDNS only when the request negotiated EDNS. The DO bit is a request
        // preference; this server does not sign records, but must not clear it.
        let resp_edns = response_edns(request, ecs_opt.as_ref());

        let matched_zone = served_zone(zones.as_ref(), &query_name_str);

        if qtype == RecordType::NS || qtype == RecordType::SOA {
            let at_apex = matched_zone
                .is_some_and(|zone| normalized_name(&zone.apex_domain) == query_name_str);
            let records = if at_apex {
                let zone = matched_zone.expect("matched zone exists when at_apex is true");
                match qtype {
                    RecordType::NS => zone_ns_records(zone),
                    RecordType::SOA => zone_soa_record(zone, zone_ttl(zone)).into_iter().collect(),
                    _ => Vec::new(),
                }
            } else {
                Vec::new()
            };
            let authorities = if records.is_empty() {
                matched_zone
                    .and_then(zone_negative_soa_record)
                    .into_iter()
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            };
            return send_records(
                &mut response_handle,
                request,
                &request_meta,
                resp_edns.as_ref(),
                &records,
                &authorities,
            )
            .await;
        }

        // Self-served ACME DNS-01: answer TXT for `_acme-challenge.<zone>` from the
        // in-memory challenge store so the panel can validate certs for the zones
        // delegated to its own GeoDNS.
        if qtype == RecordType::TXT {
            let qname = name.to_ascii().trim_end_matches('.').to_lowercase();
            let value = self.challenges.read().await.get(&qname).cloned();
            let records = match value {
                Some(v) => vec![Record::from_rdata(
                    name.clone(),
                    60,
                    RData::TXT(TXT::new(vec![v])),
                )],
                None => vec![],
            };
            let authorities = if records.is_empty() {
                matched_zone
                    .and_then(zone_negative_soa_record)
                    .into_iter()
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            };
            return send_records(
                &mut response_handle,
                request,
                &request_meta,
                resp_edns.as_ref(),
                &records,
                &authorities,
            )
            .await;
        }

        if qtype != RecordType::A {
            // Negative answers inside a served zone carry its SOA for proper
            // negative caching. Unknown names remain empty.
            let authorities = matched_zone
                .and_then(zone_negative_soa_record)
                .into_iter()
                .collect::<Vec<_>>();
            return send_records(
                &mut response_handle,
                request,
                &request_meta,
                resp_edns.as_ref(),
                &[],
                &authorities,
            )
            .await;
        }

        // Resolve via the dumb two-tier snapshot.
        let snapshot = self.snapshot.load();
        let provider = self.provider.current();
        let groups = self.groups.load();
        let now_min = answer::local_minute_of_day(
            crate::ws_server::now_ms(),
            self.tz_offset_min.load(Ordering::Relaxed),
        );
        let resolution = answer::resolve(
            provider.as_ref(),
            groups.as_ref(),
            zones.as_ref(),
            &snapshot,
            client.addr,
            &query_name_str,
            now_min,
        );

        match resolution {
            Resolution::Answer(ipv4s) => {
                let ttl = u32::try_from(self.ttl.load(Ordering::Relaxed)).unwrap_or(60);
                let records: Vec<Record> = ipv4s
                    .into_iter()
                    .map(|ip| Record::from_rdata(name.clone(), ttl, RData::A(A(ip))))
                    .collect();
                send_records(
                    &mut response_handle,
                    request,
                    &request_meta,
                    resp_edns.as_ref(),
                    &records,
                    &[],
                )
                .await
            }
            Resolution::ServFail => {
                send_servfail(
                    &mut response_handle,
                    request,
                    &request_meta,
                    resp_edns.as_ref(),
                )
                .await
            }
        }
    }
}

fn normalized_name(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

fn served_zone<'a>(zones: &'a [DnsZone], query_name: &str) -> Option<&'a DnsZone> {
    zones
        .iter()
        .filter(|zone| {
            let apex = normalized_name(&zone.apex_domain);
            !apex.is_empty() && (query_name == apex || query_name.ends_with(&format!(".{apex}")))
        })
        .max_by_key(|zone| normalized_name(&zone.apex_domain).len())
}

fn zone_ttl(zone: &DnsZone) -> u32 {
    zone.default_ttl
}

fn fqdn(value: &str) -> String {
    let value = value.trim();
    if value == "." || value.ends_with('.') {
        value.to_string()
    } else {
        format!("{value}.")
    }
}

fn zone_name(zone: &DnsZone) -> Option<Name> {
    Name::from_ascii(fqdn(&normalized_name(&zone.apex_domain))).ok()
}

fn configured_name(value: &str) -> Option<Name> {
    if value.trim().is_empty() {
        return None;
    }
    Name::from_ascii(fqdn(value)).ok()
}

fn zone_ns_records(zone: &DnsZone) -> Vec<Record> {
    let Some(owner) = zone_name(zone) else {
        return Vec::new();
    };
    zone.ns
        .iter()
        .filter_map(|ns| configured_name(ns))
        .map(|ns| Record::from_rdata(owner.clone(), zone_ttl(zone), RData::NS(NS(ns))))
        .collect()
}

fn zone_soa_data(zone: &DnsZone) -> Option<SOA> {
    let apex = normalized_name(&zone.apex_domain);
    let fallback_mname = zone
        .ns
        .iter()
        .find_map(|ns| configured_name(ns))
        .or_else(|| zone_name(zone))?;
    let fallback_rname = configured_name(&format!("hostmaster.{apex}"))?;
    let fallback = SOA::new(
        fallback_mname,
        fallback_rname,
        1,
        7_200,
        900,
        1_209_600,
        zone_ttl(zone),
    );

    // The stored SOA is seven whitespace-separated RDATA fields. Empty or
    // legacy malformed values use zone-derived defaults.
    let fields: Vec<&str> = zone.soa.split_whitespace().collect();
    if fields.len() != 7 {
        return Some(fallback);
    }
    let mname = configured_name(fields[0]);
    let rname = configured_name(fields[1]);
    let serial = fields[2].parse().ok();
    let refresh = fields[3].parse().ok();
    let retry = fields[4].parse().ok();
    let expire = fields[5].parse().ok();
    let minimum = fields[6].parse().ok();
    match (mname, rname, serial, refresh, retry, expire, minimum) {
        (
            Some(mname),
            Some(rname),
            Some(serial),
            Some(refresh),
            Some(retry),
            Some(expire),
            Some(minimum),
        ) => Some(SOA::new(
            mname, rname, serial, refresh, retry, expire, minimum,
        )),
        _ => Some(fallback),
    }
}

fn zone_soa_record(zone: &DnsZone, ttl: u32) -> Option<Record> {
    let owner = zone_name(zone)?;
    Some(Record::from_rdata(
        owner,
        ttl,
        RData::SOA(zone_soa_data(zone)?),
    ))
}

fn zone_negative_soa_record(zone: &DnsZone) -> Option<Record> {
    let soa = zone_soa_data(zone)?;
    let owner = zone_name(zone)?;
    Some(Record::from_rdata(
        owner,
        zone_ttl(zone).min(soa.minimum),
        RData::SOA(soa),
    ))
}

fn response_edns(
    request: &Request,
    query_ecs: Option<&hickory_proto::rr::rdata::opt::ClientSubnet>,
) -> Option<Edns> {
    let query_edns = request.edns.as_ref()?;
    let mut response = Edns::new();
    response.set_max_payload(request.max_payload());
    response.set_version(0);
    response.set_dnssec_ok(query_edns.flags().dnssec_ok);
    if let Some(query_ecs) = query_ecs {
        response
            .options_mut()
            .insert(hickory_proto::rr::rdata::opt::EdnsOption::Subnet(
                ecs::echo_scope(query_ecs),
            ));
    }
    Some(response)
}

async fn send_records<R: ResponseHandler>(
    response_handle: &mut R,
    request: &Request,
    request_meta: &Metadata,
    resp_edns: Option<&Edns>,
    records: &[Record],
    authorities: &[Record],
) -> ResponseInfo {
    let mut meta = Metadata::response_from_request(request_meta);
    meta.message_type = MessageType::Response;
    meta.op_code = OpCode::Query;
    meta.authoritative = true;
    meta.response_code = ResponseCode::NoError;

    let mut builder = MessageResponseBuilder::from_message_request(request);
    if let Some(resp_edns) = resp_edns {
        builder.edns(resp_edns);
    }
    let msg = builder.build(meta, records.iter(), authorities.iter(), [], []);
    match response_handle.send_response(msg).await {
        Ok(info) => info,
        Err(error) => {
            log_send_error(request, &error);
            servfail_info(request_meta)
        }
    }
}

async fn send_servfail<R: ResponseHandler>(
    response_handle: &mut R,
    request: &Request,
    request_meta: &Metadata,
    resp_edns: Option<&Edns>,
) -> ResponseInfo {
    let mut builder = MessageResponseBuilder::from_message_request(request);
    if let Some(resp_edns) = resp_edns {
        builder.edns(resp_edns);
    }
    let msg = builder.error_msg(request_meta, ResponseCode::ServFail);
    match response_handle.send_response(msg).await {
        Ok(info) => info,
        Err(error) => {
            log_send_error(request, &error);
            servfail_info(request_meta)
        }
    }
}

fn log_send_error(request: &Request, error: &dyn std::fmt::Display) {
    let query = request.queries.queries().first();
    tracing::warn!(
        qname = query.map_or_else(|| "<none>".to_string(), |q| q.name().to_ascii()),
        qtype = ?query.map(|q| q.query_type()),
        src = %request.src(),
        error = %error,
        "failed to send DNS response"
    );
}
