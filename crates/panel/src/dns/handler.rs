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
use hickory_proto::rr::rdata::{A, TXT};
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
            return send_servfail(&mut response_handle, request, &request_meta).await;
        };
        let name: Name = query.name().into();
        let qtype = query.query_type();

        // Only A queries serve records this phase (Q2 IPv4-only). Other types → empty
        // NOERROR (the zone exists; we just have no such record).
        // ECS extraction + scope echo.
        let ecs_opt = ecs::ecs_from_edns(request.edns.as_ref());
        if ecs_opt.is_some() {
            self.ecs_hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.ecs_misses.fetch_add(1, Ordering::Relaxed);
        }
        let src_ip: IpAddr = request.src().ip();
        let client = ecs::client_network(ecs_opt.as_ref(), src_ip);

        // Build the response EDNS (echo ECS scope if present).
        let mut resp_edns = Edns::new();
        resp_edns.set_max_payload(request.max_payload());
        resp_edns.set_version(0);
        if let Some(query_ecs) = ecs_opt.as_ref() {
            let echoed = ecs::echo_scope(query_ecs);
            resp_edns
                .options_mut()
                .insert(hickory_proto::rr::rdata::opt::EdnsOption::Subnet(echoed));
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
            return send_records(
                &mut response_handle,
                request,
                &request_meta,
                &resp_edns,
                &records,
            )
            .await;
        }

        if qtype != RecordType::A {
            // No A record requested → NOERROR, no answers (authoritative empty).
            return send_records(
                &mut response_handle,
                request,
                &request_meta,
                &resp_edns,
                &[],
            )
            .await;
        }

        // Resolve via the dumb two-tier snapshot.
        let snapshot = self.snapshot.load();
        let provider = self.provider.current();
        let groups = self.groups.load();
        let zones = self.zones.load();
        let query_name_str = name.to_ascii().trim_end_matches('.').to_lowercase();
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
                    &resp_edns,
                    &records,
                )
                .await
            }
            Resolution::ServFail => {
                send_servfail(&mut response_handle, request, &request_meta).await
            }
        }
    }
}

async fn send_records<R: ResponseHandler>(
    response_handle: &mut R,
    request: &Request,
    request_meta: &Metadata,
    resp_edns: &Edns,
    records: &[Record],
) -> ResponseInfo {
    let mut meta = Metadata::response_from_request(request_meta);
    meta.message_type = MessageType::Response;
    meta.op_code = OpCode::Query;
    meta.authoritative = true;
    meta.response_code = ResponseCode::NoError;

    let mut builder = MessageResponseBuilder::from_message_request(request);
    builder.edns(resp_edns);
    let msg = builder.build(meta, records.iter(), [], [], []);
    match response_handle.send_response(msg).await {
        Ok(info) => info,
        Err(_) => servfail_info(request_meta),
    }
}

async fn send_servfail<R: ResponseHandler>(
    response_handle: &mut R,
    request: &Request,
    request_meta: &Metadata,
) -> ResponseInfo {
    let builder = MessageResponseBuilder::from_message_request(request);
    let msg = builder.error_msg(request_meta, ResponseCode::ServFail);
    match response_handle.send_response(msg).await {
        Ok(info) => info,
        Err(_) => servfail_info(request_meta),
    }
}
