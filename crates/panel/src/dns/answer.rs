//! Answer builder (Line C task 3 / AC-6, AC-7, AC-11/12 DNS side).
//!
//! ClientNetwork → GeoIpProvider → (region, ISP) → match `LineGroup` (respecting
//! `priority` on overlap) → read `ArcSwap<AvailabilitySnapshot>` → that group's
//! `available` A records at `DnsZone.default_ttl`; if empty → `fallback_group` →
//! else SERVFAIL (Q3). The resolver is "dumb": it serves `available` and never learns
//! WHY an IP was excluded (the two-tier fallback is baked in by the scheduler).

use std::net::{IpAddr, Ipv4Addr};

use contract::isp::Isp;
use contract::model::{DnsZone, LineGroup, Region};
use contract::snapshot::AvailabilitySnapshot;
use geoip::GeoIpProvider;

use super::diag::{self, DiagStep};

/// The resolution outcome for a query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// Serve these A records (IPv4 only this phase, Q2).
    Answer(Vec<Ipv4Addr>),
    /// No line resolved / all empty incl. fallback → SERVFAIL (Q3 terminal).
    ServFail,
}

/// Select the best-matching line group for a (region, ISP), honoring `priority`
/// (lower number = higher priority) and `match_region`/`match_isp` specificity.
///
/// A group with `match_region == Some(p)` matches only province `p`; `None` matches
/// any. Same for `match_isp`. Among matching groups, the most specific wins, then the
/// lowest `priority` number, then a stable id order.
#[must_use]
pub fn match_line_group<'a>(
    groups: &'a [LineGroup],
    region: &Region,
    isp: Isp,
) -> Option<&'a LineGroup> {
    let mut candidates: Vec<&LineGroup> = groups
        .iter()
        .filter(|g| {
            let region_ok = g.match_region.is_none_or(|p| p == region.province_code);
            let isp_ok = g.match_isp.is_none_or(|i| i == isp);
            region_ok && isp_ok
        })
        .collect();

    candidates.sort_by(|a, b| {
        // More specific (more Some matchers) first.
        let spec_a = usize::from(a.match_region.is_some()) + usize::from(a.match_isp.is_some());
        let spec_b = usize::from(b.match_region.is_some()) + usize::from(b.match_isp.is_some());
        spec_b
            .cmp(&spec_a)
            .then(a.priority.cmp(&b.priority))
            .then(a.id.cmp(&b.id))
    });
    candidates.into_iter().next()
}

/// Convert a unix-millis instant plus a timezone offset (minutes east of UTC) into the
/// local minute-of-day in `[0,1440)`. China is a fixed UTC+8 (no DST), so a constant
/// offset is exact — this avoids pulling a timezone database into the panel.
#[must_use]
pub fn local_minute_of_day(now_ms: u64, tz_offset_min: i64) -> u16 {
    let secs = (now_ms / 1000) as i64;
    let local = secs + tz_offset_min * 60;
    let mod_day = local.rem_euclid(86_400);
    (mod_day / 60) as u16
}

/// Resolve a client network to a set of A records.
///
/// `provider` does the geo/ISP lookup; `groups` are all configured line groups;
/// `snapshot` holds the two-tier-resolved `available` sets. `now_min` is the current
/// local minute-of-day (see [`local_minute_of_day`]) used to honor each group's
/// `active_window` (e.g. evening-peak switching). Applies the Q3 empty-set policy: try
/// the matched line's `fallback_group` once, else SERVFAIL.
#[must_use]
pub fn resolve(
    provider: &dyn GeoIpProvider,
    groups: &[LineGroup],
    zones: &[DnsZone],
    snapshot: &AvailabilitySnapshot,
    client_addr: IpAddr,
    query_name: &str,
    now_min: u16,
) -> Resolution {
    let mut steps: Vec<DiagStep> = Vec::new();
    let resolution = resolve_traced(
        provider,
        groups,
        zones,
        snapshot,
        client_addr,
        query_name,
        now_min,
        &mut steps,
    );
    let (ok, summary) = match &resolution {
        Resolution::Answer(ips) => (true, format!("已解析: {ips:?}")),
        Resolution::ServFail => (false, "SERVFAIL (未返回任何 IP)".to_string()),
    };
    diag::record(query_name, client_addr, ok, &summary, steps);
    resolution
}

/// The actual resolution, pushing a structured trace into `steps` at each decision
/// point so the panel UI can show exactly where an answer — or a SERVFAIL — came from.
#[allow(clippy::too_many_arguments)]
fn resolve_traced(
    provider: &dyn GeoIpProvider,
    groups: &[LineGroup],
    zones: &[DnsZone],
    snapshot: &AvailabilitySnapshot,
    client_addr: IpAddr,
    query_name: &str,
    now_min: u16,
    steps: &mut Vec<DiagStep>,
) -> Resolution {
    let matched_zone = zones
        .iter()
        .find(|z| query_name.ends_with(&z.apex_domain) || query_name == z.apex_domain);
    let zone_id = matched_zone.map(|z| z.id.as_str());
    match matched_zone {
        Some(z) => steps.push(DiagStep::new(
            "ok",
            "step1 域名匹配",
            format!(
                "查询 {query_name} 命中域名 {}（共 {} 个域名）",
                z.apex_domain,
                zones.len()
            ),
        )),
        None => {
            let names: Vec<&str> = zones.iter().map(|z| z.apex_domain.as_str()).collect();
            steps.push(DiagStep::new(
                "warn",
                "step1 域名匹配",
                format!(
                    "查询 {query_name} 未命中任何域名（已配置: {names:?}）——按域名关联的线路组将被全部过滤"
                ),
            ));
        }
    }

    let filtered: Vec<&LineGroup> = groups
        .iter()
        .filter(|g| match (&g.zone_id, zone_id) {
            (Some(gz), Some(qz)) => gz == qz,
            (None, _) => true,
            (Some(_), None) => false,
        })
        .collect();
    let kept: Vec<String> = filtered
        .iter()
        .map(|g| {
            let region = match g.match_region {
                Some(p) => format!("{p}({})", geoip::division::province_name(p)),
                None => "不限".to_string(),
            };
            let isp = g.match_isp.map_or("不限", |i| i.zh_label());
            format!(
                "{}(地区={region},运营商={isp},成员数={})",
                g.name,
                g.member_node_ids.len()
            )
        })
        .collect();
    steps.push(DiagStep::new(
        if filtered.is_empty() { "fail" } else { "ok" },
        "step2 线路组按域名过滤",
        format!(
            "共 {} 个线路组，关联到本域名的剩 {} 个 -> {kept:?}",
            groups.len(),
            filtered.len(),
        ),
    ));

    // step2.5 生效时段过滤（晚高峰换组）。带 `active_window` 的组只在窗口内可选；窗口外
    // 被过滤掉，于是同匹配条件、始终生效的常规组自然接管。无窗口的组（绝大多数）恒生效。
    let scheduled = filtered
        .iter()
        .filter(|g| g.active_window.is_some())
        .count();
    let inactive: Vec<&str> = filtered
        .iter()
        .filter(|g| g.active_window.is_some_and(|w| !w.contains(now_min)))
        .map(|g| g.name.as_str())
        .collect();
    let time_active: Vec<&LineGroup> = filtered
        .iter()
        .copied()
        .filter(|g| g.active_window.is_none_or(|w| w.contains(now_min)))
        .collect();
    let (hh, mm) = (now_min / 60, now_min % 60);
    steps.push(DiagStep::new(
        if scheduled > 0 { "ok" } else { "info" },
        "step2.5 生效时段过滤",
        format!(
            "当前本地时间 {hh:02}:{mm:02}（按面板时区设置）；{scheduled} 个组配置了生效时段，\
             当前未生效（已过滤）: {inactive:?}",
        ),
    ));

    let (region, isp) = provider.lookup(client_addr);
    steps.push(DiagStep::new(
        "info",
        "step3 客户端地理识别",
        format!(
            "省份={}（{}） 运营商={}（须满足线路组的 匹配地区/匹配运营商）",
            region.province_code,
            geoip::division::province_name(region.province_code),
            isp.zh_label(),
        ),
    ));

    let flat: Vec<LineGroup> = time_active.into_iter().cloned().collect();
    let Some(group) = match_line_group(&flat, &region, isp) else {
        steps.push(DiagStep::new(
            "fail",
            "step4 匹配线路组",
            "没有线路组匹配（域名过滤 + 生效时段 + 地区/运营商过滤后为空）-> SERVFAIL".to_string(),
        ));
        return Resolution::ServFail;
    };
    steps.push(DiagStep::new(
        "ok",
        "step4 匹配线路组",
        format!(
            "命中线路组 {}，成员节点={:?}",
            group.name, group.member_node_ids
        ),
    ));

    // Primary line.
    let primary = ipv4_only(snapshot.available_for(&group.id));
    steps.push(DiagStep::new(
        if primary.is_empty() { "warn" } else { "ok" },
        "step5 可用 IP 集",
        format!(
            "快照gen={} 全部={:?} 实际下发(IPv4)={primary:?}（为空=组内没有健康的成员节点）",
            snapshot.generation,
            snapshot.available_for(&group.id),
        ),
    ));
    if !primary.is_empty() {
        return Resolution::Answer(primary);
    }

    // Q3 empty-set: try the fallback group once.
    if let Some(fb) = snapshot
        .fallback_for(&group.id)
        .or(group.fallback_group.as_deref())
    {
        let fallback = ipv4_only(snapshot.available_for(fb));
        steps.push(DiagStep::new(
            if fallback.is_empty() { "fail" } else { "ok" },
            "step6 兜底线路组",
            format!("主线路为空，尝试兜底线路组 {fb}：下发={fallback:?}"),
        ));
        if !fallback.is_empty() {
            return Resolution::Answer(fallback);
        }
    }

    steps.push(DiagStep::new(
        "fail",
        "结果",
        "SERVFAIL（没有可下发的 IP）".to_string(),
    ));
    Resolution::ServFail
}

/// Keep only IPv4 addresses (A records; Q2 IPv4-only this phase).
///
/// We chose to warn-on-drop here (rather than reject IPv6 `public_ip` at node-create
/// in `api.rs`): an accidental IPv6 `public_ip` would otherwise be silently filtered
/// out of a served set and could cause an unexplained SERVFAIL. The warn surfaces it.
fn ipv4_only(ips: &[IpAddr]) -> Vec<Ipv4Addr> {
    ips.iter()
        .filter_map(|ip| match ip {
            IpAddr::V4(v4) => Some(*v4),
            IpAddr::V6(v6) => {
                tracing::warn!(
                    addr = %v6,
                    "dropping IPv6 address from served set (A records are IPv4-only this phase); \
                     an accidental IPv6 public_ip can cause SERVFAIL"
                );
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use contract::snapshot::LineAvailability;
    use std::collections::HashMap;

    fn group(
        id: &str,
        region: Option<u16>,
        isp: Option<Isp>,
        priority: i32,
        fb: Option<&str>,
    ) -> LineGroup {
        LineGroup {
            id: id.into(),
            name: id.into(),
            zone_id: None,
            match_region: region,
            match_isp: isp,
            member_node_ids: vec![],
            priority,
            fallback_group: fb.map(str::to_string),
            active_window: None,
        }
    }

    fn snap_with(line: &str, ips: Vec<Ipv4Addr>) -> AvailabilitySnapshot {
        let mut lines = HashMap::new();
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

    struct FakeProvider(Region, Isp);
    impl GeoIpProvider for FakeProvider {
        fn lookup(&self, _ip: IpAddr) -> (Region, Isp) {
            (self.0.clone(), self.1)
        }
        fn format(&self) -> &'static str {
            "fake"
        }
    }

    fn region(p: u16) -> Region {
        Region {
            division_code: u32::from(p) * 10000,
            province_code: p,
        }
    }

    #[test]
    fn priority_resolves_overlap() {
        // Two groups both match 河南电信; lower priority number wins.
        let groups = vec![
            group("hi", Some(41), Some(Isp::Telecom), 1, None),
            group("lo", Some(41), Some(Isp::Telecom), 5, None),
        ];
        let m = match_line_group(&groups, &region(41), Isp::Telecom).unwrap();
        assert_eq!(m.id, "hi");
    }

    #[test]
    fn specificity_beats_wildcard() {
        let groups = vec![
            group("specific", Some(41), Some(Isp::Telecom), 9, None),
            group("wildcard", None, None, 0, None),
        ];
        let m = match_line_group(&groups, &region(41), Isp::Telecom).unwrap();
        assert_eq!(m.id, "specific");
    }

    #[test]
    fn answer_returns_available_set() {
        let groups = vec![group("g1", Some(41), Some(Isp::Telecom), 0, None)];
        let snap = snap_with("g1", vec![Ipv4Addr::new(1, 1, 1, 1)]);
        let p = FakeProvider(region(41), Isp::Telecom);
        let zones = vec![];
        let r = resolve(
            &p,
            &groups,
            &zones,
            &snap,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "test.example.com",
            600,
        );
        assert_eq!(r, Resolution::Answer(vec![Ipv4Addr::new(1, 1, 1, 1)]));
    }

    #[test]
    fn empty_falls_back_then_servfail() {
        let groups = vec![group("g1", Some(41), Some(Isp::Telecom), 0, Some("g2"))];
        let snap = snap_with("g2", vec![Ipv4Addr::new(2, 2, 2, 2)]);
        let p = FakeProvider(region(41), Isp::Telecom);
        let zones = vec![];
        let r = resolve(
            &p,
            &groups,
            &zones,
            &snap,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "test.example.com",
            600,
        );
        assert_eq!(r, Resolution::Answer(vec![Ipv4Addr::new(2, 2, 2, 2)]));

        let empty = AvailabilitySnapshot::default();
        let r2 = resolve(
            &p,
            &groups,
            &zones,
            &empty,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "test.example.com",
            600,
        );
        assert_eq!(r2, Resolution::ServFail);
    }

    #[test]
    fn no_matching_group_servfails() {
        let groups = vec![group("g1", Some(41), Some(Isp::Telecom), 0, None)];
        let snap = AvailabilitySnapshot::default();
        let p = FakeProvider(region(31), Isp::Mobile);
        let zones = vec![];
        let r = resolve(
            &p,
            &groups,
            &zones,
            &snap,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "test.example.com",
            600,
        );
        assert_eq!(r, Resolution::ServFail);
    }

    #[test]
    fn time_window_contains_and_wraps_midnight() {
        use contract::model::TimeWindow;
        let day = TimeWindow {
            start_min: 8 * 60,
            end_min: 18 * 60,
        };
        assert!(day.contains(8 * 60), "inclusive start");
        assert!(day.contains(10 * 60));
        assert!(!day.contains(18 * 60), "exclusive end");
        assert!(!day.contains(7 * 60));

        let night = TimeWindow {
            start_min: 20 * 60,
            end_min: 2 * 60,
        }; // 20:00–02:00 crosses midnight
        assert!(night.contains(20 * 60), "inclusive start");
        assert!(night.contains(23 * 60));
        assert!(night.contains(60), "01:00 is still inside");
        assert!(!night.contains(2 * 60), "exclusive end");
        assert!(!night.contains(10 * 60));
    }

    #[test]
    fn local_minute_of_day_applies_offset() {
        // Epoch 00:00 UTC + 8h = 08:00 local = 480 min.
        assert_eq!(local_minute_of_day(0, 480), 480);
        // 16:30:00 UTC with +0 offset = 990 min.
        assert_eq!(local_minute_of_day(59_400_000, 0), 990);
        // 23:00 UTC + 8h wraps to 07:00 next day = 420 min.
        assert_eq!(local_minute_of_day(23 * 3_600_000, 480), 420);
    }

    #[test]
    fn peak_window_switches_line_group() {
        use contract::model::TimeWindow;
        // Identical matcher (河南电信). `peak` is active only 20:00–24:00 and out-ranks
        // `normal`. During peak the resolver serves peak's IP; off-peak the peak group is
        // filtered out by its window and the always-on `normal` group takes over.
        let mut peak = group("peak", Some(41), Some(Isp::Telecom), 0, None);
        peak.active_window = Some(TimeWindow {
            start_min: 20 * 60,
            end_min: 24 * 60,
        });
        let normal = group("normal", Some(41), Some(Isp::Telecom), 5, None);
        let groups = vec![peak, normal];

        let mut lines = HashMap::new();
        lines.insert(
            "peak".to_string(),
            LineAvailability {
                available: vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))],
                fallback_group: None,
                classified: vec![],
            },
        );
        lines.insert(
            "normal".to_string(),
            LineAvailability {
                available: vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
                fallback_group: None,
                classified: vec![],
            },
        );
        let snap = AvailabilitySnapshot {
            generation: 1,
            built_at: 0,
            lines,
        };
        let p = FakeProvider(region(41), Isp::Telecom);
        let zones = vec![];

        let at_peak = resolve(
            &p,
            &groups,
            &zones,
            &snap,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "x.example.com",
            21 * 60,
        );
        assert_eq!(at_peak, Resolution::Answer(vec![Ipv4Addr::new(9, 9, 9, 9)]));

        let off_peak = resolve(
            &p,
            &groups,
            &zones,
            &snap,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "x.example.com",
            10 * 60,
        );
        assert_eq!(
            off_peak,
            Resolution::Answer(vec![Ipv4Addr::new(1, 1, 1, 1)])
        );
    }
}
