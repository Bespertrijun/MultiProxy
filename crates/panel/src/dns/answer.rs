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

/// Resolve a client network to a set of A records.
///
/// `provider` does the geo/ISP lookup; `groups` are all configured line groups;
/// `snapshot` holds the two-tier-resolved `available` sets. Applies the Q3 empty-set
/// policy: try the matched line's `fallback_group` once, else SERVFAIL.
#[must_use]
pub fn resolve(
    provider: &dyn GeoIpProvider,
    groups: &[LineGroup],
    zones: &[DnsZone],
    snapshot: &AvailabilitySnapshot,
    client_addr: IpAddr,
    query_name: &str,
) -> Resolution {
    let zone_id = zones
        .iter()
        .find(|z| query_name.ends_with(&z.apex_domain) || query_name == z.apex_domain)
        .map(|z| z.id.as_str());
    let filtered: Vec<&LineGroup> = groups
        .iter()
        .filter(|g| match (&g.zone_id, zone_id) {
            (Some(gz), Some(qz)) => gz == qz,
            (None, _) => true,
            (Some(_), None) => false,
        })
        .collect();
    let (region, isp) = provider.lookup(client_addr);
    let flat: Vec<LineGroup> = filtered.into_iter().cloned().collect();
    let Some(group) = match_line_group(&flat, &region, isp) else {
        return Resolution::ServFail;
    };

    // Primary line.
    let primary = ipv4_only(snapshot.available_for(&group.id));
    if !primary.is_empty() {
        return Resolution::Answer(primary);
    }

    // Q3 empty-set: try the fallback group once.
    if let Some(fb) = snapshot
        .fallback_for(&group.id)
        .or(group.fallback_group.as_deref())
    {
        let fallback = ipv4_only(snapshot.available_for(fb));
        if !fallback.is_empty() {
            return Resolution::Answer(fallback);
        }
    }

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
        );
        assert_eq!(r, Resolution::ServFail);
    }
}
