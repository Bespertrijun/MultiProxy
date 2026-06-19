//! GeoCN MMDB provider (the M1 default) + the ONE format-switch stub.
//!
//! GeoCN MMDB record schema (D5 / CRITICAL-2 — the *real* fields, verified against
//! the ljxi/GeoCN repo, NOT the HTTP-API enrichment layer):
//!   IPv4 → `division_code` (integer) + `isp` (short string: 电信/联通/移动/…)
//!   IPv6 → `division_code` + `isp` + `type` (网络类型: 宽带/基站/专线/IDC/空)
//! There is NO `net` field and NO separate `province/provinceCode/city/...` fields
//! in the MMDB itself. ISP values are the SHORT forms (电信, not 中国电信).

use std::net::IpAddr;

use contract::isp::Isp;
use contract::model::Region;
use maxminddb::Reader;
use serde::Deserialize;

use crate::{division, GeoIpError, GeoIpProvider};

/// The exact GeoCN MMDB record shape we deserialize (D5 / CRITICAL-2).
///
/// `division_code` is an integer; `isp` a short-form string. `type` exists only on
/// IPv6 records — optional here so IPv4 records (which omit it) decode fine. Unknown
/// MMDB fields are ignored by serde (forward-compatible).
#[derive(Debug, Deserialize)]
struct GeoCnRecord {
    #[serde(default)]
    division_code: u32,
    #[serde(default)]
    isp: String,
    /// IPv6-only network type (宽带/基站/专线/IDC/…). Decoded for completeness;
    /// not used by Line C's IPv4-only M1 answer path.
    #[serde(default, rename = "type")]
    net_type: Option<String>,
}

/// GeoCN MMDB-backed provider. Reads a `GeoCN.mmdb` file via `maxminddb` and decodes
/// the documented `division_code`/`isp` fields.
pub struct GeoCnProvider {
    reader: Reader<Vec<u8>>,
}

impl GeoCnProvider {
    /// Open a GeoCN MMDB file from disk.
    ///
    /// # Errors
    /// Returns [`GeoIpError::Mmdb`] if the file is missing or not a valid MMDB.
    pub fn open(path: &str) -> Result<Self, GeoIpError> {
        let reader = Reader::open_readfile(path).map_err(|e| GeoIpError::Mmdb(e.to_string()))?;
        Ok(Self { reader })
    }

    /// Build from raw MMDB bytes (used by tests that synthesize a tiny DB).
    ///
    /// # Errors
    /// Returns [`GeoIpError::Mmdb`] if the bytes are not a valid MMDB.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, GeoIpError> {
        let reader = Reader::from_source(bytes).map_err(|e| GeoIpError::Mmdb(e.to_string()))?;
        Ok(Self { reader })
    }
}

impl GeoIpProvider for GeoCnProvider {
    fn lookup(&self, ip: IpAddr) -> (Region, Isp) {
        let Ok(result) = self.reader.lookup(ip) else {
            return (Region::unknown(), Isp::Unknown);
        };
        if !result.has_data() {
            return (Region::unknown(), Isp::Unknown);
        }
        match result.decode::<GeoCnRecord>() {
            Ok(Some(rec)) => {
                let region = division::decode(rec.division_code);
                let isp = Isp::from_geocn(&rec.isp);
                let _ = rec.net_type; // IPv6 type decoded but unused in M1 (IPv4-only).
                (region, isp)
            }
            _ => (Region::unknown(), Isp::Unknown),
        }
    }

    fn format(&self) -> &'static str {
        "geocn-mmdb"
    }
}

/// The ONE format-switch stub (D5). A trivial `cidr,division_code,isp` text table,
/// proving that selecting `db.format = static_table` picks a *different* impl with no
/// recompile. NOT a production geo source — the real ipip/纯真 binary adapters are
/// the M3 follow-up.
pub struct StaticTableProvider {
    entries: Vec<TableEntry>,
}

struct TableEntry {
    network: ipnet_lite::Net,
    division_code: u32,
    isp: Isp,
}

impl StaticTableProvider {
    /// Open a static-table file from disk.
    ///
    /// # Errors
    /// Returns [`GeoIpError::Io`] on read failure or [`GeoIpError::Parse`] on a bad line.
    pub fn open(path: &str) -> Result<Self, GeoIpError> {
        let text = std::fs::read_to_string(path).map_err(|e| GeoIpError::Io(e.to_string()))?;
        Self::from_lines(&text)
    }

    /// Parse a static table from text. Format: one `cidr,division_code,isp` per line;
    /// blank lines and `#` comments ignored.
    ///
    /// # Errors
    /// Returns [`GeoIpError::Parse`] if a non-comment line is malformed.
    pub fn from_lines(text: &str) -> Result<Self, GeoIpError> {
        let mut entries = Vec::new();
        for (lineno, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.splitn(3, ',');
            let cidr = parts.next().unwrap_or("");
            let code = parts.next().unwrap_or("");
            let isp = parts.next().unwrap_or("");
            let network = ipnet_lite::Net::parse(cidr).ok_or_else(|| {
                GeoIpError::Parse(format!("line {}: bad cidr {cidr:?}", lineno + 1))
            })?;
            let division_code: u32 = code.trim().parse().map_err(|_| {
                GeoIpError::Parse(format!("line {}: bad division_code {code:?}", lineno + 1))
            })?;
            entries.push(TableEntry {
                network,
                division_code,
                isp: Isp::from_geocn(isp.trim()),
            });
        }
        Ok(Self { entries })
    }
}

impl GeoIpProvider for StaticTableProvider {
    fn lookup(&self, ip: IpAddr) -> (Region, Isp) {
        for e in &self.entries {
            if e.network.contains(ip) {
                return (division::decode(e.division_code), e.isp);
            }
        }
        (Region::unknown(), Isp::Unknown)
    }

    fn format(&self) -> &'static str {
        "static-table-stub"
    }
}

/// Minimal self-contained CIDR containment check for the format-switch stub, so the
/// stub depends on nothing extra. Supports IPv4 and IPv6 CIDRs.
mod ipnet_lite {
    use std::net::IpAddr;

    #[derive(Debug, Clone, Copy)]
    pub struct Net {
        addr: IpAddr,
        prefix: u8,
    }

    impl Net {
        pub fn parse(s: &str) -> Option<Self> {
            let (ip_str, pre_str) = s.split_once('/')?;
            let addr: IpAddr = ip_str.trim().parse().ok()?;
            let prefix: u8 = pre_str.trim().parse().ok()?;
            let max = if addr.is_ipv4() { 32 } else { 128 };
            if prefix > max {
                return None;
            }
            Some(Self { addr, prefix })
        }

        pub fn contains(&self, ip: IpAddr) -> bool {
            match (self.addr, ip) {
                (IpAddr::V4(net), IpAddr::V4(q)) => {
                    let net = u32::from(net);
                    let q = u32::from(q);
                    let mask = if self.prefix == 0 {
                        0
                    } else {
                        u32::MAX << (32 - self.prefix)
                    };
                    (net & mask) == (q & mask)
                }
                (IpAddr::V6(net), IpAddr::V6(q)) => {
                    let net = u128::from(net);
                    let q = u128::from(q);
                    let mask = if self.prefix == 0 {
                        0
                    } else {
                        u128::MAX << (128 - self.prefix)
                    };
                    (net & mask) == (q & mask)
                }
                _ => false,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn static_table_parses_and_matches() {
        let p = StaticTableProvider::from_lines(
            "# comment\n\n202.96.128.0/19,440100,电信\n221.176.0.0/13,500000,移动\n",
        )
        .expect("parse");
        let (r, isp) = p.lookup(IpAddr::V4(Ipv4Addr::new(202, 96, 130, 1)));
        assert_eq!(r.division_code, 440100);
        assert_eq!(r.province_code, 44);
        assert_eq!(isp, Isp::Telecom);

        let (r2, isp2) = p.lookup(IpAddr::V4(Ipv4Addr::new(221, 176, 0, 5)));
        assert_eq!(r2.province_code, 50);
        assert_eq!(isp2, Isp::Mobile);

        // Outside any table entry → unknown.
        let (r3, isp3) = p.lookup(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(r3, Region::unknown());
        assert_eq!(isp3, Isp::Unknown);
    }

    #[test]
    fn static_table_format_id() {
        let p = StaticTableProvider::from_lines("1.0.0.0/8,110000,联通\n").unwrap();
        assert_eq!(p.format(), "static-table-stub");
    }

    #[test]
    fn bad_line_is_parse_error() {
        assert!(StaticTableProvider::from_lines("not-a-cidr,x,y\n").is_err());
    }

    /// Live GeoCN MMDB decode test — GATED behind the `GEOCN_MMDB` env var and
    /// `#[ignore]` so CI does not fail when the real (large, network-fetched)
    /// `GeoCN.mmdb` is unavailable in the sandbox (see report notes). Run with:
    ///   `GEOCN_MMDB=/path/to/GeoCN.mmdb cargo test -p geoip -- --ignored`
    /// It asserts the decoder reads the documented `division_code`/`isp` fields
    /// from a real file (CRITICAL-2 sample-load), the M0 tie-breaker task.
    #[test]
    #[ignore = "requires a real GeoCN.mmdb via GEOCN_MMDB env var"]
    fn live_geocn_mmdb_decodes_documented_fields() {
        let path = std::env::var("GEOCN_MMDB")
            .expect("set GEOCN_MMDB to a real GeoCN.mmdb path to run this test");
        let provider = GeoCnProvider::open(&path).expect("open GeoCN.mmdb");
        assert_eq!(provider.format(), "geocn-mmdb");
        // 114.114.114.114 (南京信风 DNS, 江苏电信 space) is a stable mainland anchor.
        let (region, isp) = provider.lookup(IpAddr::V4(Ipv4Addr::new(114, 114, 114, 114)));
        // We do not hard-code the exact division here (DB revisions move it); we
        // assert the decode produced a real mainland province + a recognized ISP,
        // which is what proves the documented-field decode path works end to end.
        assert_ne!(
            region,
            Region::unknown(),
            "expected a decoded mainland region"
        );
        assert_ne!(isp, Isp::Unknown, "expected a recognized short-form ISP");
    }
}
