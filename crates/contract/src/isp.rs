//! ISP carrier enum (Line-0 task 6 / D5 / CRITICAL-2).
//!
//! Values are GeoCN's **short forms** (电信/联通/移动/…), NOT the full names
//! (中国电信/…). The *shape* is frozen here; M0 confirms the variant set against a
//! real `GeoCN.mmdb` sample before relying on it. Panel line-group selectors MUST
//! equal these lookup outputs (never UI string literals).

use serde::{Deserialize, Serialize};

/// Carrier as emitted by the GeoCN MMDB `isp` field. `from_geocn` maps the raw
/// short-form string; unknown/empty values fall to [`Isp::Unknown`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Isp {
    /// 电信
    Telecom,
    /// 联通
    Unicom,
    /// 移动
    Mobile,
    /// 鹏博士
    Pengboshi,
    /// 教育网
    Cernet,
    /// 广电
    Broadcast,
    /// 阿里云 (IPv6)
    Aliyun,
    /// 科技网 (IPv6)
    Cstnet,
    /// Unrecognized / not in the GeoCN value set.
    Unknown,
}

impl Isp {
    /// Map a raw GeoCN `isp` short-form string to a carrier.
    ///
    /// The mapping is the **explicit normalization map** required by D5 — raw
    /// observed value → enum. M0's sample-load asserts these are the values the
    /// real MMDB emits; do not change them from memory.
    #[must_use]
    pub fn from_geocn(raw: &str) -> Self {
        match raw.trim() {
            "电信" => Isp::Telecom,
            "联通" => Isp::Unicom,
            "移动" => Isp::Mobile,
            "鹏博士" => Isp::Pengboshi,
            "教育网" => Isp::Cernet,
            "广电" => Isp::Broadcast,
            "阿里云" => Isp::Aliyun,
            "科技网" => Isp::Cstnet,
            _ => Isp::Unknown,
        }
    }

    /// Stable English/UI label.
    #[must_use]
    pub const fn ui_label(self) -> &'static str {
        match self {
            Isp::Telecom => "Telecom",
            Isp::Unicom => "Unicom",
            Isp::Mobile => "Mobile",
            Isp::Pengboshi => "Pengboshi",
            Isp::Cernet => "CERNET",
            Isp::Broadcast => "Broadcast",
            Isp::Aliyun => "Aliyun",
            Isp::Cstnet => "CSTNET",
            Isp::Unknown => "Unknown",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_documented_short_forms() {
        assert_eq!(Isp::from_geocn("电信"), Isp::Telecom);
        assert_eq!(Isp::from_geocn("联通"), Isp::Unicom);
        assert_eq!(Isp::from_geocn("移动"), Isp::Mobile);
        // Full names are NOT what the MMDB emits and must not match.
        assert_eq!(Isp::from_geocn("中国电信"), Isp::Unknown);
        assert_eq!(Isp::from_geocn(""), Isp::Unknown);
    }
}
