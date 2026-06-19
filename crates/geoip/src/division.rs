//! Decode GeoCN's integer `division_code` into a [`Region`] (D5 / CRITICAL-2).
//!
//! `division_code` is a GB/T 2260 administrative-division code, e.g. `410105`
//! = 河南省(41) 郑州市(0105) 金水区(05). The province is the high-order two digits.
//! Lower-order digits encode prefecture-city + county/district, but Line C only
//! needs province granularity for `LineGroup.match_region` matching (which keys on
//! `province_code`), so we keep the full `division_code` and derive `province_code`.

use contract::model::Region;

/// Decode a GeoCN `division_code` into a [`Region`].
///
/// `0` (the GeoCN "unknown" sentinel) maps to [`Region::unknown`]. A code is
/// expected to be 4–6 GB/T-2260 digits; the province is `code / 10_000`.
#[must_use]
pub fn decode(division_code: u32) -> Region {
    if division_code == 0 {
        return Region::unknown();
    }
    // GB/T 2260 codes are 6 digits (省2 市2 县2). Province = top two digits.
    // u16 is sufficient: max province code is 65 (新疆), well under u16::MAX.
    let province_code = u16::try_from(division_code / 10_000).unwrap_or(0);
    Region {
        division_code,
        province_code,
    }
}

/// The province name for a province code, for UI labels. Covers the GB/T 2260
/// province-level prefixes. Unknown codes return `"未知"`.
///
/// This is the explicit decode table required by D5 (never inferred implicitly).
#[must_use]
pub fn province_name(province_code: u16) -> &'static str {
    match province_code {
        11 => "北京",
        12 => "天津",
        13 => "河北",
        14 => "山西",
        15 => "内蒙古",
        21 => "辽宁",
        22 => "吉林",
        23 => "黑龙江",
        31 => "上海",
        32 => "江苏",
        33 => "浙江",
        34 => "安徽",
        35 => "福建",
        36 => "江西",
        37 => "山东",
        41 => "河南",
        42 => "湖北",
        43 => "湖南",
        44 => "广东",
        45 => "广西",
        46 => "海南",
        50 => "重庆",
        51 => "四川",
        52 => "贵州",
        53 => "云南",
        54 => "西藏",
        61 => "陕西",
        62 => "甘肃",
        63 => "青海",
        64 => "宁夏",
        65 => "新疆",
        71 => "台湾",
        81 => "香港",
        82 => "澳门",
        _ => "未知",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_full_code() {
        let r = decode(410105);
        assert_eq!(r.division_code, 410105);
        assert_eq!(r.province_code, 41);
        assert_eq!(province_name(r.province_code), "河南");
    }

    #[test]
    fn decodes_municipality() {
        // 110000 = 北京 direct municipality.
        let r = decode(110000);
        assert_eq!(r.province_code, 11);
        assert_eq!(province_name(11), "北京");
    }

    #[test]
    fn zero_is_unknown() {
        assert_eq!(decode(0), Region::unknown());
    }

    #[test]
    fn unknown_province_label() {
        assert_eq!(province_name(99), "未知");
    }
}
