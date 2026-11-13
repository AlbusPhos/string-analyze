// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::rules::lazy_rule;

lazy_rule!(
    RE_TABLE_BASE64_STANDARD = r#"\b{start-half}ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\+/={0,2}\b{end-half}"#,
    "发现 标准 Base64 字符表",
    70
);
lazy_rule!(
    RE_TABLE_BASE64_URL = r#"\b{start-half}ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_={0,2}\b{end-half}"#,
    "发现 URL-Safe Base64 字符表",
    70
);
lazy_rule!(
    RE_TABLE_BASE58_BTC =
        r#"\b{start-half}123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz\b{end-half}"#,
    "发现 Base58 字符表 (Bitcoin/IPFS 标准)",
    70
);
lazy_rule!(
    RE_TABLE_BASE58_RIPPLE =
        r#"\b{start-half}rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz\b{end-half}"#,
    "发现 Base58 字符表 (Ripple 瑞波币标准)",
    70
);
lazy_rule!(
    RE_TABLE_BASE32_RFC = r#"\b{start-half}ABCDEFGHIJKLMNOPQRSTUVWXYZ234567={0,6}\b{end-half}"#,
    "发现 Base32 字符表 (RFC4648)",
    70
);
lazy_rule!(
    RE_TABLE_BASE32_HEX = r#"\b{start-half}0123456789ABCDEFGHIJKLMNOPQRSTUV={0,6}\b{end-half}"#,
    "发现 Base32 字符表 (Hex 扩展)",
    70
);
lazy_rule!(
    RE_TABLE_BASE85_Z85 = r#"\b{start-half}0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ\.\-:\+=\^!/\*\?\&<>\(\)\[\]\{\}@%\$\#\b{end-half}"#,
    "发现 Z85 (ZeroMQ Base85) 字符表",
    70
);

lazy_rule!(
    RE_TABLE_ROT13 =
        r#"\b{start-half}NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm\b{end-half}"#,
    "发现 ROT13 对照字符表",
    70
);
lazy_rule!(
    RE_TABLE_QWERTY = r#"(?i)\b{start-half}qwertyuiopasdfghjklzxcvbnm\b{end-half}"#,
    "发现 QWERTY 键盘序字符表",
    70
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::RawRule;

    #[test]
    fn tables_match_with_common_terminators() {
        let tables: [(&RawRule, &str); 9] = [
            (
                &RE_TABLE_BASE64_STANDARD,
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
            ),
            (
                &RE_TABLE_BASE64_URL,
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
            ),
            (
                &RE_TABLE_BASE58_BTC,
                "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
            ),
            (
                &RE_TABLE_BASE58_RIPPLE,
                "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz",
            ),
            (&RE_TABLE_BASE32_RFC, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"),
            (&RE_TABLE_BASE32_HEX, "0123456789ABCDEFGHIJKLMNOPQRSTUV"),
            (
                &RE_TABLE_BASE85_Z85,
                "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#",
            ),
            (
                &RE_TABLE_ROT13,
                "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
            ),
            (&RE_TABLE_QWERTY, "qwertyuiopasdfghjklzxcvbnm"),
        ];

        for &(rule, table) in &tables {
            assert!(rule.find.is_match(table), "未匹配独立字符表: {table}");
            assert!(
                rule.find.is_match(&format!("\"{table}\"")),
                "未匹配引号包裹的字符表: {table}"
            );
            assert!(
                rule.find.is_match(&format!("{table},")),
                "未匹配逗号结尾的字符表: {table}"
            );
            assert!(
                !rule.find.is_match(&format!("x{table}")),
                "不应匹配带单词前缀的字符表: {table}"
            );
            assert!(
                !rule.find.is_match(&format!("{table}x")),
                "不应匹配带单词后缀的字符表: {table}"
            );
        }
    }

    #[test]
    fn padded_tables_match() {
        assert!(
            RE_TABLE_BASE64_STANDARD
                .find
                .is_match("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
        );
        assert!(
            RE_TABLE_BASE64_STANDARD
                .find
                .is_match("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/==")
        );
        assert!(
            RE_TABLE_BASE64_URL
                .find
                .is_match("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=")
        );
        assert!(
            RE_TABLE_BASE32_RFC
                .find
                .is_match("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567======")
        );
        assert!(
            RE_TABLE_BASE32_HEX
                .find
                .is_match("0123456789ABCDEFGHIJKLMNOPQRSTUV======")
        );
    }
}
