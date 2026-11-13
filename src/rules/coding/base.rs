// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Base64 编码的 flag 前缀检测规则。
//!
//! 在编译期通过 `FLAG_PREFIXES` 生成对应的 Base64 不变前缀集合，识别文本中
//! 疑似经过 Base64 编码的 flag 头（例如 `flag{` 编码产生的确定性前缀）。

use crate::lazy_rule;
use crate::rules::core::flag::FLAG_PREFIXES;
use crate::tool::has_keyword;
use lib_unknown::encoding::base64::base64_encode;

const PATTERN_COUNT: usize = FLAG_PREFIXES.len();

/// 编译期计算所有 Base64 确定性前缀所需的总字节容量
const fn calc_total_buffer_len(prefixes: &[&str]) -> usize {
    let mut total = 0;
    let mut i = 0;
    while i < prefixes.len() {
        let src_len = prefixes[i].len() + 1; // 包含尾部的 '{'
        total += (src_len * 8) / 6; // invariant_len
        i += 1;
    }
    total
}

const TOTAL_BUFFER_LEN: usize = calc_total_buffer_len(FLAG_PREFIXES);

#[derive(Copy, Clone)]
struct Span {
    offset: usize,
    len: usize,
}

/// 编译期生成 Base64 前缀字节缓冲区与对应切片元数据
const fn generate_patterns_storage() -> ([u8; TOTAL_BUFFER_LEN], [Span; PATTERN_COUNT]) {
    let mut buf = [0u8; TOTAL_BUFFER_LEN];
    let mut spans = [Span { offset: 0, len: 0 }; PATTERN_COUNT];

    let mut buf_idx = 0;
    let mut p = 0;

    while p < FLAG_PREFIXES.len() {
        let prefix = FLAG_PREFIXES[p].as_bytes();
        let src_len = prefix.len() + 1;
        let invariant_len = (src_len * 8) / 6;

        // 构造 prefix + '{' 的输入切片（栈上临时缓冲区，支持最长 128 字节前缀）
        let mut temp_src = [0u8; 128];
        if src_len > temp_src.len() {
            panic!("FLAG_PREFIX 过长，超出 temp_src 缓冲区大小");
        }

        let mut i = 0;
        while i < prefix.len() {
            temp_src[i] = prefix[i];
            i += 1;
        }
        temp_src[prefix.len()] = b'{';

        let (src_slice, _) = temp_src.split_at(src_len);

        // 临时输出缓冲区（128 字节输入至多需要 172 字节 base64 缓冲，256 足量）
        let mut temp_dest = [0u8; 256];
        // url = false: 使用标准 Base64 字母表 (BASE64_STANDARD)
        base64_encode(src_slice, &mut temp_dest, false);

        // 仅截取 invariant_len 长度的确定性前缀（无需担心尾部 '='）
        let start = buf_idx;
        let mut k = 0;
        while k < invariant_len {
            buf[buf_idx] = temp_dest[k];
            buf_idx += 1;
            k += 1;
        }

        spans[p] = Span {
            offset: start,
            len: invariant_len,
        };

        p += 1;
    }

    (buf, spans)
}

// 编译期生成只读二进制数据
const STORAGE_DATA: ([u8; TOTAL_BUFFER_LEN], [Span; PATTERN_COUNT]) = generate_patterns_storage();
const STORAGE_BYTES: &[u8] = &STORAGE_DATA.0;

/// 使用 const split_at 提取子切片，避免在 static 块中触发尚未 const 化的 Index trait (E0658)
const fn const_subslice(src: &'static [u8], offset: usize, len: usize) -> &'static [u8] {
    let (_, tail) = src.split_at(offset);
    let (target, _) = tail.split_at(len);
    target
}

/// 编译期完成所有切片映射与 UTF-8 校验，生成静态字符串切片数组
const fn build_str_array(
    bytes: &'static [u8],
    spans: &[Span; PATTERN_COUNT],
) -> [&'static str; PATTERN_COUNT] {
    let mut result = [""; PATTERN_COUNT];
    let mut i = 0;
    while i < PATTERN_COUNT {
        let span = spans[i];
        let byte_slice = const_subslice(bytes, span.offset, span.len);

        let slice = match core::str::from_utf8(byte_slice) {
            Ok(s) => s,
            Err(_) => panic!("Base64 Pattern 生成了非法的 UTF-8 序列"),
        };
        result[i] = slice;
        i += 1;
    }
    result
}

/// 编译期完成生成的固定长度静态字符串数组，完全替代原本的 LazyLock<Vec<String>>
static FLAG_PREFIXES_B64: [&str; PATTERN_COUNT] = build_str_array(STORAGE_BYTES, &STORAGE_DATA.1);

lazy_rule!(
    FLAG_B64 = |state| (state.input.len() >= 16)
        && FLAG_PREFIXES_B64
            .iter()
            .any(|b64_prefix| has_keyword(&mut *state, b64_prefix, false)),
    "疑似 Base64 编码的 flag前缀",
    65
);

#[cfg(test)]
mod tests {
    use crate::analyze_with;
    use crate::rules::get_rules;

    #[test]
    fn test() {
        let input = r#"
b64_flag = ZmxhZ3s1dGdiOHVpaywwb2x9
b64_ctf = Y3Rme3Rlc3RfMTIzNH0=
"#;
        for line in input.lines() {
            if line.trim().is_empty() {
                continue;
            }
            println!(
                "{:#}",
                analyze_with(
                    line,
                    &get_rules(|m, _| module_path!().split("::tests").any(|s| s == m)),
                )
            )
        }
    }
}
