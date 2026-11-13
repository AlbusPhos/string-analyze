// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Hex 编码的 flag 前缀检测规则。
//!
//! 针对 `FLAG_PREFIXES` 在编译期生成多种十六进制表现形式（紧凑、`\xNN`、`0xNN,`
//! 以及空格分隔），识别文本中疑似经过 Hex 编码的 flag 头。

use crate::lazy_rule;
use crate::rules::core::flag::FLAG_PREFIXES;
use crate::tool::has_keyword;
use lib_unknown::encoding::hex::{hex_encode, hex_encode_len};

// 每个 prefix 生成 4 种表现形式
const PATTERNS_PER_PREFIX: usize = 4;
const PATTERN_COUNT: usize = FLAG_PREFIXES.len() * PATTERNS_PER_PREFIX;

/// 编译期计算存储所有 Pattern 所需的总字节数
const fn calc_total_buffer_len(prefixes: &[&str]) -> usize {
    let mut total = 0;
    let mut i = 0;
    while i < prefixes.len() {
        let src_len = prefixes[i].len() + 1; // 包含尾部的 '{'
        let compact = hex_encode_len(src_len);
        let escaped = src_len * 4;
        let ox_formatted = src_len * 5 - 1;
        let space_separated = src_len * 3 - 1;
        total += compact + escaped + ox_formatted + space_separated;
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

/// 编译期生成 Hex Pattern 缓冲区与元数据
const fn generate_patterns_storage() -> ([u8; TOTAL_BUFFER_LEN], [Span; PATTERN_COUNT]) {
    let mut buf = [0u8; TOTAL_BUFFER_LEN];
    let mut spans = [Span { offset: 0, len: 0 }; PATTERN_COUNT];

    let mut buf_idx = 0;
    let mut span_idx = 0;
    let mut p_idx = 0;

    while p_idx < FLAG_PREFIXES.len() {
        let prefix_bytes = FLAG_PREFIXES[p_idx].as_bytes();
        let src_len = prefix_bytes.len() + 1;

        macro_rules! get_byte {
            ($k:expr) => {
                if $k < prefix_bytes.len() {
                    prefix_bytes[$k]
                } else {
                    b'{'
                }
            };
        }

        // 1. 紧凑十六进制: "666c61677b"
        let start = buf_idx;
        let mut k = 0;
        while k < src_len {
            let byte = get_byte!(k);
            let mut hex_buf = [0u8; 2];
            hex_encode(&[byte], &mut hex_buf, false);
            buf[buf_idx] = hex_buf[0];
            buf[buf_idx + 1] = hex_buf[1];
            buf_idx += 2;
            k += 1;
        }
        spans[span_idx] = Span {
            offset: start,
            len: buf_idx - start,
        };
        span_idx += 1;

        // 2. 转义形式: "\x66\x6c\x61\x67\x7b"
        let start = buf_idx;
        let mut k = 0;
        while k < src_len {
            let byte = get_byte!(k);
            buf[buf_idx] = b'\\';
            buf[buf_idx + 1] = b'x';
            buf_idx += 2;

            let mut hex_buf = [0u8; 2];
            hex_encode(&[byte], &mut hex_buf, false);
            buf[buf_idx] = hex_buf[0];
            buf[buf_idx + 1] = hex_buf[1];
            buf_idx += 2;
            k += 1;
        }
        spans[span_idx] = Span {
            offset: start,
            len: buf_idx - start,
        };
        span_idx += 1;

        // 3. 0x 逗号分隔: "0x66,0x6c,0x61,0x67,0x7b"
        let start = buf_idx;
        let mut k = 0;
        while k < src_len {
            let byte = get_byte!(k);
            buf[buf_idx] = b'0';
            buf[buf_idx + 1] = b'x';
            buf_idx += 2;

            let mut hex_buf = [0u8; 2];
            hex_encode(&[byte], &mut hex_buf, false);
            buf[buf_idx] = hex_buf[0];
            buf[buf_idx + 1] = hex_buf[1];
            buf_idx += 2;

            if k + 1 < src_len {
                buf[buf_idx] = b',';
                buf_idx += 1;
            }
            k += 1;
        }
        spans[span_idx] = Span {
            offset: start,
            len: buf_idx - start,
        };
        span_idx += 1;

        // 4. 空格分隔: "66 6c 61 67 7b"
        let start = buf_idx;
        let mut k = 0;
        while k < src_len {
            let byte = get_byte!(k);
            let mut hex_buf = [0u8; 2];
            hex_encode(&[byte], &mut hex_buf, false);
            buf[buf_idx] = hex_buf[0];
            buf[buf_idx + 1] = hex_buf[1];
            buf_idx += 2;

            if k + 1 < src_len {
                buf[buf_idx] = b' ';
                buf_idx += 1;
            }
            k += 1;
        }
        spans[span_idx] = Span {
            offset: start,
            len: buf_idx - start,
        };
        span_idx += 1;

        p_idx += 1;
    }

    (buf, spans)
}

// 编译期生成只读二进制数据
const STORAGE_DATA: ([u8; TOTAL_BUFFER_LEN], [Span; PATTERN_COUNT]) = generate_patterns_storage();
const STORAGE_BYTES: &[u8] = &STORAGE_DATA.0;

/// 关键修复：用 const split_at 替代触发 Index trait 的 [start..end] 操作符
const fn const_subslice(src: &'static [u8], offset: usize, len: usize) -> &'static [u8] {
    let (_, tail) = src.split_at(offset);
    let (target, _) = tail.split_at(len);
    target
}

/// 编译期将只读字节数据映射为静态字符串切片数组
const fn build_str_array(
    bytes: &'static [u8],
    spans: &[Span; PATTERN_COUNT],
) -> [&'static str; PATTERN_COUNT] {
    let mut result = [""; PATTERN_COUNT];
    let mut i = 0;
    while i < PATTERN_COUNT {
        let span = spans[i];
        // 调用 const fn 获取切片，不触发 Index trait
        let byte_slice = const_subslice(bytes, span.offset, span.len);

        let slice = match core::str::from_utf8(byte_slice) {
            Ok(s) => s,
            Err(_) => panic!("Hex Pattern 生成了非法的 UTF-8 序列"),
        };
        result[i] = slice;
        i += 1;
    }
    result
}

/// 编译期完成所有切片与 UTF-8 校验，生成静态字符串切片数组
static FLAG_PREFIXES_HEX: [&str; PATTERN_COUNT] = build_str_array(STORAGE_BYTES, &STORAGE_DATA.1);

lazy_rule!(
    FLAG_HEX = |state| (state.input.len() >= 16)
        && FLAG_PREFIXES_HEX
            .iter()
            .any(|hex_prefix| has_keyword(&mut *state, hex_prefix, true)),
    "疑似 Hex 编码的 flag前缀",
    65
);

#[cfg(test)]
mod tests {
    use crate::analyze_with;
    use crate::rules::get_rules;

    #[test]
    fn test() {
        let input = r#"
hex_flag = 666c61677b68656c6c6f5f63746665727d
66 6c 61 67 7b 68 65 6c 6c 6f 5f 63 74 66 65 72 7d
66%6c%61%67%7b%68%65%6c%6c%6f%5f%63%74%66%65%72%7d
0x66,0x6c,0x61,0x67,0x7b,0x68,0x65,0x6c,0x6c,0x6f,0x5f,0x63,0x74,0x66,0x65,0x72,0x7d
0x660x6c0x610x670x7b0x680x650x6c0x6c0x6f0x5f0x630x740x660x650x720x7d
\x66\x6c\x61\x67\x7b\x68\x65\x6c\x6c\x6f\x5f\x63\x74\x66\x65\x72\x7d
66,6c,61,67,7b,68,65,6c,6c,6f,5f,63,74,66,65,72,7d
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
