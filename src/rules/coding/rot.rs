// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! 凯撒移位（ROT-N）与 ROT47 混淆 flag 检测规则。
//!
//! 在编译期以 `const fn` 预计算全部移位表，运行时仅动态拼接一条正则，
//! 用于发现经过字母移位（ROT-N）或 ROT47 变换后仍保留 `flag{` / `ctf{`
//! 结构的混淆文本。

use crate::rules::lazy_rule;
use std::sync::LazyLock;

// ==========================================
// 1. 编译期移位工具函数 (const fn)
// ==========================================

const fn shift_alpha_bytes<const N: usize>(s: &[u8; N], k: u8) -> [u8; N] {
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        let c = s[i];
        out[i] = if c >= b'a' && c <= b'z' {
            b'a' + (c - b'a' + k) % 26
        } else if c >= b'A' && c <= b'Z' {
            b'A' + (c - b'A' + k) % 26
        } else {
            c
        };
        i += 1;
    }
    out
}

const fn shift_rot47_bytes<const N: usize>(s: &[u8; N], k: u8) -> [u8; N] {
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        let c = s[i];
        out[i] = if c >= 33 && c <= 126 {
            33 + (c - 33 + k) % 94
        } else {
            c
        };
        i += 1;
    }
    out
}

// ==========================================
// 2. 编译期计算全量表 (Zero Runtime Cost)
// ==========================================

const FLAG_ALPHA_TABLE: [[u8; 5]; 25] = {
    let mut table = [[0u8; 5]; 25];
    let mut k = 1;
    while k <= 25 {
        table[(k - 1) as usize] = shift_alpha_bytes(b"flag{", k);
        k += 1;
    }
    table
};

const CTF_ALPHA_TABLE: [[u8; 4]; 25] = {
    let mut table = [[0u8; 4]; 25];
    let mut k = 1;
    while k <= 25 {
        table[(k - 1) as usize] = shift_alpha_bytes(b"ctf{", k);
        k += 1;
    }
    table
};

const FLAG_ROT47_TABLE: [[u8; 5]; 93] = {
    let mut table = [[0u8; 5]; 93];
    let mut k = 1;
    while k <= 93 {
        table[(k - 1) as usize] = shift_rot47_bytes(b"flag{", k);
        k += 1;
    }
    table
};

const CTF_ROT47_TABLE: [[u8; 4]; 93] = {
    let mut table = [[0u8; 4]; 93];
    let mut k = 1;
    while k <= 93 {
        table[(k - 1) as usize] = shift_rot47_bytes(b"ctf{", k);
        k += 1;
    }
    table
};

// ==========================================
// 3. 动态构建极速 Regex 表达式
// ==========================================

static ROT_ALPHA_REGEX_PATTERN: LazyLock<String> = LazyLock::new(|| {
    let mut prefixes = Vec::with_capacity(50);
    for bytes in &FLAG_ALPHA_TABLE {
        prefixes.push(regex::escape(std::str::from_utf8(bytes).unwrap()));
    }
    for bytes in &CTF_ALPHA_TABLE {
        prefixes.push(regex::escape(std::str::from_utf8(bytes).unwrap()));
    }
    format!(
        r#"(?i)\b(?:{})[^{{\}}\n\t\s]{{4,256}}\}}"#,
        prefixes.join("|")
    )
});

static ROT47_REGEX_PATTERN: LazyLock<String> = LazyLock::new(|| {
    let mut prefixes = Vec::with_capacity(186);
    for bytes in &FLAG_ROT47_TABLE {
        prefixes.push(regex::escape(std::str::from_utf8(bytes).unwrap()));
    }
    for bytes in &CTF_ROT47_TABLE {
        prefixes.push(regex::escape(std::str::from_utf8(bytes).unwrap()));
    }
    format!(r#"(?:{})[\x21-\x7e]{{4,256}}"#, prefixes.join("|"))
});

// ==========================================
// 4. 核心规则定义
// ==========================================

lazy_rule!(
    RE_ROT_ALPHA_FLAG = |s| {
        static RE: LazyLock<regex::Regex> =
            LazyLock::new(|| regex::Regex::new(&ROT_ALPHA_REGEX_PATTERN).unwrap());

        let mut hit = false;
        for m in RE.find_iter(s.input) {
            s.ranges.push((m.start(), m.end()));
            hit = true;
        }
        hit
    },
    "发现 凯撒密码 (ROT-N) 变体 Flag",
    80
);

lazy_rule!(
    RE_ROT47_FLAG = |s| {
        static RE: LazyLock<regex::Regex> =
            LazyLock::new(|| regex::Regex::new(&ROT47_REGEX_PATTERN).unwrap());

        let mut hit = false;
        for m in RE.find_iter(s.input) {
            s.ranges.push((m.start(), m.end()));
            hit = true;
        }
        hit
    },
    "发现 ROT47 混淆 Flag",
    80
);

#[cfg(test)]
mod tests {
    use crate::analyze_with;
    use crate::rules::get_rules;

    #[test]
    fn test() {
        let input = r##"
偏移量 =  1: gmbh{bgtiekelmjkoyx}
偏移量 =  2: hnci{chujflfmnklpzy}
偏移量 =  3: iodj{divkgmgnolmqaz}
偏移量 =  4: jpek{ejwlhnhopmnrba}
偏移量 =  5: kqfl{fkxmioipqnoscb}
偏移量 =  6: lrgm{glynjpjqroptdc}
偏移量 =  7: mshn{hmzokqkrspqued}
偏移量 =  8: ntio{inaplrlstqrvfe}
偏移量 =  9: oujp{jobqmsmturswgf}
偏移量 = 10: pvkq{kpcrntnuvstxhg}
偏移量 = 11: qwlr{lqdsouovwtuyih}
偏移量 = 12: rxms{mretpvpwxuvzji}
偏移量 = 13: synt{nsfuqwqxyvwakj}
偏移量 = 14: tzou{otgvrxryzwxblk}
偏移量 = 15: uapv{puhwsyszaxycml}
偏移量 = 16: vbqw{qvixtztabyzdnm}
偏移量 = 17: wcrx{rwjyuaubczaeon}
偏移量 = 18: xdsy{sxkzvbvcdabfpo}
偏移量 = 19: yetz{tylawcwdebcgqp}
偏移量 = 20: zfua{uzmbxdxefcdhrq}
偏移量 = 21: agvb{vancyeyfgdeisr}
偏移量 = 22: bhwc{wbodzfzghefjts}
偏移量 = 23: cixd{xcpeagahifgkut}
偏移量 = 24: djye{ydqfbhbijghlvu}
偏移量 = 25: ekzf{zergcicjkhimwv}
偏移量 =  1: gmbh|bgtiekelmjkoyx~
偏移量 =  2: hnci}chujflfmnklpzy!
偏移量 =  3: iodj~divkgmgnolmq{z"
偏移量 =  4: jpek!ejwlhnhopmnr|{#
偏移量 =  5: kqfl"fkxmioipqnos}|$
偏移量 =  6: lrgm#glynjpjqropt~}%
偏移量 =  7: mshn$hmzokqkrspqu!~&
偏移量 =  8: ntio%in{plrlstqrv"!'
偏移量 =  9: oujp&jo|qmsmtursw#"(
偏移量 = 10: pvkq'kp}rntnuvstx$#)
偏移量 = 11: qwlr(lq~souovwtuy%$*
偏移量 = 12: rxms)mr!tpvpwxuvz&%+
偏移量 = 13: synt*ns"uqwqxyvw{'&,
偏移量 = 14: tzou+ot#vrxryzwx|('-
偏移量 = 15: u{pv,pu$wsysz{xy})(.
偏移量 = 16: v|qw-qv%xtzt{|yz~*)/
偏移量 = 17: w}rx.rw&yu{u|}z{!+*0
偏移量 = 18: x~sy/sx'zv|v}~{|",+1
偏移量 = 19: y!tz0ty({w}w~!|}#-,2
偏移量 = 20: z"u{1uz)|x~x!"}~$.-3
偏移量 = 21: {#v|2v{*}y!y"#~!%/.4
        偏移量 = 22: |$w}3w|+~z"z#$!"&0/5
    偏移量 = 23: }%x~4x},!{#{$%"#'106
偏移量 = 24: ~&y!5y~-"|$|%&#$(217
偏移量 = 25: !'z"6z!.#}%}&'$%)328
偏移量 = 26: "({#7{"/$~&~'(%&*439
偏移量 = 27: #)|$8|#0%!'!()&'+54:
偏移量 = 28: $*}%9}$1&"(")*'(,65;
偏移量 = 29: %+~&:~%2'#)#*+()-76<
偏移量 = 30: &,!';!&3($*$+,)*.87=
偏移量 = 31: '-"(<"'4)%+%,-*+/98>
偏移量 = 32: (.#)=#(5*&,&-.+,0:9?
偏移量 = 33: )/$*>$)6+'-'./,-1;:@
偏移量 = 34: *0%+?%*7,(.(/0-.2<;A
偏移量 = 35: +1&,@&+8-)/)01./3=<B
偏移量 = 36: ,2'-A',9.*0*12/04>=C
偏移量 = 37: -3(.B(-:/+1+23015?>D
偏移量 = 38: .4)/C).;0,2,34126@?E
偏移量 = 39: /5*0D*/<1-3-45237A@F
偏移量 = 40: 06+1E+0=2.4.56348BAG
偏移量 = 41: 17,2F,1>3/5/67459CBH
偏移量 = 42: 28-3G-2?40607856:DCI
偏移量 = 43: 39.4H.3@51718967;EDJ
偏移量 = 44: 4:/5I/4A62829:78<FEK
偏移量 = 45: 5;06J05B7393:;89=GFL
偏移量 = 46: 6<17K16C84:4;<9:>HGM
偏移量 = 47: 7=28L27D95;5<=:;?IHN
偏移量 = 48: 8>39M38E:6<6=>;<@JIO
偏移量 = 49: 9?4:N49F;7=7>?<=AKJP
偏移量 = 50: :@5;O5:G<8>8?@=>BLKQ
偏移量 = 51: ;A6<P6;H=9?9@A>?CMLR
偏移量 = 52: <B7=Q7<I>:@:AB?@DNMS
偏移量 = 53: =C8>R8=J?;A;BC@AEONT
偏移量 = 54: >D9?S9>K@<B<CDABFPOU
偏移量 = 55: ?E:@T:?LA=C=DEBCGQPV
偏移量 = 56: @F;AU;@MB>D>EFCDHRQW
偏移量 = 57: AG<BV<ANC?E?FGDEISRX
偏移量 = 58: BH=CW=BOD@F@GHEFJTSY
偏移量 = 59: CI>DX>CPEAGAHIFGKUTZ
偏移量 = 60: DJ?EY?DQFBHBIJGHLVU[
偏移量 = 61: EK@FZ@ERGCICJKHIMWV\
偏移量 = 62: FLAG[AFSHDJDKLIJNXW]
偏移量 = 63: GMBH\BGTIEKELMJKOYX^
偏移量 = 64: HNCI]CHUJFLFMNKLPZY_
偏移量 = 65: IODJ^DIVKGMGNOLMQ[Z`
偏移量 = 66: JPEK_EJWLHNHOPMNR\[a
偏移量 = 67: KQFL`FKXMIOIPQNOS]\b
偏移量 = 68: LRGMaGLYNJPJQROPT^]c
偏移量 = 69: MSHNbHMZOKQKRSPQU_^d
偏移量 = 70: NTIOcIN[PLRLSTQRV`_e
偏移量 = 71: OUJPdJO\QMSMTURSWa`f
偏移量 = 72: PVKQeKP]RNTNUVSTXbag
偏移量 = 73: QWLRfLQ^SOUOVWTUYcbh
偏移量 = 74: RXMSgMR_TPVPWXUVZdci
偏移量 = 75: SYNThNS`UQWQXYVW[edj
偏移量 = 76: TZOUiOTaVRXRYZWX\fek
偏移量 = 77: U[PVjPUbWSYSZ[XY]gfl
偏移量 = 78: V\QWkQVcXTZT[\YZ^hgm
偏移量 = 79: W]RXlRWdYU[U\]Z[_ihn
偏移量 = 80: X^SYmSXeZV\V]^[\`jio
偏移量 = 81: Y_TZnTYf[W]W^_\]akjp
偏移量 = 82: Z`U[oUZg\X^X_`]^blkq
偏移量 = 83: [aV\pV[h]Y_Y`a^_cmlr
偏移量 = 84: \bW]qW\i^Z`Zab_`dnms
偏移量 = 85: ]cX^rX]j_[a[bc`aeont
偏移量 = 86: ^dY_sY^k`\b\cdabfpou
偏移量 = 87: _eZ`tZ_la]c]debcgqpv
偏移量 = 88: `f[au[`mb^d^efcdhrqw
偏移量 = 89: ag\bv\anc_e_fgdeisrx
偏移量 = 90: bh]cw]bod`f`ghefjtsy
偏移量 = 91: ci^dx^cpeagahifgkutz
偏移量 = 92: dj_ey_dqfbhbijghlvu{
偏移量 = 93: ek`fz`ergcicjkhimwv|

/5*0D*/<1-3-45237A@F gmbh{bgtiekelmjkoyx}
"##;
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
