// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::rules::lazy_rule;
use crate::tool::{has_chars, has_keyword};

pub(crate) const FLAG_PREFIXES: &[&str] = &[
    "fla9",
    "fl4g",
    "flag",
    "ctf",
    "bugku",
    "htb",
    "thm",
    "picoctf",
    "nssctf",
    "dasctf",
    "ciscn",
    "cyberpeace",
    "qwb",
    "xctf",
    "iscc",
    "seccon",
    "pctf",
    "actf",
    "mrctf",
    "vnctf",
    "litctf",
    "adworld",
    "roarctf",
    "flare",
];

lazy_rule!(
    RE_FLAG = r#"(?i)\b[a-z0-9_.-]{0,20}(?:flag|ctf)[a-z0-9\s-]{0,4}\{[^\{\}\n=\t()]{4,256}\}"#,
    "发现标准 flag",
    100
);

lazy_rule!(
    RE_PLATFORM_FLAG = r#"(?i)\b(?:bugku|htb|thm|picoctf|nssctf|dasctf|ciscn|cyberpeace|qwb|xctf|iscc|seccon|pctf|actf|mrctf|vnctf|litctf|adworld|roarctf|flare)[a-z0-9_-]{0,4}\{[^\{\}\n=\t()]{4,256}\}"#,
    "发现 特定平台/赛事的 flag",
    100
);

lazy_rule!(
    FLAG1 = |state| (state.input.len() < 256)
        && FLAG_PREFIXES
            .iter()
            .any(|&prefix| has_keyword(&mut *state, prefix, true)),
    "存在已知flag前缀以及 '{','}'",
    70,
    |_, input| has_chars(input, &['{', '}'], false, false)
        && !has_chars(
            input,
            &['(', ')', '[', ']', '=', '`', '"', '\'', ';', ':'],
            true,
            false
        )
);

lazy_rule!(
    FLAG2 = |state| (state.input.len() < 256)
        && FLAG_PREFIXES.iter().any(|&prefix| {
            let chars_vec: Vec<char> = prefix.chars().collect();
            has_chars(&mut *state, &chars_vec, false, true)
        }),
    "存在被打乱的flag前缀字符并且含有 '{','}'",
    45,
    |_, input| has_chars(input, &['{', '}'], false, false)
        && !has_chars(
            input,
            &['(', ')', '[', ']', '=', '`', '"', '\'', ';', ':'],
            true,
            false
        )
);

lazy_rule!(
    RE_CLOSED_BRACE = r#"\{[^()\[\]{} ='":;\n\t]{6,512}\}"#,
    "发现 闭合花括号结构",
    5
);

lazy_rule!(
    FLAG3 = r#"(?i)(?:fl4g|flag|ctf|bugku|htb|thm|picoctf|nssctf|dasctf|ciscn|cyberpeace|qwb|xctf|iscc|seccon|pctf|actf|mrctf|vnctf|litctf|adworld|roarctf|flare)"#,
    "可疑 flag关键字",
    8,
    ((1, false, "[_-]"), (1, false, "[_-]"), true),
    |_s, input| input.len() <= 300
);

#[cfg(test)]
mod tests {
    use crate::analyze_with;
    use crate::rules::get_rules;

    #[test]
    fn test() {
        let input = r#"
flag{5tgb8uik,0ol}
buuctf{aaac38f5-046b-43e8-a089-03813226d280}
fgaag_!l{_oun}amb_ob # railfence_group 3
[0x4CCE][0] nlen
[0x6574][0] please enter the flag:
[0x658C][0] %20s
[0x6594][0] wrong flag!
[0x65E0][0] Stack around the variable '
[0x65FC][0] ' was corrupted.
[0x6610][0] The variable '
[0x6620][0] ' is being used without being initialized.
[0x664C][0] rigth flag!
[0x6670][0] The value of ESP was not properly saved across a function call.  This is usually a result of calling a function declared with one calling convention with a function pointer declared with a different calling convention.
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
