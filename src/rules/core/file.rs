// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! 常见文件格式魔数（Magic Number）特征规则。
//!
//! 覆盖 PNG / JPEG / GIF 图像、TAR 归档、MP4/MOV（ISO BMFF）容器
//! 以及 TrueType/OpenType 字体的标志性字符串，用于从文本转储中
//! 推断原始文件类型。

use crate::lazy_rule;

// ───────────────────────────── PNG ─────────────────────────────
lazy_rule!(
    RE_FILE_PNG =
        r#"\b(?:IHDR|PLTE|IDAT|IEND|tRNS|gAMA|cHRM|sRGB|iCCP|tEXt|zTXt|iTXt|bKGD|pHYs|tIME)\b"#,
    "疑似 PNG 文件标志 (chunk type)",
    10,
    ((1, false, r"[^ \n\t\s]"), (1, false, r"[^ \n\t\s]"))
);

// ───────────────────────────── JPEG ─────────────────────────────
lazy_rule!(
    RE_FILE_JPEG =
        r#"\b(?:JFIF|Exif|ICC_PROFILE|Photoshop 3\.0)\b|http://ns\.adobe\.com/xap/1\.0/"#,
    "疑似 JPEG 文件标志 (APPn 段)",
    10,
    ((1, false, r"[^ \n\t\s]"), (1, false, r"[^ \n\t\s]"))
);

// ───────────────────────────── GIF ─────────────────────────────
lazy_rule!(
    RE_FILE_GIF = r#"\bGIF8[79]a\b"#,
    "疑似 GIF 文件签名",
    10,
    ((1, false, r"[^ \n\t\s]"), (1, false, r"[^ \n\t\s]"))
);

// ───────────────────────────── TAR ─────────────────────────────
// "ustar" 太短，非常容易在随机文本中爆出，必须加 \b
lazy_rule!(
    RE_FILE_TAR = r#"\bustar\b"#,
    "疑似 TAR 文件标志",
    15,
    ((1, false, r"[^ \n\t\s]"), (1, false, r"[^ \n\t\s]"))
);

// ───────────────────────────── MP4 / MOV ─────────────────────────────
lazy_rule!(
    RE_FILE_MP4 = r#"\bftyp(?:isom|iso[2-6]|mp4[12]|M4A |M4V |qt  |3gp[0-9]|avc1)\b"#,
    "疑似 MP4/MOV (ISO BMFF) 文件标志",
    15,
    ((1, false, r"[^ \n\t\s]"), (1, false, r"[^ \n\t\s]"))
);

lazy_rule!(
    RE_FILE_MP4_BOX = r#"\b(?:moov|mdat|moof|mfra|skip|udta|meta)\b"#,
    "疑似 MP4/MOV box 类型 (辅助，需结合 ftyp 判断)",
    10,
    ((1, false, r"[^ \n\t\s]"), (1, false, r"[^ \n\t\s]"))
);

// ───────────────────────────── TTF / OTF 字体 ─────────────────────────────
lazy_rule!(
    RE_FILE_FONT = r#"\b(?:OTTO|ttcf|cmap|glyf|hmtx|loca|maxp|CFF )\b"#,
    "疑似 TrueType/OpenType 字体表标志",
    10,
    ((1, false, r"[^ \n\t\s]"), (1, false, r"[^ \n\t\s]"))
);

lazy_rule!(
    RE_FILE_EXT = r#"(?x)
        \.
        (?:
            # 图片
            jpg|jpeg|png|gif|bmp|webp|svg|ico|tiff|heic|
            # 文档
            txt|doc|docx|pdf|ppt|pptx|xls|xlsx|csv|md|rtf|
            # 压缩包
            zip|7z|rar|tar|gz|bz2|xz|
            # 音视频
            mp3|mp4|wav|flac|avi|mov|wmv|mkv|flv|m4a|
            # 可执行/安装包
            exe|dll|apk|ipa|msi|dmg|so|
            # 代码/网页
            html|htm|css|js|json|xml|php|py|pyd|pyc|java|c|cpp|rs|ps1|sh|zsh|bat|
            # 其他
            log|pid|lock|swp|bak|bin|desktop
        )
    "#,
    "疑似 文件后缀",
    8,
    ((1, true, r"\S"), (1, false, r"[0-9a-zA-Z]"), true)
);

#[cfg(test)]
mod tests {
    use crate::analyze_with;
    use crate::rules::get_rules;

    #[test]
    fn test() {
        let input = r#"
drwxrwxr-x 1 aa   aa     44 10月14日 15:18 strata-update-archive-test-two-packages-140898-289
-rw-rw-r-- 1 aa   aa    346 10月14日 10:40 tmp.txt
drwxrwxr-x 1 aa   aa     26 10月14日 15:35 .tmpw0fmlH
-rw-rw-rw- 1 aa   aa      0 10月13日 15:36 uv-5a746652d84c4bb0.lock
drwx------ 1 root root   16 10月13日 11:21 .vbox-root-ipc
-rw-rw-r-- 1 aa   aa   6.7K 10月13日 22:07 vl_server4.log
-rw-rw-r-- 1 aa   aa   3.5K 10月13日 20:41 vl_server.log
-rw-rw-r-- 1 aa   aa      6 10月13日 20:38 vl_server.pid
-rw-rw-r-- 1 aa   aa   4.9K 10月14日 11:03 vl_test_4b.png
-rw-rw-r-- 1 aa   aa   9.0K 10月13日 20:34 vl_test.png
drwxrwxr-x 1 aa   aa     40 10月20日 09:54 vscode-typescript1000
drwx------ 1 aa   aa     32 10月11日 17:57 .wine-1000
-r--r--r-- 1 aa   aa     11 10月20日 09:54 .X0-lock
      ~/Downloads 
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
