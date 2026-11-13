// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! 编译器 / 链接器指纹规则。
//!
//! 汇集 C/C++ 工具链与目标文件格式的可辨识字符串（LLD 版本、
//! x86_64 汇编序言机器码、ELF 节名、Rust 运行时字符串），并聚合
//! [`glibc`] 子模块中的 glibc 特征规则。

pub mod glibc;

include!("./core/compiler.rs");

lazy_rule!(
    RE_META_LLD_LINKER = r#"\bLinker:\s*LLD\s+\d+\.\d+\.\d+"#,
    "发现 LD / LLD 链接器版本标识",
    25
);

// AWAVAUATUSH 是 x86_64 压栈 7 个寄存器的机器码 (push r15; push r14; push r13; push r12; push rbp; push rbx; push rsp) 在 ASCII 下的显示
lazy_rule!(
    RE_ASM_X86_PROLOGUE = r#"\b(?:AWAVAUATUSH|8\[\]A\\A\]A\^A\_)\b"#,
    "发现 x86_64 常用函数序言/弹栈指令 ASCII 机器码残留",
    1,
    ((1, false, r"[^ \n\t\s]"), (1, false, r"[^ \n\t\s]"))
);

lazy_rule!(
    RE_ELF_SECTION_NAME = r#"\b\.(?:note\.gnu\.build-id|gnu\.hash|rela\.dyn|gcc_except_table|eh_frame_hdr|eh_frame|init_array|fini_array|data\.rel\.ro|got\.plt|note\.stapsdt|shstrtab)\b"#,
    "发现 Linux ELF 常见节头表 (Section Header) 名称",
    10,
    ((1, false, r"[^ \n\t\s]"), (1, false, r"[^ \n\t\s]"))
);

lazy_rule!(
    RE_LANG_RUST_RUNTIME = r#"\b(?:RUST_BACKTRACE=|panicked at|fatal runtime error:)\b"#,
    "发现 Rust 运行时错误/调试字符串",
    5
);
