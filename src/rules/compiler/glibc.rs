// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! glibc 指纹规则。
//!
//! 覆盖 glibc Tunables 命名空间、malloc 调参环境变量、静态链接
//! `dlopen` 警告文本以及 SystemTap/DTrace 探针点符号等特征字符串，
//! 用于判断目标是否静态/动态链接了 glibc 及其大致版本特征。

use crate::rules::lazy_rule;

// ==========================================
// 1. glibc Tunables (GLIBC_TUNABLES 命名空间)
//    自 glibc 2.25 引入，静态/动态链接 glibc 的二进制中
//    几乎总会内嵌这些命名空间字符串 (用于运行时调参)
// ==========================================
lazy_rule!(
    RE_GLIBC_TUNABLES = r#"\bglibc\.(?:cpu|malloc|elision|gmon|mem|pthread|rtld)\.[a-z0-9_]+\b"#,
    "发现 glibc Tunables 命名空间字符串 (静态/动态链接 glibc 特征)",
    5
);

// ==========================================
// 2. glibc malloc 相关环境变量名
//    这些是经典的 malloc 调参环境变量，老版本 glibc 遗留
// ==========================================
lazy_rule!(
    RE_GLIBC_MALLOC_ENV = r#"\bMALLOC_(?:ARENA_MAX|ARENA_TEST|CHECK_|MMAP_MAX_|MMAP_THRESHOLD_|PERTURB_|TOP_PAD_|TRIM_THRESHOLD_)\b"#,
    "发现 glibc malloc 调参环境变量名",
    5
);

lazy_rule!(
    RE_GLIBC_LD_ENV = r#"\bLD_PREFER_MAP_32BIT_EXEC\b"#,
    "发现 glibc 动态链接器环境变量",
    5
);

// ==========================================
// 3. 静态链接 glibc 的典型警告文本
//    这是极强特征：只有"静态链接"且仍尝试 dlopen/dlmopen 时才会内嵌
// ==========================================
lazy_rule!(
    RE_GLIBC_STATIC_DLOPEN_WARN = r#"Using 'dl(?:open|mopen)' in statically linked applications requires at runtime the shared libraries from the glibc version used for linking"#,
    "发现 glibc 静态链接二进制的 dlopen/dlmopen 运行时警告文本 (该二进制为静态链接)",
    30
);

// ==========================================
// 4. SystemTap / DTrace 探针点名称 (.note.stapsdt 段)
//    glibc 内部用于性能分析埋点的符号名
// ==========================================
lazy_rule!(
    RE_GLIBC_STAP_PROBE = r#"\b(?:lll_lock_wait(?:_private)?|pthread_(?:start|create|join(?:_ret)?)|mutex_(?:acquired|entry|release)|r(?:d|w)lock_(?:entry|acquire_(?:read|write))|rwlock_unlock|longjmp_target|cond_(?:wait|signal|broadcast)|memory_(?:mallopt[a-z_]*|arena_[a-z_]*|heap_[a-z_]*|sbrk_[a-z_]*|(?:malloc|calloc|realloc|memalign)_retry|tcache_double_free)|reloc_(?:start|complete)|(?:un)?map_(?:start|complete))\b"#,
    "发现 glibc SystemTap/DTrace 探针点符号名 (.note.stapsdt 段特征)",
    5
);

// 探针参数格式字符串 (例如 "8@%rdi -4@%esi 8@%rax")，置信度较低，
// 一般配合 RE_GLIBC_STAP_PROBE 一起出现才有意义
lazy_rule!(
    RE_GLIBC_STAP_ARGS = r#"(?:-?\d+@(?:%[a-z0-9]+|-?\d*\(%[a-z0-9]+\)|[\w.]+\(%rip\)))(?:\s+-?\d+@(?:%[a-z0-9]+|-?\d*\(%[a-z0-9]+\)|[\w.]+\(%rip\)))+"#,
    "发现疑似 SystemTap 探针参数描述字符串",
    3
);
