# string-analyze

[![Type](https://img.shields.io/badge/Project%20Type-Library%2BBinary-green.svg)](#快速开始-quick-start)
[![Crates.io](https://img.shields.io/crates/v/string-analyze.svg)](https://crates.io/crates/string-analyze)
[![Downloads](https://img.shields.io/crates/d/string-analyze.svg)](https://crates.io/crates/string-analyze)
[![Release](https://img.shields.io/github/v/release/AlbusPhos/string-analyze)](https://github.com/AlbusPhos/string-analyze/releases)
[![Documentation](https://docs.rs/string-analyze/badge.svg)](https://docs.rs/string-analyze)
[![License](https://img.shields.io/crates/l/string-analyze.svg)](#开源协议-license)

[![CI](https://github.com/AlbusPhos/string-analyze/actions/workflows/ci.yml/badge.svg)](https://github.com/AlbusPhos/string-analyze/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.92-blue.svg)](#最小-rust-版本-msrv)

> **Find key strings from cluttered text** —— 基于规则流（Rule Flow）的高性能文本扫描引擎，支持并行匹配、多级过滤与高亮报告。

---

`string-analyze` 面向杂乱文本（日志、内存转储、反编译输出、CTF 题目附件）做字符串扫描。它以 `AnyRule` 规则流为核心，将「基础提取 → 熵过滤 → 上下文断言 → 自定义校验」四阶段串联，并可借助 `rayon` 并行执行全部规则。内置规则覆盖 CTF flag、云服务 / API 密钥、哈希、私钥、PII、编码特征、文件魔数与编译器指纹等场景，最终输出带 ANSI 高亮与 0–100 风险评分的报告。

## 目录

- [快速开始 (Quick Start)](#快速开始-quick-start)
- [特性](#特性)
- [规则集](#规则集)
- [API 预览 (API Overview)](#api-预览-api-overview)
- [特性标志 (Feature Flags)](#特性标志-feature-flags)
- [平台与环境支持 (Platform Support)](#平台与环境支持-platform-support)
- [最小 Rust 版本 (MSRV)](#最小-rust-版本-msrv)
- [开发](#开发)
- [问题反馈 (Issues)](#问题反馈-issues)
- [贡献 (Contributing)](#贡献-contributing)
- [变更日志 (Changelog)](#变更日志-changelog)
- [开源协议 (License)](#开源协议-license)

## 特性

- **规则流引擎**：`AnyRule { flow, out }` 四阶段管道 — 基础提取 → 熵过滤 → 上下文断言 → 自定义校验（见 `src/rules.rs` `get_rules`）
- **并行扫描**：`analyze_with` 基于 `rayon` 并发执行全部规则（`src/lib.rs`）
- **复合熵评分**：融合香农熵、差分熵、2-gram 熵的加权幂平均（`P=-1.6`），归一化至 0–10，惩罚低随机性规律串（`src/entropy.rs` `composite_entropy`）
- **启发式校验**：`is_base64` / `is_hex` / `upper_prob` 等开箱即用（`src/tool.rs`）
- **合并高亮**：`AnalyzeResult` 自动合并重叠区间，`{:#}` 开启 ANSI 颜色（`src/lib.rs`）
- **分布式注册**：`lazy_rule!` + `inventory` 实现规则的声明式注册与 `ALL_RULES` 懒加载（`src/rules.rs`）
- **风险融合**：`AnalyzeResult::score()` 采用 `1 - ∏(1-Pi)` 独立事件联合公式，0–100 分（`src/lib.rs`）

## 快速开始 (Quick Start)

### 作为库

添加依赖到 `Cargo.toml`：

```toml
[dependencies]
string-analyze = "0.1.0"
```

基本用法：

```rust
use string_analyze::{analyze_with, rules::ALL_RULES};

fn main() {
    let input = r#"
Base64: mTyqm7wjODkrNLcWl0eqO8K8gc1BPk1GNLgUpI== 444 m7wjODkrNLcWl0eqO8K8gc1BPk1GNLgUpI==
api_key = "12345678abcdefgh";
"#;
    let result = analyze_with(input, ALL_RULES.as_slice());
    println!("score: {}", result.score());
    // `{:#}` 开启 ANSI 颜色高亮
    println!("{:#}", result);
}
```

按需过滤规则（按模块路径 / 重要程度）：

```rust
use string_analyze::rules::get_rules;

let rules = get_rules(|module_path, importance| {
    // 仅保留非 compiler 规则且 importance >= 30
    !module_path.contains("compiler") && importance >= 30
});
let result = string_analyze::analyze_with("AKIAIOSFODNN7EXAMPLE", &rules);
assert!(result.score() > 0);
```

自定义规则（`lazy_rule!` DSL）：

```rust,ignore
use string_analyze::lazy_rule;
use string_analyze::entropy::entropy;

lazy_rule!(
    RE_FLAG = r#"(?i)\b[a-z0-9_.-]{0,20}(?:flag|ctf)[a-z0-9\s-]{0,4}\{[^\{\}\n=\t()]{4,256}\}"#,
    "发现标准 flag",
    100
);
```

完整 DSL 参数顺序见 `src/rules.rs` 文档：`$name = $regex|closure, $describe, $importance [, $min_entropy] [, ($before,$after)] [, |slice,input| bool]`。

### 作为命令行工具

安装（或从 [Releases](https://github.com/AlbusPhos/string-analyze/releases) 下载对应平台的预编译二进制）：

```bash
cargo install string-analyze
# 逐行扫描 stdin，仅输出命中（score != 0）的行
cat dump.txt | string-analyze
echo 'api_key = "12345678abcdefgh"' | string-analyze
echo "mTyqm7wjODkrNLcWl0eqO8K8gc1BPk1GNLgUpI==" | string-analyze
```

`src/main.rs` 实现：按行读取 `stdin`，对每行执行 `analyze_with(&line, &ALL_RULES)` 并以 `{:#}` 打印高亮报告。更多命令与参数：`string-analyze --help`。

## 规则集

内置规则按目录组织（`src/rules/`）：

| 模块 | 说明 | 示例 |
|---|---|---|
| `rules::core::flag` | CTF flag 格式 | `flag{...}` |
| `rules::core::apikey` / `apikey_ai` / `cloudkey` | 云服务与 AI 提供商密钥 | AWS / Aliyun / OpenAI |
| `rules::core::hash` / `blockchain` / `pii` | 哈希、私钥、身份信息 | - |
| `rules::core::coding` / `compiler` / `constant` | 编码特征、编译产物、常量 | - |
| `rules::core::file` | 常见文件格式魔数 | PNG / JPEG / GIF / TAR / MP4 / 字体 |
| `rules::b64file` | Base64 编码的文件头 | `H4sI...` (gzip), `iVBORw0KGgo...` (PNG) |
| `rules::hexfile` | 十六进制转储 | `0xAA...` |
| `rules::coding::rot` | 凯撒移位 / ROT47 混淆 flag | `synt{...}` (ROT13) |
| `rules::coding` | 通用编码检测（含 Base64 / Hex flag 前缀） | - |
| `rules::compiler` / `compiler::glibc` | 编译器 / 链接器 / glibc 指纹 | `.note.gnu.build-id`, `glibc.malloc.*` |

所有规则通过 `ALL_RULES: LazyLock<Vec<AnyRule>>` (`src/rules.rs`) 懒加载，`get_rules` 支持过滤。

## API 预览 (API Overview)

以下仅列出核心入口及职责，完整签名以 [docs.rs/string-analyze](https://docs.rs/string-analyze) 为准。

| 项 | 路径 | 说明 |
|---|---|---|
| `analyze_with` | `src/lib.rs` | 并行执行规则集，返回 `AnalyzeResult` |
| `AnyRule::new` / `add_flow` / `detect` | `src/lib.rs` | 规则构建与单条检测 |
| `State` / `RuleResult` / `Hit` / `AnalyzeResult` | `src/lib.rs` | 核心数据结构 |
| `entropy` / `delta_entropy` / `gram_entropy2` / `composite_entropy` | `src/entropy.rs` | 熵计算 |
| `has_keyword` / `has_regex` / `is_base64` / `is_hex` | `src/tool.rs` | 匹配工具 |
| `lazy_rule!` / `RawRule` / `Assertion` | `src/rules.rs` | 规则定义 |

## 特性标志 (Feature Flags)

本项目当前未声明 `[features]`，`default` 即全量功能。

## 平台与环境支持 (Platform Support)

- **支持操作系统**：Linux / macOS / Windows（CI 与 Release 均覆盖三平台）。
- **目标三元组**：预编译并发布 `x86_64-unknown-linux-gnu`、`aarch64-apple-darwin`、`x86_64-pc-windows-msvc`；其它三元组可由源码构建。
- **`no_std` 支持**：否（依赖 `std` 与 `rayon` 线程池）。
- **WebAssembly**：未验证（`rayon` / `inventory` 在 `wasm32` 下可能受限）。
- **系统依赖**：纯 Rust，无 C 依赖或外部系统库。

## 最小 Rust 版本 (MSRV)

**Rust 1.92** 当前已在 `rustc 1.100.0` 上验证通过。

## 开发

```bash
cargo check --all-targets --all-features
cargo test --doc --all-features
cargo test --all-features
cargo doc --no-deps --all-features
```

## 问题反馈 (Issues)

欢迎通过 [GitHub Issues](https://github.com/AlbusPhos/string-analyze/issues) 反馈问题，尤其欢迎以下两类：

- **误报（False Positive）**：正常文本被错误命中。请尽量附上触发文本片段与命中的规则描述，便于定位并调整断言 / 熵阈值。
- **规则建议（New Rule）**：希望新增的敏感信息或编码特征规则（例如某平台的密钥格式、某个文件魔数）。请附上示例文本与期望的匹配范围。

提交前建议先搜索是否已有同类 Issue。

## 贡献 (Contributing)

欢迎提交 Issue 与 Pull Request。请确保 `cargo test --doc` 与 `cargo doc` 无新增告警，新增公开 API 需补充 rustdoc 及 `CHANGELOG.md` 条目。

## 变更日志 (Changelog)

版本变更详见 [CHANGELOG.md](CHANGELOG.md)。

建议遵循 [Keep a Changelog](https://keepachangelog.com/) 与 [Semantic Versioning](https://semver.org/)。

## 开源协议 (License)

本项目采用 [Mozilla Public License 2.0](https://github.com/AlbusPhos/string-analyze/blob/main/LICENSE)（MPL-2.0）协议，Copyright (c) 2026 AlbusPhos。
