# string-analyze

> **Find key strings from cluttered text**

[![Crates.io](https://img.shields.io/crates/v/string-analyze?logo=rust&logoColor=white)](https://crates.io/crates/string-analyze)
[![Docs.rs](https://img.shields.io/docsrs/string-analyze?logo=docs.rs)](https://docs.rs/string-analyze)
[![CI](https://img.shields.io/github/actions/workflow/status/AlbusPhos/string-analyze/ci.yml?label=CI&logo=githubactions&logoColor=white)](https://github.com/AlbusPhos/string-analyze/actions)
[![MSRV](https://img.shields.io/badge/MSRV-1.92-blue)](#平台与环境支持-platform-support)
[![Type](https://img.shields.io/badge/Type-Lib%2BBin-informational)](#快速开始-quick-start)
[![Downloads](https://img.shields.io/crates/d/string-analyze?color=blue)](https://crates.io/crates/string-analyze)
[![License](https://img.shields.io/crates/l/string-analyze)](#开源协议-license)

---

`string-analyze` 是一个面向杂乱文本的规则流扫描引擎，用于从日志、内存转储、反编译输出与 CTF 附件中快速定位 flag、API 密钥、哈希、PII 以及编码 / 文件特征。它将「基础提取 → 熵过滤 → 上下文断言 → 自定义校验」串成可组合的四阶段管道，并通过 `rayon` 并行执行全部规则。内置约 160 条规则，支持按模块与重要程度过滤，也可以使用 `lazy_rule!` 宏声明自定义规则。输出带 ANSI 高亮与 0–100 风险评分，既可作为库嵌入其他工具，也可作为 stdin 过滤器直接使用。

## 目录

- [快速开始](#快速开始-quick-start)
- [API 预览](#api-预览-api-overview)
- [适用场景](#适用场景-when-to-use)
- [平台与环境支持](#平台与环境支持-platform-support)
- [安全性](#安全性-security)
- [贡献](#贡献-contributing)
- [变更日志](#变更日志-changelog)
- [开源协议](#开源协议-license)

## 快速开始 (Quick Start)

### 作为库使用 (Library)

添加依赖：

```bash
cargo add string-analyze
```

或在 `Cargo.toml` 中手动添加：

```toml
[dependencies]
string-analyze = "0.1.0"
```

基本用法：

```rust
use string_analyze::{analyze_with, rules::ALL_RULES};

fn main() {
    let input = r#"
Base64: mTyqm7wjODkrNLcWl0eqO8K8gc1BPk1GNLgUpI==
api_key = "12345678abcdefgh";
"#;

    let result = analyze_with(input, ALL_RULES.as_slice());
    println!("score: {}", result.score());
    // `{:#}` 开启 ANSI 颜色高亮
    println!("{:#}", result);
}
```

按模块路径或重要程度过滤规则：

```rust
use string_analyze::rules::get_rules;

fn main() {
    let rules = get_rules(|module_path, importance| {
        // 仅保留非 compiler 规则且 importance >= 30
        !module_path.contains("compiler") && importance >= 30
    });
    let result = string_analyze::analyze_with("AKIAIOSFODNN7EXAMPLE", &rules);
    assert!(result.score() > 0);
}
```

自定义规则（`lazy_rule!` DSL）：

```rust
use string_analyze::lazy_rule;

lazy_rule!(
    RE_FLAG = r#"(?i)\b[a-z0-9_.-]{0,20}(?:flag|ctf)[a-z0-9\s-]{0,4}\{[^\{\}\n=\t()]{4,256}\}"#,
    "发现标准 flag",
    100
);
```

### 作为命令行工具使用 (Binary)

从源码安装：

```bash
cargo install string-analyze --locked
# 或从 Git 仓库安装最新开发版
cargo install --git https://github.com/AlbusPhos/string-analyze --locked
```

免编译二进制包请前往 [Releases](https://github.com/AlbusPhos/string-analyze/releases) 页面下载。

逐行扫描 `stdin`，仅输出风险评分非零的行：

```bash
cat dump.txt | string-analyze
echo 'api_key = "12345678abcdefgh"' | string-analyze
echo "mTyqm7wjODkrNLcWl0eqO8K8gc1BPk1GNLgUpI==" | string-analyze
```

Windows PowerShell 等价写法：

```powershell
Get-Content dump.txt | string-analyze
```

查看完整命令与参数说明：`string-analyze --help`。


## API 预览 (API Overview)

完整 API 文档请参阅 [docs.rs/string-analyze](https://docs.rs/string-analyze)。

### 核心组件速查

| 核心入口 / 类型                              | 角色定位       | 职责说明                                     |
|:---------------------------------------------|:---------------|:---------------------------------------------|
| [`analyze_with`]                             | **快捷入口**   | 并行执行规则切片，返回 [`AnalyzeResult`]     |
| [`ALL_RULES`] / [`get_rules`]                | **规则集**     | 懒加载全量规则，或按模块路径与重要程度过滤   |
| [`AnyRule`] / [`RawRule`]                    | **规则定义**   | 执行流与静态配置（正则、熵阈值、断言、校验） |
| [`lazy_rule!`]                               | **声明式扩展** | 定义并自动注册自定义规则的宏 DSL             |
| [`AnalyzeResult`] / [`Hit`] / [`RuleResult`] | **输出与诊断** | 风险评分、命中描述与切片内容                 |
| [`entropy`] / [`composite_entropy`]          | **信号评估**   | 单字节熵与复合熵计算                         |
| [`State`]                                    | **中间状态**   | 规则流各阶段共享的候选区间                   |

[`analyze_with`]: https://docs.rs/string-analyze/latest/string_analyze/fn.analyze_with.html
[`ALL_RULES`]: https://docs.rs/string-analyze/latest/string_analyze/rules/static.ALL_RULES.html
[`get_rules`]: https://docs.rs/string-analyze/latest/string_analyze/rules/fn.get_rules.html
[`AnyRule`]: https://docs.rs/string-analyze/latest/string_analyze/struct.AnyRule.html
[`RawRule`]: https://docs.rs/string-analyze/latest/string_analyze/rules/struct.RawRule.html
[`lazy_rule!`]: https://docs.rs/string-analyze/latest/string_analyze/macro.lazy_rule.html
[`AnalyzeResult`]: https://docs.rs/string-analyze/latest/string_analyze/struct.AnalyzeResult.html
[`Hit`]: https://docs.rs/string-analyze/latest/string_analyze/struct.Hit.html
[`RuleResult`]: https://docs.rs/string-analyze/latest/string_analyze/struct.RuleResult.html
[`State`]: https://docs.rs/string-analyze/latest/string_analyze/struct.State.html
[`entropy`]: https://docs.rs/string-analyze/latest/string_analyze/entropy/fn.entropy.html
[`composite_entropy`]: https://docs.rs/string-analyze/latest/string_analyze/entropy/fn.composite_entropy.html



## 适用场景 (When to Use)

**适合：**

- CTF 题目附件、流量日志与内存转储中的 flag / 密钥 / 编码特征快速筛查。
- 事故响应与取证初筛：从大量日志、反编译输出中定位可疑凭据与身份信息。
- 作为规则实验平台：用 `lazy_rule!` 快速验证新的密钥格式或文件魔数规则。


## 平台与环境支持 (Platform Support)

- **MSRV**：`1.92`（`Cargo.toml` 声明，CI 独立任务验证）。
- **支持操作系统**：Linux / macOS / Windows；CI 在 Ubuntu 上执行完整检查，发布工作流为 `x86_64-unknown-linux-gnu`、`aarch64-apple-darwin`、`x86_64-pc-windows-msvc` 构建预编译二进制。
- **`no_std` 支持**：否，依赖 `std` 与 `rayon` 线程池。
- **WebAssembly**：未支持；`rayon` 与 `inventory` 在 `wasm32` 目标下受限。
- **系统与外部依赖**：纯 Rust 实现，无 C 工具链、`pkg-config` 或系统库依赖。

## 安全性 (Security)

- **`unsafe` 代码政策**：库与二进制均启用 `#![forbid(unsafe_code)]`，代码中不包含 `unsafe` 块。
- **输入处理**：规则基于 `regex` crate 的线性时间匹配引擎，不含回溯，避免恶意文本触发灾难性回溯。
- **本地运行**：扫描过程不发起网络请求，也不上传被扫描内容。


## 贡献 (Contributing)

欢迎提交 Issue 报告问题或发起 Pull Request 贡献代码！

- 尤其欢迎两类反馈：**误报（False Positive）** 请附触发文本与命中规则描述；**规则建议** 请附示例文本与期望匹配范围。
- 提交 PR 前请确保在本地通过以下检查：

  ```bash
  cargo fmt --all -- --check
  cargo clippy --all-targets --all-features -- -D warnings
  cargo test --all-features
  ```

## 变更日志 (Changelog)

本项目遵循 [语义化版本 2.0.0 (SemVer)](https://semver.org/lang/zh-CN/) 规范。各版本的详细变更记录请查阅 [CHANGELOG.md](CHANGELOG.md)。

## 开源协议 (License)

本项目基于 [Mozilla Public License 2.0](./LICENSE)（SPDX: `MPL-2.0`）协议开源。除非另有明确声明，您提交的任何贡献默认按同等协议条款授权。
