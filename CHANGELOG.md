# Changelog

所有重要变更将记录于此文件。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

> **版本号说明（0.x 阶段）**：在 1.0.0 发布之前，次版本号（`0.MINOR.0`）的变更
> 也可能包含破坏性改动，请留意标注为 **[BREAKING]** 的条目。

## [0.1.0] - 2026-11-13

正式版：在 `0.1.0-rc1` 基础上完成发布前规范化与清理。

### Changed

- 恢复 API 密钥规则测试中的完整伪造密钥样例，使规则在真实文本形态下参与回归。
- 命令行工具新增 `--help` / `--version`，并补充未知参数的错误提示。
- 移除 `src/tool.rs` 的全局 `allow(unused)`，清理遗留告警。
- 同步 MSRV 文档与徽章至 **1.92**（`lib-unknown` 要求）。
- CI 升级 `actions/checkout`，并新增 MSRV 1.92 校验任务。

## [0.1.0-rc1] - 2026-11-13

首个预发布版本，已发布至 crates.io。

### Added

- **规则流引擎**：`AnyRule { flow, out }` 提供「基础提取 → 熵过滤 → 上下文断言 → 自定义校验」四阶段管道，规则之间通过 `inventory` 分布式注册、`LazyLock` 懒加载（`src/lib.rs`、`src/rules.rs`）。
- **并行扫描**：`analyze_with` 基于 `rayon` 并发执行全部规则，返回 `AnalyzeResult`；`score()` 采用独立事件联合概率公式 `1 - ∏(1-Pi)` 输出 0–100 风险分（`src/lib.rs`）。
- **高亮报告**：`AnalyzeResult` 自动排序并合并重叠命中区间，`{:#}` 启用 ANSI 颜色输出（`src/lib.rs`）。
- **复合熵评分**：融合香农熵、差分熵与 2-gram 熵的负指数加权幂平均（`P=-1.6`），归一化至 0–10，可有效识别递增序列等伪随机文本（`src/entropy.rs`）。
- **启发式工具**：`has_keyword` / `has_chars` / `has_regex` / `upper_prob` / `is_base64` / `is_hex` / `sort_ascii_counts`，其中 Base64 校验包含长度对齐、字符集、连续同字母、大小写比例等多重启发式（`src/tool.rs`）。
- **规则 DSL**：`lazy_rule!` 支持正则或闭包匹配、最低熵阈值、前后上下文断言（可选 AND/OR 组合）以及自定义校验闭包（`src/rules.rs`）。
- **内置规则集**（约 160 条）：
  - `rules::core`：CTF flag、云服务 / API / AI 提供商密钥、哈希、区块链地址、PII、编码特征、编译器指纹、常量、文件后缀与魔数等；
  - `rules::coding`：Base64 / Hex / ROT-N / ROT47 编码与混淆检测；
  - `rules::b64file` / `rules::hexfile`：Base64 文件头与十六进制转储识别；
  - `rules::compiler` / `rules::compiler::glibc`：链接器、ELF 与 glibc 指纹。
- **上下文断言**：新增「仅后置断言」语法 `(, (offset, expected, re))`，并补充可运行的 doctest 示例。
- **命令行工具**：`string-analyze` 逐行读取 `stdin`，仅输出风险分非零的行并附带高亮报告（`src/main.rs`）。
- **工程化**：GitHub Actions 提供 fmt / clippy / test / doc 检查与多平台（Linux / macOS / Windows）发布工作流；README 通过 `#![doc = include_str!("../README.md")]` 同时作为 crate 级 rustdoc，避免文档双份维护。

### Changed

- 许可证由 MIT 变更为 **MPL-2.0**，仓库根 `LICENSE` 与各源码文件 SPDX 标识同步更新。
- 项目迁移至 `https://github.com/AlbusPhos/string-analyze`，仓库元数据、徽章、文档与发布链接全部指向新地址。
- 依赖调整：以 `lib-unknown`（`encoding-base64` / `encoding-hex`）替代独立的 `base64` / `hex` 依赖。
- `is_base64` 强化首字符、字符集与字符多样性过滤，降低源码标识符与重复字符串误报。
- 文件规则、网络指标与编码规则统一补充上下文断言，减少短文本误报。

### Fixed

- 修复上下文断言窗口为空时的判定逻辑：正向断言在文本边界不再被无条件放行，负向断言仍按预期通过。
- 修复 `is_base64` 在极端输入下可能越界的问题（补充空载荷防御检查）。
- 修复字符表规则尾随 `\b` 导致以非单词字符结尾时无法命中的问题。
- 修复 Z85 字符表中 `.`、`+`、`^`、`?` 等元字符未转义导致规则失效的问题。
- 修复 UPX 区段正则未转义导致的误报与漏报。

[0.1.0]: https://github.com/AlbusPhos/string-analyze/releases/tag/v0.1.0
[0.1.0-rc1]: https://crates.io/crates/string-analyze/0.1.0-rc1
