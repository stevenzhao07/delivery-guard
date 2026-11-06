# Changelog

本仓遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 与 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

> 首次纳入版本化记录。**尚未打 tag / 发 Release**（须所有者批准后执行）。

### Added
- **第 18 道门禁 `clef_semantic_risk`**：可选 Clef 语义门禁——Cloudflare 决策模型（`@cf/cloudflare/clef`）对交付物文本做 A/B/C/D 风险分级（营销/夸大措辞、未经授权标准自称、误导性声明），A/B 通过、C/D 阻断；无凭证或调用失败自动 N/A 通过（保持零依赖离线可用）。实测：113 技能全量 PASS（A=32/B=81，0 BLOCK）、营销/自称标准样例 BLOCK（D，P=0.57）、合规源码 PASS（A，P=0.59）。
- `--selftest`：端到端自测（真实调用 + 内容断言 + **负对照**），可脱离门户单仓运行。
- `SECURITY.md`、`CODE_OF_CONDUCT.md`：补齐社区治理文件。
- `module.json` 增加机器可读的 `stage` / `stage_name`，标明本模块在医疗器械生命周期中的位置。

### Changed
- 文档勘误：移除与实际实现不符的表述（详见项目级 `PROJECT_ATTRIBUTION.md` 与门户 README）。
- 门禁清单 17 → 18 道；README 使用说明补充 Clef 门禁可选启用方式。

### Fixed
- `--demo` 由 17/18 修至 18/18：演示样本原先写在系统临时目录**根部**，同级没有 LICENSE，第 2 道门禁 `license_present`（仓库语义，查交付物同级 LICENSE）因此恒定失败。现改为在临时**目录**内构造样本并放入本仓 LICENSE 副本；`--demo` 18/18、`--selftest` 3/3，连跑 3 次结果一致。门禁逻辑未改（负对照：无同级 LICENSE 的样本仍判 ❌，有则判 ✅）。
- **S1（退出码契约，2026-10-30）**：`--demo` 原先在任何门禁失败时仍 exit 0（README 已写明 `1 = 有门禁未过`）——把 `--demo` 放进 CI 的自动化会拿到一个永远绿的假门。现 demo 与主路径同一契约：有失败即 exit 1。`--selftest` 新增负对照（门禁未过的交付物必须 rc=1、演示样本必须 rc=0，共 4 用例）；另以注入法双向实证（注入失败门 → `[FAIL]`＋exit 1；还原 → 18/18＋exit 0）。
- **S2（失败标记，2026-10-30）**：demo 失败行标记 `[XX]` → `[FAIL]`，可用 `grep FAIL` 捕获；README 补 demo 退出码语义。原 `[XX]` 会让基于 `grep FAIL` 的自动化漏报（实测：修复前 `grep FAIL` 得 0 行）。
