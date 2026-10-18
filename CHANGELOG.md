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
