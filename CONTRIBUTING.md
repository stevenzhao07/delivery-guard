# CONTRIBUTING · delivery-guard（lgd-skeleton/1.0 可插拔模块）

> 完整《AI 参与指南》见根门户：https://github.com/stevenzhao07/medical-ai-toolkit/blob/main/AI_PARTICIPATION.md
> 红线：纯技术贡献；MedXpert 仅作署名（@stevenzhao07）；不挂机构自推；发布前需仓库所有者「go」。

## 30 秒上手
```bash
git clone https://github.com/stevenzhao07/delivery-guard.git && cd delivery-guard
python scripts/delivery_guard.py --demo
python scripts/delivery_guard.py --help
```

## 分支命名
- **AI 代理**：`agent/` `codex/` `claude/` `copilot/` `cursor/` `ai/` + 简述（如 `agent/add-fhir-observation`）
- **人类**：`feat/` `fix/` `human/` + 简述
- 一次 PR 只做一件事（one PR one task）。

## AI 自标识（写进 commit trailer + PR 正文）
```
Agent-Model: <模型名>
Agent-Task: <一句话任务>
Agent-Limitation: <已知限制 / 待校验项>
```

## 加能力（一切即插件，不动主码）
新增能力只需在主体代码注册表加一行，无需改主流程。

## 本地自检（CI 门禁）
**单仓独立克隆**：只能跑 `python scripts/delivery_guard.py --demo` / `--help` 冒烟——`harness.py`
（6 维测试）只存在于根门户，不在本仓（2026-10-12 复审修复：原指引直接让单仓跑
`python harness.py`，必然 file not found）。

**完整 6 维自检**（适配性/准确性/流畅性/外人实跑/易用性/语义回归 gold）：
```bash
git clone https://github.com/stevenzhao07/medical-ai-toolkit.git portal-dev && cd portal-dev
# 开发态布局：把你的改动同步进 portal-dev/repos/delivery-guard/ 后
python harness.py --module delivery-guard
```
（CI 同款；gold 语义回归全绿再提 PR。）

## 路由 / 总入口
本模块由 **[medical-ai-toolkit](https://github.com/stevenzhao07/medical-ai-toolkit)** 自动路由发现。
有新想法？`python idea_scaffold.py "<想法>"` → 命中复用 / 否则自动建骨架并自检（在门户开发态运行）。
