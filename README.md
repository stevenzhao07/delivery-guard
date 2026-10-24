# delivery-guard

> **Contributed by [@stevenzhao07](https://github.com/stevenzhao07) · Independent researcher · Pure technical input, no commercial promotion.**

医疗 AI / 医疗器械交付物的「门禁（gate）」开源工具。在把任何交付物（模型卡、数据集卡、代码、文档、合规模板）对外发布或交付前，按 **18 道门禁**逐条校验，并对其计算**双 SHA-256 指纹**写入**权属台账（provenance ledger）**，形成可审计的在先发表证据。

这是 MedXpert 把"治理守护者（XCGS）"理念工程化落地的参考实现之一——把抽象的门禁要求变成一条可重复运行的命令。

---

## 可插拔模块契约（lgd-skeleton/1.0）

本仓库是一个 **`lgd-skeleton/1.0` 可插拔模块**：

- **一切即插件**：仅依赖声明式 `module.json`，零配置；
- **按需装（lazy）**：仅 triggers 命中时加载；
- **可嵌套（nested）**：可被 `medical-ai-toolkit` 总入口路由发现；
- **扩展点**：`plugins/`（新增门禁只需在 `scripts/delivery_guard.py` 的 `GATES` 注册表加一行）。

机器可发现入口：`AGENTS.md` · `CLAUDE.md` · `llms.txt`。

## 为什么需要它

医疗器械 / 医疗 AI 的交付物对外发布前，需要满足一系列质量与合规基线：许可声明齐全、无硬编码密钥、含人类监督声明、关联披露到位、不自称"制定标准"等。手工逐条检查易漏且不可复现。`delivery_guard.py` 把这些基线固化为可自动化、可审计的门禁。

## 特性

- **零依赖**：仅 Python 3.8+ 标准库，可离线运行（第 18 道 Clef 语义门禁为可选增强，无凭证时自动 N/A 通过，不破坏离线承诺）。
- **18 道门禁**：覆盖存在性、许可、密钥、PII、版本、模型/数据卡、人类监督、披露、营销、标准自称、商标、语法、依赖、测试、遗留标记、指纹可生成并落台账 + **Clef 语义风险分级**（可选）。
- **双 SHA-256 指纹**：原始字节指纹 + 规范化内容指纹，抗 trivial 篡改。
- **append-only 台账**：`provenance_ledger.jsonl`，便于跨辖区（NMPA / FDA / EU MDR）溯源举证。
- **可配置**：`GATES` 注册表即门禁列表，增删一行即可扩展。

## 安装

无需安装，直接运行：

```bash
python scripts/delivery_guard.py --help
```

（可选）放入虚拟环境：

```bash
python -m venv .venv && source .venv/bin/activate
python scripts/delivery_guard.py <artifact>
```

## 免责声明

> 品牌状态限定：**MedXpert**（未申请实体注册、未申请商标注册，仅作来源标识）。本仓库由个人以独立研究者（Independent researcher）身份维护，不代表任何机构。

本工具仅提供结构化模板与计算能力，**不构成法规建议、合规结论或专业意见**。医疗 AI / 医疗器械相关的落地决策，须由合资格人员依据目标辖区（NMPA / FDA / EU MDR / PMDA）最新法规文本作出；条款与限值以官方发布文本为准。使用本工具产生的一切后果由使用者自行承担。

## 使用

```bash
# 内置演示样本（无需外部文件，不写台账）
python scripts/delivery_guard.py --demo

# 可选：启用第 18 道 Clef 语义门禁（需 Cloudflare 账号与 API Token）
# 无凭证时该门禁自动 N/A 通过（离线可用，不阻断）
export CLOUDFLARE_ACCOUNT_ID=xxx
export CLOUDFLARE_AUTH_TOKEN=xxx
python scripts/delivery_guard.py <交付物路径>
```

校验你自己的交付物：将上面 `--demo` 换成对交付物路径的校验命令（指纹写入默认台账；详见下方 18 道门禁清单）。

## 快速开始（30 秒）

```bash
git clone https://github.com/stevenzhao07/delivery-guard.git && cd delivery-guard
python scripts/delivery_guard.py --demo
```

> 想参与或遇到问题？[提 Issue](https://github.com/stevenzhao07/delivery-guard/issues)。

退出码：`0` 全部通过（指纹入台账）· `1` 有门禁未过（阻断，不入台账）· `2` 用法/IO 错误。

## 18 道门禁清单

| # | 门禁 | 说明 |
|---|---|---|
| 01 | artifact_exists_nonempty | 文件存在且非空 |
| 02 | license_present | 仓库含 LICENSE |
| 03 | no_hardcoded_secret | 无硬编码密钥/凭证 |
| 04 | no_pii | 无个人身份信息 |
| 05 | version_or_date_tag | 含版本/日期标识 |
| 06 | model_card_if_ml | 疑似 ML 产物须含模型卡要素 |
| 07 | dataset_card_if_used | 用数据须声明来源/授权 |
| 08 | human_oversight_declared | 含人类监督/人在回路声明 |
| 09 | affiliation_disclosed | 含贡献者关联披露 |
| 10 | no_commercial_marketing | 无商业营销措辞 |
| 11 | no_self_standard_claim | 不自称"制定标准/框架"（ITU 红线） |
| 12 | no_trademark_abuse | 无未授权商标符号滥用 |
| 13 | python_syntax_ok | Python 源语法编译通过 |
| 14 | requirements_present | 含依赖清单 |
| 15 | tests_present | 含测试（推荐） |
| 16 | no_todo_leak | 无 TODO/FIXME 遗留 |
| 17 | provenance_dual_fingerprint | 可计算双 SHA-256 指纹并落台账（原 17/18 两道合并，原 18 恒真） |
| 18 | clef_semantic_risk | **Clef 语义风险分级（可选）**：Cloudflare 决策模型对交付物文本判 A/B/C/D（营销/自称标准/误导风险），A/B 通过、C/D 阻断；无凭证或调用失败自动 N/A 通过 |

## 路由（总入口）

本模块由 **[medical-ai-toolkit](https://github.com/stevenzhao07/medical-ai-toolkit)** 作为 `lgd-skeleton/1.0` 总入口自动路由发现。

## 关联模块

- [ai-model-passport](https://github.com/stevenzhao07/ai-model-passport) — AI 护照身份档案参考实现
- [ai-a3-laws](https://github.com/stevenzhao07/ai-a3-laws) — A³ Laws 运行时约束库
- [samd-ra-toolkit](https://github.com/stevenzhao07/samd-ra-toolkit) — SaMD RA 工具包

## 许可

Apache-2.0 — 见 [LICENSE](./LICENSE)。

## 关联（方法论来源）

- 理念溯源：个人专家关于 AI 交付治理的公开方法论（个人观点，不构成标准）
- 同账号系列：`ai-model-passport` · `ai-a3-laws` · `samd-ra-toolkit`
