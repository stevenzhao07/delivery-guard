# AGENTS.md · delivery-guard

> 机器可发现入口（AI 编码代理 / Codex / Claude / Cursor）。单一事实源：本文件。

## 这是什么
医疗 AI / 医疗器械交付物的「门禁（gate）」可插拔模块。交付前按 **17 道门禁**逐条校验，并计算**双 SHA-256 指纹**写入**权属台账（provenance ledger）**，形成可审计的在先发表证据。是 MedXpert 把AI 交付治理理念工程化落地的参考实现之一。

## 运行
```bash
python scripts/delivery_guard.py <artifact> [--ledger ledger.jsonl] [--json]
```

## 扩展契约（lgd-skeleton/1.0）
- **一切即插件**：仅依赖声明式 `module.json`，零配置。
- **按需装（lazy）**：仅 triggers 命中时加载。
- **可嵌套（nested）**：可被 `medical-ai-toolkit` 总入口路由。
- **扩展点**：`plugins/`（新增门禁只需在 `scripts/delivery_guard.py` 的 `GATES` 注册表加一行）。

## 红线
纯技术贡献，不含商业营销；MedXpert 仅作为贡献者署名（@stevenzhao07）。
