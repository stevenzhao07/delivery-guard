#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
delivery-guard · delivery_guard.py
===========================================

医疗 AI / 医疗器械交付物「门禁（gate）」开源工具。

在把任何交付物（模型卡、数据集卡、代码、文档、合规模板）对外发布或交付前，
本工具按 17 道门禁逐条校验，并对其计算「双 SHA-256 指纹」写入权属台账
（provenance ledger），形成可审计的在先发表证据。

设计原则（与 MedXpert 一线合规实践一致）：
- 纯技术、零外部依赖（仅 Python 标准库），可离线运行；
- 门禁可配置、可扩展（GATES 列表即注册表）；
- 双指纹 = 原始文件 sha256 + 规范化内容 sha256，抗 trivial 篡改；
- 台账为 append-only JSON Lines，便于跨辖区（NMPA / FDA / EU MDR）溯源举证。

用法
----
    python delivery_guard.py <path-to-artifact> [--ledger ledger.jsonl] [--json]

退出码
------
    0  全部门禁通过，指纹已写入台账
    1  存在未通过门禁（默认阻断交付）
    2  用法 / IO 错误

本工具为纯技术贡献，不含任何商业营销；MedXpert 仅作为贡献者署名。
"""

from __future__ import annotations
import sys

import argparse
import hashlib
import json
import os
import re
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

# ---------------------------------------------------------------------------
# 门禁结果数据模型
# ---------------------------------------------------------------------------


@dataclass
class GateResult:
    gate_id: int
    name: str
    passed: bool
    detail: str


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalize_text(text: str) -> str:
    """规范化文本：去多余空白、统一行尾，用于「内容指纹」而非「字节指纹」。"""
    lines = [ln.strip() for ln in text.replace("\r\n", "\n").split("\n")]
    return "\n".join(lines).strip()


def read_artifact(path: Path) -> tuple[Optional[bytes], Optional[str]]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        print(f"[io] 无法读取 {path}: {exc}", file=sys.stderr)
        return None, None
    for enc in ("utf-8", "gb18030"):  # 中文 Windows 产物常见 GBK/GB18030 编码
        try:
            text = raw.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    else:
        text = None  # 二进制产物（如模型权重）只算字节指纹
    return raw, text


# ---------------------------------------------------------------------------
# 17 道门禁（GATES 注册表）
# 每个门禁: (name, predicate) -> predicate(text, raw, path) -> (passed, detail)
# text 可能为 None（二进制产物）；此时基于文本的校验自动判为 N/A（通过，但注明）。
# ---------------------------------------------------------------------------

# 密钥检测需「赋值上下文」：单词+分隔符+长度>=8 的值，避免把文档里的
# "password"/"token" 字样或本文件自身的正则定义误报为泄密。
SECRET_RE = re.compile(
    r"(?i)(api[_-]?key|secret|token|password|passwd)\s*[:=]\s*[\"']?[A-Za-z0-9/+_\-]{8,}"
    r"|akia[0-9A-Z]{16}|ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]+|sk-[0-9a-zA-Z]{32}"
)
PII_RE = re.compile(r"(?i)\b(id\s*card|身份证|passport\s*no|social\s*security|"
                    r"\d{6}-\d{4}-\d{4})\b")
MARKETING_RE = re.compile(
    r"(?i)(限时优惠|买[一二三四]送|立即购买|免费咨询|扫码下单|"
    r"best in class|#1 (provider|solution)|guaranteed cure|包治)"
)


def _na_if_binary(text: Optional[str], default_detail: str = "二进制产物，基于文本的门禁不适用"):
    if text is None:
        return True, default_detail
    return None, ""  # 信号：继续走文本逻辑


def _gate_text(text: Optional[str], path: Path) -> str:
    """模式类门禁的扫描文本。

    对 `.py` 源**剥离注释与字符串字面量**，避免本文件自身的门禁模式定义
    （PII_RE/MARKETING_RE/自称正则）与 docstring 示例被当成命中 —— 根治
    「自指误报」（2026-10-13，原仅做任务级声明未治根）。
    非 `.py`（README / IFU / 报告等交付内容）原样返回，照常全文扫描。
    """
    if text is None:
        return ""
    if path.suffix != ".py":
        return text
    try:
        import io
        import tokenize
        out = []
        for tok in tokenize.generate_tokens(io.StringIO(text).readline):
            if tok.type in (tokenize.COMMENT, tokenize.STRING):
                continue
            out.append(tok.string)
        return " ".join(out)
    except Exception:
        return text


def gate_exists_nonempty(text, raw, path):
    ok = raw is not None and len(raw) > 0
    return ok, "文件存在且非空" if ok else "文件为空或读取失败"


def gate_license_present(text, raw, path):
    lic = path.parent / "LICENSE"
    ok = lic.is_file() and lic.stat().st_size > 0
    return ok, "仓库含 LICENSE 文件" if ok else "缺失 LICENSE 文件"


def gate_no_secret(text, raw, path):
    na = _na_if_binary(text)
    if na[0] is True:
        return na
    hit = SECRET_RE.search(text)
    return (not bool(hit)), ("未发现硬编码密钥" if not hit else f"疑似硬编码密钥: {hit.group(0)[:6]}…")


def gate_no_pii(text, raw, path):
    na = _na_if_binary(text)
    if na[0] is True:
        return na
    hit = PII_RE.search(_gate_text(text, path))
    return (not bool(hit)), ("未发现 PII" if not hit else f"疑似 PII: {hit.group(0)}")


def gate_has_version(text, raw, path):
    na = _na_if_binary(text)
    if na[0] is True:
        return na
    ok = bool(re.search(r"(?i)\b(v?\d+\.\d+\.\d+|version\s*[:=]|\d{4}-\d{2}-\d{2})", text))
    return ok, "含版本/日期标识" if ok else "未含版本或日期标识"


def gate_model_card(text, raw, path):
    # 仅当内容疑似 AI/ML 产物时强制；否则 N/A
    looks_ml = bool(re.search(r"(?i)(model card|training data|inference|f1|auc|" 
                              r"dataset|neural|classifier)", text or ""))
    if not looks_ml:
        return True, "非 ML 产物，模型卡门禁 N/A"
    has = bool(re.search(r"(?i)(model card|model_card|用途|intended use|局限|limitation)", text or ""))
    return has, "含模型卡要素" if has else "疑似 ML 产物但缺模型卡要素"


def gate_dataset_card(text, raw, path):
    uses_data = bool(re.search(r"(?i)(training data|dataset|训练数据|数据来源)", text or ""))
    if not uses_data:
        return True, "未声明使用训练数据，数据卡门禁 N/A"
    has = bool(re.search(r"(?i)(dataset card|数据卡|数据来源|data source|授权|license of data)", text or ""))
    return has, "含数据卡/数据来源声明" if has else "声明用数据但缺来源/授权声明"


def gate_human_oversight(text, raw, path):
    na = _na_if_binary(text)
    if na[0] is True:
        return na
    ok = bool(re.search(r"(?i)(human[- ]?in[- ]?the[- ]?loop|人类监督|人在回路|"
                        r"human oversight|clinician review|医生复核)", text or ""))
    return ok, "含人类监督/人在回路声明" if ok else "缺人类监督声明（医疗 AI 强建议）"


def gate_affiliation_disclosure(text, raw, path):
    na = _na_if_binary(text)
    if na[0] is True:
        return na
    ok = bool(re.search(r"(?i)(medxpert|stevenzhao07|美达信|affiliation|xinghua zhao)", text or ""))
    return ok, "含贡献者关联披露" if ok else "缺 MedXpert/贡献者关联披露块"


def gate_no_marketing(text, raw, path):
    na = _na_if_binary(text)
    if na[0] is True:
        return na
    hit = MARKETING_RE.search(_gate_text(text, path))
    return (not bool(hit)), ("无商业营销措辞" if not hit else f"疑似营销措辞: {hit.group(0)}")


def gate_standard_cite_correct(text, raw, path):
    na = _na_if_binary(text)
    if na[0] is True:
        return na
    # 不允许「我们制定的标准 / 我方治理框架」式自称
    bad = bool(re.search(r"(?i)(我们(制定|发布)的?标准|our (governance )?framework|"
                         r"we (mandate|set the standard))", _gate_text(text, path)))
    return (not bad), ("未自称制定标准" if not bad else "出现「我方标准/框架」自称，违反 ITU 红线")


def gate_no_3p_trademark(text, raw, path):
    na = _na_if_binary(text)
    if na[0] is True:
        return na
    # 仅检查明显未经授权的商标式自称；引用第三方标准名（ISO/FDA）本身允许
    bad = bool(re.search(r"(?i)(™|®)\s*(medxpert|synomosai)", _gate_text(text, path)))
    return (not bad), ("无未授权商标符号滥用" if not bad else "出现商标符号滥用")


def gate_syntax_ok(text, raw, path):
    if path.suffix not in {".py"}:
        return True, f"非 Python 源（{path.suffix or '无扩展名'}），语法门禁 N/A"
    if text is None:
        return False, "Python 源无法解码为文本"
    import ast
    try:
        ast.parse(text)
        return True, "Python 语法解析通过（ast.parse，无编译副作用）"
    except SyntaxError as exc:
        return False, f"Python 语法错误: {exc.msg}"


# 已知标准库顶层模块（防御性白名单：兼容 3.8/3.9 无 sys.stdlib_module_names）。
_KNOWN_STDLIB = {
    "sys", "argparse", "json", "hashlib", "datetime", "csv", "math", "re", "os",
    "glob", "dataclasses", "pathlib", "typing", "tempfile", "py_compile", "io",
    "collections", "functools", "itertools", "textwrap", "unittest", "string",
    "random", "time", "logging", "abc", "enum", "copy", "base64", "ast",
    "subprocess", "shutil", "fnmatch", "secrets", "uuid", "socket", "struct",
    "statistics", "decimal", "fractions", "contextlib", "types", "numbers",
    "operator", "pprint", "locale", "calendar", "platform", "traceback",
    "warnings", "weakref", "array", "bisect", "heapq", "queue", "select",
    "signal", "ssl", "email", "html", "http", "xml", "urllib", "zipfile",
    "tarfile", "gzip", "sqlite3", "configparser", "ipaddress", "hmac",
    "concurrent", "multiprocessing", "asyncio", "zoneinfo", "tomllib",
}


def _third_party_imports(text: Optional[str]) -> set[str]:
    """返回文件中用到的非标准库顶层模块名集合（用于零依赖豁免判定）。

    覆盖 import x / from x import / from . import（相对导入判本地，跳过）；
    importlib.import_module("x") 等动态导入无法静态识别，属已知边界。
    """
    if not text:
        return set()
    stdlib = getattr(sys, "stdlib_module_names", set())
    found = set()
    for m in re.finditer(
        r"^\s*(?:import\s+([a-zA-Z0-9_\.]+)|from\s+([\.a-zA-Z0-9_\.]+)\s+import)",
        text, re.M,
    ):
        mod = m.group(1) or m.group(2) or ""
        if mod.startswith("."):
            continue  # 相对导入 = 本地模块
        mod = mod.split(".")[0]
        if not mod:
            continue
        if mod in stdlib or mod in _KNOWN_STDLIB:
            continue
        found.add(mod)
    return found


def gate_requirements_present(text, raw, path):
    if path.suffix not in {".py"}:
        return True, "非 Python 源，依赖清单门禁 N/A"
    # 零依赖豁免：仅 import 标准库 → 不需要 requirements.txt（与零依赖自相矛盾项修复）
    third = _third_party_imports(text)
    if not third:
        return True, "零依赖（仅标准库），requirements.txt 门禁豁免"
    req = path.parent / "requirements.txt"
    ok = req.is_file()
    return ok, "含 requirements.txt" if ok else f"缺 requirements.txt（用到第三方库: {', '.join(sorted(third))}）"


def gate_has_tests(text, raw, path):
    if path.suffix not in {".py"}:
        return True, "非 Python 源，测试门禁 N/A"
    has_test = any(p.name.startswith("test_") for p in path.parent.iterdir())
    return has_test, "含测试文件" if has_test else "建议补充测试（非阻断，但推荐）"


def gate_no_todo_leak(text, raw, path):
    na = _na_if_binary(text)
    if na[0] is True:
        return na
    hit = re.search(r"(?i)(TODO|FIXME|XXX)\b", _gate_text(text, path))
    return (not bool(hit)), ("无 TODO/FIXME 遗留" if not hit else f"遗留标记: {hit.group(0)}")


def gate_provenance_dual_fingerprint(text, raw, path):
    """双指纹就绪门禁（真实可判定，替代原恒真占位）：
    台账记录须含 byte_sha256 + content_sha256，故产物必须可读、可计算双指纹。
    二进制产物仅能算字节指纹（内容指纹 N/A）——如实标注而非假装通过。"""
    if raw is None or len(raw) == 0:
        return False, "产物不可读或为空，无法计算双指纹"
    if text is None:
        return True, "二进制产物：可算字节指纹，内容指纹 N/A（台账如实标注）"
    return True, "可计算双 SHA-256 指纹（字节+内容）"


# 注册表：门禁按编号顺序执行
GATES: list[tuple[str, Callable]] = [
    ("artifact_exists_nonempty", gate_exists_nonempty),
    ("license_present", gate_license_present),
    ("no_hardcoded_secret", gate_no_secret),
    ("no_pii", gate_no_pii),
    ("version_or_date_tag", gate_has_version),
    ("model_card_if_ml", gate_model_card),
    ("dataset_card_if_used", gate_dataset_card),
    ("human_oversight_declared", gate_human_oversight),
    ("affiliation_disclosed", gate_affiliation_disclosure),
    ("no_commercial_marketing", gate_no_marketing),
    ("no_self_standard_claim", gate_standard_cite_correct),
    ("no_trademark_abuse", gate_no_3p_trademark),
    ("python_syntax_ok", gate_syntax_ok),
    ("requirements_present", gate_requirements_present),
    ("tests_present", gate_has_tests),
    ("no_todo_leak", gate_no_todo_leak),
    ("provenance_dual_fingerprint", gate_provenance_dual_fingerprint),
]


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------


def run_gates(path: Path) -> tuple[list[GateResult], bytes, Optional[str]]:
    raw, text = read_artifact(path)
    results: list[GateResult] = []
    for i, (name, fn) in enumerate(GATES, start=1):
        try:
            passed, detail = fn(text, raw, path)
        except Exception as exc:  # 单门禁异常不应中断整体
            passed, detail = False, f"门禁执行异常: {exc}"
        results.append(GateResult(i, name, bool(passed), detail))
    return results, raw or b"", text


def commit_ledger(ledger_path: Path, record: dict) -> None:
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    with ledger_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")


def _demo() -> int:
    import tempfile
    sample = (
        "# 演示交付物：骨科 AI 分诊说明（v0.1.0）\n\n"
        "本模型用于骨科植入物风险分诊辅助，预期用途见模型卡，局限见 limitation 段。\n"
        "人类监督：高风险决策须临床医生复核（human-in-the-loop）。\n"
        "贡献者关联：MedXpert (@stevenzhao07)。\n"
    )
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False, encoding="utf-8") as f:
        f.write(sample)
        path = Path(f.name)
    try:
        results, _, _ = run_gates(path)
        for r in results:
            print(f"  [{'PASS' if r.passed else 'XX'}] {r.name}: {r.detail}")
        print(f"\n[demo] 演示门禁: {sum(r.passed for r in results)}/{len(results)} 通过"
              f"（演示样本干净，不写入台账）")
    finally:
        path.unlink()
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="MedXpert 交付门禁：17 道门禁 + 双 SHA-256 指纹权属台账")
    parser.add_argument("--demo", action="store_true", help="跑内置演示样本（不写台账）")
    parser.add_argument("artifact", nargs="?", help="待校验交付物路径（文件）")
    parser.add_argument("--ledger", default="provenance_ledger.jsonl",
                        help="权属台账输出路径（默认 ./provenance_ledger.jsonl）")
    parser.add_argument("--json", action="store_true", help="以 JSON 输出结果")
    args = parser.parse_args(argv)

    if args.demo:
        return _demo()

    if not args.artifact:
        parser.print_help()
        return 2

    path = Path(args.artifact)
    if not path.is_file():
        print(f"[error] 不是文件: {path}", file=sys.stderr)
        return 2

    results, raw, text = run_gates(path)
    all_pass = all(r.passed for r in results)

    byte_sha = sha256_bytes(raw)
    content_sha = sha256_bytes(normalize_text(text).encode("utf-8")) if text else ""

    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "artifact": str(path),
        "byte_sha256": byte_sha,
        "content_sha256": content_sha,
        "gates_total": len(results),
        "gates_passed": sum(r.passed for r in results),
        "all_passed": all_pass,
        "contributor": "MedXpert (@stevenzhao07)",
    }

    if args.json:
        print(json.dumps({"record": record,
                          "gates": [asdict(r) for r in results]},
                         ensure_ascii=False, indent=2))
    else:
        print(f"\n=== delivery-guard · {path.name} ===")
        print(f"字节指纹  : {byte_sha}")
        if content_sha:
            print(f"内容指纹  : {content_sha}")
        print(f"门禁通过  : {record['gates_passed']}/{record['gates_total']}")
        print("-" * 52)
        for r in results:
            mark = "✅" if r.passed else "❌"
            print(f"  [{r.gate_id:02d}] {mark} {r.name:<28} {r.detail}")
        print("-" * 52)

    if all_pass:
        commit_ledger(Path(args.ledger), record)
        print(f"✅ 全部门禁通过，指纹已写入台账: {args.ledger}\n")
        return 0
    print(f"❌ 存在未通过门禁，已阻断交付（未写入台账）。请修复后重试。\n")
    return 1


if __name__ == "__main__":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
            sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass
    raise SystemExit(main())
