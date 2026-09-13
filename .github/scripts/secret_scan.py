#!/usr/bin/env python3
"""扫描本次提交的增量内容，检测可能泄漏的密钥/凭证。

由 GitHub Actions 调用，也可本地运行：

    BASE_SHA=<sha> HEAD_SHA=<sha> python .github/scripts/secret_scan.py

输出 GitHub Actions 注解（::error / ::warning）；命中 error 级别规则时以非 0 退出。
"""
from __future__ import annotations

import os
import re
import subprocess
import sys

LEVEL_ERROR = "error"
LEVEL_WARNING = "warning"

RULES: list[tuple[str, "re.Pattern[str]", str]] = [
    ("阿里云 AccessKey ID", re.compile(r"\bLTAI[A-Za-z0-9]{12,20}\b"), LEVEL_ERROR),
    ("AWS Access Key ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), LEVEL_ERROR),
    ("GitHub Token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b"), LEVEL_ERROR),
    ("Slack Token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b"), LEVEL_ERROR),
    ("私钥内容", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), LEVEL_ERROR),
    (
        "AccessKey Secret 明文赋值",
        re.compile(
            r"(?i)\b(?:access[_\-]?key[_\-]?secret|secret[_\-]?access[_\-]?key|access[_\-]?secret)\b"
            r"\s*[:=]\s*[\"'][^\"'\s]{12,}[\"']"
        ),
        LEVEL_ERROR,
    ),
    (
        "疑似凭证明文赋值",
        re.compile(
            r"(?i)\b(?:password|passwd|pwd|secret|token|api[_\-]?key|access[_\-]?key[_\-]?id"
            r"|sts[_\-]?token|security[_\-]?token)\b\s*[:=]\s*[\"'][^\"'\s]{8,}[\"']"
        ),
        LEVEL_WARNING,
    ),
]

# 占位符 / 模板示例，不视为真实凭证
PLACEHOLDER = re.compile(
    r"(?i)(x{4,}|your[_\-]|\byour\b|\$\{|<[^>]*>|example|sample|placeholder|dummy|redacted"
    r"|changeme|fake|todo|占位|示例|\*{4,})"
)


def run_git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} 执行失败: {result.stderr.strip()}")
    return result.stdout


def shas() -> tuple[str, str]:
    """解析要比对的提交区间。"""
    head = os.environ.get("HEAD_SHA") or ""
    base = os.environ.get("BASE_SHA") or ""

    def exists(sha: str) -> bool:
        if not sha or set(sha) <= {"0"}:
            return False
        result = subprocess.run(
            ["git", "cat-file", "-e", f"{sha}^{{commit}}"],
            capture_output=True,
        )
        return result.returncode == 0

    if not exists(head) and not exists(base):
        # 本地运行或无有效区间时，退化为检查最近一次提交
        head, base = "HEAD", "HEAD~1"
    elif not exists(base):
        head, base = head or "HEAD", "HEAD~1"
    elif not exists(head):
        head = "HEAD"
    return base, head


def iter_changed_lines(base: str, head: str):
    """按 `-U0` 解析 diff，产出 (文件路径, 新文件行号, 新增内容)。"""
    output = run_git("diff", "-U0", "--no-color", "--diff-filter=ACMR", base, head)
    path: str | None = None
    line_no = 0

    for raw in output.splitlines():
        if raw.startswith("+++ "):
            target = raw[4:].strip()
            path = None if target == "/dev/null" else target.removeprefix("b/")
            continue
        if raw.startswith("--- ") or raw.startswith("diff "):
            continue

        match = re.match(r"@@ -\S+ \+(\d+)(?:,(\d+))? @@", raw)
        if match:
            line_no = int(match.group(1))
            continue

        if path is None or raw.startswith("\\"):
            continue

        if raw.startswith("+"):
            yield path, line_no, raw[1:]
            line_no += 1
        elif raw.startswith("-"):
            continue
        else:
            line_no += 1


def is_false_positive(path: str, content: str) -> bool:
    if PLACEHOLDER.search(content):
        return True
    suffix = os.path.basename(path)
    return suffix.endswith((".md", ".lock", ".svg", ".map", ".min.js"))


def annotate(level: str, path: str, line: int, message: str) -> None:
    print(f"::{level} file={path},line={line}::{message}")


def main() -> int:
    base, head = shas()
    print(f"扫描区间: {base}..{head}")

    hits = 0
    warnings = 0
    for path, line_no, content in iter_changed_lines(base, head):
        for name, pattern, level in RULES:
            if not pattern.search(content):
                continue
            if is_false_positive(path, content):
                continue
            if level == LEVEL_ERROR:
                hits += 1
            else:
                warnings += 1
            annotate(level, path, line_no, f"{name}：请确认这不是真实凭证，必要时改用环境变量 / 密钥服务")

    print(f"命中 {hits} 处高危规则，{warnings} 处可疑规则")
    if hits:
        print("::error::检测到疑似密钥泄漏，请移除或改写为环境变量后重新提交")
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RuntimeError as exc:  # pragma: no cover - 仅用于 CI 日志可读
        print(f"::warning::{exc}")
        sys.exit(0)
