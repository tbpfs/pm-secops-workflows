#!/usr/bin/env python3
"""Zero-dependency DevSecOps & Hygiene Gate for GitHub Actions Reusable Workflows.

Checks:
1. Tracked forbidden credential/environment files (.env, *.pem, *.key, *cookies*.txt, *token*.json, >5MB).
2. High-entropy / known API token & private key patterns (redacted output — never prints secrets).
3. Local/container filesystem path leaks (/workspace/, /home/antigravity/, C:\\Users\\...).
4. GitHub Actions workflow security (missing permissions:, unpinned third-party actions, unsafe run: interpolation).
5. Optional public web SEO/GEO contract (robots.txt, sitemap.xml, llms.txt, ads.txt).
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import subprocess
import sys

MAX_FILE_BYTES = 5 * 1024 * 1024

SECRET_RE = re.compile(
    r"(ghp_[A-Za-z0-9]{30,}"
    r"|gho_[A-Za-z0-9]{30,}"
    r"|github_pat_[A-Za-z0-9_]{30,}"
    r"|cfut_[A-Za-z0-9_]{20,}"
    r"|cfat_[A-Za-z0-9_]{20,}"
    r"|cfk_[A-Za-z0-9_]{20,}"
    r"|xai-[A-Za-z0-9]{20,}"
    r"|sk-[A-Za-z0-9_-]{20,}"
    r"|AIza[0-9A-Za-z_-]{35}"
    r"|GOCSPX-[A-Za-z0-9_-]{20,}"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----"
    r"|AKIA[0-9A-Z]{16})"
)

LOCAL_PATH_RE = re.compile(
    r"(/home/antigravity/|/shared/user/|/workspace/|C:\\+Users\\+[A-Za-z0-9_.-]+|C:/Users/[A-Za-z0-9_.-]+)",
    re.IGNORECASE,
)

FORBIDDEN_FILE_RE = re.compile(
    r"(^|/)\.env($|\.(?!example$))"
    r"|\.(pem|key|p12|pfx|token|safetensors|ckpt|pt|pth|onnx)$"
    r"|(^|/)[^/]*(service_account|user_oauth|client_secret|credentials|secrets|token)[^/]*\.(json|db|ya?ml)$"
    r"|(^|/)[^/]*(api_token|_token|cookies)[^/]*\.txt$"
    r"|(^|/)id_(rsa|ed25519|ecdsa)$",
    re.IGNORECASE,
)

EXEMPT_PATH_SCAN_RE = re.compile(
    r"(^|/)(tests?|fixtures|scripts|docs|\.github|\.agents)/"
    r"|(^|/)(GEMINI|AGENTS|README|CHANGELOG|PLAN)\.md$"
    r"|\.(spec|test)\.[jt]s$"
    r"|audit\.m?[jt]s$",
    re.IGNORECASE,
)

TEXT_EXTS = {
    ".html", ".htm", ".txt", ".md", ".xml", ".json", ".js", ".mjs", ".ts", ".css", ".py", ".sh", ".yml", ".yaml",
}

USES_LINE_RE = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)", re.MULTILINE)
GHA_EXPR_RE = re.compile(r"\$\{\{([\s\S]*?)\}\}")
UNSAFE_EXPR_BODY_RE = re.compile(
    r"\b(?:github\.head_ref"
    r"|github\.event\.(?:issue|pull_request|comment|commits|head_commit|discussion"
    r"|review|review_comment|pages|workflow_run|release|inputs|client_payload)"
    r"|inputs\.)"
)
UNSAFE_EXPR_IN_RUN_RE = re.compile(
    r"\$\{\{(?:(?!\}\}).)*\b(?:github\.head_ref"
    r"|github\.event\.(?:issue|pull_request|comment|commits|head_commit|discussion"
    r"|review|review_comment|pages|workflow_run|release|inputs|client_payload)"
    r"|inputs\.)(?:(?!\}\}).)*\}\}"
)
RUN_KEY_RE = re.compile(r"^(\s*(?:-\s+)?)run:\s*(.*)$")
BLOCK_SCALAR_HDR_RE = re.compile(r"^[|>](?:[+-][1-9]|[1-9][+-]|[+-]|[1-9])?\s*(?:#.*)?$")
EMPTY_OR_COMMENT_RE = re.compile(r"^(?:#.*)?$")


def _is_quoted_closed(fragment: str, quote: str, start_idx: int = 0) -> bool:
    i = start_idx
    n = len(fragment)
    if quote == '"':
        while i < n:
            ch = fragment[i]
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                return True
            i += 1
        return False
    while i < n:
        if fragment[i] == "'":
            if i + 1 < n and fragment[i + 1] == "'":
                i += 2
                continue
            return True
        i += 1
    return False


def extract_run_script_lines(yaml_text: str) -> list[tuple[int, str]]:
    """Zero-dependency indentation-aware extractor returning (1-based line_no, script_text) strictly inside `run:`."""
    collected: list[tuple[int, str]] = []
    mode: str | None = None
    key_indent = -1

    for line_no, raw_line in enumerate(yaml_text.splitlines(), 1):
        stripped = raw_line.strip()
        indent = len(raw_line) - len(raw_line.lstrip(" "))

        if mode == "block":
            if not stripped:
                continue
            if indent > key_indent:
                collected.append((line_no, raw_line))
                continue
            mode = None
        elif mode == "quoted_double":
            if stripped and indent <= key_indent:
                mode = None
            else:
                collected.append((line_no, raw_line))
                if _is_quoted_closed(raw_line, '"', 0):
                    mode = None
                continue
        elif mode == "quoted_single":
            if stripped and indent <= key_indent:
                mode = None
            else:
                collected.append((line_no, raw_line))
                if _is_quoted_closed(raw_line, "'", 0):
                    mode = None
                continue
        elif mode == "plain_cont":
            if not stripped:
                continue
            if indent > key_indent and not re.match(r"^\s*-\s+", raw_line):
                collected.append((line_no, raw_line))
                continue
            mode = None

        if not stripped or raw_line.lstrip().startswith("#"):
            continue
        m = RUN_KEY_RE.match(raw_line)
        if not m:
            continue
        # key_indent is the literal starting column of `run:` (counting leading `- ` on list items)
        key_indent = len(m.group(1))
        val = m.group(2)
        val_stripped = val.strip()
        if BLOCK_SCALAR_HDR_RE.match(val_stripped) or EMPTY_OR_COMMENT_RE.match(val_stripped):
            mode = "block"
        elif val_stripped.startswith('"'):
            collected.append((line_no, val))
            if not _is_quoted_closed(val_stripped, '"', 1):
                mode = "quoted_double"
        elif val_stripped.startswith("'"):
            collected.append((line_no, val))
            if not _is_quoted_closed(val_stripped, "'", 1):
                mode = "quoted_single"
        else:
            collected.append((line_no, val))
            mode = "plain_cont"

    return collected


def has_unsafe_run_expression(script_line: str) -> bool:
    return any(UNSAFE_EXPR_BODY_RE.search(m.group(1)) for m in GHA_EXPR_RE.finditer(script_line))


def list_tracked_files(repo_dir: Path) -> list[str]:
    res = subprocess.run(
        ["git", "-c", "core.quotePath=false", "ls-files", "-z"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
    )
    return [p.decode("utf-8", errors="replace") for p in res.stdout.split(b"\0") if p]


def audit_workflows(repo_dir: Path) -> list[str]:
    warnings_or_errors: list[str] = []
    wf_dir = repo_dir / ".github" / "workflows"
    if not wf_dir.is_dir():
        return warnings_or_errors

    for wf in sorted(wf_dir.glob("*.y*ml")):
        rel = wf.relative_to(repo_dir).as_posix()
        txt = wf.read_text(encoding="utf-8", errors="replace")
        if "permissions:" not in txt:
            warnings_or_errors.append(f"[Workflow 安全] {rel}: 缺少頂層或 Job 層級 `permissions:` 最小權限宣告")
        for m in USES_LINE_RE.finditer(txt):
            ref = m.group(1).strip().strip("'\"")
            if ref.startswith("./") or "@" not in ref:
                continue
            repo_part, ver = ref.split("@", 1)
            # Local reusable workflow repo may be referenced via @main or @v1 tag by callers; third-party actions must pin 40-char SHA
            if not repo_part.startswith("tbpfs/") and not re.fullmatch(r"[0-9a-f]{40}", ver):
                warnings_or_errors.append(f"[Workflow 供應鏈] {rel}: 第三方 Action `{ref}` 未釘選 40 字元 Commit SHA")
        for line_no, script_line in extract_run_script_lines(txt):
            if has_unsafe_run_expression(script_line):
                warnings_or_errors.append(
                    f"[Workflow 注入風險] {rel}:{line_no}: run: 區段不得直接內插不可信運算式，請改透過 env: 傳遞"
                )
    return warnings_or_errors


def scan_repository(
    repo_dir: Path,
    is_public_repo: bool = False,
    public_web_gate: bool = False,
    large_allowlist: set[str] | None = None,
) -> list[str]:
    errors: list[str] = []
    allow_large = large_allowlist or set()
    files = list_tracked_files(repo_dir)

    for rel in files:
        norm = rel.replace("\\", "/")
        fp = repo_dir / norm
        if not fp.is_file():
            continue
        # package.json / tsconfig.json etc. should not match *token*.json unless named token*.json
        if FORBIDDEN_FILE_RE.search(norm):
            errors.append(f"[敏感檔案攔截] 禁止入庫之憑證或環境檔: {norm}")
            continue

        sz = fp.stat().st_size
        if sz > MAX_FILE_BYTES and norm not in allow_large:
            errors.append(f"[檔案大小攔截] 超過 5 MiB 上限 ({sz:,} bytes): {norm}")
            continue

        if fp.suffix.lower() in TEXT_EXTS or fp.name == "Dockerfile":
            try:
                content = fp.read_text(encoding="utf-8")
            except Exception:
                continue

            for line_no, line in enumerate(content.splitlines(), 1):
                if SECRET_RE.search(line):
                    errors.append(f"[機密外洩攔截] {norm}:{line_no} 偵測到疑似 API 金鑰或私鑰標頭 (內容已遮罩)")
                    break

            scan_paths = is_public_repo and norm == "README.md" or not EXEMPT_PATH_SCAN_RE.search(norm)
            if scan_paths:
                m_p = LOCAL_PATH_RE.search(content)
                if m_p:
                    errors.append(f"[路徑外洩攔截] {norm} 含有內部開發路徑 `{m_p.group(0)}`")

    errors.extend(audit_workflows(repo_dir))

    if public_web_gate:
        roots = [
            repo_dir,
            repo_dir / "_site",
            repo_dir / "web",
            repo_dir / "public",
            repo_dir / "dist" / "waifuscan" / "browser",
            repo_dir / "dist",
        ]
        for req_f in ("robots.txt", "sitemap.xml", "llms.txt", "ads.txt"):
            if not any((r / req_f).is_file() and (r / req_f).stat().st_size > 0 for r in roots):
                errors.append(f"[公開站契約攔截] 缺少非空的 `{req_f}`")

    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Purple Maple DevSecOps Repository Gate")
    parser.add_argument("--repo-dir", default=".", help="Target repository directory")
    parser.add_argument("--public-repo", action="store_true", help="Enforce stricter public repo README path checks")
    parser.add_argument("--public-web", action="store_true", help="Enforce robots/sitemap/llms/ads.txt presence")
    parser.add_argument("--allow-large", default="", help="Comma-separated allowlist for >5MB files")
    args = parser.parse_args(argv)

    repo_dir = Path(args.repo_dir).resolve()
    allow_set = {x.strip() for x in args.allow_large.split(",") if x.strip()}
    errs = scan_repository(
        repo_dir,
        is_public_repo=args.public_repo,
        public_web_gate=args.public_web,
        large_allowlist=allow_set,
    )
    if errs:
        for e in errs:
            print(f"::error::{e}", file=sys.stderr)
        return 1
    print(f"[SECOPS PASS] {repo_dir.name}: 機密、內部路徑、檔案容量與 Workflow 供應鏈檢查全數通過！")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
