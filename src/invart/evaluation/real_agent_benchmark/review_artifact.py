from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
from pathlib import Path
from typing import Any

from invart.core.artifacts import write_json_artifact
from invart.core.models import utc_now

from .artifact_writer import summarize_p0_real_agent_package
from .provider_run_control import secure_provider_artifact_tree


REVIEW_SCHEMA_VERSION = "invart.p0_review_artifact.v0.1"

_TEXT_SUFFIXES = {".json", ".jsonl", ".md", ".tex", ".sh", ".txt"}
_SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{20,}"),
    re.compile(
        r"(?i)(OPENAI_API_KEY|ANTHROPIC_API_KEY|HF_TOKEN|DASHSCOPE_API_KEY|DASHSCOPE_TP_API_KEY)"
        r"\s*=\s*['\"]?[^\s\"']{12,}"
    ),
    re.compile(r"(?i)Authorization\s*:\s*Bearer\s+[^\s\"']{8,}"),
]
_LOCAL_PATH_PATTERNS = [
    re.compile(r"/Users/[^\s\"'`,;:)]+"),
    re.compile(r"/home/[^\s\"'`,;:)]+"),
    re.compile(r"/private/var/folders/[^\s\"'`,;:)]+"),
    re.compile(r"/var/folders/[^\s\"'`,;:)]+"),
    re.compile(r"/opt/homebrew[^\s\"'`,;:)]*"),
]


def export_p0_review_artifact(*, run_dir: Path, out_dir: Path) -> dict[str, Any]:
    source = run_dir.expanduser().resolve()
    target = out_dir.expanduser().resolve()
    if source == target:
        raise ValueError("review artifact out_dir must differ from run_dir")
    source_summary = summarize_p0_real_agent_package(source)
    staging = target.with_name(f".{target.name}.staging-{os.getpid()}")
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True, mode=0o700)

    source_files = _discover_review_files(source)
    copied: list[dict[str, Any]] = []
    for item in source_files:
        destination = staging / item.name
        text = item.read_text(encoding="utf-8", errors="replace")
        sanitized = sanitize_p0_review_text(text, run_root=source)
        if item.name == "reproduce_p0.sh":
            sanitized = _sanitize_review_reproduce_p0_script(sanitized)
        destination.write_text(sanitized, encoding="utf-8")
        if destination.suffix == ".sh":
            destination.chmod(0o700)
        else:
            destination.chmod(0o600)
        copied.append(
            {
                "file": item.name,
                "sha256": _sha256_file(destination),
                "bytes": destination.stat().st_size,
            }
        )

    reproduce_script = _write_review_reproduce_script(staging)
    copied.append(
        {
            "file": reproduce_script.name,
            "sha256": _sha256_file(reproduce_script),
            "bytes": reproduce_script.stat().st_size,
        }
    )
    secure_provider_artifact_tree(staging)
    leak_scan = scan_p0_review_artifact(staging)
    manifest = {
        "schema_version": REVIEW_SCHEMA_VERSION,
        "status": "pending",
        "generated_at": utc_now(),
        "source": {
            "package_name": source.name,
            "package_status": source_summary.get("status"),
            "evidence_hash": source_summary.get("evidence_hash"),
            "p0_scope_complete": source_summary.get("summary", {}).get("p0_scope_complete"),
            "run_rows": source_summary.get("summary", {}).get("run_rows"),
            "covered_expected_rows": source_summary.get("summary", {}).get("expected_scope", {}).get("covered_expected_rows"),
            "expected_rows": source_summary.get("summary", {}).get("expected_scope", {}).get("expected_rows"),
        },
        "files": copied,
        "leak_scan": leak_scan,
        "claim_boundary": (
            "This review artifact is a sanitized copy of frozen P0 evidence. It preserves row-level claims and "
            "hashes for review, but it does not add missing provider executions or convert a partial P0 package "
            "into evidence-complete benchmark coverage."
        ),
    }
    write_json_artifact(staging / "review_artifact_manifest.json", manifest)
    secure_provider_artifact_tree(staging)
    final_scan = scan_p0_review_artifact(staging)
    manifest["leak_scan"] = final_scan
    manifest["status"] = "pass" if final_scan["status"] == "pass" else "fail"
    write_json_artifact(staging / "review_artifact_manifest.json", manifest)
    secure_provider_artifact_tree(staging)
    final_scan = scan_p0_review_artifact(staging)
    if final_scan["status"] != "pass":
        shutil.rmtree(staging)
        raise RuntimeError("review artifact failed recursive leak scan; target was not published")
    if target.exists():
        shutil.rmtree(target)
    staging.replace(target)
    published_reproduce_script = target / reproduce_script.name
    return {
        "schema_version": "invart.p0_review_artifact_export.v0.1",
        "status": "pass" if final_scan["status"] == "pass" else "fail",
        "root": str(target),
        "source_package": source.name,
        "manifest": str(target / "review_artifact_manifest.json"),
        "reproduce_script": str(published_reproduce_script),
        "files": [item["file"] for item in copied] + ["review_artifact_manifest.json"],
        "leak_scan": final_scan,
        "claim_boundary": manifest["claim_boundary"],
    }


def sanitize_p0_review_text(text: str, *, run_root: Path) -> str:
    root = run_root.expanduser().resolve()
    repo_root = _infer_repo_root(root)
    replacements = [
        (str(root), "."),
        (str(repo_root), "$INVART_REPO") if repo_root else ("", ""),
        (str(Path.home()), "$HOME"),
        ("/opt/homebrew", "$SYSTEM_PREFIX"),
        ("/usr/local", "$SYSTEM_PREFIX"),
    ]
    sanitized = text
    for old, new in sorted([item for item in replacements if item[0]], key=lambda item: len(item[0]), reverse=True):
        sanitized = sanitized.replace(old, new)
    sanitized = re.sub(r"/private/var/folders/[^\s\"'`,;:)]+", "$TMPDIR", sanitized)
    sanitized = re.sub(r"/var/folders/[^\s\"'`,;:)]+", "$TMPDIR", sanitized)
    sanitized = re.sub(r"/Users/[^\s\"'`,;:)]*", "$LOCAL_PATH", sanitized)
    sanitized = re.sub(r"/home/[^\s\"'`,;:)]*", "$LOCAL_PATH", sanitized)
    return sanitized


def _sanitize_review_reproduce_p0_script(text: str) -> str:
    return re.sub(
        r'INVART_REPO="\$\{INVART_REPO:-[^}]*\}"',
        ': "${INVART_REPO:?set INVART_REPO to the Invart repository checkout}"\n'
        'INVART_REPO="${INVART_REPO}"',
        text,
    )


def scan_p0_review_artifact(root: Path) -> dict[str, Any]:
    resolved = root.expanduser().resolve()
    local_path_matches: list[dict[str, Any]] = []
    secret_matches: list[dict[str, Any]] = []
    scanned_files = 0
    permission_violations: list[dict[str, Any]] = []
    for item in [resolved, *sorted(resolved.rglob("*"))]:
        relative = "." if item == resolved else str(item.relative_to(resolved))
        if item.is_symlink():
            permission_violations.append({"file": relative, "reason": "symlink_not_allowed"})
            continue
        if item.stat().st_mode & 0o077:
            permission_violations.append(
                {"file": relative, "mode": oct(item.stat().st_mode & 0o777)}
            )
        if not item.is_file() or item.suffix not in _TEXT_SUFFIXES:
            continue
        scanned_files += 1
        text = item.read_text(encoding="utf-8", errors="replace")
        for pattern in _LOCAL_PATH_PATTERNS:
            for match in pattern.finditer(text):
                local_path_matches.append({"file": relative, "match": match.group(0)[:160]})
        for pattern in _SECRET_PATTERNS:
            for match in pattern.finditer(text):
                secret_matches.append({"file": relative, "match": _redact_match(match.group(0))})
    return {
        "schema_version": "invart.p0_review_artifact_leak_scan.v0.1",
        "status": "pass"
        if not local_path_matches and not secret_matches and not permission_violations
        else "fail",
        "scanned_files": scanned_files,
        "local_path_matches": local_path_matches,
        "secret_matches": secret_matches,
        "permission_violations": permission_violations,
    }


def _discover_review_files(root: Path) -> list[Path]:
    files = []
    for item in sorted(root.iterdir()):
        if not item.is_file() or item.suffix not in _TEXT_SUFFIXES:
            continue
        if item.name == "review_artifact_manifest.json":
            continue
        files.append(item)
    return files


def _infer_repo_root(path: Path) -> Path | None:
    parts = list(path.parts)
    if ".local" in parts:
        idx = parts.index(".local")
        if idx > 1:
            return Path(*parts[:idx])
    return None


def _write_review_reproduce_script(root: Path) -> Path:
    path = root / "reproduce_all.sh"
    script = """#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
"$PYTHON_BIN" - "$ROOT" <<'PY'
import hashlib
import json
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
manifest_path = root / "review_artifact_manifest.json"
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
local_patterns = [
    re.compile("/" + "Users/" + r"[^\\s\\"'`,;:)]+"),
    re.compile("/" + "home/" + r"[^\\s\\"'`,;:)]+"),
    re.compile("/" + "private/var/folders/" + r"[^\\s\\"'`,;:)]+"),
    re.compile("/" + "var/folders/" + r"[^\\s\\"'`,;:)]+"),
    re.compile("/" + "opt/homebrew" + r"[^\\s\\"'`,;:)]*"),
]
secret_patterns = [
    re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{20,}"),
    re.compile(r"(?i)(OPENAI_API_KEY|ANTHROPIC_API_KEY|HF_TOKEN|DASHSCOPE_API_KEY|DASHSCOPE_TP_API_KEY)\\s*=\\s*['\\"]?[^\\s\\\"']{12,}"),
    re.compile(r"(?i)Authorization\\s*:\\s*Bearer\\s+[^\\s\\\"']{8,}"),
]

def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()

missing = []
hash_mismatch = []
for row in manifest.get("files", []):
    name = row.get("file")
    if not name:
        continue
    candidate = root / name
    if not candidate.exists():
        missing.append(name)
        continue
    if row.get("sha256") and sha256_file(candidate) != row.get("sha256"):
        hash_mismatch.append(name)

leaks = []
for item in sorted(root.rglob("*")):
    if not item.is_file() or item.suffix not in {".json", ".jsonl", ".md", ".tex", ".sh", ".txt"}:
        continue
    text = item.read_text(encoding="utf-8", errors="replace")
    for pattern in local_patterns + secret_patterns:
        if pattern.search(text):
            leaks.append(item.name)
            break

if missing or hash_mismatch or leaks:
    print(json.dumps({"status": "fail", "missing": missing, "hash_mismatch": hash_mismatch, "leaks": sorted(set(leaks))}, indent=2))
    raise SystemExit(1)
print(json.dumps({"status": "pass", "files": len(manifest.get("files", [])), "source": manifest.get("source", {})}, indent=2, sort_keys=True))
PY
"""
    path.write_text(script, encoding="utf-8")
    mode = path.stat().st_mode
    path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _redact_match(value: str) -> str:
    if len(value) <= 12:
        return "<redacted>"
    return value[:6] + "...<redacted>..." + value[-4:]
