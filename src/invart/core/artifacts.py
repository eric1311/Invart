from __future__ import annotations

import hashlib
import html
import json
from pathlib import Path
from typing import Any


def stable_json_dumps(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def write_json_artifact(path: Path, payload: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(stable_json_dumps(payload), encoding="utf-8")
    return path


def write_html_artifact(path: Path, document: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(document, encoding="utf-8")
    return path


def stable_json_hash(payload: Any, *, prefixed: bool = True) -> str:
    digest = hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()
    return f"sha256:{digest}" if prefixed else digest


def sha256_file(path: Path, *, prefixed: bool = False) -> str:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return f"sha256:{digest}" if prefixed else digest


def relative_href(base_dir: Path, path: Path) -> str:
    try:
        value = path.relative_to(base_dir)
    except ValueError:
        value = path
    return html.escape(str(value))


__all__ = [
    "relative_href",
    "sha256_file",
    "stable_json_dumps",
    "stable_json_hash",
    "write_html_artifact",
    "write_json_artifact",
]
