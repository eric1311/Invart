from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .scanner import scan_pre_runtime


def canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def preflight_path_for_target(target: Path) -> Path:
    return target.expanduser().resolve() / ".kappaski" / "preflight.json"


def save_preflight(target: Path, output_path: Path | None = None, include_home: bool = True) -> dict[str, Any]:
    target = target.expanduser().resolve()
    output_path = output_path or preflight_path_for_target(target)
    report = scan_pre_runtime(target, include_home=include_home).to_dict()
    preflight_hash = hashlib.sha256(canonical_json(report).encode("utf-8")).hexdigest()
    envelope = {
        "schema_version": "kappaski.preflight.v0.1",
        "path": str(output_path),
        "hash": preflight_hash,
        "report": report,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(envelope, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return envelope


def load_preflight(preflight_path: Path) -> dict[str, Any] | None:
    if not preflight_path.exists():
        return None
    try:
        payload = json.loads(preflight_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def preflight_reference(preflight_path: Path | None) -> dict[str, Any] | None:
    if preflight_path is None:
        return None
    payload = load_preflight(preflight_path)
    if payload is None:
        return {"path": str(preflight_path), "available": False, "hash": None}
    return {
        "path": str(preflight_path),
        "available": True,
        "hash": payload.get("hash"),
        "schema_version": payload.get("schema_version"),
    }
