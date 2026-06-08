from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from invart.core.artifacts import sha256_file


SCHEMA_VERSION = "invart.managed_launcher.v0.42"


def preview_managed_launcher(target: Path, *, agent: str, launcher: str = "shell") -> dict[str, Any]:
    target = target.expanduser().resolve()
    path = _launcher_path(target, agent, launcher)
    content = _launcher_content(agent)
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": "preview",
        "agent": agent,
        "launcher": launcher,
        "target": str(target),
        "target_path": str(path),
        "written": False,
        "backup_path": None,
        "planned_writes": [{"path": str(path), "content_hash": _content_hash(content)}],
        "coverage_after_confirm": {"runtime_observation": "mediated", "runtime_enforcement": "mediated"},
    }


def install_managed_launcher(target: Path, *, agent: str, launcher: str = "shell") -> dict[str, Any]:
    preview = preview_managed_launcher(target, agent=agent, launcher=launcher)
    path = Path(preview["target_path"])
    content = _launcher_content(agent)
    backup_path = None
    if path.exists():
        backup = path.with_suffix(path.suffix + ".invart.bak")
        backup.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
        backup_path = str(backup)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)
    manifest = path.with_suffix(path.suffix + ".json")
    manifest_payload = {
        "schema_version": SCHEMA_VERSION,
        "agent": agent,
        "launcher": launcher,
        "target_path": str(path),
        "content_hash": sha256_file(path, prefixed=True),
        "coverage": {"runtime_observation": "mediated", "runtime_enforcement": "mediated"},
    }
    manifest.write_text(json.dumps(manifest_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {
        **preview,
        "mode": "confirm",
        "written": True,
        "backup_path": backup_path,
        "manifest_path": str(manifest),
        "content_hash": manifest_payload["content_hash"],
    }


def verify_managed_launcher(target: Path, *, agent: str, launcher: str = "shell") -> dict[str, Any]:
    target = target.expanduser().resolve()
    path = _launcher_path(target, agent, launcher)
    manifest = path.with_suffix(path.suffix + ".json")
    exists = path.exists()
    executable = exists and path.stat().st_mode & 0o111 != 0
    content_hash = sha256_file(path, prefixed=True) if exists else None
    manifest_payload: dict[str, Any] = {}
    if manifest.exists():
        try:
            loaded = json.loads(manifest.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                manifest_payload = loaded
        except json.JSONDecodeError:
            manifest_payload = {}
    hash_matches = bool(content_hash and manifest_payload.get("content_hash") == content_hash)
    status = "pass" if exists and executable and hash_matches else "fail"
    return {
        "schema_version": "invart.managed_launcher_verify.v0.42",
        "status": status,
        "agent": agent,
        "launcher": launcher,
        "target_path": str(path),
        "manifest_path": str(manifest),
        "checks": {"exists": exists, "executable": bool(executable), "hash_matches": hash_matches},
        "coverage": {"runtime_observation": "mediated" if status == "pass" else "none", "runtime_enforcement": "mediated" if status == "pass" else "none"},
    }


def _launcher_path(target: Path, agent: str, launcher: str) -> Path:
    suffix = ".sh" if launcher == "shell" else ".launcher"
    return target / ".invart" / "launchers" / f"{agent}{suffix}"


def _launcher_content(agent: str) -> str:
    return (
        "#!/usr/bin/env sh\n"
        "set -eu\n"
        f'exec python -m invart.cli adapter run --agent "{agent}" -- "$@"\n'
    )


def _content_hash(content: str) -> str:
    import hashlib

    return f"sha256:{hashlib.sha256(content.encode('utf-8')).hexdigest()}"
