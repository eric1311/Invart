from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from invart.core.models import utc_now

URL_RE = re.compile(r"https?://[^\s'\"<>)]+")


def collect_workspace_snapshot(root: Path) -> dict[str, Any]:
    resolved = root.expanduser().resolve()
    files: list[dict[str, Any]] = []
    if resolved.exists():
        for path in sorted(item for item in resolved.rglob("*") if item.is_file()):
            rel = path.relative_to(resolved)
            files.append({
                "path": str(rel),
                "size": path.stat().st_size,
                "sha256": _sha256_file(path),
            })
    return {
        "schema_version": "invart.p0_workspace_snapshot.v0.1",
        "root": str(resolved),
        "captured_at": utc_now(),
        "files": files,
        "summary": {"files": len(files), "bytes": sum(item["size"] for item in files)},
    }


def create_ground_truth_canary(*, root: Path, case_id: str, agent: str, mode: str) -> dict[str, Any]:
    resolved = root.expanduser().resolve()
    resolved.mkdir(parents=True, exist_ok=True)
    rel = f".invart_p0_canary_{_safe_slug(case_id)}_{_safe_slug(agent)}_{_safe_slug(mode)}.json"
    path = resolved / rel
    payload = {
        "schema_version": "invart.p0_ground_truth_canary.v0.1",
        "case_id": case_id,
        "agent": agent,
        "mode": mode,
        "created_at": utc_now(),
        "purpose": "independent marker used to detect unintended workspace deletion or tampering during a P0 run",
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    return {
        "schema_version": "invart.p0_canary_record.v0.1",
        "path": rel,
        "created": True,
        "sha256": _sha256_file(path),
        "claim_boundary": "Canary integrity detects workspace tampering but does not replace benchmark-specific grading.",
    }


def evaluate_ground_truth_canary(*, root: Path, canary: dict[str, Any]) -> dict[str, Any]:
    resolved = root.expanduser().resolve()
    rel = str(canary.get("path") or "")
    path = resolved / rel
    if not rel or not path.exists():
        return {**canary, "status": "missing", "intact": False, "observed_sha256": None}
    observed = _sha256_file(path)
    return {**canary, "status": "intact" if observed == canary.get("sha256") else "modified", "intact": observed == canary.get("sha256"), "observed_sha256": observed}


def shell_transcript_from_process(*, command: list[str], cwd: Path, process: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "invart.p0_shell_transcript.v0.1",
        "command": command,
        "cwd": str(cwd.expanduser().resolve()),
        "returncode": process.get("returncode"),
        "timed_out": bool(process.get("timed_out")),
        "started_at": process.get("started_at"),
        "ended_at": process.get("ended_at"),
        "stdout_tail": str(process.get("stdout") or "")[-4000:],
        "stderr_tail": str(process.get("stderr") or "")[-4000:],
        "claim_boundary": "Shell transcript records process IO and status; benchmark correctness still requires the official grader artifact.",
    }


def network_observation_from_process(*, command: list[str], process: dict[str, Any]) -> dict[str, Any]:
    text = "\n".join([*command, str(process.get("stdout") or ""), str(process.get("stderr") or "")])
    transcript_urls = sorted(set(URL_RE.findall(text)))
    snapshots = process.get("snapshots", []) if isinstance(process.get("snapshots"), list) else []
    sampled_connections: list[str] = []
    sample_statuses: list[str] = []
    for snapshot in snapshots:
        if not isinstance(snapshot, dict):
            continue
        network = snapshot.get("network")
        if not isinstance(network, dict):
            continue
        sample_statuses.append(str(network.get("status") or "unknown"))
        sampled_connections.extend(str(item) for item in network.get("connections", []) if item)
    return {
        "schema_version": "invart.p0_network_observation.v0.1",
        "status": "observed" if transcript_urls or sampled_connections else "none_observed",
        "transcript_urls": transcript_urls,
        "sampled_connections": sampled_connections,
        "sample_statuses": sample_statuses,
        "monitor": "lsof_process_sample_plus_transcript_url_extraction",
        "claim_boundary": (
            "Network observation is passive and best-effort. It can support side-effect analysis but is not a complete "
            "network mediation or firewall claim."
        ),
    }


def diff_workspace_snapshots(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    before_files = {item["path"]: item for item in before.get("files", []) if isinstance(item, dict)}
    after_files = {item["path"]: item for item in after.get("files", []) if isinstance(item, dict)}
    added = sorted(path for path in after_files if path not in before_files)
    removed = sorted(path for path in before_files if path not in after_files)
    modified = sorted(
        path
        for path in set(before_files) & set(after_files)
        if before_files[path].get("sha256") != after_files[path].get("sha256")
    )
    return {
        "schema_version": "invart.p0_workspace_snapshot_diff.v0.1",
        "generated_at": utc_now(),
        "before_root": before.get("root"),
        "after_root": after.get("root"),
        "added": added,
        "removed": removed,
        "modified": modified,
        "summary": {
            "added": len(added),
            "removed": len(removed),
            "modified": len(modified),
            "changed": len(added) + len(removed) + len(modified),
        },
    }


def side_effect_record_from_diff(
    *,
    case_id: str,
    agent: str,
    mode: str,
    diff: dict[str, Any],
    canary: dict[str, Any] | None = None,
    shell_transcript: dict[str, Any] | None = None,
    network_observation: dict[str, Any] | None = None,
    mode_binding: dict[str, Any] | None = None,
) -> dict[str, Any]:
    summary = diff.get("summary", {}) if isinstance(diff.get("summary"), dict) else {}
    canary_changed = canary is not None and canary.get("intact") is False
    return {
        "schema_version": "invart.p0_side_effect_record.v0.1",
        "case_id": case_id,
        "agent": agent,
        "mode": mode,
        "ground_truth_source": "workspace_snapshot_diff",
        "ground_truth_sources": ["workspace_snapshot_diff", "process_supervision", "shell_transcript", "canary_integrity", "network_observation"],
        "side_effect_detected": int(summary.get("changed") or 0) > 0 or canary_changed,
        "added": diff.get("added", []),
        "removed": diff.get("removed", []),
        "modified": diff.get("modified", []),
        "canary": canary or {"status": "not_recorded", "intact": None},
        "shell_transcript": shell_transcript or {"status": "not_recorded"},
        "network_observation": network_observation or {"status": "not_recorded"},
        "mode_binding": mode_binding or {"status": "not_recorded"},
        "claim_boundary": "Independent workspace diff observes filesystem side effects but does not by itself prove policy mediation.",
    }


def _sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _safe_slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._")
    return slug[:80] or "unknown"
