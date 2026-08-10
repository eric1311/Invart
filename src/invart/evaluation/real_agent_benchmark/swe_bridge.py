from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from invart.core.artifacts import sha256_file, write_json_artifact
from invart.core.models import utc_now

from .supervisor import supervise_p0_command


def write_swe_prediction_jsonl(
    *,
    instance_id: str,
    patch_path: Path,
    predictions_path: Path,
    model_name_or_path: str,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    patch = patch_path.expanduser().resolve()
    predictions = predictions_path.expanduser().resolve()
    predictions.parent.mkdir(parents=True, exist_ok=True)
    raw_patch = patch.read_text(encoding="utf-8") if patch.exists() else ""
    model_patch, excluded_paths = _filter_swe_model_patch(raw_patch)
    row = {
        "instance_id": instance_id,
        "model_name_or_path": model_name_or_path,
        "model_patch": model_patch,
    }
    predictions.write_text(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    bridge_status = "pass" if model_patch else "empty_patch"
    report = {
        "schema_version": "invart.p0_swe_prediction_bridge.v0.1",
        "status": bridge_status,
        "generated_at": utc_now(),
        "instance_id": instance_id,
        "model_name_or_path": model_name_or_path,
        "patch_path": str(patch),
        "predictions_path": str(predictions),
        "patch_sha256": sha256_file(patch, prefixed=True) if patch.exists() else None,
        "predictions_sha256": sha256_file(predictions, prefixed=True),
        "raw_patch_bytes": len(raw_patch.encode("utf-8")),
        "model_patch_bytes": len(model_patch.encode("utf-8")),
        "excluded_internal_paths": excluded_paths,
        "metadata": metadata or {},
        "claim_boundary": (
            "This bridge only converts an agent-produced patch into SWE-Bench predictions JSONL. "
            "Utility claims require the official SWE-Bench harness result attached later. "
            "Invart supervision artifacts are excluded from the submitted model_patch. "
            "An empty model_patch is still forwarded to the official harness as an empty submission."
        ),
    }
    return report


def _filter_swe_model_patch(patch_text: str) -> tuple[str, list[str]]:
    """Remove Invart supervision artifacts from a patch submitted to SWE-Bench."""
    if not patch_text:
        return "", []
    blocks: list[list[str]] = []
    current: list[str] = []
    for line in patch_text.splitlines(keepends=True):
        if line.startswith("diff --git "):
            if current:
                blocks.append(current)
            current = [line]
        else:
            current.append(line)
    if current:
        blocks.append(current)

    kept: list[str] = []
    excluded: list[str] = []
    for block in blocks:
        paths = _diff_block_paths(block[0] if block else "")
        if any(_is_internal_swe_bridge_path(path) for path in paths):
            excluded.extend(path for path in paths if _is_internal_swe_bridge_path(path))
            continue
        kept.extend(block)
    return "".join(kept), sorted(set(excluded))


def _diff_block_paths(header: str) -> list[str]:
    parts = header.strip().split()
    paths: list[str] = []
    if len(parts) >= 4 and parts[0:2] == ["diff", "--git"]:
        for value in parts[2:4]:
            if value.startswith("a/") or value.startswith("b/"):
                paths.append(value[2:])
            else:
                paths.append(value)
    return paths


def _is_internal_swe_bridge_path(path: str) -> bool:
    name = path.strip()
    return (
        name.startswith(".invart")
        or name.startswith(".kappaski")
        or name in {"agent.patch", "codex-last-message.txt", "swe-prediction-bridge.json"}
        or name.startswith("logs/run_evaluation/")
    )


def execute_swe_prediction_command(
    *,
    command: list[str],
    cwd: Path,
    instance_id: str,
    patch_path: Path,
    predictions_path: Path,
    agent: str,
    mode: str,
    timeout: float = 300.0,
    model_name_or_path: str | None = None,
    out_dir: Path | None = None,
) -> dict[str, Any]:
    if not command:
        raise ValueError("SWE prediction bridge requires an agent command")
    resolved_cwd = cwd.expanduser().resolve()
    resolved_cwd.mkdir(parents=True, exist_ok=True)
    supervision = supervise_p0_command(
        command=command,
        cwd=resolved_cwd,
        timeout=timeout,
        case_id=instance_id,
        agent=agent,
        mode=mode,
    )
    resolved_patch = patch_path if patch_path.is_absolute() else resolved_cwd / patch_path
    fallback_patch = _write_git_diff_patch_if_needed(patch_path=resolved_patch, cwd=resolved_cwd)
    prediction = write_swe_prediction_jsonl(
        instance_id=instance_id,
        patch_path=resolved_patch,
        predictions_path=predictions_path,
        model_name_or_path=model_name_or_path or agent,
        metadata={
            "agent": agent,
            "mode": mode,
            "command": command,
            "returncode": supervision["stability"].get("returncode"),
            "timed_out": supervision["stability"].get("timed_out"),
            "crashed": supervision["stability"].get("crashed"),
            "blocked": supervision["stability"].get("blocked"),
            "fallback_patch": fallback_patch,
            "mode_binding": supervision.get("mode_binding"),
        },
    )
    prediction_status = prediction["status"]
    bridge_completed = prediction_status in {"pass", "empty_patch"}
    agent_run_status = _agent_run_status(supervision["stability"])
    report = {
        "schema_version": "invart.p0_swe_prediction_command.v0.1",
        "status": "pass" if bridge_completed else "fail",
        "prediction_status": prediction_status,
        "agent_run_status": agent_run_status,
        "agent": agent,
        "mode": mode,
        "instance_id": instance_id,
        "supervision": supervision,
        "mode_binding": supervision.get("mode_binding"),
        "prediction": prediction,
        "claim_boundary": (
            "A successful prediction bridge row means Invart produced SWE-Bench predictions JSONL from the supervised provider path. "
            "The agent may still have timed out, crashed, or produced an empty patch; utility claims require the official harness result."
        ),
    }
    if out_dir is not None:
        root = out_dir.expanduser().resolve()
        root.mkdir(parents=True, exist_ok=True)
        write_json_artifact(root / "swe-prediction-bridge.json", report)
    return report


def _write_git_diff_patch_if_needed(*, patch_path: Path, cwd: Path) -> dict[str, Any]:
    patch_path.parent.mkdir(parents=True, exist_ok=True)
    existing = patch_path.read_text(encoding="utf-8") if patch_path.exists() else ""
    if existing.strip():
        return {
            "status": "not_needed",
            "reason": "patch file already contained content",
            "patch_path": str(patch_path),
        }
    git_dir = cwd / ".git"
    if not git_dir.exists():
        return {
            "status": "not_available",
            "reason": "cwd is not a git checkout",
            "patch_path": str(patch_path),
        }
    add_intent = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard"],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if add_intent.returncode == 0:
        for relpath in add_intent.stdout.splitlines():
            if _is_internal_swe_bridge_path(relpath) or relpath in {"SWE_BENCH_TASK.md", "swe_instance_workspace.json"}:
                continue
            subprocess.run(["git", "add", "-N", "--", relpath], cwd=cwd, capture_output=True, text=True, timeout=30)
    diff = subprocess.run(["git", "diff", "--binary"], cwd=cwd, capture_output=True, text=True, timeout=60)
    if diff.returncode != 0:
        return {
            "status": "fail",
            "reason": "git diff failed",
            "returncode": diff.returncode,
            "stderr_tail": diff.stderr[-1000:],
            "patch_path": str(patch_path),
        }
    patch_path.write_text(diff.stdout, encoding="utf-8")
    return {
        "status": "captured" if diff.stdout else "empty",
        "reason": "captured post-run git diff after provider command",
        "patch_path": str(patch_path),
        "bytes": len(diff.stdout.encode("utf-8")),
    }


def _agent_run_status(stability: dict[str, Any]) -> str:
    if stability.get("timed_out"):
        return "timeout"
    if stability.get("crashed"):
        return "crashed"
    if stability.get("returncode") == 0:
        return "pass"
    return "fail"
