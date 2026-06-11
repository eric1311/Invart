from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from invart.assurance.evidence_bundle import export_evidence_bundle
from invart.control.daemon import RuntimeAuthority
from invart.control.mediation import mediate_event
from invart.assurance.postruntime import export_proof_report
from invart.core.artifacts import sha256_file, write_json_artifact
from invart.core.models import utc_now
from invart.core.env import child_env
from invart.surfaces.adapter_profiles import build_adapter_profile
from invart.surfaces.enforcement import run_file_write_intercepted


def run_claude_code_adapter(
    *,
    target: Path,
    command: list[str],
    hook_events: Path | None = None,
    out_dir: Path | None = None,
    session_id: str | None = None,
    create_preflight: bool = False,
    enforcement: str = "off",
    policy_mode: str = "advisory",
) -> dict[str, Any]:
    if not command:
        raise ValueError("claude-code adapter requires a child command")
    target = target.expanduser().resolve()
    resolved_out = out_dir.expanduser().resolve() if out_dir else target / ".invart" / "claude-code-adapter"
    ledger = resolved_out / "ledger.jsonl"
    authority = RuntimeAuthority.for_target(target)
    session = authority.create_session(
        target,
        agent="claude-code",
        goal="Claude Code adapter bridge",
        session_id=session_id,
        ledger_path=ledger,
        create_preflight=create_preflight,
        metadata={"adapter": "claude-code", "bridge": "wrapper+hook-jsonl", "policy_mode": policy_mode},
    )
    permission_inventory = _permission_inventory(target)
    authority.record_event(
        session.session_id,
        {
            "type": "adapter_inventory",
            "target": str(target),
            "metadata": {
                "adapter": "claude-code-inventory",
                "operation": "permission_config_inventory",
                "permission_inventory": permission_inventory,
                "coverage_layer": "agent_log",
            },
        },
        review_mode="off",
        policy_mode="advisory",
        reviewer="heuristic",
    )
    ingested = 0
    blocking_mediation: dict[str, Any] | None = None
    if hook_events and hook_events.exists():
        for payload in _load_hook_events(hook_events):
            payload = _normalize_claude_hook_event(payload)
            metadata = dict(payload.get("metadata") or {})
            metadata.setdefault("adapter", "claude-code-hook")
            metadata.setdefault("hook_source", str(hook_events))
            metadata.setdefault("coverage_layer", "native_hook")
            payload["metadata"] = metadata
            mediation = mediate_event(
                ledger,
                session_id=session.session_id,
                surface=_surface_for_event(payload),
                event=payload,
                mode=_mediation_mode(policy_mode),
            )
            ingested += 1
            if _should_stop_for_mediation(mediation, policy_mode=policy_mode):
                blocking_mediation = mediation
                break

    supervision = _portable_supervision_evidence()
    if blocking_mediation is not None:
        decision = blocking_mediation["decision"]
        outcome = blocking_mediation["outcome"]
        authority.outcome(
            session.session_id,
            "blocked" if decision.get("effect") == "deny" else "requires_approval",
            decision_id=outcome.get("decision_id"),
            invocation_id=outcome.get("invocation_id"),
            actor="claude-code-adapter",
            reason=str(decision.get("reason") or "hook mediation stopped execution"),
        )
        returncode = 126
        child_status = "blocked" if decision.get("effect") == "deny" else "requires_approval"
        process_mediation = None
    else:
        process_event = {
            "type": "shell",
            "command": " ".join(command),
            "target": str(target),
            "metadata": {
                "adapter": "claude-code-process",
                "operation": "child_command",
                "coverage_layer": "shell_wrapper",
                "process_supervision": supervision,
            },
        }
        process_mediation = mediate_event(
            ledger,
            session_id=session.session_id,
            surface="command",
            event=process_event,
            mode=_mediation_mode(policy_mode),
        )
        if _should_stop_for_mediation(process_mediation, policy_mode=policy_mode):
            decision = process_mediation["decision"]
            outcome = process_mediation["outcome"]
            authority.outcome(
                session.session_id,
                "blocked" if decision.get("effect") == "deny" else "requires_approval",
                decision_id=outcome.get("decision_id"),
                invocation_id=outcome.get("invocation_id"),
                actor="claude-code-adapter",
                reason=str(decision.get("reason") or "managed mediation stopped child execution"),
            )
            returncode = 126
            child_status = "blocked" if decision.get("effect") == "deny" else "requires_approval"
        elif enforcement == "file-write":
            enforced = run_file_write_intercepted(command, ledger_path=ledger, session_id=session.session_id, target=target)
            returncode = int(enforced.get("returncode") if enforced.get("returncode") is not None else 1)
            child_status = str(enforced.get("status"))
        else:
            env = child_env(os.environ, session_id=session.session_id, ledger=str(ledger), adapter="claude-code")
            completed = subprocess.run(command, cwd=str(target), env=env, check=False)
            returncode = completed.returncode
            child_status = "executed" if completed.returncode == 0 else "failed"
            outcome = process_mediation["outcome"]
            authority.outcome(
                session.session_id,
                "executed" if completed.returncode == 0 else "failed",
                decision_id=outcome.get("decision_id"),
                invocation_id=outcome.get("invocation_id"),
                actor="claude-code-adapter",
                reason=f"child exited with {completed.returncode}",
            )
    authority.transition_session(session.session_id, "stopped", reason="claude-code adapter completed")
    proof, adapter_package = _export_adapter_package(
        ledger=ledger,
        out_dir=resolved_out,
        policy_mode=policy_mode,
        permission_inventory=permission_inventory,
        supervision=supervision,
    )
    return {
        "schema_version": "invart.claude_adapter.v0.9.4",
        "session_id": session.session_id,
        "returncode": returncode,
        "hook_events_ingested": ingested,
        "ledger": str(ledger),
        "proof": str(proof),
        "status": "blocked" if child_status == "blocked" else "requires_approval" if child_status == "requires_approval" else "passed" if returncode == 0 else "failed",
        "enforcement": enforcement,
        "policy_mode": policy_mode,
        "permission_inventory": permission_inventory,
        "supervision": supervision,
        "mediation": {
            "blocking": blocking_mediation,
            "process": process_mediation,
        },
        "adapter_package": adapter_package,
    }


def _load_hook_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        payload = json.loads(line)
        if not isinstance(payload, dict):
            raise ValueError("hook event must be a JSON object")
        events.append(payload)
    return events


def _normalize_claude_hook_event(payload: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(payload)
    tool_name = normalized.get("tool_name") or normalized.get("tool")
    tool_input = normalized.get("tool_input") if isinstance(normalized.get("tool_input"), dict) else {}
    if tool_name == "Bash" and tool_input.get("command"):
        normalized["type"] = "shell"
        normalized["command"] = str(tool_input["command"])
        normalized["tool"] = "Bash"
        metadata = dict(normalized.get("metadata") or {})
        metadata.setdefault("operation", "pre_tool_use")
        metadata.setdefault("source", "claude_code_hook")
        normalized["metadata"] = metadata
    elif tool_name in {"Read", "Edit", "Write", "MultiEdit"} and (tool_input.get("file_path") or tool_input.get("path")):
        normalized["type"] = "file_read" if tool_name == "Read" else "file_write"
        normalized["path"] = str(tool_input.get("file_path") or tool_input.get("path"))
        normalized["tool"] = str(tool_name)
        metadata = dict(normalized.get("metadata") or {})
        metadata.setdefault("operation", "pre_tool_use")
        metadata.setdefault("source", "claude_code_hook")
        normalized["metadata"] = metadata
    return normalized


def _surface_for_event(payload: dict[str, Any]) -> str:
    event_type = str(payload.get("type") or "")
    if event_type in {"shell", "command"} or payload.get("command"):
        return "command"
    if event_type.startswith("file") or payload.get("path"):
        return "file"
    if payload.get("url"):
        return "network"
    if payload.get("tool"):
        return "tool"
    return "agent_hook"


def _mediation_mode(policy_mode: str) -> str:
    return "managed" if policy_mode in {"managed", "ci"} else "audit" if policy_mode == "audit" else "advisory"


def _should_stop_for_mediation(mediation: dict[str, Any], *, policy_mode: str) -> bool:
    if policy_mode not in {"managed", "ci"}:
        return False
    effect = str(mediation.get("decision", {}).get("effect", ""))
    status = str(mediation.get("outcome", {}).get("status", ""))
    return effect in {"deny", "require_approval"} or status in {"blocked", "paused"}


def _portable_supervision_evidence() -> dict[str, Any]:
    return {
        "mode": "subprocess",
        "started_at": utc_now(),
        "strong_consistency": False,
        "coverage_grade": "mediated_without_process_tree",
        "degraded_reason": "portable Python wrapper; native process-tree supervision not enabled",
    }


def _permission_inventory(target: Path) -> dict[str, Any]:
    candidates = [
        target / ".claude" / "settings.json",
        target / ".claude" / "settings.local.json",
        target / ".mcp.json",
        target / "mcp.json",
        target / "CLAUDE.md",
    ]
    files = []
    for path in candidates:
        item: dict[str, Any] = {"path": str(path), "exists": path.exists()}
        if path.exists() and path.is_file():
            item["sha256"] = sha256_file(path)
            item["bytes"] = path.stat().st_size
        files.append(item)
    return {
        "status": "recorded",
        "recorded_at": utc_now(),
        "permission_sources": files,
        "credential_boundary": {
            "env_keys_recorded": True,
            "env_values_recorded": False,
            "reason": "Claude adapter records permission/config files and env key inventory via child environment without storing secret values.",
        },
    }


def _export_adapter_package(
    *,
    ledger: Path,
    out_dir: Path,
    policy_mode: str,
    permission_inventory: dict[str, Any],
    supervision: dict[str, Any],
) -> tuple[Path, dict[str, Any]]:
    proof = ledger.with_name("proof.json")
    export_proof_report(ledger, proof)
    bundle = export_evidence_bundle(
        ledger,
        out_dir / "adapter-package",
        profile={
            "name": "claude-code-reference-adapter",
            "mode": policy_mode,
            "adapter": "claude-code",
            "permission_inventory_status": permission_inventory.get("status"),
            "supervision": {
                "mode": supervision.get("mode"),
                "strong_consistency": supervision.get("strong_consistency"),
                "coverage_grade": supervision.get("coverage_grade"),
            },
        },
    )
    package = {
        "schema_version": "invart.claude_adapter_package.v0.9.4",
        "status": bundle.get("status", "fail"),
        "manifest_path": bundle.get("manifest_path"),
        "artifacts": bundle.get("artifacts", {}),
        "summary": bundle.get("summary", {}),
        "coverage_truthfulness": {
            "hook_mediation": "mediated",
            "process_tree": "degraded",
            "enforcement": "enforced" if any("enforcement" in str(item).lower() for item in bundle.get("artifacts", {}).values()) else "mediated",
        },
    }
    write_json_artifact(out_dir / "adapter-package.json", package)
    return proof, package


def check_claude_code_environment(binary: str = "claude") -> dict[str, Any]:
    resolved = shutil.which(binary) or (binary if Path(binary).exists() else None)
    profile = build_adapter_profile("claude-code")
    result: dict[str, Any] = {
        "schema_version": "invart.claude_environment.v0.10",
        "requested_binary": binary,
        "binary": resolved or binary,
        "available": resolved is not None,
        "adapter_profile": profile,
        "conformance": {
            "status": "not_run",
            "reason": "binary unavailable" if resolved is None else "version probe not requested",
        },
    }
    if resolved is not None:
        try:
            completed = subprocess.run([resolved, "--version"], check=False, capture_output=True, text=True, timeout=10)
            result["conformance"] = {
                "status": "pass" if completed.returncode == 0 else "warn",
                "returncode": completed.returncode,
                "stdout": completed.stdout.strip()[:400],
                "stderr": completed.stderr.strip()[:400],
            }
        except Exception as exc:
            result["conformance"] = {"status": "warn", "reason": str(exc)}
    return result
