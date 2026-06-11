from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

from invart.assurance.evidence_workspace import inspect_evidence_workspace
from invart.assurance.layer_runtime import export_layer_runtime_workflow
from invart.core.artifacts import write_json_artifact
from invart.core.models import utc_now
from invart.surfaces.adapter import run_adapter_command
from invart.surfaces.adapter_profiles import get_adapter_profile
from invart.surfaces.native import inventory_native_integrations


def run_live_agent_adapter(
    *,
    agent: str,
    target: Path,
    out_dir: Path,
    command: list[str] | None = None,
    binary: str | None = None,
    require_live: bool = False,
    policy_mode: str = "advisory",
) -> dict[str, Any]:
    """Run a product CLI through Invart while preserving truthful live evidence labels."""

    target = target.expanduser().resolve()
    target.mkdir(parents=True, exist_ok=True)
    out_dir = out_dir.expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    profile = get_adapter_profile(agent)
    binary_status = resolve_agent_binary(profile, binary)
    live_evidence = _live_evidence(agent, binary_status, require_live=require_live)
    native_inventory = inventory_native_integrations(target)
    if require_live and binary_status["status"] != "found":
        report = {
            "schema_version": "invart.live_agent_adapter.v0.9.10",
            "status": "blocked_missing_binary",
            "returncode": 127,
            "agent": agent,
            "profile": profile,
            "live_evidence": live_evidence,
            "native_inventory": native_inventory,
            "artifacts": {"report_json": str(out_dir / "live-agent-adapter.json")},
            "claim_boundary": "Strict live mode requires an invokable product binary; missing binaries are blocked and not counted as live validation.",
        }
        write_json_artifact(out_dir / "live-agent-adapter.json", report)
        return report

    run_command = command or [str(binary_status["path"] or binary or agent), "--version"]
    result = run_adapter_command(
        target=target,
        command=run_command,
        agent=agent,
        goal=f"{agent} live adapter run",
        session_id=f"invart_live_{_safe_id(agent)}",
        out_dir=out_dir,
        capabilities="audit",
        gate_mode="audit",
        policy_mode=policy_mode,
        create_preflight=False,
    )
    workflow = export_layer_runtime_workflow(
        Path(result.ledger),
        out_dir / "layer-runtime",
        profile={"name": f"{agent}-live-adapter", "mode": policy_mode, "agent": agent, "live_evidence": live_evidence},
    )
    workspace = inspect_evidence_workspace(
        Path(workflow["artifacts"]["evidence_manifest"]),
        out_dir=out_dir / "evidence-workspace",
        require_questions=True,
        require_layer_workflow=True,
    )
    report = {
        "schema_version": "invart.live_agent_adapter.v0.9.10",
        "status": result.status,
        "returncode": result.returncode,
        "agent": agent,
        "profile": profile,
        "live_evidence": live_evidence,
        "native_inventory": native_inventory,
        "managed_run": result.to_dict(),
        "layer_runtime": {
            "status": workflow.get("status"),
            "artifacts": workflow.get("artifacts", {}),
            "runtime_effect_matrix": workflow.get("runtime_effect_matrix", []),
            "layer_timeline": workflow.get("layer_timeline", []),
        },
        "evidence_workspace": workspace,
        "artifacts": {
            "report_json": str(out_dir / "live-agent-adapter.json"),
            "ledger": result.ledger,
            "proof": result.proof,
            "adapter_package": result.package,
            "workflow_json": workflow["artifacts"]["workflow_json"],
            "workflow_html": workflow["artifacts"]["workflow_html"],
            "evidence_workspace": workspace.get("artifacts", {}).get("workspace_json"),
        },
        "claim_boundary": "Managed-wrapper evidence is Invart-mediated only for actions routed through the wrapper; native plugin/config inventory remains observed or vendor-owned unless bridged before side effects.",
    }
    write_json_artifact(out_dir / "live-agent-adapter.json", report)
    return report


def resolve_agent_binary(profile: dict[str, Any], override: str | None = None) -> dict[str, Any]:
    candidates = [override] if override else list(profile.get("binary_candidates", []))
    for candidate in candidates:
        if not candidate:
            continue
        resolved = shutil.which(str(candidate)) or _existing_path(str(candidate))
        if not resolved:
            continue
        probe = _probe_version(Path(resolved))
        return {
            "status": "found",
            "requested": candidate,
            "path": resolved,
            "version_probe": probe,
            "resolved_at": utc_now(),
        }
    return {"status": "missing", "requested": override or candidates, "path": None, "version_probe": {}, "resolved_at": utc_now()}


def _live_evidence(agent: str, binary_status: dict[str, Any], *, require_live: bool) -> dict[str, Any]:
    found = binary_status.get("status") == "found"
    return {
        "schema_version": "invart.live_agent_evidence.v0.9.10",
        "agent": agent,
        "strict_live_required": require_live,
        "binary": binary_status,
        "evidence_level": "binary_backed_live_or_fixture" if found else "missing_binary",
        "control_position": "managed_wrapper" if found else "unavailable",
        "side_effect_timing": "pre_side_effect_mediation",
        "coverage_grade": "managed_wrapper_adapter" if found else "blocked_missing_binary",
    }


def _probe_version(path: Path) -> dict[str, Any]:
    try:
        completed = subprocess.run([str(path), "--version"], check=False, capture_output=True, text=True, timeout=15)
        return {
            "status": "pass" if completed.returncode == 0 else "warn",
            "returncode": completed.returncode,
            "stdout": completed.stdout.strip()[:400],
            "stderr": completed.stderr.strip()[:400],
        }
    except Exception as exc:
        return {"status": "warn", "returncode": None, "stdout": "", "stderr": str(exc)[:400]}


def _existing_path(candidate: str) -> str | None:
    path = Path(candidate).expanduser()
    return str(path.resolve()) if path.exists() else None


def _safe_id(value: str) -> str:
    return "".join(char if char.isalnum() else "_" for char in value).strip("_") or "agent"


__all__ = ["resolve_agent_binary", "run_live_agent_adapter"]
