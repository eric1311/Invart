from __future__ import annotations

import html
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from invart.core.artifacts import stable_json_hash, write_html_artifact, write_json_artifact
from invart.core.models import utc_now
from invart.surfaces.adapter import run_adapter_command
from invart.surfaces.adapter_profiles import get_adapter_profile, list_adapter_profiles, validate_adapter_profile_truthfulness


SCHEMA_VERSION = "invart.real_agent_conformance.v0.9.3"
DEFAULT_REQUIRED_AGENTS = ("claude-code", "codex", "hermes", "openclaw")


def run_real_agent_conformance(
    *,
    out_dir: Path,
    agents: list[str] | None = None,
    binary_overrides: dict[str, str] | None = None,
    require_live: bool = False,
    target: Path | None = None,
) -> dict[str, Any]:
    root = out_dir.expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    target_root = (target or root / "workspace").expanduser().resolve()
    target_root.mkdir(parents=True, exist_ok=True)
    selected_agents = list(agents or DEFAULT_REQUIRED_AGENTS)
    overrides = dict(binary_overrides or {})
    profile_validation = validate_adapter_profile_truthfulness(list_adapter_profiles())
    rows = [
        _run_agent_check(
            agent=agent,
            out_dir=root / _safe_id(agent),
            target=target_root,
            binary_override=overrides.get(agent),
        )
        for agent in selected_agents
    ]
    failed_rows = [
        row
        for row in rows
        if row["status"] == "failed_run" or (require_live and row["status"] == "blocked_missing_binary")
    ]
    status = "fail" if failed_rows or profile_validation["status"] != "pass" else "pass"
    report_json = root / "real-agent-conformance.json"
    report_html = root / "real-agent-conformance.html"
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "generated_at": utc_now(),
        "required_live": require_live,
        "required_agents": selected_agents,
        "profile_validation": profile_validation,
        "summary": {
            "agents": len(rows),
            "passed_agents": sum(1 for row in rows if row["status"] == "pass"),
            "blocked_missing_binary": sum(1 for row in rows if row["status"] == "blocked_missing_binary"),
            "failed_agents": len(failed_rows),
            "claim_boundary": "Fixture-backed checks validate Invart's conformance harness. Strict live mode fails when requested real binaries are unavailable or do not produce managed-run evidence.",
        },
        "agents": rows,
        "artifacts": {"report_json": str(report_json), "report_html": str(report_html)},
        "evidence_hash": stable_json_hash({"agents": rows, "required_live": require_live}),
    }
    write_json_artifact(report_json, report)
    write_html_artifact(report_html, render_real_agent_conformance_html(report))
    return report


def export_real_agent_report_html(run_dir: Path, out: Path) -> dict[str, Any]:
    report_path = run_dir.expanduser().resolve() / "real-agent-conformance.json"
    report = _load_json(report_path)
    write_html_artifact(out.expanduser().resolve(), render_real_agent_conformance_html(report))
    return {
        "schema_version": "invart.real_agent_conformance_report.v0.9.3",
        "status": "pass",
        "source": str(report_path),
        "out": str(out.expanduser().resolve()),
    }


def render_real_agent_conformance_html(report: dict[str, Any]) -> str:
    rows = []
    for agent in report.get("agents", []):
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(agent.get('agent')))}</td>"
            f"<td>{html.escape(str(agent.get('status')))}</td>"
            f"<td>{html.escape(str(agent.get('coverage', {}).get('coverage_grade')))}</td>"
            f"<td>{html.escape(str(agent.get('binary', {}).get('status')))}</td>"
            f"<td>{html.escape(str(agent.get('managed_run', {}).get('status')))}</td>"
            f"<td>{html.escape(str(agent.get('claim_boundary')))}</td>"
            "</tr>"
        )
    return (
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Real Agent Conformance</title>"
        "<style>body{font-family:Inter,Arial,sans-serif;margin:0;background:#f8fafc;color:#172033}"
        "main{max-width:1120px;margin:0 auto;padding:32px 24px}table{width:100%;border-collapse:collapse;background:white;border:1px solid #dfe5ef}"
        "td,th{border-bottom:1px solid #e5e7eb;padding:8px;text-align:left;vertical-align:top}</style></head><body><main>"
        f"<h1>Real Agent Conformance</h1><p>Status: <strong>{html.escape(str(report.get('status')))}</strong></p>"
        f"<p>{html.escape(str(report.get('summary', {}).get('claim_boundary', '')))}</p>"
        "<table><tr><th>Agent</th><th>Status</th><th>Coverage Grade</th><th>Binary</th><th>Managed Run</th><th>Claim Boundary</th></tr>"
        f"{''.join(rows)}</table></main></body></html>"
    )


def _run_agent_check(*, agent: str, out_dir: Path, target: Path, binary_override: str | None) -> dict[str, Any]:
    profile = get_adapter_profile(agent)
    out_dir.mkdir(parents=True, exist_ok=True)
    binary = _resolve_binary(profile, binary_override)
    row: dict[str, Any] = {
        "agent": agent,
        "display_name": profile["display_name"],
        "status": "blocked_missing_binary",
        "binary": binary,
        "native_inventory": {"status": "not_run", "reason": "v0.9.3 conformance focuses on binary/profile/managed-run contract"},
        "managed_run": {"status": "not_run", "reason": "binary unavailable"},
        "risk_run": {"status": "not_run", "reason": "risk workflow belongs to later adapter hardening"},
        "coverage": {
            "coverage_grade": profile["coverage_grade"],
            "supports_mediation": profile["supports_mediation"],
            "can_block": profile["can_block"],
            "can_pause_resume": profile["can_pause_resume"],
        },
        "evidence": {},
        "claim_boundary": profile["claim_boundary"],
        "source_urls": profile["source_urls"],
    }
    if binary["status"] != "found":
        return row

    run = run_adapter_command(
        target=target,
        command=[str(binary["path"]), "--version"],
        agent=agent,
        goal=f"{agent} conformance version probe",
        session_id=f"invart_conformance_{_safe_id(agent)}",
        out_dir=out_dir,
        capabilities="off",
        gate_mode="off",
        create_preflight=False,
    )
    row["managed_run"] = {
        "status": "pass" if run.status == "passed" else "fail",
        "returncode": run.returncode,
        "ledger": run.ledger,
        "proof": run.proof,
    }
    row["evidence"] = {"ledger": run.ledger, "proof": run.proof}
    row["status"] = "pass" if run.status == "passed" else "failed_run"
    return row


def _resolve_binary(profile: dict[str, Any], override: str | None) -> dict[str, Any]:
    candidates = [override] if override else list(profile.get("binary_candidates", []))
    for candidate in candidates:
        if not candidate:
            continue
        resolved = shutil.which(str(candidate)) or _existing_path(candidate)
        if not resolved:
            continue
        version = _probe_version(Path(resolved))
        return {
            "status": "found",
            "path": resolved,
            "version": version.get("stdout") or version.get("stderr") or "",
            "returncode": version.get("returncode"),
        }
    return {"status": "missing", "path": None, "version": "", "returncode": None}


def _probe_version(path: Path) -> dict[str, Any]:
    try:
        completed = subprocess.run([str(path), "--version"], check=False, capture_output=True, text=True, timeout=15)
        return {
            "returncode": completed.returncode,
            "stdout": completed.stdout.strip()[:400],
            "stderr": completed.stderr.strip()[:400],
        }
    except Exception as exc:
        return {"returncode": None, "stdout": "", "stderr": str(exc)[:400]}


def _existing_path(candidate: str) -> str | None:
    path = Path(candidate).expanduser()
    return str(path.resolve()) if path.exists() else None


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _safe_id(value: str) -> str:
    return "".join(char if char.isalnum() else "_" for char in value).strip("_") or "agent"


__all__ = [
    "DEFAULT_REQUIRED_AGENTS",
    "SCHEMA_VERSION",
    "export_real_agent_report_html",
    "render_real_agent_conformance_html",
    "run_real_agent_conformance",
]
