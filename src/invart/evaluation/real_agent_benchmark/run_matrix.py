from __future__ import annotations

from pathlib import Path
from typing import Any

from .supervisor import supervise_p0_command


def execute_p0_command_row(
    *,
    row: dict[str, Any],
    command: list[str],
    cwd: Path,
    timeout: float = 120.0,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not command:
        raise ValueError("P0 command row execution requires a command")
    case_id = str(row.get("case_id") or "unknown_case")
    agent = str(row.get("agent") or "unknown_agent")
    mode = str(row.get("mode") or "unknown_mode")
    supervision = supervise_p0_command(
        command=command,
        cwd=cwd,
        timeout=timeout,
        case_id=case_id,
        agent=agent,
        mode=mode,
    )
    process = supervision["process"]
    stability = supervision["stability"]
    run_status = _run_status(stability)
    executed = {
        **row,
        "run_status": run_status,
        "runner_kind": row.get("runner_kind") or "official_benchmark_runner",
        "execution_binding": row.get("execution_binding") or "explicit_command",
        "executed_command": command,
        "cwd": str(cwd.expanduser().resolve()),
        "returncode": stability.get("returncode"),
        "timed_out": stability.get("timed_out"),
        "crashed": stability.get("crashed"),
        "blocked": stability.get("blocked"),
        "mode_binding": supervision.get("mode_binding"),
        "stdout_tail": process.get("stdout", ""),
        "stderr_tail": process.get("stderr", ""),
        "side_effect_result": "changed" if supervision["side_effect"].get("side_effect_detected") else "unchanged",
        "claim_boundary": (
            str(row.get("claim_boundary") or "")
            + " This row records an explicit command execution under P0 supervision; official benchmark claims still require official grader artifacts."
        ).strip(),
    }
    return executed, supervision["side_effect"]


def stability_summary_from_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    crashes = sum(1 for row in rows if row.get("crashed") is True)
    timeouts = sum(1 for row in rows if row.get("timed_out") is True)
    fatal = any(row.get("fatal_workspace_corruption") is True for row in rows)
    return {
        "schema_version": "invart.p0_stability_summary.v0.1",
        "status": "attached" if rows else "pending",
        "rows": len(rows),
        "crashes": crashes,
        "timeouts": timeouts,
        "fatal_workspace_corruption": fatal,
    }


def cost_summary_from_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    total = 0.0
    cost_rows: list[dict[str, Any]] = []
    for row in rows:
        value = row.get("cost_usd")
        if isinstance(value, (int, float)):
            total += float(value)
        cost_rows.append({
            "case_id": row.get("case_id"),
            "agent": row.get("agent"),
            "mode": row.get("mode"),
            "cost_usd": value,
            "source": row.get("cost_source") or "not_reported",
        })
    return {
        "schema_version": "invart.p0_cost_summary.v0.1",
        "status": "attached" if rows else "pending",
        "total_usd": total,
        "rows": cost_rows,
        "claim_boundary": "Costs are included only when reported by the provider CLI or explicit runner metadata.",
    }


def _run_status(stability: dict[str, Any]) -> str:
    if stability.get("blocked"):
        return "blocked"
    if stability.get("timed_out"):
        return "timeout"
    if stability.get("crashed"):
        return "crashed"
    return "pass" if stability.get("returncode") == 0 else "fail"
