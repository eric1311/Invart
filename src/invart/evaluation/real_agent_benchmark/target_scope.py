from __future__ import annotations

from dataclasses import asdict
from typing import Any

from .case_manifest import P0_MODES, default_p0_cases


SCHEMA_VERSION = "invart.p0_target_scope.v0.1"


def build_p0_target_scope_report(*, manifest: dict[str, Any], run_rows: list[dict[str, Any]]) -> dict[str, Any]:
    agents = [str(item.get("agent")) for item in manifest.get("agents", []) if isinstance(item, dict) and item.get("agent")]
    modes = [str(item.get("mode")) for item in manifest.get("modes", []) if isinstance(item, dict) and item.get("mode")]
    if not modes:
        modes = list(P0_MODES)
    target_cases = [asdict(item) for item in default_p0_cases()]
    target_case_by_id = {str(item["case_id"]): item for item in target_cases}
    target_case_ids = {str(item["case_id"]) for item in target_cases}
    manifest_cases = [item for item in manifest.get("cases", []) if isinstance(item, dict)]
    manifest_case_ids = {str(item.get("case_id")) for item in manifest_cases if item.get("case_id")}
    covered_rows = {
        (str(row.get("case_id")), str(row.get("agent")), str(row.get("mode")))
        for row in run_rows
        if row.get("case_id") and row.get("agent") and row.get("mode") and row.get("run_status") in {"pass", "fail", "blocked", "timeout", "crashed"}
    }
    target_expected_rows = {
        (case_id, agent, mode)
        for case_id in target_case_ids
        for agent in agents
        for mode in modes
    }
    manifest_expected_rows = {
        (case_id, agent, mode)
        for case_id in manifest_case_ids
        for agent in agents
        for mode in modes
    }
    missing_target_case_ids = sorted(target_case_ids - manifest_case_ids)
    extra_manifest_case_ids = sorted(manifest_case_ids - target_case_ids)
    covered_target_rows = len(target_expected_rows & covered_rows)
    missing_target_rows = _missing_rows(
        expected_rows=target_expected_rows - covered_rows,
        target_case_by_id=target_case_by_id,
        manifest_case_ids=manifest_case_ids,
    )
    missing_manifest_rows = _missing_rows(
        expected_rows=manifest_expected_rows - covered_rows,
        target_case_by_id=target_case_by_id,
        manifest_case_ids=manifest_case_ids,
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "target_rule": "P0 target scope is the default 8-case representative matrix unless a paper explicitly narrows the claim.",
        "status": "complete" if not missing_target_case_ids and target_expected_rows <= covered_rows else "incomplete",
        "target_scope_complete": not missing_target_case_ids and target_expected_rows <= covered_rows,
        "manifest_scope_complete": manifest_expected_rows <= covered_rows if manifest_expected_rows else False,
        "agents": agents,
        "modes": modes,
        "target_cases": target_cases,
        "manifest_cases": manifest_cases,
        "missing_target_case_ids": missing_target_case_ids,
        "extra_manifest_case_ids": extra_manifest_case_ids,
        "missing_target_rows": missing_target_rows,
        "missing_manifest_rows": missing_manifest_rows,
        "continuation_plan": {
            "schema_version": "invart.p0_target_continuation.v0.1",
            "current_manifest_rows": [
                row for row in missing_target_rows if row.get("gap_type") == "missing_from_manifest_run_matrix"
            ],
            "target_expansion_rows": [
                row for row in missing_target_rows if row.get("gap_type") == "absent_from_manifest"
            ],
            "action_order": [
                "Run current-manifest runnable rows when provider credentials are available.",
                "Expand the package manifest to include missing target cases before claiming full P0 target coverage.",
                "For each newly added target case, run baseline_agent, invart_observe_only, and invart_mediated for Claude Code and Codex.",
                "Attach official/upstream grader artifacts and independent side-effect records before paper-facing claims.",
            ],
        },
        "summary": {
            "target_cases": len(target_cases),
            "manifest_cases": len(manifest_case_ids),
            "target_expected_rows": len(target_expected_rows),
            "manifest_expected_rows": len(manifest_expected_rows),
            "covered_target_rows": covered_target_rows,
            "covered_manifest_rows": len(manifest_expected_rows & covered_rows),
            "missing_target_rows": len(missing_target_rows),
            "missing_manifest_rows": len(missing_manifest_rows),
        },
        "claim_boundary": (
            "This report separates the original P0 target scope from the current artifact package manifest. "
            "A package may be useful representative evidence while still being target-scope incomplete."
        ),
    }


def render_p0_target_scope_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    lines = [
        "# P0 Target Scope",
        "",
        f"- Status: `{report.get('status', 'unknown')}`",
        f"- Target scope complete: `{str(report.get('target_scope_complete', False)).lower()}`",
        f"- Manifest scope complete: `{str(report.get('manifest_scope_complete', False)).lower()}`",
        f"- Target cases: `{summary.get('target_cases', 0)}`",
        f"- Manifest cases: `{summary.get('manifest_cases', 0)}`",
        f"- Covered target rows: `{summary.get('covered_target_rows', 0)} / {summary.get('target_expected_rows', 0)}`",
        f"- Covered manifest rows: `{summary.get('covered_manifest_rows', 0)} / {summary.get('manifest_expected_rows', 0)}`",
        "",
        "## Missing Target Cases",
        "",
    ]
    missing = report.get("missing_target_case_ids") if isinstance(report.get("missing_target_case_ids"), list) else []
    if missing:
        lines.extend(f"- `{item}`" for item in missing)
    else:
        lines.append("- none")
    continuation = report.get("continuation_plan") if isinstance(report.get("continuation_plan"), dict) else {}
    current_rows = continuation.get("current_manifest_rows") if isinstance(continuation.get("current_manifest_rows"), list) else []
    expansion_rows = continuation.get("target_expansion_rows") if isinstance(continuation.get("target_expansion_rows"), list) else []
    preview_rows = current_rows + expansion_rows
    lines.extend([
        "",
        "## Continuation Plan",
        "",
        f"- Current-manifest missing rows: `{len(current_rows)}`",
        f"- Target-expansion rows: `{len(expansion_rows)}`",
        "",
        "| Gap | Case | Agent | Mode | Action |",
        "|---|---|---|---|---|",
    ])
    for item in preview_rows[:24]:
        if isinstance(item, dict):
            lines.append(
                f"| {_md(item.get('gap_type'))} | {_md(item.get('case_id'))} | {_md(item.get('agent'))} | "
                f"{_md(item.get('mode'))} | {_md(item.get('required_action'))} |"
            )
    remaining = len(preview_rows) - min(24, len(preview_rows))
    if remaining > 0:
        lines.append(f"| more | `{remaining}` additional rows in JSON |  |  | see p0_target_scope.json |")
    lines.extend(["", "## Target Cases", "", "| Family | Case | Risk |", "|---|---|---|"])
    for item in report.get("target_cases", []):
        if isinstance(item, dict):
            lines.append(f"| {_md(item.get('family'))} | {_md(item.get('case_id'))} | {_md(item.get('expected_risk'))} |")
    lines.extend(["", "## Boundary", "", str(report.get("claim_boundary") or "")])
    return "\n".join(lines).rstrip() + "\n"


def _md(value: Any) -> str:
    return str(value or "").replace("|", "\\|").replace("\n", " ")


def _missing_rows(
    *,
    expected_rows: set[tuple[str, str, str]],
    target_case_by_id: dict[str, dict[str, Any]],
    manifest_case_ids: set[str],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for case_id, agent, mode in sorted(expected_rows):
        case = target_case_by_id.get(case_id, {})
        absent = case_id not in manifest_case_ids
        rows.append({
            "row_id": f"{case_id}_{agent}_{mode}",
            "case_id": case_id,
            "family": case.get("family"),
            "benchmark_case_ref": case.get("benchmark_case_ref"),
            "expected_risk": case.get("expected_risk"),
            "agent": agent,
            "mode": mode,
            "gap_type": "absent_from_manifest" if absent else "missing_from_manifest_run_matrix",
            "required_action": "expand_manifest_then_run_official_row" if absent else "run_or_attach_current_manifest_row",
            "claim_boundary": (
                "This row is part of the original P0 target scope. It cannot support target-scope completion until "
                "a real run row, independent side-effect record, and appropriate grader artifact are attached."
            ),
        })
    return rows
