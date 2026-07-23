from __future__ import annotations

from typing import Any


def render_claim_matrix(
    manifest: dict[str, Any],
    run_rows: list[dict[str, Any]],
    *,
    side_effects_complete: bool = False,
    grader_attached: bool = False,
    cost_summary: dict[str, Any] | None = None,
) -> str:
    official_result_rows = _claimable_official_result_rows(run_rows)
    override_result_rows = _override_official_result_rows(run_rows)
    dry_run_rows = _dry_run_readiness_rows(run_rows)
    utility_status = _row_status(len(official_result_rows))
    if not official_result_rows and override_result_rows:
        utility_status = f"fixture_or_override_only ({len(override_result_rows)} row{'s' if len(override_result_rows) != 1 else ''})"
    elif not official_result_rows and grader_attached:
        utility_status = "grader_attached_no_row_binding"
    assurance_status = "attached" if run_rows and side_effects_complete else "pending"
    provider_bridge_rows = [row for row in run_rows if isinstance(row.get("provider_bridge"), dict)]
    bridge_status = _row_status(len(provider_bridge_rows))
    mediation_status = _mediation_status(run_rows)
    cost_status = _cost_status(cost_summary)
    lines = [
        "# P0 Claim Matrix",
        "",
        "| Claim | Required evidence | Current status | Boundary |",
        "|---|---|---|---|",
        f"| Agent bridge outcome | provider CLI bridge report linked to run row | {bridge_status} | bridge success is not an official benchmark score |",
        f"| Utility preservation | row-level official_result derived from validated upstream grader output | {utility_status} | official runner command required; command_override fixtures are not paper score evidence |",
        f"| Runtime assurance | ledger/proof plus independent side-effect records | {assurance_status} | observe-only is not enforcement |",
        f"| Safety mediation | mediated rows with pre-side-effect block/pause/enforce | {mediation_status} | managed surfaces only |",
        f"| Cost accounting | per-agent token/time/cost rows | {cost_status} | provider-reported or CLI-measured only |",
        f"| Benchmark readiness gaps | official dry-run or preflight artifact for externally blocked runners | {_row_status(len(dry_run_rows))} | readiness rows are not utility, safety, or provider-execution evidence |",
        "",
        "## Non-Claims",
    ]
    for item in manifest.get("non_claims", []):
        lines.append(f"- {item}")
    return "\n".join(lines) + "\n"


def render_results_table(run_rows: list[dict[str, Any]]) -> str:
    if not run_rows:
        return (
            "% P0 table intentionally empty until official benchmark rows are attached.\n"
            "\\begin{tabular}{llllllll}\\toprule\n"
            "Family & Case & Agent & Mode & Run & Bridge & Utility & Safety \\\\\n"
            "\\midrule\n"
            "\\multicolumn{8}{l}{P0 official benchmark runs pending.} \\\\\n"
            "\\bottomrule\n"
            "\\end{tabular}\n"
        )
    body = []
    for row in run_rows:
        body.append(
            f"{_tex(row.get('family'))} & {_tex(row.get('case_id'))} & {_tex(row.get('agent'))} & "
            f"{_tex(row.get('mode'))} & {_tex(row.get('run_status'))} & {_tex(_bridge_cell(row))} & "
            f"{_tex(_utility_cell(row))} & {_tex(row.get('safety_result'))} \\\\"
        )
    return (
        "\\begin{tabular}{llllllll}\\toprule\n"
        "Family & Case & Agent & Mode & Run & Bridge & Utility & Safety \\\\\n"
        "\\midrule\n"
        + "\n".join(body)
        + "\n\\bottomrule\n\\end{tabular}\n"
    )


def render_completion_audit_markdown(audit: dict[str, Any]) -> str:
    summary = audit.get("summary") if isinstance(audit.get("summary"), dict) else {}
    remaining = audit.get("remaining") if isinstance(audit.get("remaining"), dict) else {}
    target_continuation = audit.get("target_continuation") if isinstance(audit.get("target_continuation"), dict) else {}
    lines = [
        "# P0 Completion Audit",
        "",
        f"- Status: `{audit.get('status', 'unknown')}`",
        f"- P0 scope complete: `{str(audit.get('p0_scope_complete', False)).lower()}`",
        f"- Coverage: `{summary.get('covered_expected_rows', 0)} / {summary.get('expected_rows', 0)}` expected rows",
        f"- Target coverage: `{summary.get('covered_target_rows', 0)} / {summary.get('target_expected_rows', 0)}` target rows",
        f"- Target continuation rows: `{target_continuation.get('row_actions', 0)}`",
        f"- Target official command specs: `{target_continuation.get('official_command_spec_rows', 0)}`",
        f"- Target readiness: `{_summary_counts(target_continuation.get('readiness_by_status'))}`",
        f"- Target external inputs: `{len(target_continuation.get('external_inputs', []) or [])}`",
        f"- Remaining required keys: `{', '.join(remaining.get('required_api_keys', []) or []) or 'none'}`",
        "",
        "| Requirement | Status | Evidence |",
        "|---|---|---|",
    ]
    for item in audit.get("requirements", []):
        if not isinstance(item, dict):
            continue
        lines.append(
            f"| {_md(item.get('requirement'))} | `{_md(item.get('status'))}` | {_md(_evidence_cell(item.get('evidence')))} |"
        )
    lines.extend([
        "",
        "## Boundary",
        "",
        str(audit.get("claim_boundary") or ""),
    ])
    return "\n".join(lines).rstrip() + "\n"


def render_completion_audit_table(audit: dict[str, Any]) -> str:
    rows = []
    for item in audit.get("requirements", []):
        if not isinstance(item, dict):
            continue
        rows.append(
            f"{_tex(item.get('requirement'))} & {_tex(item.get('status'))} & {_tex(_evidence_cell(item.get('evidence')))} \\\\"
        )
    if not rows:
        rows.append("\\multicolumn{3}{l}{No completion-audit requirements attached.} \\\\")
    return (
        "\\begin{tabular}{lll}\\toprule\n"
        "Requirement & Status & Evidence \\\\\n"
        "\\midrule\n"
        + "\n".join(rows)
        + "\n\\bottomrule\n\\end{tabular}\n"
    )


def _bridge_cell(row: dict[str, Any]) -> str:
    bridge = row.get("provider_bridge")
    if not isinstance(bridge, dict):
        return "not_attached"
    status = str(bridge.get("status") or "unknown")
    prediction = bridge.get("prediction_status")
    agent_run = bridge.get("agent_run_status")
    parts = [status]
    if prediction:
        parts.append(str(prediction))
    if agent_run:
        parts.append(str(agent_run))
    return "/".join(parts)


def _utility_cell(row: dict[str, Any]) -> str:
    utility = str(row.get("utility_result") or "pending")
    if row.get("execution_binding") == "official_runner_dry_run" or utility == "dry_run_readiness":
        return "dry_run_readiness (readiness only)"
    official = row.get("official_result")
    if not isinstance(official, dict):
        return utility
    metrics = official.get("metrics")
    if not isinstance(metrics, dict):
        return utility
    submitted = metrics.get("submitted_instances")
    resolved = metrics.get("resolved_instances")
    empty_patch = metrics.get("empty_patch_instances")
    if submitted is None and resolved is None and empty_patch is None:
        leaderboard_rows = metrics.get("leaderboard_rows")
        top_score = metrics.get("top_score")
        top_tool = metrics.get("top_tool")
        if leaderboard_rows is not None or top_score is not None:
            parts = [f"score={top_score}"]
            if top_tool:
                parts.append(f"tool={top_tool}")
            if leaderboard_rows is not None:
                parts.append(f"rows={leaderboard_rows}")
            return f"{utility} ({', '.join(parts)})"
        task_results = metrics.get("task_results")
        utility_passed = metrics.get("utility_passed")
        errors = metrics.get("errors")
        if task_results is None and utility_passed is None and errors is None:
            return utility
        return f"{utility} (tasks={task_results}, pass={utility_passed}, errors={errors})"
    return f"{utility} (submitted={submitted}, resolved={resolved}, empty={empty_patch})"


def _mediation_status(run_rows: list[dict[str, Any]]) -> str:
    active = 0
    enforced = 0
    for row in run_rows:
        binding = _row_mode_binding(row)
        if not isinstance(binding, dict):
            continue
        is_mediated = binding.get("mode") == "invart_mediated" or binding.get("control_mode") == "mediated_pre_side_effect"
        if not is_mediated:
            continue
        active += 1
        decision = binding.get("decision") if isinstance(binding.get("decision"), dict) else {}
        enforcement_status = binding.get("enforcement_status")
        decision_effect = decision.get("effect") or binding.get("decision_effect")
        if enforcement_status in {"blocked", "enforced", "paused"} or decision_effect in {"deny", "block"}:
            enforced += 1
    if enforced:
        return f"attached ({enforced} enforced row{'s' if enforced != 1 else ''})"
    if active:
        return f"mediated_allow_only ({active} row{'s' if active != 1 else ''})"
    return "pending"


def _row_mode_binding(row: dict[str, Any]) -> dict[str, Any] | None:
    binding = row.get("mode_binding")
    if not isinstance(binding, dict) and isinstance(row.get("provider_bridge"), dict):
        binding = row["provider_bridge"].get("mode_binding")
    return binding if isinstance(binding, dict) else None


def _claimable_official_result_rows(run_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in run_rows:
        official = row.get("official_result")
        if not isinstance(official, dict):
            continue
        if row.get("execution_binding") == "official_runner_dry_run":
            continue
        if row.get("command_override_used") is True:
            continue
        if row.get("official_grader_status") not in {"attached", "pass"}:
            continue
        if official.get("status") in {None, "missing_or_invalid"}:
            continue
        rows.append(row)
    return rows


def _dry_run_readiness_rows(run_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        row
        for row in run_rows
        if row.get("execution_binding") == "official_runner_dry_run"
        or row.get("official_runner_dry_run") is True
        or row.get("utility_result") == "dry_run_readiness"
    ]


def _override_official_result_rows(run_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in run_rows:
        if row.get("command_override_used") is not True:
            continue
        official = row.get("official_result")
        if not isinstance(official, dict):
            continue
        if row.get("official_grader_status") not in {"attached", "pass"}:
            continue
        if official.get("status") in {None, "missing_or_invalid"}:
            continue
        rows.append(row)
    return rows


def _row_status(count: int) -> str:
    return f"attached ({count} row{'s' if count != 1 else ''})" if count else "pending"


def _cost_status(cost_summary: dict[str, Any] | None) -> str:
    if not isinstance(cost_summary, dict) or cost_summary.get("status") not in {"attached", "pass"}:
        return "pending"
    rows = cost_summary.get("rows")
    if not isinstance(rows, list) or not rows:
        return "attached_no_rows"
    reported = [row for row in rows if isinstance(row, dict) and isinstance(row.get("cost_usd"), (int, float))]
    if reported:
        return f"attached ({len(reported)} reported row{'s' if len(reported) != 1 else ''})"
    return f"attached_not_reported ({len(rows)} row{'s' if len(rows) != 1 else ''})"


def _tex(value: Any) -> str:
    text = str(value if value is not None else "pending")
    return text.replace("\\", "\\textbackslash{}").replace("&", "\\&").replace("_", "\\_")


def _md(value: Any) -> str:
    text = str(value if value is not None else "pending")
    return text.replace("|", "\\|").replace("\n", " ")


def _summary_counts(value: Any) -> str:
    if not isinstance(value, dict) or not value:
        return "none"
    return ", ".join(f"{key}={value[key]}" for key in sorted(value))


def _evidence_cell(value: Any) -> str:
    if not isinstance(value, dict):
        return str(value if value is not None else "pending")
    preferred = [
        "covered_expected_rows",
        "expected_rows",
        "missing_rows",
        "official_runner_command_rows",
        "provider_bridge_rows",
        "side_effect_rows",
        "run_rows",
        "cost_status",
        "stability_status",
    ]
    parts = [f"{key}={value[key]}" for key in preferred if key in value]
    if not parts:
        parts = [f"{key}={value[key]}" for key in sorted(value)[:3]]
    return ", ".join(parts) if parts else "attached"
