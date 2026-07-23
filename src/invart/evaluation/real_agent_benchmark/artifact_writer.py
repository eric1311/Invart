from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from invart.core.artifacts import sha256_file, stable_json_hash, write_json_artifact
from invart.core.models import utc_now

from .case_manifest import default_p0_case_manifest, validate_p0_case_manifest
from .doctor import run_p0_doctor
from .environment import freeze_p0_environment
from .execution_validity import summarize_execution_validity
from .first_batch import generate_p0_first_batch_plan
from .graders import (
    attach_official_grader_artifact,
    merge_grader_results,
    pending_grader_results,
    resolve_official_grader_artifact,
)
from .official_runners import (
    build_agentdojo_command,
    build_agentsecbench_command,
    build_skill_inject_command,
    build_swe_bench_verified_command,
)
from .official_setup import prepare_p0_official_environment
from .paper_tables import (
    render_claim_matrix,
    render_completion_audit_markdown,
    render_completion_audit_table,
    render_results_table,
)
from .provider_credentials import provider_credential_label, provider_credential_shell_missing_condition
from .protocol_definitions import build_p0_protocol_definitions, render_p0_protocol_definitions_markdown
from .run_matrix import cost_summary_from_rows, execute_p0_command_row, stability_summary_from_rows
from .side_effects import summarize_side_effect_records
from .target_continuation import write_p0_target_continuation_artifacts
from .target_scope import build_p0_target_scope_report, render_p0_target_scope_markdown


SCHEMA_VERSION = "invart.p0_real_agent_artifact_package.v0.1"


def run_p0_real_agent_plan(*, out_dir: Path, agents: list[str] | None = None) -> dict[str, Any]:
    root = out_dir.expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    manifest = default_p0_case_manifest(agents=agents)
    result = write_p0_artifact_package(out_dir=root, manifest=manifest)
    result["planning_status"] = "protocol_ready"
    return result


def materialize_p0_run_matrix(
    *,
    manifest_path: Path,
    out_dir: Path,
    modes: list[str] | None = None,
    agents: list[str] | None = None,
) -> dict[str, Any]:
    manifest = _load_json_object(manifest_path)
    validation = validate_p0_case_manifest(manifest)
    if validation["status"] != "pass":
        return write_p0_artifact_package(out_dir=out_dir, manifest={**manifest, "validation": validation})
    selected_modes = modes or [item["mode"] for item in manifest.get("modes", []) if isinstance(item, dict)]
    selected_agents = agents or [item["agent"] for item in manifest.get("agents", []) if isinstance(item, dict)]
    run_rows = _materialized_rows_from_manifest(manifest, modes=selected_modes, agents=selected_agents)
    return write_p0_artifact_package(out_dir=out_dir, manifest=manifest, run_matrix=run_rows)


def execute_p0_real_agent_command(
    *,
    manifest_path: Path,
    out_dir: Path,
    command: list[str],
    cwd: Path,
    case_id: str,
    agent: str,
    mode: str,
    timeout: float = 120.0,
) -> dict[str, Any]:
    manifest = _load_json_object(manifest_path)
    rows = _materialized_rows_from_manifest(manifest, modes=[mode], agents=[agent])
    candidates = [row for row in rows if row.get("case_id") == case_id and row.get("agent") == agent and row.get("mode") == mode]
    if not candidates:
        raise ValueError(f"no P0 row for case={case_id} agent={agent} mode={mode}")
    executed, side_effect = execute_p0_command_row(row=candidates[0], command=command, cwd=cwd, timeout=timeout)
    return write_p0_artifact_package(
        out_dir=out_dir,
        manifest=manifest,
        run_matrix=[executed],
        side_effects=[side_effect],
        cost_summary=cost_summary_from_rows([executed]),
        stability_summary=stability_summary_from_rows([executed]),
    )


def attach_p0_official_grader(
    *,
    run_dir: Path,
    family: str,
    artifact: Path,
    status: str = "attached",
) -> dict[str, Any]:
    root = run_dir.expanduser().resolve()
    manifest = _load_json_object(root / "p0_case_manifest.json")
    run_rows = _read_jsonl(root / "p0_run_matrix.jsonl")
    side_effect_rows = _read_jsonl(root / "p0_side_effects.jsonl")
    current_grader = _read_json_object_or_empty(root / "p0_grader_results.json") or pending_grader_results()
    attached = attach_official_grader_artifact(family=family, artifact=artifact, status=status)
    grader_results = merge_grader_results(current_grader, attached)
    cost_summary = _read_json_object_or_empty(root / "p0_cost_summary.json") or _pending_cost_summary()
    stability_summary = _read_json_object_or_empty(root / "p0_stability_summary.json") or _pending_stability_summary()
    return write_p0_artifact_package(
        out_dir=root,
        manifest=manifest,
        run_matrix=run_rows,
        side_effects=side_effect_rows,
        grader_results=grader_results,
        cost_summary=cost_summary,
        stability_summary=stability_summary,
    )


def collect_p0_child_runs(*, run_dir: Path, child_runs_dir: Path | None = None) -> dict[str, Any]:
    root = run_dir.expanduser().resolve()
    manifest = _load_json_object(root / "p0_case_manifest.json")
    children_root = (child_runs_dir or (root / "runs")).expanduser().resolve()
    child_dirs = _discover_child_run_dirs(children_root)
    run_rows: list[dict[str, Any]] = []
    side_effect_rows: list[dict[str, Any]] = []
    grader_results = pending_grader_results()
    child_reports: list[dict[str, Any]] = []
    for child in child_dirs:
        child_run_rows = _read_jsonl(child / "p0_run_matrix.jsonl") if (child / "p0_run_matrix.jsonl").exists() else []
        child_side_effects = _read_jsonl(child / "p0_side_effects.jsonl") if (child / "p0_side_effects.jsonl").exists() else []
        child_grader = _read_json_object_or_empty(child / "p0_grader_results.json")
        run_rows.extend(child_run_rows)
        side_effect_rows.extend(child_side_effects)
        if child_grader:
            grader_results = merge_grader_results(grader_results, child_grader)
        child_reports.append({
            "path": str(child),
            "run_rows": len(child_run_rows),
            "side_effect_rows": len(child_side_effects),
            "grader_status": child_grader.get("status") if child_grader else "missing",
        })
    raw_run_rows = len(run_rows)
    raw_side_effect_rows = len(side_effect_rows)
    run_rows = _dedupe_p0_run_rows(run_rows)
    side_effect_rows = _dedupe_p0_side_effect_rows(side_effect_rows)
    cost_summary = cost_summary_from_rows(run_rows)
    stability_summary = stability_summary_from_rows(run_rows)
    write_json_artifact(root / "p0_child_runs.json", {
        "schema_version": "invart.p0_child_runs.v0.1",
        "generated_at": utc_now(),
        "runs_dir": str(children_root),
        "children": child_reports,
        "summary": {
            "child_runs": len(child_reports),
            "raw_run_rows": raw_run_rows,
            "run_rows": len(run_rows),
            "deduped_run_rows": raw_run_rows - len(run_rows),
            "raw_side_effect_rows": raw_side_effect_rows,
            "side_effect_rows": len(side_effect_rows),
            "deduped_side_effect_rows": raw_side_effect_rows - len(side_effect_rows),
        },
        "claim_boundary": "Child-run aggregation only collects row packages produced by P0 commands; it does not create official benchmark results.",
    })
    result = write_p0_artifact_package(
        out_dir=root,
        manifest=manifest,
        run_matrix=run_rows,
        side_effects=side_effect_rows,
        grader_results=grader_results,
        cost_summary=cost_summary,
        stability_summary=stability_summary,
    )
    result["collected_child_runs"] = child_reports
    return result


def merge_p0_artifact_packages(
    *,
    out_dir: Path,
    package_dirs: list[Path],
    manifest_path: Path | None = None,
) -> dict[str, Any]:
    root = out_dir.expanduser().resolve()
    packages = [_load_p0_package_dir(path) for path in package_dirs]
    if not packages:
        raise ValueError("merge_p0_artifact_packages requires at least one package directory")
    manifest = _load_json_object(manifest_path) if manifest_path else _merged_manifest_from_packages(packages)
    run_rows: list[dict[str, Any]] = []
    side_effect_rows: list[dict[str, Any]] = []
    for package in packages:
        run_rows.extend(package["run_rows"])
        side_effect_rows.extend(package["side_effect_rows"])
    raw_run_rows = len(run_rows)
    raw_side_effect_rows = len(side_effect_rows)
    run_rows = _dedupe_p0_run_rows(run_rows)
    side_effect_rows = _dedupe_p0_side_effect_rows(side_effect_rows)
    grader_results = _merged_grader_results_from_packages(packages)
    result = write_p0_artifact_package(
        out_dir=root,
        manifest=manifest,
        run_matrix=run_rows,
        side_effects=side_effect_rows,
        grader_results=grader_results,
        cost_summary=cost_summary_from_rows(run_rows),
        stability_summary=stability_summary_from_rows(run_rows),
    )
    merge_report = {
        "schema_version": "invart.p0_merged_packages.v0.1",
        "generated_at": utc_now(),
        "packages": [
            {
                "path": str(package["root"]),
                "run_rows": len(package["run_rows"]),
                "side_effect_rows": len(package["side_effect_rows"]),
                "grader_status": package["grader_results"].get("status"),
            }
            for package in packages
        ],
        "summary": {
            "packages": len(packages),
            "raw_run_rows": raw_run_rows,
            "run_rows": len(run_rows),
            "deduped_run_rows": raw_run_rows - len(run_rows),
            "raw_side_effect_rows": raw_side_effect_rows,
            "side_effect_rows": len(side_effect_rows),
            "deduped_side_effect_rows": raw_side_effect_rows - len(side_effect_rows),
            "families": sorted({str(row.get("family")) for row in run_rows if row.get("family")}),
            "agents": sorted({str(row.get("agent")) for row in run_rows if row.get("agent")}),
            "modes": sorted({str(row.get("mode")) for row in run_rows if row.get("mode")}),
        },
        "claim_boundary": (
            "Merged P0 packages aggregate row-level artifacts that already exist. "
            "Merging does not create new provider executions, official benchmark scores, or side-effect evidence."
        ),
    }
    write_json_artifact(root / "p0_merged_packages.json", merge_report)
    result = summarize_p0_real_agent_package(root)
    result["merged_packages"] = merge_report
    return result


def execute_p0_official_runner(
    *,
    manifest_path: Path,
    out_dir: Path,
    family: str,
    case_id: str,
    agent: str,
    mode: str,
    cwd: Path,
    grader_artifact: Path,
    timeout: float = 120.0,
    command_override: list[str] | None = None,
    python_executable: str = "python",
    predictions_path: str | None = None,
    run_id: str | None = None,
    report_dir: str | None = None,
    instance_ids: list[str] | None = None,
    model: str | None = None,
    model_id: str | None = None,
    suite: str = "workspace",
    module_to_load: str | None = None,
    user_tasks: list[str] | None = None,
    injection_tasks: list[str] | None = None,
    attack: str | None = "tool_knowledge",
    defense: str | None = None,
    logdir: str | None = None,
    tools: str = "semgrep",
    apps: str = "benchmark/apps",
    runner: str = "scripts/smoke_test_all.py",
    output_dir: str | None = None,
    extra_args: list[str] | None = None,
    bridge_report: Path | None = None,
) -> dict[str, Any]:
    manifest = _load_json_object(manifest_path)
    rows = _materialized_rows_from_manifest(manifest, modes=[mode], agents=[agent])
    candidates = [
        row
        for row in rows
        if row.get("family") == family and row.get("case_id") == case_id and row.get("agent") == agent and row.get("mode") == mode
    ]
    if not candidates:
        raise ValueError(f"no P0 row for family={family} case={case_id} agent={agent} mode={mode}")
    spec = _official_spec_for_family(
        family=family,
        agent=agent,
        python_executable=python_executable,
        predictions_path=predictions_path,
        run_id=run_id,
        report_dir=report_dir,
        instance_ids=instance_ids,
        model=model,
        model_id=model_id,
        suite=suite,
        module_to_load=module_to_load,
        user_tasks=user_tasks,
        injection_tasks=injection_tasks,
        attack=attack,
        defense=defense,
        logdir=logdir,
        tools=tools,
        apps=apps,
        runner=runner,
        output_dir=output_dir,
        extra_args=extra_args,
    )
    command = command_override or list(spec["command"])
    is_dry_run = command_override is None and "--dry-run" in command
    execution_binding = "official_runner_command_override"
    if command_override is None:
        execution_binding = "official_runner_dry_run" if is_dry_run else "official_runner_command"
    row = {
        **candidates[0],
        "official_command_spec": spec,
        "execution_binding": execution_binding,
        "claim_boundary": (
            str(candidates[0].get("claim_boundary") or "")
            + (
                " Official-runner dry-run rows record setup/readiness only and are not benchmark score evidence."
                if is_dry_run
                else " Official-runner rows are claimable only when command_override is absent or transparently marked as fixture/smoke."
            )
        ).strip(),
    }
    executed, side_effect = execute_p0_command_row(row=row, command=command, cwd=cwd, timeout=timeout)
    executed["official_command"] = spec["command"]
    executed["command_override_used"] = command_override is not None
    executed["official_runner_dry_run"] = is_dry_run
    bridge_summary = _summarize_bridge_report(bridge_report)
    if bridge_summary is not None:
        executed["provider_bridge"] = bridge_summary
        executed["claim_boundary"] = (
            str(executed.get("claim_boundary") or "")
            + " Provider bridge status is recorded separately from the official grader result."
        ).strip()
        side_effect = _attach_provider_bridge_side_effect(side_effect, bridge_report)
    pre_side_effect_block = bool(executed.get("blocked")) and mode == "invart_mediated"
    if pre_side_effect_block:
        grader_results = pending_grader_results()
        official_result = {
            "schema_version": "invart.p0_official_result_summary.v0.1",
            "family": family,
            "status": "pre_side_effect_block",
            "artifact": None,
            "utility_result": "not_run_pre_side_effect_block",
            "safety_result": "blocked_by_policy",
            "metrics": {
                "task_results": 0,
                "utility_passed": 0,
                "security_passed": 0,
                "errors": 0,
            },
            "claim_boundary": (
                "Invart mediated the official runner command before upstream execution. No upstream benchmark score "
                "is claimed for this row; the evidence supports only the managed-surface pre-side-effect block."
            ),
        }
    else:
        grader_resolution = resolve_official_grader_artifact(
            family=family,
            requested_artifact=grader_artifact,
            cwd=cwd,
            report_dir=Path(report_dir) if report_dir else None,
            run_id=run_id,
            model_name_or_path=agent,
        )
        grader_results = attach_official_grader_artifact(
            family=family,
            artifact=Path(grader_resolution.get("artifact") or grader_artifact),
            resolution=grader_resolution,
        )
        official_result = _summarize_official_result(family=family, grader_results=grader_results)
    if is_dry_run:
        artifact_path = (
            grader_results.get("families", {}).get(family, {}).get("artifact")
            if isinstance(grader_results.get("families"), dict)
            and isinstance(grader_results.get("families", {}).get(family), dict)
            else str(grader_artifact)
        )
        official_result = {
            "schema_version": "invart.p0_official_result_summary.v0.1",
            "family": family,
            "status": "dry_run_readiness",
            "artifact": artifact_path,
            "utility_result": "dry_run_readiness",
            "safety_result": "dry_run_readiness",
            "metrics": {
                "task_results": 0,
                "utility_passed": 0,
                "security_passed": 0,
                "errors": 0,
            },
            "claim_boundary": (
                "Official runner dry-run completed under P0 supervision. This is setup/readiness evidence only; "
                "it is not an upstream benchmark score, provider execution result, or safety/utility pass rate."
            ),
        }
    executed["official_grader_status"] = grader_results.get("status")
    executed["official_result"] = official_result
    executed["utility_result"] = official_result.get("utility_result") or executed.get("utility_result")
    executed["safety_result"] = official_result.get("safety_result") or executed.get("safety_result")
    return write_p0_artifact_package(
        out_dir=out_dir,
        manifest=manifest,
        run_matrix=[executed],
        side_effects=[side_effect],
        grader_results=grader_results,
        cost_summary=cost_summary_from_rows([executed]),
        stability_summary=stability_summary_from_rows([executed]),
    )


def write_p0_artifact_package(
    *,
    out_dir: Path,
    manifest: dict[str, Any],
    run_matrix: list[dict[str, Any]] | None = None,
    side_effects: list[dict[str, Any]] | None = None,
    grader_results: dict[str, Any] | None = None,
    cost_summary: dict[str, Any] | None = None,
    stability_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    root = out_dir.expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    validation = validate_p0_case_manifest(manifest)
    normalized_run_matrix = run_matrix or []
    normalized_side_effects = _augment_side_effects_with_provider_bridges(
        run_rows=normalized_run_matrix,
        side_effect_rows=side_effects or [],
    )
    write_json_artifact(root / "p0_case_manifest.json", {**manifest, "validation": validation})
    _write_jsonl(root / "p0_run_matrix.jsonl", normalized_run_matrix)
    _write_jsonl(root / "p0_side_effects.jsonl", normalized_side_effects)
    write_json_artifact(root / "p0_grader_results.json", grader_results or pending_grader_results())
    write_json_artifact(root / "p0_cost_summary.json", cost_summary or _pending_cost_summary())
    write_json_artifact(root / "p0_stability_summary.json", stability_summary or _pending_stability_summary())
    write_json_artifact(root / "p0_environment_freeze.json", freeze_p0_environment(manifest=manifest, cwd=root))
    _ensure_p0_official_setup(manifest=manifest, root=root)
    generate_p0_first_batch_plan(manifest=manifest, out_dir=root)
    _write_p0_protocol_definitions(root=root, manifest=manifest)
    _write_p0_target_scope(root=root, manifest=manifest, run_rows=normalized_run_matrix)
    _write_p0_target_continuation(root=root, manifest=manifest, run_rows=normalized_run_matrix)
    _write_p0_continuation_artifacts(root=root, manifest=manifest, run_rows=normalized_run_matrix)
    run_p0_doctor(run_dir=root, manifest=manifest)
    _write_p0_paper_artifacts(
        root=root,
        manifest=manifest,
        run_rows=normalized_run_matrix,
        side_effect_rows=normalized_side_effects,
        grader_results=grader_results or pending_grader_results(),
        cost_summary=cost_summary or _pending_cost_summary(),
    )
    generate_p0_reproduce_script(root)
    _write_p0_completion_audit(
        root=root,
        manifest=manifest,
        run_rows=normalized_run_matrix,
        side_effect_rows=normalized_side_effects,
        grader_results=grader_results or pending_grader_results(),
        cost_summary=cost_summary or _pending_cost_summary(),
        stability_summary=stability_summary or _pending_stability_summary(),
    )
    return summarize_p0_real_agent_package(root)


def rebuild_p0_paper_artifacts(run_dir: Path) -> dict[str, Any]:
    root = run_dir.expanduser().resolve()
    manifest = _load_json_object(root / "p0_case_manifest.json")
    run_rows = _read_jsonl(root / "p0_run_matrix.jsonl")
    side_effect_rows = _read_jsonl(root / "p0_side_effects.jsonl")
    grader_results = _read_json_object_or_empty(root / "p0_grader_results.json")
    cost_summary = _read_json_object_or_empty(root / "p0_cost_summary.json")
    stability_summary = _read_json_object_or_empty(root / "p0_stability_summary.json")
    _write_p0_paper_artifacts(
        root=root,
        manifest=manifest,
        run_rows=run_rows,
        side_effect_rows=side_effect_rows,
        grader_results=grader_results,
        cost_summary=cost_summary,
    )
    _write_p0_protocol_definitions(root=root, manifest=manifest)
    _write_p0_target_scope(root=root, manifest=manifest, run_rows=run_rows)
    _write_p0_target_continuation(root=root, manifest=manifest, run_rows=run_rows)
    _write_p0_continuation_artifacts(root=root, manifest=manifest, run_rows=run_rows)
    if not (root / "reproduce_p0.sh").exists():
        generate_p0_reproduce_script(root)
    _write_p0_completion_audit(
        root=root,
        manifest=manifest,
        run_rows=run_rows,
        side_effect_rows=side_effect_rows,
        grader_results=grader_results,
        cost_summary=cost_summary,
        stability_summary=stability_summary,
    )
    report = summarize_p0_real_agent_package(root)
    report["rebuilt_artifacts"] = [
        "p0_claim_matrix.md",
        "p0_results_table.tex",
        "p0_remaining_rows.json",
        "p0_remaining_commands.sh",
        "p0_protocol_definitions.json",
        "p0_protocol_definitions.md",
        "p0_target_scope.json",
        "p0_target_scope.md",
        "p0_target_expansion_manifest.json",
        "p0_target_continuation.json",
        "p0_target_continuation.md",
        "p0_target_continuation_commands.sh",
        "p0_completion_audit.json",
        "p0_completion_audit.md",
        "p0_completion_audit.tex",
        "reproduce_p0.sh",
    ]
    return report


def generate_p0_remaining_artifacts(run_dir: Path) -> dict[str, Any]:
    root = run_dir.expanduser().resolve()
    manifest = _load_json_object(root / "p0_case_manifest.json")
    run_rows = _read_jsonl(root / "p0_run_matrix.jsonl")
    if not (root / "p0_first_batch_plan.json").exists():
        generate_p0_first_batch_plan(manifest=manifest, out_dir=root)
    _write_p0_continuation_artifacts(root=root, manifest=manifest, run_rows=run_rows)
    remaining = _read_json_object_or_empty(root / "p0_remaining_rows.json")
    package = summarize_p0_real_agent_package(root)
    return {
        "schema_version": "invart.p0_remaining_refresh.v0.1",
        "status": remaining.get("status") or "unknown",
        "generated_at": utc_now(),
        "root": str(root),
        "summary": {
            "missing_expected_rows": len(remaining.get("missing_expected_rows", [])),
            "runnable_rows": len(remaining.get("runnable_rows", [])),
            "unsupported_rows": len(remaining.get("unsupported_rows", [])),
            "required_api_keys": remaining.get("required_api_keys", []),
            "p0_scope_complete": package.get("summary", {}).get("p0_scope_complete"),
        },
        "artifacts": {
            "p0_remaining_rows.json": str(root / "p0_remaining_rows.json"),
            "p0_remaining_commands.sh": str(root / "p0_remaining_commands.sh"),
        },
        "claim_boundary": remaining.get("claim_boundary"),
    }


def generate_p0_target_continuation(run_dir: Path) -> dict[str, Any]:
    root = run_dir.expanduser().resolve()
    manifest = _load_json_object(root / "p0_case_manifest.json")
    run_rows = _read_jsonl(root / "p0_run_matrix.jsonl")
    report = write_p0_target_continuation_artifacts(root=root, manifest=manifest, run_rows=run_rows)
    package = summarize_p0_real_agent_package(root)
    return {
        "schema_version": "invart.p0_target_continuation_refresh.v0.1",
        "status": report.get("status") or "unknown",
        "generated_at": utc_now(),
        "root": str(root),
        "summary": report.get("summary", {}),
        "target_scope_complete": report.get("target_scope_complete"),
        "package_scope_complete": package.get("summary", {}).get("p0_scope_complete"),
        "artifacts": report.get("artifacts", {}),
        "claim_boundary": report.get("claim_boundary"),
    }


def generate_p0_completion_audit(run_dir: Path) -> dict[str, Any]:
    root = run_dir.expanduser().resolve()
    manifest = _load_json_object(root / "p0_case_manifest.json")
    run_rows = _read_jsonl(root / "p0_run_matrix.jsonl")
    side_effect_rows = _read_jsonl(root / "p0_side_effects.jsonl")
    grader_results = _read_json_object_or_empty(root / "p0_grader_results.json")
    cost_summary = _read_json_object_or_empty(root / "p0_cost_summary.json")
    stability_summary = _read_json_object_or_empty(root / "p0_stability_summary.json")
    if not (root / "p0_remaining_rows.json").exists():
        if not (root / "p0_first_batch_plan.json").exists():
            generate_p0_first_batch_plan(manifest=manifest, out_dir=root)
        _write_p0_continuation_artifacts(root=root, manifest=manifest, run_rows=run_rows)
    _write_p0_completion_audit(
        root=root,
        manifest=manifest,
        run_rows=run_rows,
        side_effect_rows=side_effect_rows,
        grader_results=grader_results,
        cost_summary=cost_summary,
        stability_summary=stability_summary,
    )
    audit = _read_json_object_or_empty(root / "p0_completion_audit.json")
    return {
        "schema_version": "invart.p0_completion_audit_refresh.v0.1",
        "status": audit.get("status") or "unknown",
        "generated_at": utc_now(),
        "root": str(root),
        "p0_scope_complete": audit.get("p0_scope_complete"),
        "summary": audit.get("summary", {}),
        "remaining": audit.get("remaining", {}),
        "artifacts": {
            "p0_completion_audit.json": str(root / "p0_completion_audit.json"),
            "p0_completion_audit.md": str(root / "p0_completion_audit.md"),
            "p0_completion_audit.tex": str(root / "p0_completion_audit.tex"),
        },
        "claim_boundary": audit.get("claim_boundary"),
    }


def write_p0_reproduce_report(
    *,
    run_dir: Path,
    reproduce_script: Path,
    package_summary: dict[str, Any],
) -> dict[str, Any]:
    root = run_dir.expanduser().resolve()
    summary = package_summary.get("summary", {}) if isinstance(package_summary.get("summary"), dict) else {}
    expected_scope = summary.get("expected_scope", {}) if isinstance(summary.get("expected_scope"), dict) else {}
    report = {
        "schema_version": "invart.p0_reproduce_report.v0.1",
        "status": package_summary.get("status") or "unknown",
        "generated_at": utc_now(),
        "root": str(root),
        "reproduce_script": str(reproduce_script.expanduser().resolve()),
        "package_status": package_summary.get("status"),
        "evidence_hash": package_summary.get("evidence_hash"),
        "summary": {
            "run_rows": summary.get("run_rows"),
            "covered_expected_rows": expected_scope.get("covered_expected_rows"),
            "expected_rows": expected_scope.get("expected_rows"),
            "p0_scope_complete": summary.get("p0_scope_complete"),
            "package_rows_complete": summary.get("package_rows_complete"),
            "missing_artifacts": summary.get("missing_artifacts"),
        },
        "claim_boundary": (
            "This report records that the local reproducibility script regenerated the package summary. "
            "It does not add provider executions, official scores, or side-effect evidence."
        ),
    }
    write_json_artifact(root / "p0_reproduce_report.json", report)
    return report


def summarize_p0_real_agent_package(root: Path) -> dict[str, Any]:
    resolved = root.expanduser().resolve()
    _refresh_p0_paper_artifacts_if_possible(resolved)
    required = [
        "p0_case_manifest.json",
        "p0_run_matrix.jsonl",
        "p0_side_effects.jsonl",
        "p0_grader_results.json",
        "p0_cost_summary.json",
        "p0_stability_summary.json",
        "p0_environment_freeze.json",
        "p0_official_setup.json",
        "p0_doctor.json",
        "p0_first_batch_plan.json",
        "p0_first_batch_commands.sh",
        "p0_protocol_definitions.json",
        "p0_protocol_definitions.md",
        "p0_target_scope.json",
        "p0_target_scope.md",
        "p0_target_expansion_manifest.json",
        "p0_target_continuation.json",
        "p0_target_continuation.md",
        "p0_target_continuation_commands.sh",
        "p0_claim_matrix.md",
        "p0_results_table.tex",
        "p0_remaining_rows.json",
        "p0_remaining_commands.sh",
        "p0_completion_audit.json",
        "p0_completion_audit.md",
        "p0_completion_audit.tex",
        "reproduce_p0.sh",
    ]
    artifacts = {name: str(resolved / name) for name in required}
    optional_artifacts = ["p0_reproduce_report.json"]
    for name in optional_artifacts:
        path = resolved / name
        if path.exists():
            artifacts[name] = str(path)
    missing = [name for name, path in artifacts.items() if not Path(path).exists()]
    hashes = {name: sha256_file(Path(path), prefixed=True) for name, path in artifacts.items() if Path(path).exists()}
    run_rows = _read_jsonl(resolved / "p0_run_matrix.jsonl") if (resolved / "p0_run_matrix.jsonl").exists() else []
    side_effect_rows = _read_jsonl(resolved / "p0_side_effects.jsonl") if (resolved / "p0_side_effects.jsonl").exists() else []
    manifest = _read_json_object_or_empty(resolved / "p0_case_manifest.json")
    grader_results = _read_json_object_or_empty(resolved / "p0_grader_results.json")
    cost_summary = _read_json_object_or_empty(resolved / "p0_cost_summary.json")
    stability_summary = _read_json_object_or_empty(resolved / "p0_stability_summary.json")
    complete_rows = [row for row in run_rows if row.get("run_status") in {"pass", "fail", "blocked", "timeout", "crashed"}]
    official_rows = [row for row in run_rows if row.get("runner_kind") == "official_benchmark_runner"]
    official_command_rows = [row for row in official_rows if row.get("execution_binding") == "official_runner_command"]
    official_dry_run_rows = [row for row in official_rows if row.get("execution_binding") == "official_runner_dry_run"]
    official_override_rows = [row for row in official_rows if row.get("execution_binding") == "official_runner_command_override"]
    provider_bridge_rows = [row for row in run_rows if isinstance(row.get("provider_bridge"), dict)]
    execution_validity_rows = [
        (
            row["execution_validity"]
            if isinstance(row.get("execution_validity"), dict)
            else {
                "eligibility_status": "missing",
                "technical_valid": False,
                "security_effect_eligible": False,
                "reasons": ["execution_validity_missing"],
            }
        )
        for row in run_rows
    ]
    run_matrix_complete = bool(run_rows) and len(complete_rows) == len(run_rows)
    side_effects_complete = bool(run_rows) and len(side_effect_rows) >= len(run_rows)
    grader_attached = grader_results.get("status") in {"attached", "pass"}
    cost_attached = cost_summary.get("status") in {"attached", "pass"}
    stability_attached = stability_summary.get("status") in {"attached", "pass"}
    expected_scope = _expected_scope(manifest=manifest, run_rows=run_rows)
    package_rows_complete = run_matrix_complete and side_effects_complete and grader_attached and cost_attached and stability_attached
    p0_scope_complete = package_rows_complete and expected_scope["covered_expected_rows"] == expected_scope["expected_rows"] and expected_scope["expected_rows"] > 0
    report = {
        "schema_version": SCHEMA_VERSION,
        "status": "pass" if not missing else "incomplete",
        "generated_at": utc_now(),
        "root": str(resolved),
        "summary": {
            "required_artifacts": len(required),
            "missing_artifacts": len(missing),
            "run_rows": len(run_rows),
            "complete_run_rows": len(complete_rows),
            "official_runner_rows": len(official_rows),
            "official_runner_command_rows": len(official_command_rows),
            "official_runner_dry_run_rows": len(official_dry_run_rows),
            "official_runner_override_rows": len(official_override_rows),
            "provider_bridge_rows": len(provider_bridge_rows),
            "provider_bridge_summary": _provider_bridge_summary(provider_bridge_rows),
            "execution_validity": summarize_execution_validity(
                execution_validity_rows,
                expected_rows=expected_scope["expected_rows"],
            ),
            "side_effect_rows": len(side_effect_rows),
            "side_effect_summary": summarize_side_effect_records(side_effect_rows),
            "run_matrix_complete": run_matrix_complete,
            "side_effects_complete": side_effects_complete,
            "grader_attached": grader_attached,
            "cost_attached": cost_attached,
            "stability_attached": stability_attached,
            "expected_scope": expected_scope,
            "package_rows_complete": package_rows_complete,
            "p0_scope_complete": p0_scope_complete,
            "p0_execution_complete": p0_scope_complete,
        },
        "artifacts": artifacts,
        "missing": missing,
        "hashes": hashes,
        "claim_boundary": (
            "This package is protocol-complete when all required artifacts exist. It is P0 evidence-complete only after "
            "non-empty baseline/observe/mediated rows are produced through official benchmark runners or explicitly "
            "marked generic CLI bridges, with independent side-effect records and grader outputs."
        ),
    }
    report["evidence_hash"] = stable_json_hash({"summary": report["summary"], "hashes": hashes})
    write_json_artifact(resolved / "p0_package_summary.json", report)
    return report


def _refresh_p0_paper_artifacts_if_possible(root: Path) -> None:
    required_inputs = [
        root / "p0_case_manifest.json",
        root / "p0_run_matrix.jsonl",
        root / "p0_side_effects.jsonl",
        root / "p0_grader_results.json",
        root / "p0_cost_summary.json",
    ]
    if not all(path.exists() for path in required_inputs):
        return
    manifest = _read_json_object_or_empty(root / "p0_case_manifest.json")
    run_rows = _read_jsonl(root / "p0_run_matrix.jsonl")
    side_effect_rows = _read_jsonl(root / "p0_side_effects.jsonl")
    grader_results = _read_json_object_or_empty(root / "p0_grader_results.json")
    cost_summary = _read_json_object_or_empty(root / "p0_cost_summary.json")
    _write_p0_paper_artifacts(
        root=root,
        manifest=manifest,
        run_rows=run_rows,
        side_effect_rows=side_effect_rows,
        grader_results=grader_results,
        cost_summary=cost_summary,
    )
    _write_p0_target_scope(root=root, manifest=manifest, run_rows=run_rows)
    _write_p0_target_continuation(root=root, manifest=manifest, run_rows=run_rows)
    _write_p0_continuation_artifacts(root=root, manifest=manifest, run_rows=run_rows)


def _write_p0_paper_artifacts(
    *,
    root: Path,
    manifest: dict[str, Any],
    run_rows: list[dict[str, Any]],
    side_effect_rows: list[dict[str, Any]],
    grader_results: dict[str, Any],
    cost_summary: dict[str, Any] | None = None,
) -> None:
    grader_attached = grader_results.get("status") in {"attached", "pass"}
    (root / "p0_claim_matrix.md").write_text(
        render_claim_matrix(
            manifest,
            run_rows,
            side_effects_complete=bool(side_effect_rows),
            grader_attached=grader_attached,
            cost_summary=cost_summary,
        ),
        encoding="utf-8",
    )
    (root / "p0_results_table.tex").write_text(render_results_table(run_rows), encoding="utf-8")


def _write_p0_protocol_definitions(*, root: Path, manifest: dict[str, Any]) -> None:
    definitions = build_p0_protocol_definitions(manifest)
    write_json_artifact(root / "p0_protocol_definitions.json", definitions)
    (root / "p0_protocol_definitions.md").write_text(
        render_p0_protocol_definitions_markdown(definitions),
        encoding="utf-8",
    )


def _write_p0_target_scope(*, root: Path, manifest: dict[str, Any], run_rows: list[dict[str, Any]]) -> None:
    report = build_p0_target_scope_report(manifest=manifest, run_rows=run_rows)
    write_json_artifact(root / "p0_target_scope.json", report)
    (root / "p0_target_scope.md").write_text(render_p0_target_scope_markdown(report), encoding="utf-8")


def _write_p0_target_continuation(*, root: Path, manifest: dict[str, Any], run_rows: list[dict[str, Any]]) -> None:
    write_p0_target_continuation_artifacts(root=root, manifest=manifest, run_rows=run_rows)


def _write_p0_continuation_artifacts(*, root: Path, manifest: dict[str, Any], run_rows: list[dict[str, Any]]) -> None:
    missing = _missing_expected_rows(manifest=manifest, run_rows=run_rows)
    first_batch_plan = _read_json_object_or_empty(root / "p0_first_batch_plan.json")
    agentdojo_rows = {
        (str(row.get("case_id")), str(row.get("agent")), str(row.get("mode"))): row
        for row in first_batch_plan.get("agentdojo_rows", [])
        if isinstance(row, dict)
    }
    skill_rows = {
        (str(row.get("case_id")), str(row.get("agent")), str(row.get("mode"))): row
        for row in first_batch_plan.get("skill_inject_rows", [])
        if isinstance(row, dict)
    }
    runnable_rows: list[dict[str, Any]] = []
    unsupported_rows: list[dict[str, Any]] = []
    for item in missing:
        key = (item["case_id"], item["agent"], item["mode"])
        if item["family"] == "agentdojo" and key in agentdojo_rows:
            runnable_rows.append({**item, **agentdojo_rows[key]})
        elif item["family"] == "skill_inject" and key in skill_rows:
            runnable_rows.append({**item, **skill_rows[key]})
        else:
            unsupported_rows.append({
                **item,
                "reason": "no continuation renderer is registered for this missing row",
            })
    required_keys = sorted({
        str(key)
        for row in runnable_rows
        for key in row.get("required_api_keys", [])
        if key
    })
    payload = {
        "schema_version": "invart.p0_remaining_rows.v0.1",
        "root": str(root),
        "status": "complete" if not missing else ("runnable" if runnable_rows else "needs_manual_continuation"),
        "missing_expected_rows": missing,
        "runnable_rows": runnable_rows,
        "unsupported_rows": unsupported_rows,
        "required_api_keys": required_keys,
        "continuation_script": str(root / "p0_remaining_commands.sh"),
        "after_run_output": str(root / "p0-continuation" / "merged"),
        "claim_boundary": (
            "Continuation artifacts identify missing expected P0 rows and commands to attempt them. "
            "They do not create provider executions, official benchmark scores, or side-effect evidence until the script is run with provider credentials."
        ),
    }
    payload["generated_at"] = _stable_remaining_generated_at(root / "p0_remaining_rows.json", payload)
    write_json_artifact(root / "p0_remaining_rows.json", payload)
    _write_p0_remaining_commands(root=root, rows=runnable_rows)


def _write_p0_completion_audit(
    *,
    root: Path,
    manifest: dict[str, Any],
    run_rows: list[dict[str, Any]],
    side_effect_rows: list[dict[str, Any]],
    grader_results: dict[str, Any],
    cost_summary: dict[str, Any],
    stability_summary: dict[str, Any],
) -> None:
    _write_p0_target_scope(root=root, manifest=manifest, run_rows=run_rows)
    _write_p0_target_continuation(root=root, manifest=manifest, run_rows=run_rows)
    target_scope = _read_json_object_or_empty(root / "p0_target_scope.json")
    target_continuation = _read_json_object_or_empty(root / "p0_target_continuation.json")
    remaining = _read_json_object_or_empty(root / "p0_remaining_rows.json")
    expected_scope = _expected_scope(manifest=manifest, run_rows=run_rows)
    side_effect_summary = summarize_side_effect_records(side_effect_rows)
    missing_rows = remaining.get("missing_expected_rows", [])
    required_keys = remaining.get("required_api_keys", [])
    complete_run_rows = [row for row in run_rows if row.get("run_status") in {"pass", "fail", "blocked", "timeout", "crashed"}]
    official_rows = [row for row in run_rows if row.get("runner_kind") == "official_benchmark_runner"]
    official_command_rows = [row for row in official_rows if row.get("execution_binding") == "official_runner_command"]
    provider_bridge_rows = [row for row in run_rows if isinstance(row.get("provider_bridge"), dict)]
    families_in_rows = sorted({str(row.get("family")) for row in run_rows if row.get("family")})
    modes_in_rows = sorted({str(row.get("mode")) for row in run_rows if row.get("mode")})
    agents_in_rows = sorted({str(row.get("agent")) for row in run_rows if row.get("agent")})
    required_families = sorted({str(case.get("family")) for case in manifest.get("cases", []) if isinstance(case, dict) and case.get("family")})
    required_modes = sorted({str(mode.get("mode")) for mode in manifest.get("modes", []) if isinstance(mode, dict) and mode.get("mode")})
    required_agents = sorted({str(agent.get("agent")) for agent in manifest.get("agents", []) if isinstance(agent, dict) and agent.get("agent")})
    package_rows_complete = (
        bool(run_rows)
        and len(complete_run_rows) == len(run_rows)
        and len(side_effect_rows) >= len(run_rows)
        and grader_results.get("status") in {"attached", "pass"}
        and cost_summary.get("status") in {"attached", "pass"}
        and stability_summary.get("status") in {"attached", "pass"}
    )
    p0_scope_complete = (
        package_rows_complete
        and expected_scope["expected_rows"] > 0
        and expected_scope["covered_expected_rows"] == expected_scope["expected_rows"]
    )
    requirements = [
        _audit_requirement(
            "case_manifest_and_scope",
            required_families == families_in_rows or set(required_families).issubset(set(families_in_rows)),
            "P0 manifest declares the benchmark families, agents, modes, and claim boundaries used by the package.",
            {"families": families_in_rows, "agents": agents_in_rows, "modes": modes_in_rows},
        ),
        _audit_requirement(
            "target_scope_coverage",
            bool(target_scope.get("target_scope_complete")),
            "The package must disclose whether it covers the original 8-case P0 target scope, not only the current manifest subset.",
            {
                "target_cases": target_scope.get("summary", {}).get("target_cases"),
                "manifest_cases": target_scope.get("summary", {}).get("manifest_cases"),
                "covered_target_rows": target_scope.get("summary", {}).get("covered_target_rows"),
                "target_expected_rows": target_scope.get("summary", {}).get("target_expected_rows"),
                "missing_target_case_ids": target_scope.get("missing_target_case_ids", []),
            },
            incomplete_status="incomplete_target_scope",
        ),
        _audit_requirement(
            "real_agent_run_matrix",
            p0_scope_complete,
            "All manifest case x agent x mode rows must be present before P0 is complete.",
            {
                "covered_expected_rows": expected_scope["covered_expected_rows"],
                "expected_rows": expected_scope["expected_rows"],
                "missing_rows": len(missing_rows) if isinstance(missing_rows, list) else 0,
            },
            incomplete_status="blocked_by_external_credentials" if required_keys else "incomplete",
        ),
        _audit_requirement(
            "official_runner_binding",
            bool(official_command_rows),
            "Rows must preserve official runner command evidence or explicitly bounded provider bridge evidence.",
            {
                "official_runner_command_rows": len(official_command_rows),
                "official_runner_rows": len(official_rows),
                "provider_bridge_rows": len(provider_bridge_rows),
            },
        ),
        _audit_requirement(
            "independent_side_effect_ground_truth",
            bool(run_rows) and len(side_effect_rows) >= len(run_rows),
            "Every run row must have independent side-effect evidence rather than relying on agent-native logs alone.",
            {
                "side_effect_rows": len(side_effect_rows),
                "run_rows": len(run_rows),
                "ground_truth_sources": side_effect_summary.get("ground_truth_sources", []),
            },
        ),
        _audit_requirement(
            "claim_matrix_and_paper_table",
            (root / "p0_claim_matrix.md").exists() and (root / "p0_results_table.tex").exists(),
            "Paper-facing claims must be derived from the ledger-style run matrix and bounded by claim text.",
            {
                "claim_matrix": str(root / "p0_claim_matrix.md"),
                "results_table": str(root / "p0_results_table.tex"),
            },
        ),
        _audit_requirement(
            "clean_room_reproduce",
            (root / "reproduce_p0.sh").exists(),
            "A clean-room script must rebuild paper tables and package summary from frozen artifacts.",
            {"reproduce_script": str(root / "reproduce_p0.sh")},
        ),
        _audit_requirement(
            "cost_and_stability_attached",
            cost_summary.get("status") in {"attached", "pass"} and stability_summary.get("status") in {"attached", "pass"},
            "Cost and stability evidence must be attached before paper-facing claims are made.",
            {
                "cost_status": cost_summary.get("status"),
                "stability_status": stability_summary.get("status"),
            },
        ),
    ]
    status = "complete" if p0_scope_complete and all(row["status"] == "pass" for row in requirements) else (
        "blocked_by_external_credentials" if required_keys and missing_rows else "incomplete"
    )
    payload = {
        "schema_version": "invart.p0_completion_audit.v0.1",
        "root": str(root),
        "status": status,
        "p0_scope_complete": p0_scope_complete,
        "requirements": requirements,
        "remaining": {
            "status": remaining.get("status"),
            "missing_expected_rows": missing_rows,
            "runnable_rows": remaining.get("runnable_rows", []),
            "unsupported_rows": remaining.get("unsupported_rows", []),
            "required_api_keys": required_keys,
            "continuation_script": str(root / "p0_remaining_commands.sh"),
        },
        "target_continuation": {
            "status": target_continuation.get("status"),
            "current_manifest_rows": target_continuation.get("summary", {}).get("current_manifest_rows"),
            "target_expansion_rows": target_continuation.get("summary", {}).get("target_expansion_rows"),
            "target_expansion_cases": target_continuation.get("summary", {}).get("target_expansion_cases"),
            "row_actions": target_continuation.get("summary", {}).get("row_actions"),
            "official_command_spec_rows": target_continuation.get("summary", {}).get("official_command_spec_rows"),
            "readiness_summary": target_continuation.get("readiness", {}).get("summary", {}),
            "readiness_by_status": target_continuation.get("readiness", {}).get("by_status", {}),
            "row_action_counts": target_continuation.get("row_action_counts", {}),
            "external_inputs": target_continuation.get("external_inputs", []),
            "required_api_keys": target_continuation.get("required_api_keys", []),
            "continuation_script": str(root / "p0_target_continuation_commands.sh"),
            "expansion_manifest": str(root / "p0_target_expansion_manifest.json"),
        },
        "summary": {
            "run_rows": len(run_rows),
            "complete_run_rows": len(complete_run_rows),
            "official_runner_command_rows": len(official_command_rows),
            "provider_bridge_rows": len(provider_bridge_rows),
            "side_effect_rows": len(side_effect_rows),
            "covered_expected_rows": expected_scope["covered_expected_rows"],
            "expected_rows": expected_scope["expected_rows"],
            "target_expected_rows": target_scope.get("summary", {}).get("target_expected_rows"),
            "covered_target_rows": target_scope.get("summary", {}).get("covered_target_rows"),
            "target_scope_complete": target_scope.get("target_scope_complete"),
        },
        "claim_boundary": (
            "This audit is derived from current P0 package artifacts. A pass on protocol artifacts is not a claim "
            "that all real provider benchmark rows have run; missing rows remain explicit until attached as run rows."
        ),
    }
    payload["generated_at"] = _stable_generated_at(root / "p0_completion_audit.json", payload)
    write_json_artifact(root / "p0_completion_audit.json", payload)
    (root / "p0_completion_audit.md").write_text(render_completion_audit_markdown(payload), encoding="utf-8")
    (root / "p0_completion_audit.tex").write_text(render_completion_audit_table(payload), encoding="utf-8")


def _audit_requirement(
    requirement: str,
    passed: bool,
    evidence_rule: str,
    evidence: dict[str, Any],
    *,
    incomplete_status: str = "incomplete",
) -> dict[str, Any]:
    return {
        "requirement": requirement,
        "status": "pass" if passed else incomplete_status,
        "evidence_rule": evidence_rule,
        "evidence": evidence,
    }


def _stable_generated_at(path: Path, payload_without_timestamp: dict[str, Any]) -> str:
    existing = _read_json_object_or_empty(path)
    if not existing.get("generated_at"):
        return utc_now()
    comparable_existing = dict(existing)
    comparable_existing.pop("generated_at", None)
    return str(existing["generated_at"]) if comparable_existing == payload_without_timestamp else utc_now()


def _stable_remaining_generated_at(path: Path, payload_without_timestamp: dict[str, Any]) -> str:
    return _stable_generated_at(path, payload_without_timestamp)


def _missing_expected_rows(*, manifest: dict[str, Any], run_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    cases = [case for case in manifest.get("cases", []) if isinstance(case, dict) and case.get("case_id") and case.get("family")]
    agents = [agent for agent in manifest.get("agents", []) if isinstance(agent, dict) and agent.get("agent")]
    modes = [mode for mode in manifest.get("modes", []) if isinstance(mode, dict) and mode.get("mode")]
    covered = {
        (str(row.get("case_id")), str(row.get("agent")), str(row.get("mode")))
        for row in run_rows
        if row.get("case_id") and row.get("agent") and row.get("mode")
    }
    missing: list[dict[str, Any]] = []
    for case in cases:
        for agent in agents:
            for mode in modes:
                key = (str(case["case_id"]), str(agent["agent"]), str(mode["mode"]))
                if key in covered:
                    continue
                missing.append({
                    "case_id": key[0],
                    "family": str(case["family"]),
                    "benchmark_case_ref": case.get("benchmark_case_ref"),
                    "agent": key[1],
                    "mode": key[2],
                    "row_id": f"{key[0]}_{key[1]}_{key[2]}".replace("/", "_"),
                    "claim_boundary": case.get("claim_boundary") or mode.get("claim"),
                })
    return missing


def _write_p0_remaining_commands(*, root: Path, rows: list[dict[str, Any]]) -> Path:
    script = root / "p0_remaining_commands.sh"
    repo_hint = _invart_repo_hint()
    lines = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        "ROOT=\"$(cd \"$(dirname \"$0\")\" && pwd)\"",
        "PYTHON_BIN=\"${PYTHON:-python3}\"",
        f"INVART_REPO=\"${{INVART_REPO:-{_shell_default(repo_hint)}}}\"",
        "if [[ -d \"$INVART_REPO/src/invart\" ]]; then",
        "  export PYTHONPATH=\"$INVART_REPO/src:${PYTHONPATH:-}\"",
        "fi",
        "CONTINUATION_ROOT=\"${INVART_P0_CONTINUATION_ROOT:-$ROOT/p0-continuation}\"",
        "mkdir -p \"$CONTINUATION_ROOT/runs\" \"$CONTINUATION_ROOT/skips\"",
        "SKILL_INJECT_REPO=\"${INVART_SKILL_INJECT_REPO:-}\"",
        "if [[ -z \"$SKILL_INJECT_REPO\" ]]; then",
        "  if [[ -f \"$ROOT/upstream/skill-inject/scripts/smoke_test_all.py\" ]]; then",
        "    SKILL_INJECT_REPO=\"$ROOT/upstream/skill-inject\"",
        "  else",
        "    SKILL_INJECT_REPO=\"$INVART_REPO/.local/upstream/skill-inject\"",
        "  fi",
        "fi",
        "MERGE_ARGS=(--package-dir \"$ROOT\")",
        "mkdir -p \"$CONTINUATION_ROOT/boundaries\"",
    ]
    agentdojo_rows = [row for row in rows if row.get("family") == "agentdojo"]
    skill_inject_rows = [row for row in rows if row.get("family") == "skill_inject"]
    if agentdojo_rows:
        lines.extend([
            "",
            "# Missing AgentDojo rows. Without a registered AgentDojo model/adapter id, write boundary artifacts instead of claiming official scores.",
        ])
        for row in agentdojo_rows:
            lines.extend(_render_p0_remaining_agentdojo_row(row))
    lines.extend([
        "if [[ ! -f \"$SKILL_INJECT_REPO/scripts/smoke_test_all.py\" ]]; then",
        "  printf '{\"status\":\"skipped\",\"reason\":\"missing Skill-Inject repository\",\"expected_repo\":\"%s\"}\\n' \"$SKILL_INJECT_REPO\" > \"$CONTINUATION_ROOT/skips/missing-skill-inject-repo.json\"",
        "else",
    ])
    if not skill_inject_rows:
        lines.extend([
            "  : # No runnable continuation rows remain.",
        ])
    for row in skill_inject_rows:
        lines.extend(_render_p0_remaining_skill_inject_row(row))
    lines.extend([
        "fi",
        "\"$PYTHON_BIN\" -m invart.cli experiment p0-real-agent merge-packages --out-dir \"$CONTINUATION_ROOT/merged\" \"${MERGE_ARGS[@]}\"",
        "\"$PYTHON_BIN\" -m invart.cli experiment p0-real-agent summarize --run-dir \"$CONTINUATION_ROOT/merged\"",
        "",
    ])
    script.write_text("\n".join(lines), encoding="utf-8")
    script.chmod(0o755)
    return script


def _render_p0_remaining_agentdojo_row(row: dict[str, Any]) -> list[str]:
    row_id = str(row["row_id"])
    case_id = str(row["case_id"])
    benchmark_case_ref = str(row.get("benchmark_case_ref") or "")
    agent = str(row["agent"])
    mode = str(row["mode"])
    suite = str(row.get("suite") or "workspace")
    user_task = row.get("user_task")
    injection_task = row.get("injection_task") or "injection_task_0"
    model_env = str(row.get("model_env") or _agentdojo_model_env(agent))
    model_id_env = str(row.get("model_id_env") or _agentdojo_model_id_env(agent))
    local_port_env = str(row.get("local_port_env") or _agentdojo_local_port_env(agent))
    logdir = str(row.get("logdir") or f"agentdojo-logs/{row_id}")
    out_dir = f"$CONTINUATION_ROOT/runs/{row_id}"
    boundary_dir = f"$CONTINUATION_ROOT/boundaries/{row_id}"
    user_task_args = f' --user-task "{user_task}"' if user_task else ""
    injection_task_args = f' --injection-task "{injection_task}"' if injection_task else ""
    return [
        "",
        f"  # Missing AgentDojo row: {row_id}",
        f"  AGENTDOJO_MODEL=\"${{{model_env}:-}}\"",
        f"  AGENTDOJO_MODEL_ID=\"${{{model_id_env}:-}}\"",
        f"  AGENTDOJO_LOCAL_PORT=\"${{{local_port_env}:-}}\"",
        "  if [[ -n \"$AGENTDOJO_MODEL\" ]]; then",
        "    AGENTDOJO_MODEL_ID_ARGS=()",
        "    if [[ -n \"$AGENTDOJO_MODEL_ID\" ]]; then AGENTDOJO_MODEL_ID_ARGS=(--model-id \"$AGENTDOJO_MODEL_ID\"); fi",
        "    AGENTDOJO_ENV_ARGS=()",
        "    if [[ -n \"$AGENTDOJO_LOCAL_PORT\" ]]; then AGENTDOJO_ENV_ARGS=(env \"LOCAL_LLM_PORT=$AGENTDOJO_LOCAL_PORT\"); fi",
        "    AGENTDOJO_BRIDGE_ARGS=()",
        "    if [[ -n \"$AGENTDOJO_LOCAL_PORT\" ]]; then AGENTDOJO_BRIDGE_ARGS=(--bridge-report \"$CONTINUATION_ROOT/proxy-log/p0_agentdojo_proxy_calls.jsonl\"); fi",
        f"    mkdir -p \"$CONTINUATION_ROOT/agentdojo-logs/{row_id}\" \"$CONTINUATION_ROOT/proxy-log\"",
        f"    \"${{AGENTDOJO_ENV_ARGS[@]}}\" \"$PYTHON_BIN\" -m invart.cli experiment p0-real-agent execute-official --manifest \"$ROOT/p0_case_manifest.json\" --out-dir \"{out_dir}\" --family agentdojo --case-id \"{case_id}\" --agent \"{agent}\" --mode \"{mode}\" --cwd \"$ROOT\" --grader-artifact \"$CONTINUATION_ROOT/{logdir}\" --python \"$PYTHON_BIN\" --model \"$AGENTDOJO_MODEL\" \"${{AGENTDOJO_MODEL_ID_ARGS[@]}}\" --suite \"{suite}\"{user_task_args}{injection_task_args} --logdir \"$CONTINUATION_ROOT/{logdir}\" \"${{AGENTDOJO_BRIDGE_ARGS[@]}}\"",
        f"    if [[ -f \"{out_dir}/p0_run_matrix.jsonl\" ]]; then MERGE_ARGS+=(--package-dir \"{out_dir}\"); fi",
        "  else",
        f"    \"$PYTHON_BIN\" -m invart.cli experiment p0-real-agent agentdojo-boundary --out-dir \"{boundary_dir}\" --case-id \"{case_id}\" --benchmark-case-ref \"{benchmark_case_ref}\" --agent \"{agent}\" --mode \"{mode}\" --suite \"{suite}\"{user_task_args} --model-env \"{model_env}\" --python \"$PYTHON_BIN\" >/dev/null",
        f"    printf '{{\"status\":\"boundary\",\"row_id\":\"{row_id}\",\"reason\":\"missing AgentDojo model adapter\",\"model_env\":\"{model_env}\"}}\\n' > \"$CONTINUATION_ROOT/skips/{row_id}.json\"",
        "  fi",
    ]


def _render_p0_remaining_skill_inject_row(row: dict[str, Any]) -> list[str]:
    row_id = str(row["row_id"])
    case_id = str(row["case_id"])
    agent = str(row["agent"])
    mode = str(row["mode"])
    runner = str(row.get("runner") or "experiments/contextual.py")
    model = str(row.get("model") or "")
    result_dir = str(row.get("result_dir") or "")
    missing_checks = provider_credential_shell_missing_condition(agent)
    missing_message = provider_credential_label(agent)
    extra_args = " ".join(f"--extra-arg={_shell_single_quote(str(item))}" for item in row.get("extra_args", []))
    timeout_arg = '--extra-arg=--timeout --extra-arg="${INVART_SKILL_INJECT_SANDBOX_TIMEOUT:-180}"'
    out_dir = f"$CONTINUATION_ROOT/runs/{row_id}"
    return [
        "",
        f"  # Missing Skill-Inject row: {row_id}",
        f"  if {missing_checks}; then",
        f"    printf '{{\"status\":\"skipped\",\"row_id\":\"{row_id}\",\"reason\":\"missing provider credentials\",\"missing\":\"{missing_message}\"}}\\n' > \"$CONTINUATION_ROOT/skips/{row_id}.json\"",
        "  else",
        f"    \"$PYTHON_BIN\" -m invart.cli experiment p0-real-agent execute-official --manifest \"$ROOT/p0_case_manifest.json\" --out-dir \"{out_dir}\" --family skill_inject --case-id \"{case_id}\" --agent \"{agent}\" --mode \"{mode}\" --cwd \"$SKILL_INJECT_REPO\" --grader-artifact \"$SKILL_INJECT_REPO/{result_dir}\" --timeout \"${{INVART_P0_OFFICIAL_TIMEOUT:-2400}}\" --python \"$PYTHON_BIN\" --runner \"{runner}\" --model \"{model}\" {extra_args} {timeout_arg}",
        f"    if [[ -f \"{out_dir}/p0_run_matrix.jsonl\" ]]; then MERGE_ARGS+=(--package-dir \"{out_dir}\"); fi",
        "  fi",
    ]


def _shell_single_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _agentdojo_env_suffix(agent: str) -> str:
    return "".join(char.upper() if char.isalnum() else "_" for char in agent).strip("_")


def _agentdojo_model_env(agent: str) -> str:
    suffix = _agentdojo_env_suffix(agent)
    return f"INVART_AGENTDOJO_MODEL_{suffix or 'AGENT'}"


def _agentdojo_model_id_env(agent: str) -> str:
    suffix = _agentdojo_env_suffix(agent)
    return f"INVART_AGENTDOJO_MODEL_ID_{suffix or 'AGENT'}"


def _agentdojo_local_port_env(agent: str) -> str:
    suffix = _agentdojo_env_suffix(agent)
    return f"INVART_AGENTDOJO_LOCAL_PORT_{suffix or 'AGENT'}"


def _load_p0_package_dir(path: Path) -> dict[str, Any]:
    root = path.expanduser().resolve()
    if not root.exists():
        raise ValueError(f"P0 package directory does not exist: {root}")
    manifest_path = root / "p0_case_manifest.json"
    run_path = root / "p0_run_matrix.jsonl"
    side_effect_path = root / "p0_side_effects.jsonl"
    grader_path = root / "p0_grader_results.json"
    missing = [str(item.name) for item in [manifest_path, run_path, side_effect_path, grader_path] if not item.exists()]
    if missing:
        raise ValueError(f"P0 package directory is missing required artifacts: {root}: {', '.join(missing)}")
    return {
        "root": root,
        "manifest": _read_json_object_or_empty(manifest_path),
        "run_rows": _read_jsonl(run_path),
        "side_effect_rows": _read_jsonl(side_effect_path),
        "grader_results": _read_json_object_or_empty(grader_path),
    }


def _dedupe_p0_run_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    selected: dict[tuple[str, ...], tuple[int, int, dict[str, Any]]] = {}
    for index, row in enumerate(rows):
        key = _p0_row_identity(row)
        score = _p0_run_row_score(row)
        current = selected.get(key)
        if current is None or (score, index) >= (current[0], current[1]):
            selected[key] = (score, index, row)
    return [item[2] for item in sorted(selected.values(), key=lambda item: item[1])]


def _dedupe_p0_side_effect_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    selected: dict[tuple[str, ...], tuple[int, int, dict[str, Any]]] = {}
    for index, row in enumerate(rows):
        key = _p0_side_effect_identity(row)
        score = _p0_side_effect_score(row)
        current = selected.get(key)
        if current is None or (score, index) >= (current[0], current[1]):
            selected[key] = (score, index, row)
    return [item[2] for item in sorted(selected.values(), key=lambda item: item[1])]


def _p0_row_identity(row: dict[str, Any]) -> tuple[str, ...]:
    row_id = str(row.get("row_id") or "").strip()
    if row_id:
        return ("row_id", row_id)
    return (
        "tuple",
        str(row.get("family") or ""),
        str(row.get("case_id") or ""),
        str(row.get("agent") or ""),
        str(row.get("mode") or ""),
    )


def _p0_side_effect_identity(row: dict[str, Any]) -> tuple[str, ...]:
    row_id = str(row.get("row_id") or "").strip()
    if row_id:
        return ("row_id", row_id)
    return (
        "tuple",
        str(row.get("family") or ""),
        str(row.get("case_id") or ""),
        str(row.get("agent") or ""),
        str(row.get("mode") or ""),
    )


def _p0_run_row_score(row: dict[str, Any]) -> int:
    official_result = row.get("official_result") if isinstance(row.get("official_result"), dict) else {}
    bridge = row.get("provider_bridge") if isinstance(row.get("provider_bridge"), dict) else {}
    score = 0
    if official_result.get("status") == "attached":
        score += 1000
    if official_result.get("utility_result") == "resolved":
        score += 200
    if row.get("official_grader_status") == "attached":
        score += 100
    if row.get("run_status") == "pass":
        score += 80
    elif row.get("run_status") in {"fail", "timeout", "crashed"}:
        score += 20
    if row.get("execution_binding") == "official_runner_command":
        score += 10
    if bridge.get("status") == "pass":
        score += 5
    if official_result.get("utility_result") == "official_grader_missing":
        score -= 100
    if row.get("command_override_used"):
        score -= 5
    return score


def _p0_side_effect_score(row: dict[str, Any]) -> int:
    score = 0
    if row.get("provider_bridge_side_effect"):
        score += 20
    if row.get("official_runner_side_effect_detected") is not None:
        score += 10
    if row.get("side_effect_detected") is True:
        score += 5
    return score


def _merged_manifest_from_packages(packages: list[dict[str, Any]]) -> dict[str, Any]:
    base = dict(packages[0]["manifest"])
    cases_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    agents_by_id: dict[str, dict[str, Any]] = {}
    modes_by_id: dict[str, dict[str, Any]] = {}
    contracts_by_family: dict[str, dict[str, Any]] = {}
    non_claims: list[str] = []
    row_case_keys = {
        (str(row.get("family")), str(row.get("case_id")))
        for package in packages
        for row in package["run_rows"]
        if row.get("family") and row.get("case_id")
    }
    row_agents = {str(row.get("agent")) for package in packages for row in package["run_rows"] if row.get("agent")}
    row_modes = {str(row.get("mode")) for package in packages for row in package["run_rows"] if row.get("mode")}
    for package in packages:
        manifest = package["manifest"]
        for case in manifest.get("cases", []):
            if (
                isinstance(case, dict)
                and case.get("case_id")
                and case.get("family")
                and (str(case["family"]), str(case["case_id"])) in row_case_keys
            ):
                cases_by_key[(str(case["family"]), str(case["case_id"]))] = case
        for agent in manifest.get("agents", []):
            if isinstance(agent, dict) and agent.get("agent") and str(agent["agent"]) in row_agents:
                agents_by_id[str(agent["agent"])] = agent
        for mode in manifest.get("modes", []):
            if isinstance(mode, dict) and mode.get("mode") and str(mode["mode"]) in row_modes:
                modes_by_id[str(mode["mode"])] = mode
        for contract in manifest.get("official_runner_contracts", []):
            if isinstance(contract, dict) and contract.get("family"):
                contracts_by_family[str(contract["family"])] = contract
        for item in manifest.get("non_claims", []):
            if isinstance(item, str) and item not in non_claims:
                non_claims.append(item)
        for row in package["run_rows"]:
            family = str(row.get("family") or "")
            case_id = str(row.get("case_id") or "")
            agent = str(row.get("agent") or "")
            mode = str(row.get("mode") or "")
            if family and case_id and (family, case_id) not in cases_by_key:
                cases_by_key[(family, case_id)] = {
                    "case_id": case_id,
                    "family": family,
                    "benchmark_case_ref": row.get("benchmark_case_ref"),
                    "claim_boundary": row.get("claim_boundary"),
                }
            if agent and agent not in agents_by_id:
                agents_by_id[agent] = {"agent": agent}
            if mode and mode not in modes_by_id:
                modes_by_id[mode] = {"mode": mode}
    base["name"] = str(base.get("name") or "p0-real-agent-official-benchmark-bridge") + "-merged"
    base["cases"] = list(cases_by_key.values())
    base["agents"] = list(agents_by_id.values())
    base["modes"] = list(modes_by_id.values())
    base["official_runner_contracts"] = list(contracts_by_family.values())
    base["non_claims"] = non_claims
    base.pop("validation", None)
    base["merge_boundary"] = (
        "This manifest is derived from completed P0 packages for paper-table aggregation. "
        "Expected scope is the cartesian product of merged cases, agents, and modes."
    )
    return base


def _merged_grader_results_from_packages(packages: list[dict[str, Any]]) -> dict[str, Any]:
    family_artifacts: dict[str, list[dict[str, Any]]] = {}
    for package in packages:
        families = package["grader_results"].get("families", {})
        if not isinstance(families, dict):
            continue
        for family, payload in families.items():
            if not isinstance(payload, dict):
                continue
            family_artifacts.setdefault(str(family), []).append({
                "package": str(package["root"]),
                "artifact": payload.get("artifact"),
                "sha256": payload.get("sha256"),
                "exists": payload.get("exists"),
                "validation": payload.get("validation"),
                "resolution": payload.get("resolution"),
                "claim_boundary": payload.get("claim_boundary"),
            })
    families: dict[str, dict[str, Any]] = {}
    for family, artifacts in family_artifacts.items():
        validations = [item.get("validation") for item in artifacts if isinstance(item.get("validation"), dict)]
        families[family] = {
            "artifacts": artifacts,
            "exists": all(item.get("exists") is not False for item in artifacts),
            "validation": {
                "schema_version": "invart.p0_merged_grader_validation.v0.1",
                "status": "pass" if validations and all(item.get("status") == "pass" for item in validations) else "pending",
                "artifacts": len(artifacts),
            },
            "claim_boundary": "Merged grader entries preserve package-level official artifacts; row-level official_result remains the score source.",
        }
    status = "attached" if families and all(item["validation"]["status"] == "pass" for item in families.values()) else "pending"
    return {
        "schema_version": "invart.p0_grader_results.v0.1",
        "status": status,
        "families": families,
        "claim_boundary": "Merged grader artifacts are an index of already-attached upstream runner outputs; merging does not create new official scores.",
    }


def _load_json_object(path: Path) -> dict[str, Any]:
    loaded = json.loads(path.expanduser().read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError("P0 manifest must be a JSON object")
    return loaded


def _ensure_p0_official_setup(*, manifest: dict[str, Any], root: Path) -> None:
    setup_path = root / "p0_official_setup.json"
    if setup_path.exists():
        return
    prepare_p0_official_environment(manifest=manifest, out_dir=root)


def _materialized_rows_from_manifest(manifest: dict[str, Any], *, modes: list[str], agents: list[str]) -> list[dict[str, Any]]:
    contracts = {item["family"]: item for item in manifest.get("official_runner_contracts", []) if isinstance(item, dict)}
    run_rows: list[dict[str, Any]] = []
    for case in manifest.get("cases", []):
        if not isinstance(case, dict):
            continue
        contract = contracts.get(case.get("family"), {})
        for agent in agents:
            for mode in modes:
                run_rows.append({
                    "schema_version": "invart.p0_run_record.v0.1",
                    "row_id": f"{case.get('case_id')}_{agent}_{mode}".replace("/", "_"),
                    "case_id": case.get("case_id"),
                    "family": case.get("family"),
                    "benchmark_case_ref": case.get("benchmark_case_ref"),
                    "agent": agent,
                    "mode": mode,
                    "runner_kind": "official_benchmark_runner",
                    "official_entrypoint": contract.get("official_entrypoint"),
                    "official_grader": contract.get("official_grader"),
                    "agent_bridge": contract.get("invart_integration") or "generic_cli_agent_bridge",
                    "run_status": "planned",
                    "utility_result": "pending",
                    "safety_result": "pending",
                    "cost_result": "pending",
                    "side_effect_result": "pending",
                    "claim_boundary": contract.get("claim_rule") or case.get("claim_boundary"),
                })
    return run_rows


def _official_spec_for_family(
    *,
    family: str,
    agent: str | None,
    python_executable: str,
    predictions_path: str | None,
    run_id: str | None,
    report_dir: str | None,
    instance_ids: list[str] | None,
    model: str | None,
    model_id: str | None,
    suite: str,
    module_to_load: str | None,
    user_tasks: list[str] | None,
    injection_tasks: list[str] | None,
    attack: str | None,
    defense: str | None,
    logdir: str | None,
    tools: str,
    apps: str,
    runner: str,
    output_dir: str | None,
    extra_args: list[str] | None,
) -> dict[str, Any]:
    if family == "swe_bench_verified":
        if not predictions_path:
            raise ValueError("predictions_path is required for SWE-Bench Verified official runner")
        return build_swe_bench_verified_command(
            python_executable=python_executable,
            predictions_path=predictions_path,
            run_id=run_id or "invart_p0_swe_verified",
            report_dir=report_dir,
            instance_ids=instance_ids,
        )
    if family == "agentdojo":
        if not model:
            raise ValueError("model is required for AgentDojo official runner")
        return build_agentdojo_command(
            python_executable=python_executable,
            model=model,
            model_id=model_id,
            suite=suite,
            module_to_load=module_to_load,
            user_tasks=user_tasks,
            injection_tasks=injection_tasks,
            attack=attack,
            defense=defense,
            logdir=logdir,
        )
    if family == "agentsecbench":
        return build_agentsecbench_command(
            python_executable=python_executable,
            tools=tools,
            apps=apps,
            output_dir=output_dir,
            extra_args=extra_args,
        )
    if family == "skill_inject":
        return build_skill_inject_command(
            python_executable=python_executable,
            runner=runner,
            agent=agent,
            model=model,
            output_dir=output_dir,
            extra_args=extra_args,
        )
    raise ValueError(f"official execute helper does not support family: {family}")


def _summarize_official_result(*, family: str, grader_results: dict[str, Any]) -> dict[str, Any]:
    family_payload = grader_results.get("families", {}).get(family, {}) if isinstance(grader_results.get("families"), dict) else {}
    artifact = Path(str(family_payload.get("artifact") or "")) if isinstance(family_payload, dict) and family_payload.get("artifact") else None
    validation = family_payload.get("validation", {}) if isinstance(family_payload, dict) else {}
    validation_status = validation.get("status") if isinstance(validation, dict) else None
    if not artifact or validation_status != "pass":
        return {
            "schema_version": "invart.p0_official_result_summary.v0.1",
            "family": family,
            "status": "missing_or_invalid",
            "grader_validation_status": validation_status or "missing",
            "utility_result": "official_grader_missing",
            "safety_result": "pending",
            "claim_boundary": "No official benchmark outcome can be claimed without a validated upstream grader artifact.",
        }
    if family == "swe_bench_verified":
        return _summarize_swe_official_report(artifact)
    if family == "agentdojo":
        return _summarize_agentdojo_official_artifact(artifact)
    if family == "agentsecbench":
        return _summarize_task_result_artifact(
            path=artifact,
            family="agentsecbench",
            claim_boundary=(
                "AgentSecBench utility/security status is derived only from parseable upstream result records "
                "emitted by the official or ancillary benchmark runner."
            ),
        )
    if family == "skill_inject":
        return _summarize_task_result_artifact(
            path=artifact,
            family="skill_inject",
            claim_boundary=(
                "Skill-Inject utility/security status is derived only from parseable upstream experiment or judge "
                "records emitted by the repository runner."
            ),
        )
    return {
        "schema_version": "invart.p0_official_result_summary.v0.1",
        "family": family,
        "status": "attached",
        "artifact": str(artifact),
        "grader_validation_status": validation_status,
        "utility_result": "upstream_artifact_attached",
        "safety_result": "upstream_artifact_attached",
        "claim_boundary": "Generic upstream artifact attachment records benchmark-run evidence but does not infer benchmark-specific metrics.",
    }


def _summarize_swe_official_report(path: Path) -> dict[str, Any]:
    payload = _read_json_object_or_empty(path)
    submitted = _int_metric(payload.get("submitted_instances"))
    completed = _int_metric(payload.get("completed_instances"))
    resolved = _int_metric(payload.get("resolved_instances"))
    unresolved = _int_metric(payload.get("unresolved_instances"))
    empty_patch = _int_metric(payload.get("empty_patch_instances"))
    errors = _int_metric(payload.get("error_instances"))
    utility = "official_grader_attached"
    if errors > 0:
        utility = "grader_error"
    elif submitted == 0:
        utility = "no_submission"
    elif empty_patch > 0 and completed == 0:
        utility = "empty_submission"
    elif resolved > 0:
        utility = "resolved"
    elif completed > 0 and unresolved > 0:
        utility = "unresolved"
    elif completed == 0:
        utility = "no_completed_instance"
    return {
        "schema_version": "invart.p0_official_result_summary.v0.1",
        "family": "swe_bench_verified",
        "status": "attached",
        "artifact": str(path),
        "utility_result": utility,
        "safety_result": "not_applicable_benign",
        "metrics": {
            "total_instances": _int_metric(payload.get("total_instances")),
            "submitted_instances": submitted,
            "completed_instances": completed,
            "resolved_instances": resolved,
            "unresolved_instances": unresolved,
            "empty_patch_instances": empty_patch,
            "error_instances": errors,
        },
        "ids": {
            "submitted_ids": _string_list(payload.get("submitted_ids")),
            "completed_ids": _string_list(payload.get("completed_ids")),
            "resolved_ids": _string_list(payload.get("resolved_ids")),
            "unresolved_ids": _string_list(payload.get("unresolved_ids")),
            "empty_patch_ids": _string_list(payload.get("empty_patch_ids")),
            "error_ids": _string_list(payload.get("error_ids")),
        },
        "claim_boundary": "SWE-Bench utility status is derived only from the official harness report, not from provider bridge success.",
    }


def _summarize_agentdojo_official_artifact(path: Path) -> dict[str, Any]:
    task_results = _agentdojo_task_results(path)
    if not task_results:
        return {
            "schema_version": "invart.p0_official_result_summary.v0.1",
            "family": "agentdojo",
            "status": "attached_no_task_metrics",
            "artifact": str(path),
            "utility_result": "upstream_artifact_attached",
            "safety_result": "upstream_artifact_attached",
            "metrics": {
                "task_results": 0,
                "utility_passed": 0,
                "security_passed": 0,
                "errors": 0,
            },
            "claim_boundary": "AgentDojo artifact was validated, but no task-result JSON with utility/security fields was found.",
        }
    utility_passed = sum(1 for item in task_results if item.get("utility") is True)
    security_passed = sum(1 for item in task_results if item.get("security") is True)
    errors = sum(1 for item in task_results if item.get("error"))
    total = len(task_results)
    utility_result = "utility_passed" if utility_passed == total and errors == 0 else "utility_failed"
    safety_result = "security_passed" if security_passed == total and errors == 0 else "security_failed"
    return {
        "schema_version": "invart.p0_official_result_summary.v0.1",
        "family": "agentdojo",
        "status": "attached",
        "artifact": str(path),
        "utility_result": utility_result,
        "safety_result": safety_result,
        "metrics": {
            "task_results": total,
            "utility_passed": utility_passed,
            "utility_failed": total - utility_passed,
            "security_passed": security_passed,
            "security_failed": total - security_passed,
            "errors": errors,
        },
        "task_ids": [
            {
                "suite_name": item.get("suite_name"),
                "user_task_id": item.get("user_task_id"),
                "injection_task_id": item.get("injection_task_id"),
                "attack_type": item.get("attack_type"),
            }
            for item in task_results
        ],
        "claim_boundary": "AgentDojo utility/security status is derived from official TraceLogger task-result JSON files under the runner logdir.",
    }


def _agentdojo_task_results(path: Path) -> list[dict[str, Any]]:
    candidates = sorted(path.rglob("*.json")) if path.is_dir() else [path]
    results: list[dict[str, Any]] = []
    for candidate in candidates:
        payload = _read_json_object_or_empty(candidate)
        if not payload:
            continue
        if "utility" not in payload or "security" not in payload:
            continue
        results.append({
            "suite_name": payload.get("suite_name"),
            "pipeline_name": payload.get("pipeline_name"),
            "user_task_id": payload.get("user_task_id"),
            "injection_task_id": payload.get("injection_task_id"),
            "attack_type": payload.get("attack_type"),
            "utility": payload.get("utility") is True,
            "security": payload.get("security") is True,
            "error": payload.get("error"),
            "duration": payload.get("duration"),
        })
    return results


def _summarize_task_result_artifact(*, path: Path, family: str, claim_boundary: str) -> dict[str, Any]:
    task_results = _skill_inject_result_records(path) if family == "skill_inject" else _task_result_records(path)
    if not task_results:
        if family == "agentsecbench":
            leaderboard = _agentsecbench_leaderboard_records(path)
            if leaderboard:
                best = leaderboard[0]
                return {
                    "schema_version": "invart.p0_official_result_summary.v0.1",
                    "family": family,
                    "status": "attached_score_metrics",
                    "artifact": str(path),
                    "utility_result": "benchmark_score_attached",
                    "safety_result": "benchmark_score_attached",
                    "metrics": {
                        "leaderboard_rows": len(leaderboard),
                        "top_tool": best.get("tool"),
                        "top_type": best.get("type"),
                        "top_detection": best.get("detection"),
                        "top_quality": best.get("quality"),
                        "top_auditability": best.get("auditability"),
                        "top_surface": best.get("surface"),
                        "top_score": best.get("score"),
                        "task_results": 0,
                        "utility_passed": 0,
                        "security_passed": 0,
                        "errors": 0,
                    },
                    "leaderboard": leaderboard,
                    "claim_boundary": (
                        "AgentSecBench artifact was validated and score metrics were parsed from the official "
                        "leaderboard; no per-task utility/security pass rate is claimed."
                    ),
                }
        return {
            "schema_version": "invart.p0_official_result_summary.v0.1",
            "family": family,
            "status": "attached_no_result_metrics",
            "artifact": str(path),
            "utility_result": "upstream_artifact_attached",
            "safety_result": "upstream_artifact_attached",
            "metrics": {
                "task_results": 0,
                "utility_passed": 0,
                "security_passed": 0,
                "errors": 0,
            },
            "claim_boundary": (
                f"{family} artifact was validated, but no parseable per-task utility/security result records were found."
            ),
        }
    total = len(task_results)
    utility_passed = sum(1 for item in task_results if item.get("utility") is True)
    security_passed = sum(1 for item in task_results if item.get("security") is True)
    errors = sum(1 for item in task_results if item.get("error"))
    utility_result = "utility_passed" if utility_passed == total and errors == 0 else "utility_failed"
    safety_result = "security_passed" if security_passed == total and errors == 0 else "security_failed"
    return {
        "schema_version": "invart.p0_official_result_summary.v0.1",
        "family": family,
        "status": "attached",
        "artifact": str(path),
        "utility_result": utility_result,
        "safety_result": safety_result,
        "metrics": {
            "task_results": total,
            "utility_passed": utility_passed,
            "utility_failed": total - utility_passed,
            "security_passed": security_passed,
            "security_failed": total - security_passed,
            "errors": errors,
        },
        "task_ids": [
            {
                "case_id": item.get("case_id"),
                "task_id": item.get("task_id"),
                "tool": item.get("tool"),
                "app": item.get("app"),
            }
            for item in task_results
        ],
        "claim_boundary": claim_boundary,
    }


def _skill_inject_result_records(path: Path) -> list[dict[str, Any]]:
    candidates = sorted(path.rglob("run_status.jsonl")) if path.is_dir() else []
    if path.is_file() and path.name == "run_status.jsonl":
        candidates = [path]
    for candidate in candidates:
        rows = _read_jsonl_objects(candidate)
        sandbox_rows = [row for row in rows if row.get("event") == "sandbox_complete"]
        if sandbox_rows:
            return [
                {
                    "case_id": row.get("sandbox_id"),
                    "task_id": row.get("sandbox_id"),
                    "utility": row.get("success") is True,
                    "security": row.get("success") is True,
                    "error": None if row.get("success") is True else "sandbox_failed",
                }
                for row in sandbox_rows
            ]
    return _task_result_records(path)


def _task_result_records(path: Path) -> list[dict[str, Any]]:
    candidates = sorted(child for child in path.rglob("*") if child.is_file()) if path.is_dir() else [path]
    records: list[dict[str, Any]] = []
    for candidate in candidates:
        suffix = candidate.suffix.lower()
        if suffix == ".json":
            payload = _read_json_object_or_empty(candidate)
            if payload:
                records.extend(_normalize_task_result_payload(payload))
                continue
            items = _read_json_list_or_empty(candidate)
            records.extend(_normalize_task_result_payload(items))
        elif suffix == ".jsonl":
            records.extend(_normalize_task_result_payload(_read_jsonl_objects(candidate)))
        elif suffix == ".csv":
            records.extend(_normalize_task_result_payload(_read_csv_rows(candidate)))
    return records


def _normalize_task_result_payload(payload: Any) -> list[dict[str, Any]]:
    raw_records: list[dict[str, Any]] = []
    if isinstance(payload, list):
        raw_records.extend(item for item in payload if isinstance(item, dict))
    elif isinstance(payload, dict):
        nested = None
        for key in ("results", "records", "tasks", "cases", "runs", "evaluations"):
            if isinstance(payload.get(key), list):
                nested = payload[key]
                break
        if nested is not None:
            raw_records.extend(item for item in nested if isinstance(item, dict))
        elif _looks_like_task_result(payload):
            raw_records.append(payload)
    normalized: list[dict[str, Any]] = []
    for item in raw_records:
        utility = _extract_positive_bool(
            item,
            ("utility", "utility_passed", "task_success", "success", "passed", "completed", "benign_success"),
        )
        security = _extract_positive_bool(item, ("security", "security_passed", "safety", "safety_passed", "safe"))
        if security is None:
            negative_security = _extract_positive_bool(
                item,
                ("attack_success", "injection_success", "policy_violation", "violation", "compromised", "unsafe"),
            )
            if negative_security is not None:
                security = not negative_security
        error = _truthy(item.get("error")) or _truthy(item.get("exception")) or _truthy(item.get("crash"))
        if utility is None and security is None and not error:
            continue
        normalized.append({
            "case_id": item.get("case_id") or item.get("case") or item.get("id"),
            "task_id": item.get("task_id") or item.get("task") or item.get("scenario"),
            "tool": item.get("tool"),
            "app": item.get("app") or item.get("application"),
            "utility": utility is True,
            "security": security is True,
            "error": item.get("error") or item.get("exception") or item.get("crash"),
        })
    return normalized


def _agentsecbench_leaderboard_records(path: Path) -> list[dict[str, Any]]:
    candidates = sorted(path.rglob("leaderboard.md")) if path.is_dir() else [path]
    records: list[dict[str, Any]] = []
    for candidate in candidates:
        if candidate.name != "leaderboard.md" and candidate.suffix.lower() != ".md":
            continue
        for line in candidate.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped.startswith("|") or "---" in stripped or "Rank" in stripped:
                continue
            cells = [cell.strip().strip("*") for cell in stripped.strip("|").split("|")]
            if len(cells) < 8:
                continue
            try:
                rank = int(cells[0])
            except ValueError:
                continue
            records.append({
                "rank": rank,
                "tool": cells[1],
                "type": cells[2],
                "detection": _float_metric(cells[3]),
                "quality": _float_metric(cells[4]),
                "auditability": _float_metric(cells[5]),
                "surface": _float_metric(cells[6]),
                "score": _float_metric(cells[7]),
                "artifact": str(candidate),
            })
    return records


def _looks_like_task_result(payload: dict[str, Any]) -> bool:
    keys = {
        "utility",
        "utility_passed",
        "task_success",
        "success",
        "passed",
        "completed",
        "benign_success",
        "security",
        "security_passed",
        "safety",
        "safety_passed",
        "safe",
        "attack_success",
        "injection_success",
        "policy_violation",
        "violation",
        "compromised",
        "unsafe",
        "error",
        "exception",
        "crash",
    }
    return bool(keys.intersection(payload))


def _extract_positive_bool(payload: dict[str, Any], keys: tuple[str, ...]) -> bool | None:
    for key in keys:
        if key in payload:
            return _truthy(payload.get(key))
    return None


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, (int, float)):
        return value != 0
    text = str(value).strip().lower()
    if text in {"", "0", "false", "no", "none", "null", "n/a", "na"}:
        return False
    if text in {"1", "true", "yes", "pass", "passed", "success", "succeeded", "safe"}:
        return True
    return True


def _read_json_list_or_empty(path: Path) -> list[Any]:
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    return loaded if isinstance(loaded, list) else []


def _read_jsonl_objects(path: Path) -> list[dict[str, Any]]:
    objects: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            loaded = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(loaded, dict):
            objects.append(loaded)
    return objects


def _read_csv_rows(path: Path) -> list[dict[str, Any]]:
    try:
        with path.open(newline="", encoding="utf-8") as handle:
            return [dict(row) for row in csv.DictReader(handle)]
    except Exception:
        return []


def _int_metric(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _float_metric(value: Any) -> float:
    text = str(value or "0").strip().strip("*")
    try:
        return float(text)
    except (TypeError, ValueError):
        return 0.0


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def generate_p0_reproduce_script(root: Path) -> Path:
    path = root.expanduser().resolve() / "reproduce_p0.sh"
    repo_hint = _invart_repo_hint()
    path.write_text(
        (
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "ROOT=\"$(cd \"$(dirname \"$0\")\" && pwd)\"\n"
            "PYTHON_BIN=\"${PYTHON:-python3}\"\n"
            f"INVART_REPO=\"${{INVART_REPO:-{_shell_default(repo_hint)}}}\"\n"
            "if [[ -d \"$INVART_REPO/src/invart\" ]]; then\n"
            "  export PYTHONPATH=\"$INVART_REPO/src:${PYTHONPATH:-}\"\n"
            "fi\n"
            "\"$PYTHON_BIN\" -m invart.cli experiment list >/dev/null\n"
            "\"$PYTHON_BIN\" -m invart.cli experiment p0-real-agent rebuild-tables --run-dir \"$ROOT\"\n"
            "\"$PYTHON_BIN\" -m invart.cli experiment p0-real-agent summarize --run-dir \"$ROOT\"\n"
        ),
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        loaded = json.loads(line)
        if isinstance(loaded, dict):
            rows.append(loaded)
    return rows


def _invart_repo_hint() -> str:
    path = Path(__file__).resolve()
    for parent in path.parents:
        if (parent / "src" / "invart").exists() and (parent / "pyproject.toml").exists():
            return str(parent)
    return ""


def _shell_default(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$")


def _read_json_object_or_empty(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    loaded = json.loads(path.read_text(encoding="utf-8"))
    return loaded if isinstance(loaded, dict) else {}


def _read_agentdojo_proxy_records(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            loaded = json.loads(line)
        except json.JSONDecodeError:
            return []
        if not isinstance(loaded, dict):
            return []
        if loaded.get("schema_version") != "invart.p0_agentdojo_cli_proxy.v0.1":
            return []
        records.append(loaded)
    return records


def _discover_child_run_dirs(root: Path) -> list[Path]:
    if not root.exists():
        return []
    return sorted(
        child.resolve()
        for child in root.iterdir()
        if child.is_dir() and (child / "p0_run_matrix.jsonl").exists()
    )


def _summarize_bridge_report(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    resolved = path.expanduser().resolve()
    summary: dict[str, Any] = {
        "schema_version": "invart.p0_provider_bridge_summary.v0.1",
        "artifact": str(resolved),
        "exists": resolved.exists(),
        "sha256": sha256_file(resolved, prefixed=True) if resolved.exists() else None,
        "claim_boundary": (
            "This summarizes the provider/agent bridge outcome. It is not an official benchmark score; "
            "utility and safety scores require the matching official grader artifact."
        ),
    }
    if not resolved.exists():
        summary["status"] = "missing"
        return summary
    proxy_records = _read_agentdojo_proxy_records(resolved)
    if proxy_records:
        summary.update(_summarize_agentdojo_proxy_bridge_records(proxy_records))
        return summary
    loaded = _read_json_object_or_empty(resolved)
    summary.update({
        "status": loaded.get("status") or "unknown",
        "prediction_status": loaded.get("prediction_status"),
        "agent_run_status": loaded.get("agent_run_status"),
        "agent": loaded.get("agent"),
        "mode": loaded.get("mode"),
        "instance_id": loaded.get("instance_id"),
    })
    prediction = loaded.get("prediction")
    if isinstance(prediction, dict):
        summary["predictions_path"] = prediction.get("predictions_path")
        summary["predictions_sha256"] = prediction.get("predictions_sha256")
        summary["model_patch_bytes"] = prediction.get("model_patch_bytes")
        summary["excluded_internal_paths"] = prediction.get("excluded_internal_paths")
    supervision = loaded.get("supervision")
    if isinstance(supervision, dict) and isinstance(supervision.get("stability"), dict):
        stability = supervision["stability"]
        summary["returncode"] = stability.get("returncode")
        summary["timed_out"] = stability.get("timed_out")
        summary["crashed"] = stability.get("crashed")
        summary["blocked"] = stability.get("blocked")
    mode_binding = loaded.get("mode_binding")
    if isinstance(mode_binding, dict):
        decision = mode_binding.get("decision") if isinstance(mode_binding.get("decision"), dict) else {}
        summary["mode_binding"] = {
            "control_mode": mode_binding.get("control_mode"),
            "coverage_label": mode_binding.get("coverage_label"),
            "pre_side_effect_gate": mode_binding.get("pre_side_effect_gate"),
            "mediation_status": mode_binding.get("mediation_status"),
            "enforcement_status": mode_binding.get("enforcement_status"),
            "decision_effect": decision.get("effect"),
        }
    return summary


def _summarize_agentdojo_proxy_bridge_records(records: list[dict[str, Any]]) -> dict[str, Any]:
    agents = sorted({str(record.get("agent")) for record in records if record.get("agent")})
    modes = sorted({str(record.get("mode")) for record in records if record.get("mode")})
    case_ids = sorted({str(record.get("case_id")) for record in records if record.get("case_id")})
    model_ids = sorted({str(record.get("model_id") or record.get("model")) for record in records if record.get("model_id") or record.get("model")})
    returncodes: list[int] = []
    timed_out = 0
    blocked = 0
    crashed = 0
    side_effect_counts: dict[str, int] = {}
    mode_binding_counts: dict[str, int] = {}
    for record in records:
        supervision = record.get("supervision") if isinstance(record.get("supervision"), dict) else {}
        returncode = supervision.get("returncode")
        if isinstance(returncode, int):
            returncodes.append(returncode)
            if returncode != 0:
                crashed += 1
        if supervision.get("timed_out") is True:
            timed_out += 1
        if supervision.get("blocked") is True:
            blocked += 1
        side_effect = supervision.get("side_effect_result")
        if side_effect:
            _count(side_effect_counts, side_effect)
        binding = supervision.get("mode_binding") if isinstance(supervision.get("mode_binding"), dict) else {}
        if binding.get("control_mode"):
            _count(mode_binding_counts, binding.get("control_mode"))
    failed = timed_out + blocked + crashed
    status = "pass" if failed == 0 else "partial" if failed < len(records) else "fail"
    agent_run_status = "pass" if failed == 0 else "mixed" if failed < len(records) else "failed"
    first_binding = {}
    first_supervision = records[0].get("supervision") if isinstance(records[0].get("supervision"), dict) else {}
    if isinstance(first_supervision.get("mode_binding"), dict):
        binding = first_supervision["mode_binding"]
        first_binding = {
            "control_mode": binding.get("control_mode"),
            "coverage_label": binding.get("coverage_label"),
            "pre_side_effect_gate": binding.get("pre_side_effect_gate"),
            "mediation_status": binding.get("mediation_status"),
            "enforcement_status": binding.get("enforcement_status"),
            "decision_effect": binding.get("decision_effect"),
        }
    return {
        "status": status,
        "bridge_kind": "agentdojo_cli_proxy",
        "records": len(records),
        "prediction_status": "chat_completion",
        "agent_run_status": agent_run_status,
        "agent": agents[0] if len(agents) == 1 else None,
        "agents": agents,
        "mode": modes[0] if len(modes) == 1 else None,
        "modes": modes,
        "case_id": case_ids[0] if len(case_ids) == 1 else None,
        "case_ids": case_ids,
        "model_id": model_ids[0] if len(model_ids) == 1 else None,
        "model_ids": model_ids,
        "returncodes": sorted(set(returncodes)),
        "timed_out_calls": timed_out,
        "blocked_calls": blocked,
        "crashed_calls": crashed,
        "side_effect_result_counts": side_effect_counts,
        "mode_binding_counts": mode_binding_counts,
        "mode_binding": first_binding,
        "claim_boundary": (
            "This summarizes OpenAI-compatible local backend calls made by the official AgentDojo runner. "
            "It is provider bridge runtime evidence; utility and safety scores still come from AgentDojo outputs."
        ),
    }


def _augment_side_effects_with_provider_bridges(
    *,
    run_rows: list[dict[str, Any]],
    side_effect_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if not run_rows or not side_effect_rows:
        return side_effect_rows
    bridge_by_key: dict[tuple[str, str, str], Path] = {}
    for row in run_rows:
        bridge = row.get("provider_bridge")
        if not isinstance(bridge, dict) or not bridge.get("artifact"):
            continue
        key = (str(row.get("case_id")), str(row.get("agent")), str(row.get("mode")))
        bridge_by_key[key] = Path(str(bridge["artifact"]))
    if not bridge_by_key:
        return side_effect_rows
    augmented: list[dict[str, Any]] = []
    for record in side_effect_rows:
        key = (str(record.get("case_id")), str(record.get("agent")), str(record.get("mode")))
        bridge_path = bridge_by_key.get(key)
        augmented.append(_attach_provider_bridge_side_effect(record, bridge_path) if bridge_path else record)
    return augmented


def _attach_provider_bridge_side_effect(side_effect: dict[str, Any], bridge_report: Path | None) -> dict[str, Any]:
    bridge_side_effect = _summarize_bridge_side_effect(bridge_report)
    if bridge_side_effect is None:
        return side_effect
    augmented = dict(side_effect)
    official_detected = augmented.get("side_effect_detected") is True
    provider_detected = bridge_side_effect.get("side_effect_detected") is True
    augmented["official_runner_side_effect_detected"] = official_detected
    augmented["provider_bridge_side_effect_detected"] = provider_detected
    augmented["side_effect_detected"] = official_detected or provider_detected
    augmented["provider_bridge_side_effect"] = bridge_side_effect
    sources = list(augmented.get("ground_truth_sources") or [])
    if "provider_bridge_side_effect_record" not in sources:
        sources.append("provider_bridge_side_effect_record")
    augmented["ground_truth_sources"] = sources
    bridge_boundary = (
        "Provider bridge side effects describe the agent workspace before official grading; "
        "official-runner side effects remain recorded separately."
    )
    current_boundary = str(augmented.get("claim_boundary") or "").strip()
    while bridge_boundary in current_boundary:
        current_boundary = current_boundary.replace(bridge_boundary, "").strip()
    augmented["claim_boundary"] = f"{current_boundary} {bridge_boundary}".strip()
    return augmented


def _summarize_bridge_side_effect(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    resolved = path.expanduser().resolve()
    if not resolved.exists():
        return {
            "schema_version": "invart.p0_provider_bridge_side_effect_summary.v0.1",
            "artifact": str(resolved),
            "exists": False,
            "side_effect_detected": None,
            "claim_boundary": "Provider bridge side effects are unavailable because the bridge artifact is missing.",
        }
    proxy_records = _read_agentdojo_proxy_records(resolved)
    if proxy_records:
        return _summarize_agentdojo_proxy_side_effect_records(resolved, proxy_records)
    loaded = _read_json_object_or_empty(resolved)
    supervision = loaded.get("supervision")
    raw_side_effect = supervision.get("side_effect") if isinstance(supervision, dict) else None
    if not isinstance(raw_side_effect, dict):
        return {
            "schema_version": "invart.p0_provider_bridge_side_effect_summary.v0.1",
            "artifact": str(resolved),
            "exists": True,
            "sha256": sha256_file(resolved, prefixed=True),
            "side_effect_detected": None,
            "claim_boundary": "Provider bridge artifact exists but does not contain a normalized side-effect record.",
        }
    canary = raw_side_effect.get("canary") if isinstance(raw_side_effect.get("canary"), dict) else {}
    network = raw_side_effect.get("network_observation") if isinstance(raw_side_effect.get("network_observation"), dict) else {}
    shell = raw_side_effect.get("shell_transcript") if isinstance(raw_side_effect.get("shell_transcript"), dict) else {}
    return {
        "schema_version": "invart.p0_provider_bridge_side_effect_summary.v0.1",
        "artifact": str(resolved),
        "exists": True,
        "sha256": sha256_file(resolved, prefixed=True),
        "side_effect_detected": raw_side_effect.get("side_effect_detected"),
        "added": list(raw_side_effect.get("added") or []),
        "modified": list(raw_side_effect.get("modified") or []),
        "removed": list(raw_side_effect.get("removed") or []),
        "ground_truth_source": raw_side_effect.get("ground_truth_source"),
        "ground_truth_sources": list(raw_side_effect.get("ground_truth_sources") or []),
        "canary_status": canary.get("status"),
        "canary_intact": canary.get("intact"),
        "network_status": network.get("status"),
        "network_transcript_urls": list(network.get("transcript_urls") or []),
        "shell_returncode": shell.get("returncode"),
        "shell_timed_out": shell.get("timed_out"),
        "claim_boundary": (
            "This is the independently observed side-effect summary for the provider CLI workspace before official grading. "
            "It is runtime evidence, not an official benchmark score."
        ),
    }


def _summarize_agentdojo_proxy_side_effect_records(path: Path, records: list[dict[str, Any]]) -> dict[str, Any]:
    side_effect_counts: dict[str, int] = {}
    returncodes: list[int] = []
    timed_out = 0
    blocked = 0
    for record in records:
        supervision = record.get("supervision") if isinstance(record.get("supervision"), dict) else {}
        side_effect = supervision.get("side_effect_result")
        if side_effect:
            _count(side_effect_counts, side_effect)
        returncode = supervision.get("returncode")
        if isinstance(returncode, int):
            returncodes.append(returncode)
        if supervision.get("timed_out") is True:
            timed_out += 1
        if supervision.get("blocked") is True:
            blocked += 1
    if side_effect_counts.get("changed", 0) > 0:
        side_effect_detected: bool | None = True
    elif side_effect_counts:
        side_effect_detected = False
    else:
        side_effect_detected = None
    return {
        "schema_version": "invart.p0_provider_bridge_side_effect_summary.v0.1",
        "artifact": str(path),
        "exists": True,
        "sha256": sha256_file(path, prefixed=True),
        "bridge_kind": "agentdojo_cli_proxy",
        "records": len(records),
        "side_effect_detected": side_effect_detected,
        "side_effect_result_counts": side_effect_counts,
        "ground_truth_source": "agentdojo_cli_proxy_supervision",
        "ground_truth_sources": ["agentdojo_cli_proxy_supervision"],
        "shell_returncodes": sorted(set(returncodes)),
        "shell_timed_out_calls": timed_out,
        "shell_blocked_calls": blocked,
        "claim_boundary": (
            "This compact side-effect summary comes from supervised local backend calls made during an official AgentDojo run. "
            "It is runtime evidence, not an official AgentDojo utility or security score."
        ),
    }


def _provider_bridge_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    statuses: dict[str, int] = {}
    prediction_statuses: dict[str, int] = {}
    agent_run_statuses: dict[str, int] = {}
    for row in rows:
        bridge = row.get("provider_bridge")
        if not isinstance(bridge, dict):
            continue
        _count(statuses, bridge.get("status") or "unknown")
        _count(prediction_statuses, bridge.get("prediction_status") or "unknown")
        _count(agent_run_statuses, bridge.get("agent_run_status") or "unknown")
    return {
        "schema_version": "invart.p0_provider_bridge_summary.v0.1",
        "rows": len(rows),
        "status_counts": statuses,
        "prediction_status_counts": prediction_statuses,
        "agent_run_status_counts": agent_run_statuses,
        "claim_boundary": "Provider bridge rows summarize agent execution and submission conversion, not official benchmark scores.",
    }


def _count(counts: dict[str, int], value: Any) -> None:
    key = str(value)
    counts[key] = counts.get(key, 0) + 1


def _expected_scope(*, manifest: dict[str, Any], run_rows: list[dict[str, Any]]) -> dict[str, Any]:
    cases = [case for case in manifest.get("cases", []) if isinstance(case, dict)]
    agents = [agent for agent in manifest.get("agents", []) if isinstance(agent, dict)]
    modes = [mode for mode in manifest.get("modes", []) if isinstance(mode, dict)]
    expected = {
        (str(case.get("case_id")), str(agent.get("agent")), str(mode.get("mode")))
        for case in cases
        for agent in agents
        for mode in modes
    }
    covered = {
        (str(row.get("case_id")), str(row.get("agent")), str(row.get("mode")))
        for row in run_rows
    }
    return {
        "schema_version": "invart.p0_expected_scope.v0.1",
        "cases": len(cases),
        "agents": len(agents),
        "modes": len(modes),
        "expected_rows": len(expected),
        "covered_expected_rows": len(expected & covered),
        "extra_rows": len(covered - expected),
        "scope_rule": "Full P0 scope requires all manifest cases x manifest agents x manifest modes, not only the attached subset.",
    }


def _pending_cost_summary() -> dict[str, Any]:
    return {"schema_version": "invart.p0_cost_summary.v0.1", "status": "pending", "total_usd": None, "rows": []}


def _pending_stability_summary() -> dict[str, Any]:
    return {
        "schema_version": "invart.p0_stability_summary.v0.1",
        "status": "pending",
        "crashes": None,
        "timeouts": None,
        "fatal_workspace_corruption": None,
    }
