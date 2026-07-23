from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from invart.core.artifacts import write_json_artifact
from invart.core.models import utc_now
from invart.surfaces.adapter_profiles import get_adapter_profile

from .first_batch import _render_agentdojo_row, _render_swe_row, _shell_default


SELECTED_SCHEMA_VERSION = "invart.p0_first_batch_selection.v0.1"
SELECTED_DOCTOR_SCHEMA_VERSION = "invart.p0_first_batch_selection_doctor.v0.1"


def select_p0_first_batch_rows(
    *,
    plan_path: Path,
    out_dir: Path,
    families: list[str] | None = None,
    agents: list[str] | None = None,
    modes: list[str] | None = None,
    case_ids: list[str] | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    resolved_plan_path = plan_path.expanduser().resolve()
    plan = _load_json_object(resolved_plan_path)
    root = out_dir.expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    source_manifest = _source_manifest_path(plan=plan, plan_path=resolved_plan_path)
    source_manifest_payload = _load_json_object(source_manifest)
    family_filter = set(families or [])
    agent_filter = set(agents or [])
    mode_filter = set(modes or [])
    case_filter = set(case_ids or [])

    selected: list[dict[str, Any]] = []
    for row in plan.get("swe_prediction_rows", []):
        if isinstance(row, dict) and _matches(row, "swe_bench_verified", family_filter, agent_filter, mode_filter, case_filter):
            selected.append(_selection_row(row, "swe_bench_verified"))
    for row in plan.get("agentdojo_rows", []):
        if isinstance(row, dict) and _matches(row, "agentdojo", family_filter, agent_filter, mode_filter, case_filter):
            selected.append(_selection_row(row, "agentdojo"))

    if limit is not None:
        if limit < 0:
            raise ValueError("--limit must be non-negative")
        selected = selected[:limit]

    selected_manifest_payload = _narrow_manifest_for_selection(source_manifest_payload, selected)
    selected_manifest = root / "p0_case_manifest.json"
    write_json_artifact(selected_manifest, selected_manifest_payload)

    script = _render_selected_script(plan, selected)
    script_path = root / "p0_first_batch_selected_commands.sh"
    script_path.write_text(script, encoding="utf-8")
    script_path.chmod(0o755)
    report = {
        "schema_version": SELECTED_SCHEMA_VERSION,
        "generated_at": utc_now(),
        "source_plan": str(resolved_plan_path),
        "source_manifest": str(source_manifest),
        "filters": {
            "family": sorted(family_filter),
            "agent": sorted(agent_filter),
            "mode": sorted(mode_filter),
            "case_id": sorted(case_filter),
            "limit": limit,
        },
        "selected_rows": selected,
        "selected_count": len(selected),
        "selection_scope": selected_manifest_payload.get("selection_scope", {}),
        "artifacts": {
            "p0_case_manifest.json": str(selected_manifest),
            "p0_first_batch_selected_rows.json": str(root / "p0_first_batch_selected_rows.json"),
            "p0_first_batch_selected_commands.sh": str(script_path),
            "p0_first_batch_selected_doctor.json": str(root / "p0_first_batch_selected_doctor.json"),
            "p0_first_batch_provider_skip.json": str(root / "p0_first_batch_provider_skip.json"),
        },
        "script": str(script_path),
        "official_method": {
            "swe_bench_verified": (
                "Generic provider CLIs produce a patch/predictions JSONL. The score must come from "
                "SWE-Bench's official swebench.harness.run_evaluation runner."
            ),
            "agentdojo": (
                "Rows use agentdojo.scripts.benchmark only when a registered AgentDojo model/adapter id "
                "is supplied. Otherwise the selector emits an explicit boundary artifact, not an official score."
            ),
        },
        "claim_boundary": (
            "This selection is a reproducible command plan, not benchmark evidence. It becomes evidence only after "
            "the selected rows run and attach official grader artifacts, side-effect records, and cost/stability summaries."
        ),
        "provider_run_gate": {
            "env": "INVART_P0_ALLOW_PROVIDER_RUN",
            "required_value": "1",
            "default": "skip_provider_commands",
            "skip_artifact": str(root / "p0_first_batch_provider_skip.json"),
            "claim_boundary": "Provider CLI rows require explicit opt-in because they may consume quota, tokens, wall time, or external service state.",
        },
    }
    write_json_artifact(root / "p0_first_batch_selected_rows.json", report)
    doctor_p0_first_batch_selection(run_dir=root)
    return report


def doctor_p0_first_batch_selection(*, run_dir: Path, python_executable: str | None = None) -> dict[str, Any]:
    root = run_dir.expanduser().resolve()
    python_bin = python_executable or sys.executable
    selection = _read_json_object_or_empty(root / "p0_first_batch_selected_rows.json")
    selected_rows = [row for row in selection.get("selected_rows", []) if isinstance(row, dict)]
    report: dict[str, Any] = {
        "schema_version": SELECTED_DOCTOR_SCHEMA_VERSION,
        "generated_at": utc_now(),
        "root": str(root),
        "status": "ready",
        "checks": {},
        "blocking": [],
        "warnings": [],
        "claim_boundary": (
            "Selected first-batch doctor checks readiness only. It does not install dependencies, run provider CLIs, "
            "or produce benchmark evidence."
        ),
    }
    report["checks"]["artifacts"] = _selected_artifact_checks(root)
    report["checks"]["script"] = _selected_script_check(root)
    report["checks"]["invart_import"] = _selected_invart_import_check(root, python_bin)
    report["checks"]["selected_rows"] = _selected_row_checks(selected_rows)
    report["checks"]["agents"] = _selected_agent_checks(selected_rows)
    report["checks"]["system_tools"] = _selected_system_tool_checks(selected_rows)
    report["checks"]["official_setup"] = _selected_official_setup_checks(root, selected_rows)
    report["checks"]["swe_instances"] = _selected_swe_instance_checks(root, selected_rows)
    report["checks"]["agentdojo_models"] = _selected_agentdojo_model_checks(selected_rows)
    _classify_selected_doctor(report)
    write_json_artifact(root / "p0_first_batch_selected_doctor.json", report)
    return report


def _matches(
    row: dict[str, Any],
    family: str,
    family_filter: set[str],
    agent_filter: set[str],
    mode_filter: set[str],
    case_filter: set[str],
) -> bool:
    if family_filter and family not in family_filter:
        return False
    if agent_filter and str(row.get("agent")) not in agent_filter:
        return False
    if mode_filter and str(row.get("mode")) not in mode_filter:
        return False
    if case_filter and str(row.get("case_id")) not in case_filter:
        return False
    return True


def _selection_row(row: dict[str, Any], family: str) -> dict[str, Any]:
    selected = {
        "row_id": row.get("row_id"),
        "family": family,
        "case_id": row.get("case_id"),
        "agent": row.get("agent"),
        "mode": row.get("mode"),
        "execution_status": "commands_emitted_only",
        "provider_spend_status": "not_executed_by_selector",
    }
    if family == "swe_bench_verified":
        selected.update({
            "instance_id": row.get("instance_id"),
            "official_input": row.get("predictions_path"),
            "official_grader": "swebench.harness.run_evaluation",
            "bridge": "generic_cli_agent_produces_patch_then_predictions_jsonl",
        })
    elif family == "agentdojo":
        selected.update({
            "benchmark_case_ref": row.get("benchmark_case_ref"),
            "model_env": row.get("model_env"),
            "official_grader": "agentdojo.scripts.benchmark when model_env is registered",
            "bridge": "registered_agentdojo_model_or_explicit_cli_boundary_artifact",
        })
    return selected


def _render_selected_script(plan: dict[str, Any], selected_rows: list[dict[str, Any]]) -> str:
    env = plan.get("script_environment") if isinstance(plan.get("script_environment"), dict) else {}
    invart_repo_hint = str(env.get("invart_repo_hint") or "")
    by_id = _row_lookup(plan)
    selected_families = sorted({str(row.get("family")) for row in selected_rows if row.get("family")})
    setup_family_args = " ".join(f"--family {family}" for family in selected_families)
    lines = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        'ROOT="$(cd "$(dirname "$0")" && pwd)"',
        'PYTHON_BIN="${PYTHON:-python3}"',
        f'INVART_REPO="${{INVART_REPO:-{_shell_default(invart_repo_hint)}}}"',
        'if [[ -d "$INVART_REPO/src/invart" ]]; then',
        '  export PYTHONPATH="$INVART_REPO/src:${PYTHONPATH:-}"',
        "fi",
        '"$PYTHON_BIN" -m invart.cli experiment list >/dev/null',
        'OFFICIAL_PY="${INVART_P0_OFFICIAL_PY:-$ROOT/.p0-official-venv/bin/python}"',
        "",
        "# Selected first-batch rows. This script intentionally emits an explicit, narrow run plan.",
        "# It may call provider CLIs only for the selected rows; use the JSON selection artifact as the audit handle.",
    ]
    if selected_families:
        lines.extend([
            "",
            "# Prepare only the official benchmark dependencies needed by the selected rows.",
            'if [[ -n "${INVART_P0_OFFICIAL_PY:-}" ]]; then',
            f'  "$PYTHON_BIN" -m invart.cli experiment p0-real-agent setup-official --manifest "$ROOT/p0_case_manifest.json" --out-dir "$ROOT" {setup_family_args} --python "$OFFICIAL_PY"',
            "else",
            f'  "$PYTHON_BIN" -m invart.cli experiment p0-real-agent setup-official --manifest "$ROOT/p0_case_manifest.json" --out-dir "$ROOT" {setup_family_args} --create-venv --install',
            "fi",
        ])
    if any(row.get("family") == "swe_bench_verified" for row in selected_rows):
        lines.extend([
            "",
            "# SWE-Bench Verified setup and official row export.",
            'mkdir -p "$ROOT/swe-instances" "$ROOT/repo-cache" "$ROOT/predictions" "$ROOT/swe-reports"',
            '"$PYTHON_BIN" -m invart.cli experiment p0-real-agent export-swe-instances --manifest "$ROOT/p0_case_manifest.json" --out-dir "$ROOT/swe-instances"',
        ])
    if any(row.get("family") == "agentdojo" for row in selected_rows):
        lines.extend([
            "",
            "# AgentDojo setup. Official scores require registered AgentDojo model/adapter ids.",
            'mkdir -p "$ROOT/agentdojo-logs" "$ROOT/agentdojo-boundaries"',
        ])
        lines.extend([
            "",
            "# AgentDojo boundary artifacts are safe to emit before provider execution.",
            "# They document that a provider CLI is not yet a registered AgentDojo model score.",
        ])
        for selected in selected_rows:
            source = by_id.get((str(selected.get("family")), str(selected.get("row_id"))))
            if isinstance(source, dict) and selected.get("family") == "agentdojo":
                lines.extend(_render_agentdojo_boundary_preview(source))
    if selected_rows:
        lines.extend(_render_provider_run_gate())
    for selected in selected_rows:
        source = by_id.get((str(selected.get("family")), str(selected.get("row_id"))))
        if not source:
            continue
        if selected.get("family") == "swe_bench_verified":
            lines.extend(_render_swe_row(source))
        elif selected.get("family") == "agentdojo":
            lines.extend(_render_agentdojo_row(source))
    lines.extend([
        "",
        "# Collect selected row packages into this root package for paper tables and claim matrix.",
        '"$PYTHON_BIN" -m invart.cli experiment p0-real-agent collect-runs --run-dir "$ROOT"',
        "",
    ])
    return "\n".join(lines)


def _render_agentdojo_boundary_preview(row: dict[str, Any]) -> list[str]:
    row_id = str(row["row_id"])
    case_id = str(row["case_id"])
    benchmark_case_ref = str(row["benchmark_case_ref"])
    agent = str(row["agent"])
    mode = str(row["mode"])
    suite = str(row["suite"])
    user_task = row.get("user_task")
    model_env = str(row["model_env"])
    boundary_dir = str(row["boundary_dir"])
    user_task_args = f' --user-task "{user_task}"' if user_task else ""
    return [
        "",
        f"# AgentDojo boundary preview: {row_id}",
        f'AGENTDOJO_MODEL="${{{model_env}:-}}"',
        'if [[ -z "$AGENTDOJO_MODEL" ]]; then',
        f'  "$PYTHON_BIN" -m invart.cli experiment p0-real-agent agentdojo-boundary --out-dir "$ROOT/{boundary_dir}" --case-id "{case_id}" --benchmark-case-ref "{benchmark_case_ref}" --agent "{agent}" --mode "{mode}" --suite "{suite}"{user_task_args} --model-env "{model_env}" --python "$OFFICIAL_PY"',
        "fi",
    ]


def _row_lookup(plan: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    for row in plan.get("swe_prediction_rows", []):
        if isinstance(row, dict):
            rows[("swe_bench_verified", str(row.get("row_id")))] = row
    for row in plan.get("agentdojo_rows", []):
        if isinstance(row, dict):
            rows[("agentdojo", str(row.get("row_id")))] = row
    return rows


def _load_json_object(path: Path) -> dict[str, Any]:
    loaded = json.loads(path.expanduser().read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError("first-batch plan must be a JSON object")
    return loaded


def _read_json_object_or_empty(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    loaded = json.loads(path.read_text(encoding="utf-8"))
    return loaded if isinstance(loaded, dict) else {}


def _source_manifest_path(*, plan: dict[str, Any], plan_path: Path) -> Path:
    candidates = [plan_path.parent / "p0_case_manifest.json"]
    artifacts = plan.get("artifacts")
    if isinstance(artifacts, dict) and artifacts.get("p0_case_manifest.json"):
        candidates.append(Path(str(artifacts["p0_case_manifest.json"])).expanduser())
    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()
    raise ValueError("selected first-batch package requires p0_case_manifest.json beside or referenced by the source plan")


def _narrow_manifest_for_selection(manifest: dict[str, Any], selected_rows: list[dict[str, Any]]) -> dict[str, Any]:
    selected_case_ids = {str(row.get("case_id")) for row in selected_rows if row.get("case_id")}
    selected_agents = {str(row.get("agent")) for row in selected_rows if row.get("agent")}
    selected_modes = {str(row.get("mode")) for row in selected_rows if row.get("mode")}
    selected_families = {str(row.get("family")) for row in selected_rows if row.get("family")}

    source_cases = [case for case in manifest.get("cases", []) if isinstance(case, dict)]
    source_agents = [agent for agent in manifest.get("agents", []) if isinstance(agent, dict)]
    source_modes = [mode for mode in manifest.get("modes", []) if isinstance(mode, dict)]
    source_agent_contracts = [item for item in manifest.get("agent_bridge_contracts", []) if isinstance(item, dict)]
    source_runner_contracts = [item for item in manifest.get("official_runner_contracts", []) if isinstance(item, dict)]

    cases = [case for case in source_cases if str(case.get("case_id")) in selected_case_ids]
    agents = [agent for agent in source_agents if str(agent.get("agent")) in selected_agents]
    modes = [mode for mode in source_modes if str(mode.get("mode")) in selected_modes]
    agent_contracts = [item for item in source_agent_contracts if str(item.get("agent")) in selected_agents]
    runner_contracts = [item for item in source_runner_contracts if str(item.get("family")) in selected_families]

    missing_cases = sorted(selected_case_ids - {str(case.get("case_id")) for case in cases})
    missing_agents = sorted(selected_agents - {str(agent.get("agent")) for agent in agents})
    missing_modes = sorted(selected_modes - {str(mode.get("mode")) for mode in modes})
    missing_families = sorted(selected_families - {str(item.get("family")) for item in runner_contracts})
    errors = []
    if selected_rows and (missing_cases or missing_agents or missing_modes or missing_families):
        errors.append({
            "missing_cases": missing_cases,
            "missing_agents": missing_agents,
            "missing_modes": missing_modes,
            "missing_families": missing_families,
        })
    if not selected_rows:
        errors.append({"reason": "selection is empty"})

    narrowed = dict(manifest)
    narrowed["name"] = str(manifest.get("name") or "p0-real-agent-official-benchmark-bridge") + "-selected"
    narrowed["generated_at"] = utc_now()
    narrowed["agents"] = agents
    narrowed["agent_bridge_contracts"] = agent_contracts
    narrowed["modes"] = modes
    narrowed["official_runner_contracts"] = runner_contracts
    narrowed["cases"] = cases
    narrowed["selection_scope"] = {
        "schema_version": "invart.p0_selected_manifest_scope.v0.1",
        "source_schema_version": manifest.get("schema_version"),
        "selected_rows": len(selected_rows),
        "case_ids": sorted(selected_case_ids),
        "agents": sorted(selected_agents),
        "modes": sorted(selected_modes),
        "families": sorted(selected_families),
        "claim_boundary": (
            "This selected manifest intentionally narrows the full P0 manifest for a first-batch execution slice. "
            "It is not evidence that the full 8-12 case P0 scope is complete."
        ),
    }
    narrowed["selection_validation"] = {
        "schema_version": "invart.p0_selected_manifest_validation.v0.1",
        "status": "pass" if not errors else "fail",
        "errors": errors,
        "summary": {
            "cases": len(cases),
            "agents": len(agents),
            "modes": len(modes),
            "families": sorted({str(case.get("family")) for case in cases}),
        },
    }
    narrowed["validation"] = {
        "schema_version": "invart.p0_real_agent_manifest_validation.v0.1",
        "status": "selected_scope",
        "errors": [],
        "summary": {
            "cases": len(cases),
            "families": sorted({str(case.get("family")) for case in cases}),
            "contracts": len(runner_contracts),
        },
        "claim_boundary": "Full P0 manifest validation is intentionally replaced by selected-scope validation for this mini-package.",
    }
    return narrowed


def _selected_artifact_checks(root: Path) -> dict[str, Any]:
    names = [
        "p0_case_manifest.json",
        "p0_first_batch_selected_rows.json",
        "p0_first_batch_selected_commands.sh",
    ]
    rows = [{"name": name, "exists": (root / name).exists()} for name in names]
    return {"status": "pass" if all(row["exists"] for row in rows) else "fail", "files": rows}


def _selected_script_check(root: Path) -> dict[str, Any]:
    path = root / "p0_first_batch_selected_commands.sh"
    if not path.exists():
        return {"status": "fail", "reason": "missing selected command script"}
    result = _run(["bash", "-n", str(path)], cwd=root, timeout=30)
    text = path.read_text(encoding="utf-8")
    return {
        "status": "pass" if result.get("returncode") == 0 else "fail",
        "syntax_probe": result,
        "contains_setup_official": "setup-official" in text,
        "contains_provider_bridge": "swe-prediction" in text or "agentdojo-boundary" in text or "execute-official" in text,
        "contains_provider_run_gate": "INVART_P0_ALLOW_PROVIDER_RUN" in text and "p0_first_batch_provider_skip.json" in text,
    }


def _selected_invart_import_check(root: Path, python_bin: str) -> dict[str, Any]:
    repo_hint = _invart_repo_hint()
    env = os.environ.copy()
    if repo_hint:
        env["PYTHONPATH"] = str(Path(repo_hint) / "src") + os.pathsep + env.get("PYTHONPATH", "")
    result = _run([python_bin, "-m", "invart.cli", "experiment", "list"], cwd=root, timeout=30, env=env)
    return {
        "status": "pass" if result.get("returncode") == 0 else "fail",
        "python": python_bin,
        "invart_repo_hint": repo_hint,
        "probe": result,
    }


def _selected_row_checks(selected_rows: list[dict[str, Any]]) -> dict[str, Any]:
    row_ids = [str(row.get("row_id")) for row in selected_rows if row.get("row_id")]
    return {
        "status": "pass" if selected_rows and len(row_ids) == len(set(row_ids)) else "fail",
        "selected_count": len(selected_rows),
        "row_ids": row_ids,
        "families": sorted({str(row.get("family")) for row in selected_rows if row.get("family")}),
        "claim_boundary": "Selected rows are command-plan rows until their scripts produce run matrix and grader artifacts.",
    }


def _selected_agent_checks(selected_rows: list[dict[str, Any]]) -> dict[str, Any]:
    agents = sorted({str(row.get("agent")) for row in selected_rows if row.get("agent")})
    rows = []
    for agent in agents:
        profile = get_adapter_profile(agent)
        binaries = []
        for candidate in profile.get("binary_candidates", []) or []:
            path = shutil.which(str(candidate))
            binaries.append({"candidate": candidate, "path": path, "available": path is not None})
        rows.append({
            "agent": agent,
            "available": any(item["available"] for item in binaries),
            "binary_candidates": binaries,
            "claim_boundary": "Binary availability does not prove provider authentication, quota, or spend permission.",
        })
    return {"status": "pass" if rows and all(row["available"] for row in rows) else "blocked", "agents": rows}


def _selected_official_setup_checks(root: Path, selected_rows: list[dict[str, Any]]) -> dict[str, Any]:
    families = sorted({str(row.get("family")) for row in selected_rows if row.get("family")})
    setup_path = root / "p0_official_setup.json"
    if not setup_path.exists():
        return {
            "status": "needs_setup",
            "families": families,
            "reason": "p0_official_setup.json is not present yet; selected script will run setup-official before benchmark rows.",
        }
    setup = _read_json_object_or_empty(setup_path)
    entrypoints = setup.get("entrypoints", {}) if isinstance(setup.get("entrypoints"), dict) else {}
    selected = {family: entrypoints.get(family, {}) for family in families}
    ready = bool(selected) and all(isinstance(value, dict) and value.get("status") in {"pass", "skipped"} for value in selected.values())
    return {"status": "pass" if ready else "needs_setup", "setup_status": setup.get("status"), "entrypoints": selected}


def _selected_swe_instance_checks(root: Path, selected_rows: list[dict[str, Any]]) -> dict[str, Any]:
    rows = [row for row in selected_rows if row.get("family") == "swe_bench_verified"]
    if not rows:
        return {"status": "not_applicable", "instances": []}
    instances = []
    for row in rows:
        instance_id = str(row.get("instance_id") or "")
        path = root / "swe-instances" / f"{instance_id}.json"
        instances.append({"instance_id": instance_id, "path": str(path), "exists": path.exists()})
    return {
        "status": "pass" if instances and all(item["exists"] for item in instances) else "will_export",
        "instances": instances,
        "note": "selected script exports official SWE rows before workspace preparation.",
    }


def _selected_agentdojo_model_checks(selected_rows: list[dict[str, Any]]) -> dict[str, Any]:
    rows = []
    for row in selected_rows:
        if row.get("family") != "agentdojo":
            continue
        env_name = str(row.get("model_env") or "")
        rows.append({"row_id": row.get("row_id"), "agent": row.get("agent"), "env": env_name, "set": bool(os.environ.get(env_name))})
    return {
        "status": "pass" if rows and all(row["set"] for row in rows) else ("boundary_only" if rows else "not_applicable"),
        "models": rows,
        "claim_boundary": "Unset AgentDojo model env means selected script writes boundary artifacts instead of official AgentDojo scores.",
    }


def _classify_selected_doctor(report: dict[str, Any]) -> None:
    blocking = []
    warnings = []
    checks = report.get("checks", {})
    for name in ("artifacts", "script", "invart_import", "selected_rows", "agents", "system_tools"):
        status = checks.get(name, {}).get("status") if isinstance(checks.get(name), dict) else None
        if status in {"fail", "blocked"}:
            blocking.append({"check": name, "status": status})
    for name in ("official_setup", "swe_instances", "agentdojo_models"):
        status = checks.get(name, {}).get("status") if isinstance(checks.get(name), dict) else None
        if status not in {"pass", "not_applicable", None}:
            warnings.append({"check": name, "status": status})
    report["blocking"] = blocking
    report["warnings"] = warnings
    report["status"] = "ready" if not blocking else "blocked"


def _render_provider_run_gate() -> list[str]:
    return [
        "",
        "# Provider CLIs may consume external quota or tokens. Keep setup/export safe by default.",
        'if [[ "${INVART_P0_ALLOW_PROVIDER_RUN:-0}" != "1" ]]; then',
        '  ROOT_JSON="$ROOT" "$PYTHON_BIN" - <<\'PY\'',
        "import json, os, pathlib",
        "root = pathlib.Path(os.environ['ROOT_JSON'])",
        "payload = {",
        "    'schema_version': 'invart.p0_first_batch_provider_skip.v0.1',",
        "    'status': 'provider_run_skipped',",
        "    'required_env': {'INVART_P0_ALLOW_PROVIDER_RUN': '1'},",
        "    'claim_boundary': 'Official setup and row export may have run, but provider CLI rows and official grader rows were not executed.',",
        "}",
        "root.joinpath('p0_first_batch_provider_skip.json').write_text(json.dumps(payload, indent=2, sort_keys=True) + '\\n', encoding='utf-8')",
        "PY",
        '  echo "Provider rows skipped. Set INVART_P0_ALLOW_PROVIDER_RUN=1 to execute selected provider CLI rows." >&2',
        "  exit 0",
        "fi",
    ]


def _selected_system_tool_checks(selected_rows: list[dict[str, Any]]) -> dict[str, Any]:
    families = {str(row.get("family")) for row in selected_rows if row.get("family")}
    required = ["bash", "git"]
    if "swe_bench_verified" in families:
        required.append("docker")
    rows = []
    for tool in required:
        path = shutil.which(tool)
        rows.append({
            "tool": tool,
            "path": path,
            "available": path is not None,
            "reason": _tool_reason(tool),
        })
    return {
        "status": "pass" if rows and all(row["available"] for row in rows) else "blocked",
        "tools": rows,
        "claim_boundary": "System tool availability is execution readiness only; it is not benchmark evidence.",
    }


def _tool_reason(tool: str) -> str:
    if tool == "docker":
        return "SWE-Bench official harness executes tests in Docker images by default."
    if tool == "git":
        return "SWE workspace preparation and patch capture require git."
    return "selected shell scripts require bash."


def _run(command: list[str], *, cwd: Path, timeout: int, env: dict[str, str] | None = None) -> dict[str, Any]:
    try:
        completed = subprocess.run(command, cwd=str(cwd), env=env, capture_output=True, text=True, timeout=timeout)
        return {
            "command": command,
            "returncode": completed.returncode,
            "stdout_tail": completed.stdout[-2000:],
            "stderr_tail": completed.stderr[-2000:],
        }
    except Exception as exc:
        return {"command": command, "returncode": None, "error": type(exc).__name__, "message": str(exc)}


def _invart_repo_hint() -> str:
    path = Path(__file__).resolve()
    for parent in path.parents:
        if (parent / "src" / "invart").exists() and (parent / "pyproject.toml").exists():
            return str(parent)
    return ""
