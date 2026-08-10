from __future__ import annotations

import os
import shutil
from collections import Counter
from pathlib import Path
from typing import Any

from invart.core.artifacts import write_json_artifact
from invart.core.models import utc_now

from .case_manifest import default_p0_case_manifest
from .official_runners import (
    build_agentdojo_command,
    build_agentsecbench_command,
    build_skill_inject_command,
    build_swe_bench_verified_command,
)
from .provider_credentials import (
    provider_api_keys,
    provider_credential_missing_label,
    provider_credential_options,
    provider_credential_present,
)
from .target_scope import build_p0_target_scope_report
from invart.surfaces.adapter_profiles import get_adapter_profile


SCHEMA_VERSION = "invart.p0_target_continuation.v0.1"


def write_p0_target_continuation_artifacts(
    *,
    root: Path,
    manifest: dict[str, Any],
    run_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    resolved = root.expanduser().resolve()
    target_scope = build_p0_target_scope_report(manifest=manifest, run_rows=run_rows)
    expansion_manifest = build_p0_target_expansion_manifest(manifest, target_scope=target_scope)
    write_json_artifact(resolved / "p0_target_expansion_manifest.json", expansion_manifest)
    payload = build_p0_target_continuation_report(
        root=resolved,
        target_scope=target_scope,
        expansion_manifest=expansion_manifest,
    )
    write_json_artifact(resolved / "p0_target_continuation.json", payload)
    (resolved / "p0_target_continuation.md").write_text(render_p0_target_continuation_markdown(payload), encoding="utf-8")
    script = render_p0_target_continuation_script(payload)
    script_path = resolved / "p0_target_continuation_commands.sh"
    script_path.write_text(script, encoding="utf-8")
    script_path.chmod(0o755)
    payload["artifacts"] = {
        **payload.get("artifacts", {}),
        "p0_target_continuation_commands.sh": str(script_path),
    }
    write_json_artifact(resolved / "p0_target_continuation.json", payload)
    return payload


def build_p0_target_expansion_manifest(
    manifest: dict[str, Any],
    *,
    target_scope: dict[str, Any] | None = None,
) -> dict[str, Any]:
    agents = [str(item.get("agent")) for item in manifest.get("agents", []) if isinstance(item, dict) and item.get("agent")]
    expansion = default_p0_case_manifest(agents=agents or None)
    absent_case_ids = _absent_case_ids(target_scope or {})
    if target_scope is not None:
        expansion["cases"] = [
            item
            for item in expansion.get("cases", [])
            if isinstance(item, dict) and str(item.get("case_id")) in absent_case_ids
        ]
    mode_ids = {str(item.get("mode")) for item in manifest.get("modes", []) if isinstance(item, dict) and item.get("mode")}
    if mode_ids:
        expansion["modes"] = [
            item for item in expansion.get("modes", []) if isinstance(item, dict) and str(item.get("mode")) in mode_ids
        ]
    expansion["name"] = "p0-real-agent-target-expansion-manifest"
    expansion["source_manifest_boundary"] = (
        "Generated from the current package manifest to run target-scope cases absent from the current package. "
        "This manifest is a row-specific run plan, not evidence."
    )
    expansion["target_expansion_scope"] = {
        "schema_version": "invart.p0_target_expansion_scope.v0.1",
        "case_ids": [
            str(item.get("case_id"))
            for item in expansion.get("cases", [])
            if isinstance(item, dict) and item.get("case_id")
        ],
        "source_target_cases": len((target_scope or {}).get("target_cases", [])),
        "claim_boundary": (
            "This manifest intentionally includes only target cases absent from the current package manifest. "
            "Current-manifest missing rows are handled by p0_remaining_commands.sh."
        ),
    }
    expansion["validation"] = {
        "schema_version": "invart.p0_real_agent_manifest_validation.v0.1",
        "status": "target_expansion_scope",
        "errors": [],
        "summary": {
            "cases": len(expansion.get("cases", [])),
            "families": sorted({
                str(case.get("family"))
                for case in expansion.get("cases", [])
                if isinstance(case, dict) and case.get("family")
            }),
            "contracts": len(expansion.get("official_runner_contracts", [])),
        },
        "claim_boundary": (
            "Full P0 manifest validation is intentionally replaced by target-expansion-scope validation for this "
            "continuation package."
        ),
    }
    return expansion


def build_p0_target_continuation_report(
    *,
    root: Path,
    target_scope: dict[str, Any],
    expansion_manifest: dict[str, Any],
) -> dict[str, Any]:
    continuation = target_scope.get("continuation_plan") if isinstance(target_scope.get("continuation_plan"), dict) else {}
    current_rows = [row for row in continuation.get("current_manifest_rows", []) if isinstance(row, dict)]
    expansion_rows = [row for row in continuation.get("target_expansion_rows", []) if isinstance(row, dict)]
    row_actions = [_row_action(row) for row in current_rows + expansion_rows]
    row_action_counts = _row_action_counts(row_actions)
    external_inputs = _external_inputs(row_actions)
    readiness = _readiness_checks(row_actions, root=root)
    required_keys = sorted({
        key
        for action in row_actions
        for key in action.get("required_api_keys", [])
        if isinstance(key, str) and key
    })
    missing_external_rows = readiness["summary"]["missing_external_input_rows"]
    status = "complete" if not row_actions else (
        "blocked_by_external_credentials" if missing_external_rows else "needs_target_expansion_run"
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "root": str(root),
        "status": status,
        "target_scope_status": target_scope.get("status"),
        "target_scope_complete": target_scope.get("target_scope_complete"),
        "summary": {
            "current_manifest_rows": len(current_rows),
            "target_expansion_rows": len(expansion_rows),
            "row_actions": len(row_actions),
            "official_command_spec_rows": sum(1 for row in row_actions if row.get("official_command_spec")),
            "required_api_keys": required_keys,
            "target_expansion_cases": len(expansion_manifest.get("cases", [])),
            "agents": len(expansion_manifest.get("agents", [])),
            "modes": len(expansion_manifest.get("modes", [])),
            "ready_after_run_gate_rows": readiness["summary"]["ready_after_run_gate_rows"],
            "missing_external_input_rows": readiness["summary"]["missing_external_input_rows"],
            "missing_prerequisite_rows": readiness["summary"]["missing_prerequisite_rows"],
            "missing_official_setup_rows": readiness["summary"]["missing_official_setup_rows"],
        },
        "row_action_counts": row_action_counts,
        "external_inputs": external_inputs,
        "readiness": readiness,
        "required_api_keys": required_keys,
        "provider_run_gate": {
            "env": "INVART_P0_ALLOW_TARGET_EXPANSION_RUN",
            "required_value": "1",
            "default": "plan_only",
            "claim_boundary": (
                "Target continuation may invoke provider CLIs, official benchmark runners, Docker, or networked "
                "dependencies. The generated script emits plans by default and runs provider paths only after opt-in."
            ),
        },
        "row_actions": row_actions,
        "artifacts": {
            "p0_target_expansion_manifest.json": str(root / "p0_target_expansion_manifest.json"),
            "p0_target_continuation.json": str(root / "p0_target_continuation.json"),
            "p0_target_continuation.md": str(root / "p0_target_continuation.md"),
        },
        "claim_boundary": (
            "Target continuation artifacts make the remaining original P0 target rows executable or explicitly gated. "
            "They do not create benchmark evidence, provider executions, side-effect records, or official scores."
        ),
    }


def render_p0_target_continuation_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    counts = report.get("row_action_counts") if isinstance(report.get("row_action_counts"), dict) else {}
    lines = [
        "# P0 Target Continuation",
        "",
        f"- Status: `{report.get('status', 'unknown')}`",
        f"- Target scope complete: `{str(report.get('target_scope_complete', False)).lower()}`",
        f"- Current-manifest rows: `{summary.get('current_manifest_rows', 0)}`",
        f"- Target-expansion rows: `{summary.get('target_expansion_rows', 0)}`",
        f"- Ready after run gate: `{summary.get('ready_after_run_gate_rows', 0)}`",
        f"- Missing external input rows: `{summary.get('missing_external_input_rows', 0)}`",
        f"- Missing prerequisite rows: `{summary.get('missing_prerequisite_rows', 0)}`",
        f"- Missing official setup rows: `{summary.get('missing_official_setup_rows', 0)}`",
        f"- Required API keys: `{', '.join(report.get('required_api_keys', [])) or 'none'}`",
        "",
        "## Execution Boundary",
        "",
        str(report.get("claim_boundary") or ""),
        "",
        "## Action Summary",
        "",
        f"- By gap: `{_summary_counts(counts.get('by_gap_type'))}`",
        f"- By family: `{_summary_counts(counts.get('by_family'))}`",
        f"- By gate: `{_summary_counts(counts.get('by_gate'))}`",
        "",
        "## Readiness",
        "",
        "| Status | Rows |",
        "|---|---:|",
    ]
    readiness = report.get("readiness") if isinstance(report.get("readiness"), dict) else {}
    readiness_counts = readiness.get("by_status") if isinstance(readiness.get("by_status"), dict) else {}
    if readiness_counts:
        for status in sorted(readiness_counts):
            lines.append(f"| {_md(status)} | {readiness_counts[status]} |")
    else:
        lines.append("| none | 0 |")
    lines.extend([
        "",
        "## Official Runner Recipes",
        "",
        "| Family | Example command | Boundary |",
        "|---|---|---|",
    ])
    command_examples = _example_official_command_specs(report.get("row_actions", []))
    for item in command_examples:
        lines.append(
            f"| {_md(item.get('family'))} | `{_md(' '.join(item.get('command', [])))}` | "
            f"{_md(item.get('claim_boundary'))} |"
        )
    if not command_examples:
        lines.append("| none |  |  |")
    lines.extend([
        "",
        "## External Inputs",
        "",
        "| Input | Kind | Rows | Present |",
        "|---|---|---:|---|",
    ])
    external_inputs = report.get("external_inputs") if isinstance(report.get("external_inputs"), list) else []
    if external_inputs:
        for item in external_inputs:
            if isinstance(item, dict):
                lines.append(
                    f"| `{_md(item.get('name'))}` | {_md(item.get('kind'))} | "
                    f"{_md(item.get('required_for_rows'))} | `{str(bool(item.get('present'))).lower()}` |"
                )
    else:
        lines.append("| none |  | 0 | `false` |")
    lines.extend([
        "",
        "## Row Actions",
        "",
        "| Gap | Family | Case | Agent | Mode | Action | Gate |",
        "|---|---|---|---|---|---|---|",
    ])
    for action in report.get("row_actions", [])[:36]:
        if isinstance(action, dict):
            lines.append(
                f"| {_md(action.get('gap_type'))} | {_md(action.get('family'))} | {_md(action.get('case_id'))} | "
                f"{_md(action.get('agent'))} | {_md(action.get('mode'))} | {_md(action.get('action'))} | "
                f"{_md(action.get('gate'))} |"
            )
    remaining = len(report.get("row_actions", [])) - min(36, len(report.get("row_actions", [])))
    if remaining > 0:
        lines.append(f"| more | `{remaining}` additional actions in JSON |  |  |  |  |  |")
    return "\n".join(lines).rstrip() + "\n"


def render_p0_target_continuation_script(report: dict[str, Any]) -> str:
    rows = [row for row in report.get("row_actions", []) if isinstance(row, dict)]
    agentsecbench_rows = [row for row in rows if row.get("family") == "agentsecbench"]
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    has_current_manifest_rows = int(summary.get("current_manifest_rows") or 0) > 0
    has_target_expansion_rows = int(summary.get("target_expansion_rows") or 0) > 0
    lines = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        "ROOT=\"$(cd \"$(dirname \"$0\")\" && pwd)\"",
        "PYTHON_BIN=\"${PYTHON:-python3}\"",
        "INVART_REPO=\"${INVART_REPO:-$(cd \"$ROOT/../../..\" 2>/dev/null && pwd)}\"",
        "if [[ -d \"$INVART_REPO/src/invart\" ]]; then",
        "  export PYTHONPATH=\"$INVART_REPO/src:${PYTHONPATH:-}\"",
        "fi",
        "TARGET_ROOT=\"${INVART_P0_TARGET_ROOT:-$ROOT/p0-target-continuation}\"",
        "mkdir -p \"$TARGET_ROOT\" \"$TARGET_ROOT/skips\"",
        "if [[ \"${INVART_P0_ALLOW_TARGET_EXPANSION_RUN:-0}\" != \"1\" ]]; then",
        "  printf '{\"status\":\"planned\",\"reason\":\"set INVART_P0_ALLOW_TARGET_EXPANSION_RUN=1 to run provider/official continuation commands\"}\\n' > \"$TARGET_ROOT/skips/provider-run-gate.json\"",
        "  exit 0",
        "fi",
    ]
    if has_current_manifest_rows:
        lines.extend([
            "",
            "# Current-manifest rows are already declared by the source package; run its guarded continuation first.",
            "if [[ -x \"$ROOT/p0_remaining_commands.sh\" ]]; then",
            "  INVART_P0_CONTINUATION_ROOT=\"$TARGET_ROOT/current-manifest\" \"$ROOT/p0_remaining_commands.sh\"",
            "else",
            "  printf '{\"status\":\"skipped\",\"reason\":\"missing p0_remaining_commands.sh\"}\\n' > \"$TARGET_ROOT/skips/missing-current-manifest-continuation.json\"",
            "fi",
        ])
    if has_target_expansion_rows:
        lines.extend([
            "",
            "# Target-expansion rows use a narrowed manifest containing only absent target cases.",
            "\"$PYTHON_BIN\" -m invart.cli experiment p0-real-agent first-batch --manifest \"$ROOT/p0_target_expansion_manifest.json\" --out-dir \"$TARGET_ROOT/target-expansion\"",
            "\"$TARGET_ROOT/target-expansion/p0_first_batch_commands.sh\"",
        ])
    if agentsecbench_rows:
        lines.extend([
            "",
            "# AgentSecBench target-expansion rows. The upstream repository must be provided explicitly.",
            "AGENTSECBENCH_REPO=\"${INVART_AGENTSECBENCH_REPO:-}\"",
            "if [[ -z \"$AGENTSECBENCH_REPO\" || ! -d \"$AGENTSECBENCH_REPO\" ]]; then",
            "  printf '{\"status\":\"skipped\",\"reason\":\"missing AgentSecBench repository\",\"env\":\"INVART_AGENTSECBENCH_REPO\"}\\n' > \"$TARGET_ROOT/skips/missing-agentsecbench-repo.json\"",
            "else",
        ])
        for row in agentsecbench_rows:
            lines.extend(_render_agentsecbench_target_row(row))
        lines.append("fi")
    lines.extend([
        "\"$PYTHON_BIN\" -m invart.cli experiment p0-real-agent collect-runs --run-dir \"$TARGET_ROOT\"",
        "\"$PYTHON_BIN\" -m invart.cli experiment p0-real-agent merge-packages --out-dir \"$TARGET_ROOT/merged-with-source\" --package-dir \"$ROOT\" --package-dir \"$TARGET_ROOT\"",
        "",
    ])
    return "\n".join(lines)


def _row_action(row: dict[str, Any]) -> dict[str, Any]:
    family = str(row.get("family") or "")
    agent = str(row.get("agent") or "")
    gap = str(row.get("gap_type") or "")
    required_keys = _required_keys(family=family, agent=agent)
    if gap == "missing_from_manifest_run_matrix":
        action = "run_or_attach_current_manifest_row"
        gate = "provider_credentials" if required_keys else "official_runner_artifact"
    else:
        action = "expand_manifest_then_run_official_row"
        gate = "provider_credentials_or_official_dependency" if required_keys else "official_dependency"
    return {
        "row_id": row.get("row_id"),
        "gap_type": gap,
        "family": family,
        "case_id": row.get("case_id"),
        "benchmark_case_ref": row.get("benchmark_case_ref"),
        "agent": agent,
        "mode": row.get("mode"),
        "action": action,
        "gate": gate,
        "required_api_keys": required_keys,
        "provider_credential_options": provider_credential_options(agent),
        "official_method": _official_method(family),
        "official_command_spec": _official_command_spec(
            family=family,
            case_id=str(row.get("case_id") or ""),
            benchmark_case_ref=str(row.get("benchmark_case_ref") or ""),
            agent=agent,
            mode=str(row.get("mode") or ""),
            row_id=str(row.get("row_id") or ""),
        ),
        "claim_boundary": row.get("claim_boundary"),
    }


def _row_action_counts(row_actions: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    return {
        "by_gap_type": _counter_dict(row.get("gap_type") for row in row_actions),
        "by_family": _counter_dict(row.get("family") for row in row_actions),
        "by_gate": _counter_dict(row.get("gate") for row in row_actions),
        "by_action": _counter_dict(row.get("action") for row in row_actions),
    }


def _external_inputs(row_actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    inputs: dict[tuple[str, str], dict[str, Any]] = {}

    def add(
        name: str,
        kind: str,
        row_id: Any,
        *,
        secret_material: bool = False,
        required: bool = True,
        present: bool | None = None,
    ) -> None:
        key = (name, kind)
        payload = inputs.setdefault(
            key,
            {
                "name": name,
                "kind": kind,
                "required": required,
                "secret_material": secret_material,
                "present": bool(os.environ.get(name)) if present is None else bool(present),
                "required_for_rows": 0,
                "row_ids": [],
                "claim_boundary": (
                    "Only boolean presence is recorded. Secret values, tokens, repository paths, and provider "
                    "configuration contents are never serialized into P0 artifacts."
                ),
            },
        )
        payload["required_for_rows"] += 1
        if row_id:
            payload["row_ids"].append(str(row_id))

    for action in row_actions:
        row_id = action.get("row_id")
        family = str(action.get("family") or "")
        agent = str(action.get("agent") or "")
        for key in action.get("required_api_keys", []):
            if key:
                add(str(key), "provider_api_key", row_id, secret_material=True)
        for option in action.get("provider_credential_options", []):
            if isinstance(option, dict) and option.get("kind") == "provider_cli_config":
                add(
                    str(option.get("name") or "PROVIDER_CLI_CONFIG"),
                    "provider_cli_config",
                    row_id,
                    secret_material=True,
                    present=bool(option.get("present")),
                )
        if family == "skill_inject":
            add("INVART_SKILL_INJECT_REPO", "upstream_repository", row_id)
        if family == "agentsecbench":
            add("INVART_AGENTSECBENCH_REPO", "upstream_repository", row_id)
        if family == "agentdojo":
            add(_agentdojo_model_env(agent), "official_runner_model_adapter", row_id)
            add(_agentdojo_model_id_env(agent), "official_runner_model_id", row_id, required=False)
            add(_agentdojo_local_port_env(agent), "official_runner_local_port", row_id, required=False)

    return sorted(inputs.values(), key=lambda item: (str(item["kind"]), str(item["name"])))


def _readiness_checks(row_actions: list[dict[str, Any]], *, root: Path) -> dict[str, Any]:
    official_setup = _official_setup_status(root)
    rows = [_row_readiness(action, official_setup=official_setup) for action in row_actions]
    by_status = _counter_dict(row.get("status") for row in rows)
    ready_after_gate = sum(1 for row in rows if row.get("status") == "ready_after_run_gate")
    missing_inputs = sum(1 for row in rows if row.get("missing_external_inputs"))
    missing_prerequisites = sum(1 for row in rows if row.get("missing_prerequisites"))
    missing_official_setup = sum(1 for row in rows if row.get("official_setup_ready") is False)
    return {
        "schema_version": "invart.p0_target_continuation_readiness.v0.1",
        "provider_run_gate": {
            "env": "INVART_P0_ALLOW_TARGET_EXPANSION_RUN",
            "present": os.environ.get("INVART_P0_ALLOW_TARGET_EXPANSION_RUN") == "1",
            "claim_boundary": "A false gate means generated scripts remain plan-only even when other prerequisites are present.",
        },
        "summary": {
            "rows": len(rows),
            "ready_after_run_gate_rows": ready_after_gate,
            "missing_external_input_rows": missing_inputs,
            "missing_prerequisite_rows": missing_prerequisites,
            "missing_official_setup_rows": missing_official_setup,
        },
        "official_setup": official_setup,
        "by_status": by_status,
        "rows": rows,
        "claim_boundary": (
            "Readiness is preflight evidence only. It records whether a row appears attemptable from local binaries "
            "and named external inputs; it is not execution evidence, side-effect evidence, or an official score."
        ),
    }


def _row_readiness(action: dict[str, Any], *, official_setup: dict[str, Any]) -> dict[str, Any]:
    family = str(action.get("family") or "")
    agent = str(action.get("agent") or "")
    row_id = str(action.get("row_id") or "")
    missing_external_inputs = _missing_external_inputs(action)
    agent_available = _agent_binary_available(agent)
    command_spec = action.get("official_command_spec")
    has_command_spec = isinstance(command_spec, dict) and bool(command_spec.get("command"))
    family_setup = official_setup.get("families", {}).get(family, {}) if isinstance(official_setup.get("families"), dict) else {}
    official_setup_ready = family_setup.get("ready") is True
    gate_open = os.environ.get("INVART_P0_ALLOW_TARGET_EXPANSION_RUN") == "1"
    blockers: list[str] = []
    if not agent_available:
        blockers.append("agent_cli")
    if not has_command_spec:
        blockers.append("official_command_spec")
    if not official_setup_ready:
        blockers.append(f"official_setup:{family}")
    blockers.extend(missing_external_inputs)
    if missing_external_inputs:
        status = "missing_external_inputs"
    elif blockers:
        status = "missing_prerequisites"
    elif gate_open:
        status = "ready_to_attempt"
    else:
        status = "ready_after_run_gate"
    return {
        "row_id": row_id,
        "family": family,
        "case_id": action.get("case_id"),
        "agent": agent,
        "mode": action.get("mode"),
        "status": status,
        "agent_cli_available": agent_available,
        "official_command_spec_present": has_command_spec,
        "official_setup_ready": official_setup_ready,
        "official_setup_status": family_setup.get("status", "missing"),
        "missing_external_inputs": missing_external_inputs,
        "missing_prerequisites": blockers,
        "missing_inputs": blockers,
        "run_gate_open": gate_open,
        "claim_boundary": (
            "This row-level readiness check contains only names and booleans. It does not prove provider authentication, "
            "benchmark execution, or score validity."
        ),
    }


def _official_setup_status(root: Path) -> dict[str, Any]:
    setup_path = root / "p0_official_setup.json"
    if not setup_path.exists():
        return {
            "status": "missing",
            "families": {},
            "claim_boundary": "No p0_official_setup.json was found. Official runner entrypoint readiness is unknown.",
        }
    try:
        setup = _read_json_object(setup_path)
    except Exception:
        return {
            "status": "unreadable",
            "families": {},
            "claim_boundary": "p0_official_setup.json could not be parsed. Official runner entrypoint readiness is unknown.",
        }
    entrypoints = setup.get("entrypoints") if isinstance(setup.get("entrypoints"), dict) else {}
    families: dict[str, dict[str, Any]] = {}
    for family in ("agentdojo", "agentsecbench", "skill_inject", "swe_bench_verified"):
        entrypoint = entrypoints.get(family) if isinstance(entrypoints.get(family), dict) else {}
        status = str(entrypoint.get("status") or "missing")
        families[family] = {
            "status": status,
            "ready": status == "pass",
            "claim_boundary": (
                "Official setup readiness is based on entrypoint preflight only. It is not benchmark execution evidence."
            ),
        }
    return {
        "status": str(setup.get("status") or "unknown"),
        "families": families,
        "claim_boundary": (
            "Official setup status is serialized only as coarse readiness fields; command output and local paths remain "
            "in p0_official_setup.json, not duplicated into target continuation rows."
        ),
    }


def _read_json_object(path: Path) -> dict[str, Any]:
    import json

    loaded = json.loads(path.read_text(encoding="utf-8"))
    return loaded if isinstance(loaded, dict) else {}


def _missing_external_inputs(action: dict[str, Any]) -> list[str]:
    missing: list[str] = []
    family = str(action.get("family") or "")
    agent = str(action.get("agent") or "")
    required_keys = {str(key) for key in action.get("required_api_keys", []) if key}
    for key in action.get("required_api_keys", []):
        if key and not os.environ.get(str(key)):
            missing.append(str(key))
    if family == "skill_inject" and required_keys:
        missing = [item for item in missing if item not in required_keys]
        if not provider_credential_present(agent):
            missing.append(provider_credential_missing_label(agent))
    if family == "skill_inject" and not os.environ.get("INVART_SKILL_INJECT_REPO"):
        missing.append("INVART_SKILL_INJECT_REPO")
    if family == "agentsecbench" and not os.environ.get("INVART_AGENTSECBENCH_REPO"):
        missing.append("INVART_AGENTSECBENCH_REPO")
    if family == "agentdojo" and not os.environ.get(_agentdojo_model_env(agent)):
        missing.append(_agentdojo_model_env(agent))
    return sorted(set(missing))


def _agent_binary_available(agent: str) -> bool:
    try:
        profile = get_adapter_profile(agent)
    except KeyError:
        return False
    for candidate in profile.get("binary_candidates", []) or []:
        if shutil.which(str(candidate)):
            return True
    return False


def _required_keys(*, family: str, agent: str) -> list[str]:
    if family != "skill_inject":
        return []
    return provider_api_keys(agent)


def _official_method(family: str) -> str:
    methods = {
        "agentdojo": "agentdojo.scripts.benchmark with registered model/adapter id or explicit boundary artifact",
        "agentsecbench": "upstream benchmark.run ancillary runner under Invart supervision",
        "skill_inject": "upstream Skill-Inject Docker/experiment runner with provider credentials from API keys or mounted CLI config",
        "swe_bench_verified": "provider CLI generates patch/predictions JSONL, official SWE-Bench harness grades",
    }
    return methods.get(family, "unknown")


def _official_command_spec(
    *,
    family: str,
    case_id: str,
    benchmark_case_ref: str,
    agent: str,
    mode: str,
    row_id: str,
) -> dict[str, Any]:
    row_safe = row_id or f"{case_id}_{agent}_{mode}"
    if family == "swe_bench_verified":
        instance_id = _swe_instance_id(benchmark_case_ref) or case_id.replace("swe_verified_", "").replace("_", "__", 1)
        spec = build_swe_bench_verified_command(
            python_executable="$PYTHON_BIN",
            predictions_path=f"$TARGET_ROOT/bridges/{row_safe}/predictions.jsonl",
            run_id=row_safe,
            report_dir=f"$TARGET_ROOT/swe-reports/{row_safe}",
            instance_ids=[instance_id] if instance_id else None,
        )
    elif family == "agentdojo":
        user_task = _agentdojo_user_task(benchmark_case_ref)
        spec = build_agentdojo_command(
            python_executable="$PYTHON_BIN",
            model=f"${{{_agentdojo_model_env(agent)}}}",
            model_id=f"${{{_agentdojo_model_id_env(agent)}:-}}",
            suite="workspace",
            module_to_load="invart.evaluation.real_agent_benchmark.agentdojo_cli_proxy",
            user_tasks=[user_task] if user_task else None,
            injection_tasks=["injection_task_0"],
            attack="tool_knowledge",
            logdir=f"$TARGET_ROOT/agentdojo-logdir/{row_safe}",
        )
    elif family == "agentsecbench":
        spec = build_agentsecbench_command(
            python_executable="$PYTHON_BIN",
            output_dir=f"$TARGET_ROOT/agentsecbench-results/{row_safe}",
        )
    elif family == "skill_inject":
        model = "sonnet" if agent == "claude-code" else "gpt-5.1-codex-mini" if agent == "codex" else agent
        spec = build_skill_inject_command(
            python_executable="$PYTHON_BIN",
            agent=agent,
            model=model,
            output_dir=f"$TARGET_ROOT/skill-inject-results/{row_safe}",
            extra_args=["--smoke-test", "--skip-eval", "--force", "--parallel", "1"],
        )
    else:
        return {
            "family": family,
            "command": [],
            "status": "unknown_family",
            "claim_boundary": "No official command spec is available for this benchmark family.",
        }
    spec["row_binding"] = {
        "row_id": row_safe,
        "case_id": case_id,
        "benchmark_case_ref": benchmark_case_ref,
        "agent": agent,
        "mode": mode,
    }
    spec["status"] = "command_spec_only"
    spec["claim_boundary"] = (
        str(spec.get("claim_boundary") or "")
        + " This target-continuation command spec is an execution recipe only; it is not provider execution, "
        "side-effect evidence, or an official score until run artifacts are attached."
    )
    return spec


def _swe_instance_id(benchmark_case_ref: str) -> str:
    if ":" in benchmark_case_ref:
        return benchmark_case_ref.rsplit(":", 1)[-1]
    return ""


def _agentdojo_user_task(benchmark_case_ref: str) -> str:
    if ":" in benchmark_case_ref:
        return benchmark_case_ref.rsplit(":", 1)[-1]
    return ""


def _render_agentsecbench_target_row(row: dict[str, Any]) -> list[str]:
    row_id = str(row.get("row_id") or "agentsecbench-row").replace("/", "_")
    case_id = str(row.get("case_id") or "")
    agent = str(row.get("agent") or "")
    mode = str(row.get("mode") or "")
    result_dir = f"$TARGET_ROOT/agentsecbench-results/{row_id}"
    return [
        "",
        f"  # AgentSecBench row: {row_id}",
        f"  mkdir -p \"{result_dir}\"",
        "  if [ -n \"${INVART_AGENTSECBENCH_BIN_DIR:-}\" ]; then",
        "    export PATH=\"$INVART_AGENTSECBENCH_BIN_DIR:$PATH\"",
        "  fi",
        f"  \"$PYTHON_BIN\" -m invart.cli experiment p0-real-agent execute-official --manifest \"$ROOT/p0_target_expansion_manifest.json\" --out-dir \"$TARGET_ROOT/runs/{row_id}\" --family agentsecbench --case-id \"{case_id}\" --agent \"{agent}\" --mode \"{mode}\" --cwd \"$AGENTSECBENCH_REPO\" --grader-artifact \"{result_dir}\" --timeout \"${{INVART_P0_OFFICIAL_TIMEOUT:-2400}}\" --python \"$PYTHON_BIN\" --tools \"${{INVART_AGENTSECBENCH_TOOLS:-semgrep}}\" --apps \"${{INVART_AGENTSECBENCH_APPS:-benchmark/apps}}\" --output-dir \"{result_dir}\"",
    ]


def _md(value: Any) -> str:
    return str(value or "").replace("|", "\\|").replace("\n", " ")


def _counter_dict(values: Any) -> dict[str, int]:
    counter: Counter[str] = Counter()
    for value in values:
        text = str(value or "")
        if text:
            counter[text] += 1
    return dict(sorted(counter.items()))


def _summary_counts(value: Any) -> str:
    if not isinstance(value, dict) or not value:
        return "none"
    return ", ".join(f"{key}={value[key]}" for key in sorted(value))


def _example_official_command_specs(row_actions: Any) -> list[dict[str, Any]]:
    if not isinstance(row_actions, list):
        return []
    examples: dict[str, dict[str, Any]] = {}
    for action in row_actions:
        if not isinstance(action, dict):
            continue
        spec = action.get("official_command_spec")
        if not isinstance(spec, dict):
            continue
        family = str(spec.get("family") or action.get("family") or "")
        command = spec.get("command")
        if family and family not in examples and isinstance(command, list) and command:
            examples[family] = spec
    return [examples[key] for key in sorted(examples)]


def _agentdojo_model_env(agent: str) -> str:
    suffix = "".join(char.upper() if char.isalnum() else "_" for char in agent).strip("_")
    return f"INVART_AGENTDOJO_MODEL_{suffix or 'AGENT'}"


def _agentdojo_model_id_env(agent: str) -> str:
    suffix = "".join(char.upper() if char.isalnum() else "_" for char in agent).strip("_")
    return f"INVART_AGENTDOJO_MODEL_ID_{suffix or 'AGENT'}"


def _agentdojo_local_port_env(agent: str) -> str:
    suffix = "".join(char.upper() if char.isalnum() else "_" for char in agent).strip("_")
    return f"INVART_AGENTDOJO_LOCAL_PORT_{suffix or 'AGENT'}"


def _absent_case_ids(target_scope: dict[str, Any]) -> set[str]:
    continuation = target_scope.get("continuation_plan") if isinstance(target_scope.get("continuation_plan"), dict) else {}
    rows = continuation.get("target_expansion_rows") if isinstance(continuation.get("target_expansion_rows"), list) else []
    return {
        str(row.get("case_id"))
        for row in rows
        if isinstance(row, dict) and row.get("case_id")
    }
