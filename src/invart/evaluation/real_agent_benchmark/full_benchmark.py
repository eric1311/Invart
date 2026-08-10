from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, Iterable, Optional

from invart.core.artifacts import stable_json_hash, write_json_artifact
from invart.core.models import utc_now

from .mediation_prompts import POLICY_VARIANTS


AGENTDOJO_CENSUS_SCHEMA_VERSION = "invart.agentdojo_full_census.v0.1"
AGENTDOJO_FULL_MANIFEST_SCHEMA_VERSION = "invart.agentdojo_full_manifest.v0.1"
AGENTDOJO_COMPLETENESS_SCHEMA_VERSION = "invart.agentdojo_full_completeness.v0.1"
FULL_MODES = ("baseline_agent", "invart_observe_only", "invart_mediated")
FULL_CONDITIONS = ("no_attack_utility", "canonical_attack")
POLICY_VARIANT_MODES = {
    "V0": "baseline_agent",
    "V1": "invart_mediated",
    "V2": "invart_observe_only",
    "V2H": "invart_mediated",
    "V3": "invart_observe_only",
    "V4": "invart_mediated",
    "V5": "invart_mediated",
}


_AGENTDOJO_CENSUS_SCRIPT = r"""
import importlib
import importlib.metadata
import json
import sys

benchmark_version = sys.argv[1]
for module_name in sys.argv[2:]:
    importlib.import_module(module_name)

from agentdojo.task_suite.load_suites import get_suites

suites = get_suites(benchmark_version)
payload = {
    "agentdojo_package_version": importlib.metadata.version("agentdojo"),
    "benchmark_version": benchmark_version,
    "suites": [],
}
for suite_id, suite in sorted(suites.items()):
    user_task_ids = sorted(str(item) for item in suite.user_tasks.keys())
    injection_task_ids = sorted(str(item) for item in suite.injection_tasks.keys())
    payload["suites"].append({
        "suite": str(suite_id),
        "user_task_ids": user_task_ids,
        "injection_task_ids": injection_task_ids,
        "user_tasks": len(user_task_ids),
        "injection_tasks": len(injection_task_ids),
        "security_pairs": len(user_task_ids) * len(injection_task_ids),
    })
print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
"""


def collect_agentdojo_full_census(
    *,
    out_dir: Path,
    python_executable: str,
    benchmark_version: str = "v1.2.2",
    modules_to_load: Optional[list[str]] = None,
) -> dict[str, Any]:
    root = out_dir.expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    command = [
        python_executable,
        "-c",
        _AGENTDOJO_CENSUS_SCRIPT,
        benchmark_version,
        *(modules_to_load or []),
    ]
    process = subprocess.run(command, capture_output=True, text=True, check=False)
    if process.returncode != 0:
        payload = {
            "schema_version": AGENTDOJO_CENSUS_SCHEMA_VERSION,
            "generated_at": utc_now(),
            "status": "blocked",
            "python_executable": python_executable,
            "benchmark_version": benchmark_version,
            "modules_to_load": modules_to_load or [],
            "returncode": process.returncode,
            "stdout_tail": process.stdout[-4000:],
            "stderr_tail": process.stderr[-4000:],
            "claim_boundary": (
                "The official AgentDojo environment could not be enumerated. "
                "No full-benchmark denominator or score may be claimed."
            ),
        }
        write_json_artifact(root / "agentdojo_full_census.json", payload)
        (root / "agentdojo_full_census.md").write_text(render_agentdojo_census_markdown(payload), encoding="utf-8")
        return payload
    try:
        discovered = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError(f"AgentDojo census returned invalid JSON: {exc}") from exc
    suites = discovered.get("suites") if isinstance(discovered, dict) else None
    if not isinstance(suites, list) or not suites:
        raise ValueError("AgentDojo census returned no suites")
    summary = {
        "suites": len(suites),
        "user_tasks": sum(int(item.get("user_tasks") or 0) for item in suites if isinstance(item, dict)),
        "injection_tasks": sum(int(item.get("injection_tasks") or 0) for item in suites if isinstance(item, dict)),
        "security_pairs": sum(int(item.get("security_pairs") or 0) for item in suites if isinstance(item, dict)),
    }
    summary["canonical_attack_task_executions"] = summary["security_pairs"] + summary["injection_tasks"]
    summary["no_attack_task_executions"] = summary["user_tasks"]
    payload = {
        "schema_version": AGENTDOJO_CENSUS_SCHEMA_VERSION,
        "generated_at": utc_now(),
        "status": "pass",
        "python_executable": str(Path(python_executable).expanduser()),
        "agentdojo_package_version": discovered.get("agentdojo_package_version"),
        "benchmark_version": discovered.get("benchmark_version"),
        "modules_to_load": modules_to_load or [],
        "suites": suites,
        "summary": summary,
        "census_hash": stable_json_hash(
            {
                "agentdojo_package_version": discovered.get("agentdojo_package_version"),
                "benchmark_version": discovered.get("benchmark_version"),
                "suites": suites,
            }
        ),
        "claim_boundary": (
            "This census freezes the official benchmark denominator exposed by the selected AgentDojo package and "
            "benchmark version. It is protocol evidence, not an executed benchmark result."
        ),
    }
    write_json_artifact(root / "agentdojo_full_census.json", payload)
    (root / "agentdojo_full_census.md").write_text(render_agentdojo_census_markdown(payload), encoding="utf-8")
    return payload


def build_agentdojo_full_manifest(
    *,
    census_path: Path,
    out_dir: Path,
    agents: list[str],
    suites: Optional[list[str]] = None,
    user_tasks: Optional[list[str]] = None,
    injection_tasks: Optional[list[str]] = None,
    modes: Optional[list[str]] = None,
    policy_variants: Optional[list[str]] = None,
    trials: int = 1,
    attack: str = "tool_knowledge",
    defense: Optional[str] = None,
    policy_hash: Optional[str] = None,
) -> dict[str, Any]:
    if trials < 1:
        raise ValueError("trials must be at least 1")
    selected_agents = _dedupe_nonempty(agents)
    if not selected_agents:
        raise ValueError("at least one agent is required")
    selected_variants = _dedupe_nonempty(policy_variants or [])
    invalid_variants = [variant for variant in selected_variants if variant not in POLICY_VARIANTS]
    if invalid_variants:
        raise ValueError(f"unsupported policy variants: {', '.join(invalid_variants)}")
    if selected_variants and modes is not None:
        raise ValueError("select either policy_variants or compatibility modes, not both")
    selected_modes = _dedupe_nonempty(
        [POLICY_VARIANT_MODES[variant] for variant in selected_variants]
        if selected_variants
        else modes or list(FULL_MODES)
    )
    invalid_modes = [mode for mode in selected_modes if mode not in FULL_MODES]
    if invalid_modes:
        raise ValueError(f"unsupported full benchmark modes: {', '.join(invalid_modes)}")
    census = _read_json_object(census_path)
    if census.get("status") != "pass":
        raise ValueError("AgentDojo full manifest requires a passing census")
    census_suites = census.get("suites")
    if not isinstance(census_suites, list) or not census_suites:
        raise ValueError("AgentDojo census has no suites")
    requested_suites = _dedupe_nonempty(suites or [])
    available_suite_ids = [str(item.get("suite") or "") for item in census_suites if isinstance(item, dict)]
    unknown_suites = [suite for suite in requested_suites if suite not in available_suite_ids]
    if unknown_suites:
        raise ValueError(f"AgentDojo census does not contain suites: {', '.join(unknown_suites)}")
    selected_suites = [
        item
        for item in census_suites
        if isinstance(item, dict) and (not requested_suites or str(item.get("suite") or "") in requested_suites)
    ]
    requested_user_tasks = _dedupe_nonempty(user_tasks or [])
    requested_injection_tasks = _dedupe_nonempty(injection_tasks or [])
    if (requested_user_tasks or requested_injection_tasks) and len(selected_suites) != 1:
        raise ValueError("task-filtered AgentDojo smoke manifests require exactly one selected suite")
    if requested_user_tasks or requested_injection_tasks:
        suite = dict(selected_suites[0])
        available_user_tasks = [str(item) for item in suite.get("user_task_ids", [])]
        available_injection_tasks = [str(item) for item in suite.get("injection_task_ids", [])]
        unknown_user_tasks = [item for item in requested_user_tasks if item not in available_user_tasks]
        unknown_injection_tasks = [item for item in requested_injection_tasks if item not in available_injection_tasks]
        if unknown_user_tasks:
            raise ValueError(f"AgentDojo suite does not contain user tasks: {', '.join(unknown_user_tasks)}")
        if unknown_injection_tasks:
            raise ValueError(
                f"AgentDojo suite does not contain injection tasks: {', '.join(unknown_injection_tasks)}"
            )
        suite["user_task_ids"] = requested_user_tasks or available_user_tasks
        suite["injection_task_ids"] = requested_injection_tasks or available_injection_tasks
        suite["user_tasks"] = len(suite["user_task_ids"])
        suite["injection_tasks"] = len(suite["injection_task_ids"])
        suite["security_pairs"] = suite["user_tasks"] * suite["injection_tasks"]
        selected_suites = [suite]
    protocol_scope = "full"
    if requested_user_tasks or requested_injection_tasks:
        protocol_scope = "smoke"
    elif len(selected_suites) != len(census_suites):
        protocol_scope = "pilot"
    jobs: list[dict[str, Any]] = []
    for trial in range(1, trials + 1):
        for agent in selected_agents:
            variant_modes = (
                [(variant, POLICY_VARIANT_MODES[variant]) for variant in selected_variants]
                if selected_variants
                else [(None, mode) for mode in selected_modes]
            )
            for policy_variant, mode in variant_modes:
                for suite in selected_suites:
                    if not isinstance(suite, dict):
                        continue
                    for condition in FULL_CONDITIONS:
                        job = _full_job(
                            suite=suite,
                            agent=agent,
                            mode=mode,
                            trial=trial,
                            condition=condition,
                            attack=attack,
                            defense=defense,
                            policy_variant=policy_variant,
                        )
                        jobs.append(job)
    expected = _sum_expected_channels(jobs)
    payload = {
        "schema_version": AGENTDOJO_FULL_MANIFEST_SCHEMA_VERSION,
        "generated_at": utc_now(),
        "status": "frozen",
        "benchmark": {
            "family": "agentdojo",
            "agentdojo_package_version": census.get("agentdojo_package_version"),
            "benchmark_version": census.get("benchmark_version"),
            "census_hash": census.get("census_hash"),
            "census_path": str(census_path.expanduser().resolve()),
        },
        "protocol": {
            "agents": selected_agents,
            "suites": [str(item.get("suite") or "") for item in selected_suites],
            "scope": protocol_scope,
            "modes": selected_modes,
            "policy_variants": selected_variants,
            "trials": trials,
            "conditions": list(FULL_CONDITIONS),
            "task_filters": {
                "user_tasks": requested_user_tasks,
                "injection_tasks": requested_injection_tasks,
            },
            "canonical_attack": attack,
            "defense": defense,
            "policy_hash": policy_hash or "unfrozen",
            "execution_unit": "one official AgentDojo suite per agent, mode, trial, and condition",
            "execution_order": "ascending frozen per-job random_seed",
            "result_rule": "timeouts, crashes, errors, and missing jobs remain in the denominator",
        },
        "summary": {
            "jobs": len(jobs),
            "suites": len(selected_suites),
            "agents": len(selected_agents),
            "modes": len(selected_modes),
            "policy_variants": len(selected_variants),
            "trials": trials,
            "expected_result_channels": expected,
        },
        "jobs": jobs,
        "manifest_hash": stable_json_hash(
            {
                "census_hash": census.get("census_hash"),
                "agents": selected_agents,
                "suites": [str(item.get("suite") or "") for item in selected_suites],
                "user_tasks": requested_user_tasks,
                "injection_tasks": requested_injection_tasks,
                "modes": selected_modes,
                "policy_variants": selected_variants,
                "trials": trials,
                "attack": attack,
                "defense": defense,
                "policy_hash": policy_hash or "unfrozen",
                "jobs": jobs,
            }
        ),
        "claim_boundary": (
            "This manifest freezes the full official AgentDojo execution denominator. "
            "It is not evidence that any provider job ran or that any result was officially graded."
        ),
    }
    root = out_dir.expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    write_json_artifact(root / "agentdojo_full_manifest.json", payload)
    _write_jsonl(root / "agentdojo_full_jobs.jsonl", jobs)
    (root / "agentdojo_full_run_records.jsonl").touch(exist_ok=True)
    (root / "agentdojo_full_manifest.md").write_text(render_agentdojo_full_manifest_markdown(payload), encoding="utf-8")
    return payload


def audit_agentdojo_full_completeness(
    *,
    manifest_path: Path,
    run_records_path: Path,
    out_dir: Path,
) -> dict[str, Any]:
    manifest = _read_json_object(manifest_path)
    if manifest.get("status") != "frozen":
        raise ValueError("completeness audit requires a frozen AgentDojo full manifest")
    jobs = [item for item in manifest.get("jobs", []) if isinstance(item, dict)]
    records = _latest_records_by_job(_read_jsonl(run_records_path))
    audited_jobs: list[dict[str, Any]] = []
    for job in jobs:
        job_id = str(job.get("job_id") or "")
        record = records.get(job_id)
        audited_jobs.append(_audit_full_job(job=job, record=record))
    known_job_ids = {str(job.get("job_id") or "") for job in jobs}
    unknown_records = sorted(job_id for job_id in records if job_id not in known_job_ids)
    status_counts = _count_values(str(item.get("audit_status") or "unknown") for item in audited_jobs)
    observed_channels = _sum_observed_channels(audited_jobs)
    expected_channels = _sum_expected_channels(jobs)
    complete = bool(audited_jobs) and all(item.get("audit_status") == "graded_complete" for item in audited_jobs)
    payload = {
        "schema_version": AGENTDOJO_COMPLETENESS_SCHEMA_VERSION,
        "generated_at": utc_now(),
        "status": "complete" if complete else "incomplete",
        "manifest_path": str(manifest_path.expanduser().resolve()),
        "manifest_hash": manifest.get("manifest_hash"),
        "run_records_path": str(run_records_path.expanduser().resolve()),
        "summary": {
            "expected_jobs": len(jobs),
            "recorded_jobs": len([item for item in audited_jobs if item.get("record_present")]),
            "launched_jobs": len([item for item in audited_jobs if item.get("launched")]),
            "completed_jobs": len([item for item in audited_jobs if item.get("completed")]),
            "officially_graded_jobs": len([item for item in audited_jobs if item.get("officially_graded")]),
            "graded_complete_jobs": status_counts.get("graded_complete", 0),
            "missing_jobs": status_counts.get("missing", 0),
            "partial_jobs": status_counts.get("graded_partial", 0),
            "timeout_jobs": status_counts.get("timeout", 0),
            "crashed_jobs": status_counts.get("crashed", 0),
            "failed_jobs": status_counts.get("failed", 0),
            "unknown_record_jobs": unknown_records,
            "expected_result_channels": expected_channels,
            "observed_result_channels": observed_channels,
        },
        "jobs": audited_jobs,
        "claim_boundary": (
            "A full AgentDojo benchmark claim is permitted only when every frozen job is officially graded with "
            "the expected result-channel counts. Partial, timeout, crash, failed, and missing jobs remain visible."
        ),
    }
    root = out_dir.expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    write_json_artifact(root / "agentdojo_full_completeness.json", payload)
    (root / "agentdojo_full_completeness.md").write_text(
        render_agentdojo_full_completeness_markdown(payload), encoding="utf-8"
    )
    return payload


def render_agentdojo_census_markdown(payload: dict[str, Any]) -> str:
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    lines = [
        "# AgentDojo Full Benchmark Census",
        "",
        f"- Status: `{payload.get('status')}`",
        f"- AgentDojo package: `{payload.get('agentdojo_package_version', 'unknown')}`",
        f"- Benchmark version: `{payload.get('benchmark_version', 'unknown')}`",
        f"- Census hash: `{payload.get('census_hash', 'unavailable')}`",
        "",
        "| Suite | User tasks | Injection tasks | Security pairs |",
        "| --- | ---: | ---: | ---: |",
    ]
    for suite in payload.get("suites", []):
        if isinstance(suite, dict):
            lines.append(
                f"| {suite.get('suite')} | {suite.get('user_tasks', 0)} | "
                f"{suite.get('injection_tasks', 0)} | {suite.get('security_pairs', 0)} |"
            )
    if summary:
        lines.extend(
            [
                "",
                f"Total: {summary.get('suites', 0)} suites, {summary.get('user_tasks', 0)} user tasks, "
                f"{summary.get('injection_tasks', 0)} injection tasks, and "
                f"{summary.get('security_pairs', 0)} canonical non-DoS security pairs.",
            ]
        )
    lines.extend(["", str(payload.get("claim_boundary") or "")])
    return "\n".join(lines).rstrip() + "\n"


def render_agentdojo_full_manifest_markdown(payload: dict[str, Any]) -> str:
    protocol = payload.get("protocol") if isinstance(payload.get("protocol"), dict) else {}
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    lines = [
        "# AgentDojo Full Benchmark Manifest",
        "",
        f"- Status: `{payload.get('status')}`",
        f"- Manifest hash: `{payload.get('manifest_hash')}`",
        f"- Scope: `{protocol.get('scope', 'unknown')}`",
        f"- Suites: {', '.join(protocol.get('suites') or [])}",
        f"- Agents: {', '.join(protocol.get('agents') or [])}",
        f"- Modes: {', '.join(protocol.get('modes') or [])}",
        f"- Trials: {protocol.get('trials', 0)}",
        f"- Canonical attack: `{protocol.get('canonical_attack')}`",
        f"- Jobs: {summary.get('jobs', 0)}",
        "",
        "| Suite | Agent | Mode | Trial | Condition | Job id |",
        "| --- | --- | --- | ---: | --- | --- |",
    ]
    for job in payload.get("jobs", []):
        if isinstance(job, dict):
            lines.append(
                f"| {job.get('suite')} | {job.get('agent')} | {job.get('mode')} | {job.get('trial')} | "
                f"{job.get('condition')} | `{job.get('job_id')}` |"
            )
    lines.extend(["", str(payload.get("claim_boundary") or "")])
    return "\n".join(lines).rstrip() + "\n"


def render_agentdojo_full_completeness_markdown(payload: dict[str, Any]) -> str:
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    lines = [
        "# AgentDojo Full Benchmark Completeness Audit",
        "",
        f"- Status: `{payload.get('status')}`",
        f"- Expected jobs: {summary.get('expected_jobs', 0)}",
        f"- Launched jobs: {summary.get('launched_jobs', 0)}",
        f"- Completed jobs: {summary.get('completed_jobs', 0)}",
        f"- Officially graded jobs: {summary.get('officially_graded_jobs', 0)}",
        f"- Graded-complete jobs: {summary.get('graded_complete_jobs', 0)}",
        f"- Missing jobs: {summary.get('missing_jobs', 0)}",
        f"- Partial jobs: {summary.get('partial_jobs', 0)}",
        f"- Timeout jobs: {summary.get('timeout_jobs', 0)}",
        f"- Crashed jobs: {summary.get('crashed_jobs', 0)}",
        f"- Failed jobs: {summary.get('failed_jobs', 0)}",
        "",
        "| Job | Run status | Audit status | Expected channels | Observed channels |",
        "| --- | --- | --- | --- | --- |",
    ]
    for job in payload.get("jobs", []):
        if isinstance(job, dict):
            lines.append(
                f"| `{job.get('job_id')}` | {job.get('run_status')} | {job.get('audit_status')} | "
                f"`{json.dumps(job.get('expected_results') or {}, sort_keys=True)}` | "
                f"`{json.dumps(job.get('observed_results') or {}, sort_keys=True)}` |"
            )
    lines.extend(["", str(payload.get("claim_boundary") or "")])
    return "\n".join(lines).rstrip() + "\n"


def _full_job(
    *,
    suite: dict[str, Any],
    agent: str,
    mode: str,
    trial: int,
    condition: str,
    attack: str,
    defense: Optional[str],
    policy_variant: Optional[str] = None,
) -> dict[str, Any]:
    suite_id = str(suite.get("suite") or "")
    expected_results = (
        {"utility": int(suite.get("user_tasks") or 0)}
        if condition == "no_attack_utility"
        else {
            "paired_utility": int(suite.get("security_pairs") or 0),
            "security": int(suite.get("security_pairs") or 0),
            "injection_utility": int(suite.get("injection_tasks") or 0),
        }
    )
    identity = {
        "suite": suite_id,
        "agent": agent,
        "mode": mode,
        "trial": trial,
        "condition": condition,
        "user_task_ids": suite.get("user_task_ids") or [],
        "injection_task_ids": suite.get("injection_task_ids") or [],
    }
    if policy_variant is not None:
        identity["policy_variant"] = policy_variant
    public_identity = {
        "suite": suite_id,
        "agent": agent,
        "mode": mode,
        "trial": trial,
        "condition": condition,
    }
    return {
        "job_id": "agentdojo_" + stable_json_hash(identity, prefixed=False)[:20],
        **public_identity,
        **({"policy_variant": policy_variant} if policy_variant is not None else {}),
        "attack": attack if condition == "canonical_attack" else None,
        "defense": defense,
        "user_task_ids": suite.get("user_task_ids") or [],
        "injection_task_ids": suite.get("injection_task_ids") or [],
        "expected_results": expected_results,
        "random_seed": int(stable_json_hash(identity, prefixed=False)[:8], 16),
        "status": "planned",
        "claim_boundary": "This job is claimable only after the official AgentDojo result counts match the frozen denominator.",
    }


def _audit_full_job(*, job: dict[str, Any], record: Optional[dict[str, Any]]) -> dict[str, Any]:
    expected = job.get("expected_results") if isinstance(job.get("expected_results"), dict) else {}
    if record is None:
        return {
            "job_id": job.get("job_id"),
            "suite": job.get("suite"),
            "agent": job.get("agent"),
            "mode": job.get("mode"),
            "trial": job.get("trial"),
            "condition": job.get("condition"),
            "record_present": False,
            "launched": False,
            "completed": False,
            "officially_graded": False,
            "run_status": "missing",
            "audit_status": "missing",
            "expected_results": expected,
            "observed_results": {},
        }
    run_status = str(record.get("run_status") or "unknown")
    observed = record.get("official_result_counts")
    observed = observed if isinstance(observed, dict) else {}
    launched = run_status not in {"planned", "missing", "unknown"}
    completed = run_status in {"completed", "graded"}
    officially_graded = record.get("official_result_status") == "graded"
    if run_status == "timeout":
        audit_status = "timeout"
    elif run_status == "crashed":
        audit_status = "crashed"
    elif run_status in {"failed", "error"}:
        audit_status = "failed"
    elif officially_graded and all(int(observed.get(key) or 0) == int(value or 0) for key, value in expected.items()):
        audit_status = "graded_complete"
    elif officially_graded:
        audit_status = "graded_partial"
    elif completed:
        audit_status = "completed_ungraded"
    elif launched:
        audit_status = "launched_incomplete"
    else:
        audit_status = "recorded_unlaunched"
    return {
        "job_id": job.get("job_id"),
        "suite": job.get("suite"),
        "agent": job.get("agent"),
        "mode": job.get("mode"),
        "trial": job.get("trial"),
        "condition": job.get("condition"),
        "record_present": True,
        "launched": launched,
        "completed": completed,
        "officially_graded": officially_graded,
        "run_status": run_status,
        "audit_status": audit_status,
        "expected_results": expected,
        "observed_results": {str(key): int(value or 0) for key, value in observed.items()},
        "artifact_path": record.get("artifact_path"),
        "recorded_at": record.get("recorded_at"),
    }


def _sum_expected_channels(jobs: Iterable[dict[str, Any]]) -> dict[str, int]:
    totals: dict[str, int] = {}
    for job in jobs:
        expected = job.get("expected_results") if isinstance(job.get("expected_results"), dict) else {}
        for key, value in expected.items():
            totals[str(key)] = totals.get(str(key), 0) + int(value or 0)
    return dict(sorted(totals.items()))


def _sum_observed_channels(jobs: Iterable[dict[str, Any]]) -> dict[str, int]:
    totals: dict[str, int] = {}
    for job in jobs:
        observed = job.get("observed_results") if isinstance(job.get("observed_results"), dict) else {}
        for key, value in observed.items():
            totals[str(key)] = totals.get(str(key), 0) + int(value or 0)
    return dict(sorted(totals.items()))


def _latest_records_by_job(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    for record in records:
        job_id = str(record.get("job_id") or "")
        if not job_id:
            continue
        previous = latest.get(job_id)
        if previous is None or str(record.get("recorded_at") or "") >= str(previous.get("recorded_at") or ""):
            latest[job_id] = record
    return latest


def _count_values(values: Iterable[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def _dedupe_nonempty(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        normalized = str(value).strip()
        if normalized and normalized not in result:
            result.append(normalized)
    return result


def _read_json_object(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.expanduser().read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"JSON artifact does not exist: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON artifact {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"JSON artifact must contain an object: {path}")
    return payload


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    try:
        lines = path.expanduser().read_text(encoding="utf-8").splitlines()
    except FileNotFoundError as exc:
        raise ValueError(f"JSONL artifact does not exist: {path}") from exc
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSONL at {path}:{line_number}: {exc}") from exc
        if not isinstance(payload, dict):
            raise ValueError(f"JSONL row must be an object at {path}:{line_number}")
        rows.append(payload)
    return rows


def _write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


__all__ = [
    "AGENTDOJO_CENSUS_SCHEMA_VERSION",
    "AGENTDOJO_COMPLETENESS_SCHEMA_VERSION",
    "AGENTDOJO_FULL_MANIFEST_SCHEMA_VERSION",
    "FULL_CONDITIONS",
    "FULL_MODES",
    "audit_agentdojo_full_completeness",
    "build_agentdojo_full_manifest",
    "collect_agentdojo_full_census",
    "render_agentdojo_census_markdown",
    "render_agentdojo_full_completeness_markdown",
    "render_agentdojo_full_manifest_markdown",
]
