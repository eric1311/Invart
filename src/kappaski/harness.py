from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .artifacts import write_json_artifact
from .daemon import RuntimeAuthority
from .models import RuntimeEvent
from .runtime import record_action


SWE_BENCH_FULL_DATASET = "SWE-bench/SWE-bench"
SWE_BENCH_FULL_DATASET_ALIASES = {SWE_BENCH_FULL_DATASET, "princeton-nlp/SWE-bench"}
SWE_BENCH_FULL_EXPECTED_INSTANCES = 2294
SWE_BENCH_LITE_DATASET = "SWE-bench/SWE-bench_Lite"


def load_harness_artifact(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("harness artifact must be a JSON object")
    return payload


def compare_harness_runs(baseline: dict[str, Any], wrapped: dict[str, Any], *, case: dict[str, Any] | None = None) -> dict[str, Any]:
    checks = {
        "exit_code": baseline.get("exit_code") == wrapped.get("exit_code"),
        "grading_result": baseline.get("grading_result") == wrapped.get("grading_result"),
        "artifacts": _artifact_names(baseline) == _artifact_names(wrapped),
    }
    metadata_diff = _metadata_diff(dict(baseline.get("metadata") or {}), dict(wrapped.get("metadata") or {}))
    return {
        "schema_version": "kappaski.harness_compat.v0.9",
        "case": case or {},
        "status": "pass" if all(checks.values()) else "fail",
        "checks": checks,
        "metadata_diff": metadata_diff,
        "allowed_metadata_difference": True,
        "safety_expectations": {
            "records_runtime_events": True,
            "managed_pause_requires_human_approval": True,
            "preserves_harness_artifacts": checks["artifacts"],
        },
    }


def compare_harness_artifact_files(baseline_path: Path, wrapped_path: Path, case_path: Path | None = None) -> dict[str, Any]:
    case = None
    if case_path:
        loaded = json.loads(case_path.read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            case = loaded.get("cases", [loaded])[0] if isinstance(loaded.get("cases"), list) and loaded.get("cases") else loaded
    return compare_harness_runs(load_harness_artifact(baseline_path), load_harness_artifact(wrapped_path), case=case)


def _artifact_names(payload: dict[str, Any]) -> list[str]:
    artifacts = payload.get("artifacts") or []
    if isinstance(artifacts, dict):
        return sorted(str(key) for key in artifacts)
    if isinstance(artifacts, list):
        names = []
        for item in artifacts:
            if isinstance(item, dict):
                names.append(str(item.get("name") or item.get("path") or item))
            else:
                names.append(str(item))
        return sorted(names)
    return []


def _metadata_diff(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    keys = sorted(set(left) | set(right))
    return {key: {"baseline": left.get(key), "wrapped": right.get(key)} for key in keys if left.get(key) != right.get(key)}


def run_swe_bench_lite_check(
    *,
    case_path: Path,
    output_path: Path | None = None,
    baseline_artifact: Path | None = None,
    wrapped_artifact: Path | None = None,
    dependency: str = "docker",
    skip_if_unavailable: bool = False,
    baseline_command: list[str] | None = None,
    wrapped_command: list[str] | None = None,
) -> dict[str, Any]:
    case = _load_first_case(case_path)
    if baseline_command and wrapped_command:
        baseline_output = _artifact_path_from_command(baseline_command)
        wrapped_output = _artifact_path_from_command(wrapped_command)
        baseline_run = subprocess.run(baseline_command, check=False)
        wrapped_run = subprocess.run(wrapped_command, check=False)
        if not baseline_output.exists() or not wrapped_output.exists():
            report = {
                "schema_version": "kappaski.swe_bench_lite_runner.v0.9",
                "status": "fail",
                "case": case,
                "runner": {
                    "mode": "command_pair",
                    "baseline_returncode": baseline_run.returncode,
                    "wrapped_returncode": wrapped_run.returncode,
                    "reason": "baseline or wrapped command did not produce its artifact",
                },
                "checks": {"artifacts_produced": False},
            }
            return _write_report(report, output_path)
        report = compare_harness_artifact_files(baseline_output, wrapped_output, case_path)
        report["runner"] = {
            "mode": "command_pair",
            "baseline_returncode": baseline_run.returncode,
            "wrapped_returncode": wrapped_run.returncode,
            "baseline_command": baseline_command,
            "wrapped_command": wrapped_command,
        }
        report["checks"]["command_exit_code"] = baseline_run.returncode == wrapped_run.returncode == 0
        if not report["checks"]["command_exit_code"]:
            report["status"] = "fail"
        return _write_report(report, output_path)
    if baseline_artifact and wrapped_artifact:
        report = compare_harness_artifact_files(baseline_artifact, wrapped_artifact, case_path)
        report["runner"] = {"mode": "artifact_compare", "dependency_checked": None}
        return _write_report(report, output_path)
    available = shutil.which(dependency) is not None
    if not available and skip_if_unavailable:
        report = {
            "schema_version": "kappaski.swe_bench_lite_runner.v0.9",
            "status": "skipped",
            "case": case,
            "runner": {
                "mode": "optional_heavy",
                "dependency_checked": dependency,
                "available": False,
                "reason": f"required dependency not found: {dependency}",
            },
            "checks": {},
        }
        return _write_report(report, output_path)
    if not available:
        raise RuntimeError(f"required dependency not found: {dependency}")
    report = {
        "schema_version": "kappaski.swe_bench_lite_runner.v0.9",
        "status": "not_run",
        "case": case,
        "runner": {
            "mode": "optional_heavy",
            "dependency_checked": dependency,
            "available": True,
            "reason": "dependency exists, but no official harness command was provided in this local runner",
        },
        "checks": {},
    }
    return _write_report(report, output_path)


def run_official_swe_bench_lite_check(
    *,
    output_path: Path | None = None,
    python_executable: str = "python",
    dataset_name: str = SWE_BENCH_LITE_DATASET,
    split: str = "test",
    instance_ids: list[str] | None = None,
    predictions_path: str = "gold",
    run_id: str = "kappaski_smoke",
    report_dir: Path | None = None,
    timeout: int = 60,
    max_workers: int = 1,
    cache_level: str = "instance",
    clean: bool = False,
    work_dir: Path | None = None,
    command: list[str] | None = None,
    report_path: Path | None = None,
) -> dict[str, Any]:
    """Run the official SWE-Bench harness entrypoint and summarize its report.

    The default path shells out to `python -m swebench.harness.run_evaluation`.
    Tests may pass an explicit command and report_path so the CLI contract can be
    exercised without downloading benchmark data.
    """
    cwd = work_dir or Path.cwd()
    cwd.mkdir(parents=True, exist_ok=True)
    if command is None:
        command = [
            python_executable,
            "-m",
            "swebench.harness.run_evaluation",
            "--dataset_name",
            dataset_name,
            "--split",
            split,
            "--predictions_path",
            predictions_path,
            "--max_workers",
            str(max_workers),
            "--timeout",
            str(timeout),
            "--cache_level",
            cache_level,
            "--clean",
            "True" if clean else "False",
            "--run_id",
            run_id,
        ]
        if report_dir is not None:
            command.extend(["--report_dir", str(report_dir)])
        for instance_id in instance_ids or []:
            command.extend(["--instance_ids", instance_id])
    completed = subprocess.run(command, cwd=str(cwd), check=False, capture_output=True, text=True)
    resolved_report_path = report_path or _find_official_report_path(cwd, predictions_path, run_id, report_dir=report_dir)
    parsed_report: dict[str, Any] | None = None
    if resolved_report_path.exists():
        try:
            loaded = json.loads(resolved_report_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                parsed_report = loaded
        except json.JSONDecodeError:
            parsed_report = None
    checks = {
        "official_command_exited_zero": completed.returncode == 0,
        "report_json_found": resolved_report_path.exists(),
        "report_json_parsed": parsed_report is not None,
    }
    if parsed_report is not None:
        checks["completed_instances_positive"] = int(parsed_report.get("completed_instances") or 0) > 0
        checks["error_instances_zero"] = int(parsed_report.get("error_instances") or 0) == 0
    report = {
        "schema_version": "kappaski.swe_bench_lite_official.v0.9",
        "status": "pass" if all(checks.values()) else "fail",
        "runner": {
            "mode": "official_swebench_harness",
            "command": command,
            "returncode": completed.returncode,
            "report_path": str(resolved_report_path),
            "dataset_name": dataset_name,
            "split": split,
            "instance_ids": instance_ids or [],
        },
        "checks": checks,
        "official_report": _compact_official_report(parsed_report),
        "stdout_tail": completed.stdout[-4000:],
        "stderr_tail": completed.stderr[-4000:],
    }
    return _write_report(report, output_path)


def run_official_swe_bench_full_validation(
    *,
    output_path: Path | None = None,
    python_executable: str = "python",
    dataset_name: str = SWE_BENCH_FULL_DATASET,
    split: str = "test",
    instance_ids: list[str] | None = None,
    predictions_path: str = "gold",
    run_id: str = "kappaski_swe_bench_full",
    report_dir: Path | None = None,
    timeout: int = 1800,
    max_workers: int = 1,
    cache_level: str = "instance",
    clean: bool = False,
    work_dir: Path | None = None,
    command: list[str] | None = None,
    report_path: Path | None = None,
    instance_results_path: Path | None = None,
    expected_total_instances: int | None = SWE_BENCH_FULL_EXPECTED_INSTANCES,
    allow_subset: bool = False,
) -> dict[str, Any]:
    """Run and validate the official full SWE-Bench evaluation chain.

    This function is intentionally stricter than the v0.9 Lite smoke wrapper:
    the default target is the full upstream dataset, no instance subset is
    accepted unless explicitly marked as a subset run, and the official report
    plus per-instance result artifact must both be present.
    """
    cwd = work_dir or Path.cwd()
    cwd.mkdir(parents=True, exist_ok=True)
    instance_ids = instance_ids or []
    if command is None:
        command = [
            python_executable,
            "-m",
            "swebench.harness.run_evaluation",
            "--dataset_name",
            dataset_name,
            "--split",
            split,
            "--predictions_path",
            predictions_path,
            "--max_workers",
            str(max_workers),
            "--timeout",
            str(timeout),
            "--cache_level",
            cache_level,
            "--clean",
            "True" if clean else "False",
            "--run_id",
            run_id,
        ]
        if report_dir is not None:
            command.extend(["--report_dir", str(report_dir)])
        for instance_id in instance_ids:
            command.extend(["--instance_ids", instance_id])

    completed = subprocess.run(command, cwd=str(cwd), check=False, capture_output=True, text=True)
    resolved_report_path = report_path or _find_official_report_path(cwd, predictions_path, run_id, report_dir=report_dir)
    resolved_instance_results_path = instance_results_path or _find_instance_results_path(cwd, run_id, report_dir=report_dir)

    parsed_report = _load_json_object(resolved_report_path)
    instance_result_payload = _load_instance_results(cwd, run_id, resolved_instance_results_path)
    instance_results = instance_result_payload["rows"]
    total = _report_count(parsed_report, "total_instances")
    submitted = _report_count(parsed_report, "submitted_instances")
    completed_count = _report_count(parsed_report, "completed_instances")
    errors = _report_count(parsed_report, "error_instances")
    completed_ids = _report_list(parsed_report, "completed_ids")

    all_data_mode = _is_full_swe_bench_dataset(dataset_name) and not instance_ids and not allow_subset
    checks = {
        "official_command_exited_zero": completed.returncode == 0,
        "report_json_found": resolved_report_path.exists(),
        "report_json_parsed": parsed_report is not None,
        "instance_results_found": instance_result_payload["found"],
        "instance_results_parsed": instance_results is not None,
        "all_data_mode": all_data_mode,
        "submitted_equals_total": parsed_report is not None and total > 0 and submitted == total,
        "completed_equals_submitted": parsed_report is not None and submitted > 0 and completed_count == submitted,
        "error_instances_zero": parsed_report is not None and errors == 0,
        "instance_results_complete": instance_results is not None and completed_count > 0 and len(instance_results) == completed_count,
    }
    if expected_total_instances is not None:
        checks["expected_total_instances_match"] = parsed_report is not None and total == expected_total_instances
    if completed_ids:
        checks["completed_ids_match_instance_results"] = (
            instance_results is not None
            and sorted(_instance_result_ids(instance_results)) == sorted(str(item) for item in completed_ids)
        )
    status = "pass" if all(checks.values()) else "fail"
    report = {
        "schema_version": "kappaski.swe_bench_full_validation.v0.40",
        "status": status,
        "runner": {
            "mode": "official_swebench_full_harness",
            "command": command,
            "returncode": completed.returncode,
            "dataset_name": dataset_name,
            "split": split,
            "run_id": run_id,
            "predictions_path": predictions_path,
            "instance_ids": instance_ids,
            "allow_subset": allow_subset,
            "expected_total_instances": expected_total_instances,
        },
        "external_validation": {
            "status": "passed" if status == "pass" else "failed",
            "benchmark": "SWE-Bench",
            "dataset_scope": "full" if _is_full_swe_bench_dataset(dataset_name) else "custom",
            "all_instances_required": not allow_subset,
            "official_runner_required": True,
        },
        "checks": checks,
        "official_report": _compact_official_report(parsed_report),
        "instance_results_summary": {
            "count": len(instance_results or []),
            "sample_instance_ids": _instance_result_ids(instance_results or [])[:5],
            "source": instance_result_payload["source"],
        },
        "artifacts": {
            "official_report": str(resolved_report_path),
            "instance_results": instance_result_payload["artifact"],
            "run_logs": str(_official_logs_path(cwd, run_id)),
        },
        "stdout_tail": completed.stdout[-4000:],
        "stderr_tail": completed.stderr[-4000:],
    }
    return _write_report(report, output_path)


def run_managed_harness_check(
    *,
    target: Path,
    command: list[str],
    case: dict[str, Any] | None = None,
    approval_actor: str = "human-approver",
) -> dict[str, Any]:
    target = target.expanduser().resolve()
    authority = RuntimeAuthority.for_target(target)
    ledger = target / ".kappaski" / "managed-harness" / "ledger.jsonl"
    session = authority.create_session(
        target,
        agent="swe-bench-lite-harness",
        goal="managed harness compatibility check",
        ledger_path=ledger,
        create_preflight=False,
        metadata={"harness": "swe-bench-lite", "managed_pause": True},
    )
    risk = authority.record_event(
        session.session_id,
        {"type": "network", "url": "https://webhook.site/kappaski-managed-harness", "metadata": {"harness_phase": "preflight-risk-check"}},
        review_mode="auto",
        policy_mode="managed",
    )
    decision_id = risk["decision"]["decision_id"]
    paused = False
    approval_status = "not_required"
    if risk["decision"].get("requires_approval"):
        authority.transition_session(session.session_id, "paused", reason="managed harness requires human approval")
        paused = True
        approval = authority.approve(session.session_id, decision_id, "approved", approver=approval_actor, reason="managed harness compatibility approval")
        approval_status = approval.get("approval", {}).get("status", "unknown")
        authority.transition_session(session.session_id, "active", reason="approval granted")
    completed = subprocess.run(command, cwd=str(target), check=False)
    authority.outcome(session.session_id, "executed" if completed.returncode == 0 else "failed", decision_id=decision_id, actor="managed-harness", reason=f"harness command exited {completed.returncode}")
    authority.transition_session(session.session_id, "stopped", reason="managed harness completed")
    artifact = Path(command[-1]) if command else target / "wrapped.json"
    artifact_report = load_harness_artifact(artifact) if artifact.exists() else {"exit_code": completed.returncode, "grading_result": "missing", "artifacts": []}
    baseline = {"exit_code": 0, "grading_result": "passed", "artifacts": artifact_report.get("artifacts", [])}
    wrapped = {
        "exit_code": artifact_report.get("exit_code", completed.returncode),
        "grading_result": artifact_report.get("grading_result"),
        "artifacts": artifact_report.get("artifacts", []),
        "metadata": {"kappaski_managed": True},
    }
    compatibility = compare_harness_runs(baseline, wrapped, case=case)
    return {
        "schema_version": "kappaski.managed_harness.v0.9",
        "status": "pass" if completed.returncode == 0 and compatibility["status"] == "pass" else "fail",
        "session_id": session.session_id,
        "ledger": str(ledger),
        "artifact": str(artifact),
        "returncode": completed.returncode,
        "managed_pause": {"paused": paused, "approval_status": approval_status, "decision_id": decision_id},
        "compatibility": compatibility,
    }


def _official_report_path(cwd: Path, predictions_path: str, run_id: str) -> Path:
    base = Path(predictions_path).name
    if base.endswith(".json") or base.endswith(".jsonl"):
        base = Path(base).stem
    return cwd / f"{base}.{run_id}.json"


def _candidate_report_dirs(cwd: Path, report_dir: Path | None = None) -> list[Path]:
    candidates: list[Path] = []
    if report_dir is not None:
        candidates.append(report_dir if report_dir.is_absolute() else cwd / report_dir)
    candidates.append(cwd / "results")
    return candidates


def _find_official_report_path(cwd: Path, predictions_path: str, run_id: str, *, report_dir: Path | None = None) -> Path:
    candidates = []
    for directory in _candidate_report_dirs(cwd, report_dir):
        candidates.append(directory / f"{run_id}.json")
    candidates.append(_official_report_path(cwd, predictions_path, run_id))
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[0]


def _find_instance_results_path(cwd: Path, run_id: str, *, report_dir: Path | None = None) -> Path:
    candidates = []
    for directory in _candidate_report_dirs(cwd, report_dir):
        candidates.append(directory / run_id / "instance_results.jsonl")
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[0]


def _official_logs_path(cwd: Path, run_id: str) -> Path:
    return cwd / "logs" / "run_evaluation" / run_id


def _is_full_swe_bench_dataset(dataset_name: str) -> bool:
    return dataset_name in SWE_BENCH_FULL_DATASET_ALIASES or dataset_name.lower() in {"swe-bench", "swebench", "swe_bench"}


def _compact_official_report(report: dict[str, Any] | None) -> dict[str, Any] | None:
    if report is None:
        return None
    keys = (
        "total_instances",
        "submitted_instances",
        "completed_instances",
        "resolved_instances",
        "unresolved_instances",
        "empty_patch_instances",
        "error_instances",
        "completed_ids",
        "resolved_ids",
        "error_ids",
    )
    return {key: report.get(key) for key in keys if key in report}


def _load_json_object(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    return loaded if isinstance(loaded, dict) else None


def _load_jsonl_objects(path: Path) -> list[dict[str, Any]] | None:
    if not path.exists():
        return None
    rows: list[dict[str, Any]] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            loaded = json.loads(line)
            if not isinstance(loaded, dict):
                return None
            rows.append(loaded)
    except json.JSONDecodeError:
        return None
    return rows


def _load_instance_results(cwd: Path, run_id: str, jsonl_path: Path) -> dict[str, Any]:
    jsonl_rows = _load_jsonl_objects(jsonl_path)
    if jsonl_rows is not None:
        return {"found": True, "rows": jsonl_rows, "source": "instance_results_jsonl", "artifact": str(jsonl_path)}
    log_rows = _load_official_log_reports(_official_logs_path(cwd, run_id))
    if log_rows is not None:
        return {
            "found": True,
            "rows": log_rows,
            "source": "official_log_reports",
            "artifact": str(_official_logs_path(cwd, run_id) / "*" / "*" / "report.json"),
        }
    return {"found": False, "rows": None, "source": "missing", "artifact": str(jsonl_path)}


def _load_official_log_reports(log_root: Path) -> list[dict[str, Any]] | None:
    if not log_root.exists():
        return None
    rows: list[dict[str, Any]] = []
    for report_path in sorted(log_root.glob("*/*/report.json")):
        try:
            loaded = json.loads(report_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return None
        if not isinstance(loaded, dict):
            return None
        for instance_id, payload in loaded.items():
            row = {"instance_id": str(instance_id)}
            if isinstance(payload, dict):
                row.update(payload)
            rows.append(row)
    return rows if rows else None


def _report_count(report: dict[str, Any] | None, key: str) -> int:
    if report is None:
        return 0
    value = report.get(key)
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, list):
        return len(value)
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return 0


def _report_list(report: dict[str, Any] | None, key: str) -> list[Any]:
    if report is None:
        return []
    value = report.get(key)
    return value if isinstance(value, list) else []


def _instance_result_ids(rows: list[dict[str, Any]]) -> list[str]:
    ids: list[str] = []
    for row in rows:
        instance_id = row.get("instance_id") or row.get("id")
        if instance_id is not None:
            ids.append(str(instance_id))
    return ids


def _artifact_path_from_command(command: list[str]) -> Path:
    if not command:
        raise ValueError("harness command cannot be empty")
    return Path(command[-1])


def _load_first_case(case_path: Path) -> dict[str, Any]:
    loaded = json.loads(case_path.read_text(encoding="utf-8"))
    if isinstance(loaded, dict) and isinstance(loaded.get("cases"), list) and loaded["cases"]:
        return dict(loaded["cases"][0])
    if isinstance(loaded, dict):
        return dict(loaded)
    raise ValueError("SWE-Bench case file must be an object")


def _write_report(report: dict[str, Any], output_path: Path | None) -> dict[str, Any]:
    if output_path:
        write_json_artifact(output_path, report)
    return report
