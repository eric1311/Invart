from __future__ import annotations

import csv
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from invart.core.models import utc_now
from invart.core.artifacts import sha256_file, stable_json_hash

from .benchmark_adapters.agentharm import (
    agentharm_split_contract,
    bind_agentharm_capability_control,
    build_agentharm_capability_control,
    dump_agentharm_inspect_eval,
    extract_agentharm_inspect_rows,
    validate_agentharm_bound_artifact,
)


SWE_BENCH_VERIFIED_DATASET = "SWE-bench/SWE-bench_Verified"


@dataclass(frozen=True)
class OfficialCommandSpec:
    family: str
    command: list[str]
    expected_artifacts: list[str]
    claim_boundary: str
    source_url: str
    source_checked_at: str
    invocation_role: str = "official_benchmark_runner"
    execution_status: str = "ready_to_probe"
    blocker: str | None = None
    working_directory: str | None = None
    environment_overrides: dict[str, str] | None = None


def build_swe_bench_verified_command(
    *,
    python_executable: str = "python",
    predictions_path: str,
    run_id: str = "invart_p0_swe_verified",
    report_dir: str | None = None,
    instance_ids: list[str] | None = None,
    split: str = "test",
    max_workers: int = 1,
    timeout: int = 1800,
    cache_level: str = "instance",
    clean: bool = False,
) -> dict[str, Any]:
    command = [
        python_executable,
        "-m",
        "swebench.harness.run_evaluation",
        "--dataset_name",
        SWE_BENCH_VERIFIED_DATASET,
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
    if report_dir:
        command.extend(["--report_dir", report_dir])
    for instance_id in instance_ids or []:
        command.extend(["--instance_ids", instance_id])
    return asdict(
        OfficialCommandSpec(
            family="swe_bench_verified",
            command=command,
            expected_artifacts=["SWE-Bench report JSON", "instance_results.jsonl", "per-instance logs"],
            claim_boundary="SWE-Bench utility claims require the official harness report and instance results; local patch tests are not substitutes.",
            source_url="https://github.com/SWE-bench/SWE-bench",
            source_checked_at=utc_now(),
        )
    )


def build_agentdojo_command(
    *,
    python_executable: str = "python",
    model: str,
    model_id: str | None = None,
    suite: str = "workspace",
    module_to_load: str | None = None,
    user_tasks: list[str] | None = None,
    injection_tasks: list[str] | None = None,
    attack: str | None = "tool_knowledge",
    defense: str | None = None,
    logdir: str | None = None,
    benchmark_version: str | None = None,
) -> dict[str, Any]:
    model = _agentdojo_model_cli_value(model)
    command = [python_executable, "-m", "agentdojo.scripts.benchmark", "-s", suite, "--model", model]
    if model_id:
        command.extend(["--model-id", model_id])
    if module_to_load:
        command.extend(["--module-to-load", module_to_load])
    for task in user_tasks or []:
        command.extend(["-ut", task])
    for task in injection_tasks or []:
        command.extend(["-it", task])
    if attack:
        command.extend(["--attack", attack])
    if defense:
        command.extend(["--defense", defense])
    if logdir:
        command.extend(["--logdir", logdir])
    if benchmark_version:
        command.extend(["--benchmark-version", benchmark_version])
    return asdict(
        OfficialCommandSpec(
            family="agentdojo",
            command=command,
            expected_artifacts=[
                "AgentDojo TraceLogger JSON files under logdir",
                "per-task utility/security fields emitted by agentdojo.scripts.benchmark",
            ],
            claim_boundary="AgentDojo security/utility claims require outputs from agentdojo.scripts.benchmark; source-mapped traces are not official scores.",
            source_url="https://github.com/ethz-spylab/agentdojo",
            source_checked_at=utc_now(),
        )
    )


def build_agentsecbench_command(
    *,
    python_executable: str = "python",
    tools: str = "semgrep",
    apps: str = "benchmark/apps",
    output_dir: str | None = None,
    extra_args: list[str] | None = None,
) -> dict[str, Any]:
    command = [
        python_executable,
        "-m",
        "benchmark.run",
        "--tools",
        tools,
        "--apps",
        apps,
    ]
    if output_dir:
        command.extend(["--output", output_dir])
    command.extend(extra_args or [])
    return asdict(
        OfficialCommandSpec(
            family="agentsecbench",
            command=command,
            expected_artifacts=["AgentSecBench artifacts directory", "per-task result files", "summary outputs emitted by the upstream package"],
            claim_boundary="AgentSecBench claims require the arXiv ancillary benchmark runner output; Invart-converted traces are adapter evidence only.",
            source_url="https://github.com/Kalmantic/AgentSecBench",
            source_checked_at=utc_now(),
        )
    )


def build_skill_inject_command(
    *,
    python_executable: str = "python",
    runner: str = "scripts/smoke_test_all.py",
    agent: str | None = None,
    model: str | None = None,
    output_dir: str | None = None,
    extra_args: list[str] | None = None,
) -> dict[str, Any]:
    command = [python_executable, runner]
    if agent:
        command.extend(["--agent", _skill_inject_agent_cli_value(agent)])
    if model:
        command.extend(["--model", model])
    if output_dir:
        command.extend(["--output-dir", output_dir])
    command.extend(extra_args or [])
    return asdict(
        OfficialCommandSpec(
            family="skill_inject",
            command=command,
            expected_artifacts=["Skill-Inject upstream experiment outputs", "judge/evaluation artifacts", "sandbox logs when emitted"],
            claim_boundary="Skill-Inject claims require upstream Docker/script experiment artifacts; local skill-corpus conversions are not official benchmark scores.",
            source_url="https://github.com/aisa-group/skill-inject",
            source_checked_at=utc_now(),
        )
    )


def build_agentharm_command(
    *,
    repository_root: str,
    inspect_executable: str | None = None,
    split: str,
    model_name: str,
    prompt_template_name: str = "empty",
    refusal_judge: str | None = None,
    semantic_judge: str | None = None,
    behavior_ids: list[str] | None = None,
    log_dir: str | None = None,
    epochs: int = 1,
    max_connections: int = 1,
    max_retries: int = 0,
    timeout: int = 120,
    max_tokens: int = 4096,
    token_limit: int | None = None,
    cost_limit: float | None = None,
    runtime_home: str | None = None,
) -> dict[str, Any]:
    task, native_split, _task_kind = agentharm_split_contract(split)
    repository = Path(repository_root).expanduser().resolve()
    if inspect_executable is None:
        executable_dir = "Scripts" if sys.platform == "win32" else "bin"
        executable_name = "inspect.exe" if sys.platform == "win32" else "inspect"
        inspect_executable = str(repository / ".venv" / executable_dir / executable_name)
    agent_kwargs = json.dumps({"user_prompt_template": prompt_template_name}, sort_keys=True, separators=(",", ":"))
    if epochs <= 0 or max_connections <= 0 or max_retries < 0 or timeout <= 0 or max_tokens <= 0:
        raise ValueError("AgentHarm execution limits are invalid")
    command = [
        inspect_executable,
        "eval",
        task,
        "--model",
        model_name,
        "-T",
        f"split={native_split}",
        "-T",
        f"agent_kwargs={agent_kwargs}",
    ]
    if refusal_judge:
        command.extend(["-T", f"refusal_judge={refusal_judge}"])
    if semantic_judge:
        command.extend(["-T", f"semantic_judge={semantic_judge}"])
    if behavior_ids:
        normalized_ids = sorted({str(item).strip() for item in behavior_ids if str(item).strip()})
        if len(normalized_ids) != len(behavior_ids):
            raise ValueError("AgentHarm behavior IDs must be unique and nonempty")
        command.extend(
            ["-T", f"behavior_ids={json.dumps(normalized_ids, separators=(',', ':'))}"]
        )
    command.extend(
        [
            "--epochs",
            str(epochs),
            "--max-connections",
            str(max_connections),
            "--max-samples",
            "1",
            "--max-retries",
            str(max_retries),
            "--timeout",
            str(timeout),
            "--max-tokens",
            str(max_tokens),
        ]
    )
    if token_limit is not None:
        if token_limit <= 0:
            raise ValueError("AgentHarm token limit must be positive")
        command.extend(["--token-limit", str(token_limit)])
    if cost_limit is not None:
        if cost_limit <= 0:
            raise ValueError("AgentHarm cost limit must be positive")
        command.extend(["--cost-limit", str(cost_limit)])
    if log_dir:
        resolved_log_dir = Path(log_dir).expanduser().resolve()
        command.extend(["--log-dir", str(resolved_log_dir)])
    else:
        resolved_log_dir = repository / ".invart" / "agentharm"
    resolved_runtime_home = (
        Path(runtime_home).expanduser().resolve()
        if runtime_home
        else resolved_log_dir.parent / "agentharm-runtime-home"
    )
    return asdict(
        OfficialCommandSpec(
            family="agentharm",
            command=command,
            expected_artifacts=["Inspect Eval log", "AgentHarm refusal and functional grader outputs", "tool-call trajectory"],
            claim_boundary=(
                "AgentHarm claims require the pinned Inspect Evals runner, pinned dataset split, and its native refusal "
                "and functional graders. Invart action evidence remains a separate joined artifact."
            ),
            source_url="https://github.com/UKGovernmentBEIS/inspect_evals/tree/main/src/inspect_evals/agentharm",
            source_checked_at=utc_now(),
            working_directory=str(repository),
            environment_overrides={
                "INSPECT_TRACE_FILE": str(
                    resolved_log_dir.parent / f"{resolved_log_dir.name}-inspect-trace.log"
                ),
                "HOME": str(resolved_runtime_home),
                "XDG_CACHE_HOME": str(resolved_runtime_home / ".cache"),
                "XDG_DATA_HOME": str(resolved_runtime_home / ".local" / "share"),
                "HF_HOME": str(resolved_runtime_home / ".cache" / "huggingface"),
            },
        )
    )


def build_mcptox_command() -> dict[str, Any]:
    """Represent the upstream limitation instead of inventing an official runner."""

    return asdict(
        OfficialCommandSpec(
            family="mcptox",
            command=[],
            expected_artifacts=["pinned pure_tool.json", "pinned response_all.json", "independently captured MCP calls"],
            claim_boundary=(
                "The pinned AAAI artifact repository exposes data and analysis artifacts but no supported end-to-end "
                "runner. Full MCPTox execution is blocked until a reproducible runner and judge contract are qualified."
            ),
            source_url="https://github.com/zhiqiangwang4/MCPTox-Benchmark",
            source_checked_at=utc_now(),
            execution_status="blocked_missing_official_runner",
            blocker="No supported command-line benchmark runner exists at the pinned source revision.",
        )
    )


def build_mcp_agentbench_command() -> dict[str, Any]:
    return asdict(
        OfficialCommandSpec(
            family="mcp_agentbench",
            command=[],
            expected_artifacts=["MCP-Eval judge outputs", "frozen server manifest", "agent trajectories"],
            claim_boundary=(
                "The AAAI paper is peer reviewed, but an official executable code revision and license were not "
                "identified from the publication source. Utility execution remains blocked."
            ),
            source_url="https://doi.org/10.1609/aaai.v40i37.40347",
            source_checked_at=utc_now(),
            execution_status="blocked_missing_official_code",
            blocker="Official executable code revision and license are unresolved.",
        )
    )


def validate_official_grader_artifact(*, family: str, artifact: Path) -> dict[str, Any]:
    resolved = artifact.expanduser().resolve()
    if not resolved.exists():
        return _validation(family, resolved, "fail", {"exists": False}, "official grader artifact does not exist")
    if family == "swe_bench_verified":
        return _validate_swe_bench_report(resolved)
    if family == "agentdojo":
        return _validate_agentdojo_artifact(resolved)
    if family == "agentharm":
        return _validate_agentharm_artifact(resolved)
    if family == "mcptox":
        return _validate_mcptox_artifact(resolved)
    if family in {"agentsecbench", "skill_inject"}:
        return _validate_generic_upstream_artifact(family, resolved)
    return _validation(family, resolved, "fail", {"known_family": False}, f"unknown benchmark family: {family}")


def validate_agentharm_execution_package(
    *,
    package_dir: Path,
    inspect_executable: Path,
    expected_harmful_case_ids: list[str],
    minimum_scored_cases: int,
    minimum_mean_functional_grader: float,
    minimum_tool_use_rate: float,
) -> dict[str, Any]:
    """Re-dump retained logs and reproduce every bound AgentHarm artifact."""

    root = package_dir.expanduser().absolute()
    if root.is_symlink() or not root.is_dir():
        raise ValueError("AgentHarm execution package must be a regular non-symlink directory")
    expected_ids = sorted({str(value).strip() for value in expected_harmful_case_ids if str(value).strip()})
    if not expected_ids or len(expected_ids) != len(expected_harmful_case_ids):
        raise ValueError("AgentHarm expected harmful case IDs must be unique and nonempty")
    archives = sorted(item for item in root.glob("*.eval") if item.is_file() and not item.is_symlink())
    if not archives:
        return _agentharm_package_validation(root, status="fail", reason="retained Inspect Eval archives are missing")
    harmful_rows: list[dict[str, Any]] = []
    benign_rows: list[dict[str, Any]] = []
    for archive in archives:
        dumped = dump_agentharm_inspect_eval(archive, inspect_executable=inspect_executable)
        payload = dumped["payload"]
        split = _agentharm_adapter_split_from_dump(payload)
        rows = extract_agentharm_inspect_rows(
            payload,
            split=split,
            upstream_artifact_hash=dumped["upstream_artifact_hash"],
        )
        if split.endswith("_benign"):
            benign_rows.extend(rows)
        else:
            harmful_rows.extend(rows)
    observed_ids = sorted(str(row["case_id"]) for row in harmful_rows)
    if observed_ids != expected_ids:
        return _agentharm_package_validation(
            root,
            status="fail",
            reason="harmful case set does not match the frozen pilot selection",
            observed_harmful_case_ids=observed_ids,
        )
    control = build_agentharm_capability_control(
        benign_rows,
        minimum_scored_cases=minimum_scored_cases,
        minimum_mean_functional_grader=minimum_mean_functional_grader,
        minimum_tool_use_rate=minimum_tool_use_rate,
    )
    reproduced = [bind_agentharm_capability_control(row, control) for row in harmful_rows]
    reproduced_by_hash = {str(artifact["artifact_hash"]): artifact for artifact in reproduced}
    retained_by_hash: dict[str, dict[str, Any]] = {}
    for path in sorted(root.glob("*.agentharm-bound.json")):
        payload = _read_json_object(path)
        if payload is None:
            return _agentharm_package_validation(root, status="fail", reason="bound artifact JSON is invalid")
        try:
            normalized = validate_agentharm_bound_artifact(payload)
        except ValueError:
            return _agentharm_package_validation(root, status="fail", reason="bound artifact validation failed")
        retained_by_hash[str(normalized["artifact_hash"])] = payload
    if set(retained_by_hash) != set(reproduced_by_hash):
        return _agentharm_package_validation(root, status="fail", reason="reproduced and retained artifact hashes differ")
    return _agentharm_package_validation(
        root,
        status="pass",
        reason="retained Inspect logs reproduce the frozen bound artifacts",
        observed_harmful_case_ids=observed_ids,
        harmful_artifact_hashes=sorted(reproduced_by_hash),
        capability_control=control,
    )


def _agentharm_adapter_split_from_dump(payload: dict[str, Any]) -> str:
    eval_payload = payload.get("eval")
    if not isinstance(eval_payload, dict):
        raise ValueError("AgentHarm Inspect dump is missing eval metadata")
    task_args = eval_payload.get("task_args")
    if not isinstance(task_args, dict):
        raise ValueError("AgentHarm Inspect dump is missing task arguments")
    key = (eval_payload.get("task"), task_args.get("split"))
    mapping = {
        ("inspect_evals/agentharm", "val"): "validation",
        ("inspect_evals/agentharm", "test_public"): "test_public",
        ("inspect_evals/agentharm_benign", "val"): "validation_benign",
        ("inspect_evals/agentharm_benign", "test_public"): "test_public_benign",
    }
    try:
        return mapping[key]
    except KeyError as exc:
        raise ValueError("AgentHarm Inspect dump task/split is unsupported") from exc


def _agentharm_package_validation(
    root: Path,
    *,
    status: str,
    reason: str,
    **evidence: Any,
) -> dict[str, Any]:
    result = {
        "schema_version": "invart.agentharm_execution_package_validation.v0.1",
        "status": status,
        "official_artifact_status": "valid" if status == "pass" else "invalid",
        "reason": reason,
        "package_dir": str(root),
        **evidence,
    }
    result["validation_hash"] = stable_json_hash(result)
    return result


def _validate_agentharm_artifact(path: Path) -> dict[str, Any]:
    candidates = [path] if path.is_file() else [item for item in path.rglob("*") if item.is_file()]
    inspect_archives = 0
    semantic_json = 0
    archive_hashes: set[str] = set()
    for item in candidates:
        if item.suffix.lower() == ".eval" and item.stat().st_size > 0:
            inspect_archives += 1
            archive_hashes.add(sha256_file(item, prefixed=True))
    for item in candidates:
        if item.suffix.lower() != ".json":
            continue
        payload = _read_json_object(item)
        if payload is not None:
            try:
                normalized = validate_agentharm_bound_artifact(payload)
            except ValueError:
                continue
            if normalized["upstream_artifact_hash"] in archive_hashes:
                semantic_json += 1
    checks = {
        "exists": True,
        "inspect_archives": inspect_archives,
        "hash_bound_json_matching_archive": semantic_json,
        "inspect_dump_revalidation_required": True,
        "native_fields_validated": False,
    }
    return _validation(
        "agentharm",
        path,
        "fail",
        checks,
        "AgentHarm native claims require re-dumping each retained .eval through the pinned Inspect executable and comparing extracted rows; portable JSON alone cannot pass",
    )

def _validate_mcptox_artifact(path: Path) -> dict[str, Any]:
    candidates = [path] if path.is_file() else [item for item in path.rglob("*.json") if item.is_file()]
    named = [item for item in candidates if item.name in {"pure_tool.json", "response_all.json"}]
    names = {item.name for item in named}
    required_names = {"pure_tool.json", "response_all.json"}
    parseable = names == required_names and all(_is_parseable_result_file(item) for item in named)
    checks = {
        "exists": True,
        "recognized_upstream_files": sorted(names),
        "required_upstream_files": sorted(required_names),
        "parseable": parseable,
    }
    return _validation(
        "mcptox",
        path,
        "pass" if parseable else "fail",
        checks,
        "MCPTox repository artifact validation; this does not prove a fresh benchmark execution",
    )


def _agentdojo_model_cli_value(model: str) -> str:
    normalized = model.strip()
    aliases = {
        "local": "LOCAL",
        "vllm_parsed": "VLLM_PARSED",
    }
    return aliases.get(normalized.lower(), normalized)


def _skill_inject_agent_cli_value(agent: str) -> str:
    normalized = agent.strip().replace("_", "-").lower()
    aliases = {
        "claude-code": "claude",
        "openai-codex": "codex",
        "gemini-cli": "gemini",
    }
    return aliases.get(normalized, normalized)


def _validate_swe_bench_report(path: Path) -> dict[str, Any]:
    payload = _read_json_object(path)
    numeric_fields = [
        "submitted_instances",
        "completed_instances",
        "resolved_instances",
        "empty_patch_instances",
        "error_instances",
    ]
    checks = {
        "exists": path.exists(),
        "json_object": payload is not None,
        "has_submitted_instances_field": payload is not None and "submitted_instances" in payload,
        "has_completed_instances_field": payload is not None and "completed_instances" in payload,
        "has_resolved_instances_field": payload is not None and "resolved_instances" in payload,
        "has_empty_patch_instances_field": payload is not None and "empty_patch_instances" in payload,
        "has_error_instances_field": payload is not None and "error_instances" in payload,
    }
    if payload is not None:
        for field in numeric_fields:
            checks[f"{field}_numeric"] = _is_int_like(payload.get(field))
    if payload is not None and "error_instances" in payload:
        try:
            checks["error_instances_zero"] = int(payload.get("error_instances") or 0) == 0
        except (TypeError, ValueError):
            checks["error_instances_zero"] = False
    status = "pass" if all(checks.values()) else "fail"
    return _validation("swe_bench_verified", path, status, checks, "SWE-Bench Verified official report validation")


def _validate_agentdojo_artifact(path: Path) -> dict[str, Any]:
    if path.is_dir():
        artifacts = [item for item in path.rglob("*") if item.is_file() and item.suffix.lower() in {".json", ".jsonl", ".csv", ".log"}]
        checks = {"exists": True, "directory": True, "has_result_like_files": bool(artifacts), "files": len(artifacts)}
        return _validation("agentdojo", path, "pass" if checks["has_result_like_files"] else "fail", checks, "AgentDojo logdir validation")
    checks = {"exists": True, "directory": False, "parseable": _is_parseable_result_file(path)}
    return _validation("agentdojo", path, "pass" if checks["parseable"] else "fail", checks, "AgentDojo result file validation")


def _validate_generic_upstream_artifact(family: str, path: Path) -> dict[str, Any]:
    if path.is_dir():
        files = [item for item in path.rglob("*") if item.is_file()]
        checks = {"exists": True, "directory": True, "files": len(files), "nonempty": bool(files)}
    else:
        checks = {"exists": True, "directory": False, "nonempty": path.stat().st_size > 0, "parseable": _is_parseable_result_file(path)}
    return _validation(family, path, "pass" if checks.get("nonempty") or checks.get("parseable") else "fail", checks, "upstream artifact presence validation")


def _is_parseable_result_file(path: Path) -> bool:
    suffix = path.suffix.lower()
    try:
        if suffix == ".json":
            return _read_json_object(path) is not None or _read_json_list(path) is not None
        if suffix == ".jsonl":
            return any(json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip())
        if suffix == ".csv":
            with path.open(newline="", encoding="utf-8") as handle:
                return bool(list(csv.reader(handle)))
        return path.stat().st_size > 0
    except Exception:
        return False


def _read_json_object(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _read_json_list(path: Path) -> list[Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, list) else None


def _is_int_like(value: Any) -> bool:
    try:
        int(value)
        return True
    except (TypeError, ValueError):
        return False


def _validation(family: str, artifact: Path, status: str, checks: dict[str, Any], reason: str) -> dict[str, Any]:
    return {
        "schema_version": "invart.p0_official_grader_validation.v0.1",
        "family": family,
        "artifact": str(artifact),
        "status": status,
        "checks": checks,
        "reason": reason,
    }
