from __future__ import annotations

import json
import math
import os
import subprocess
from pathlib import Path
from typing import Any, Mapping, Sequence

from invart.core.artifacts import sha256_file, stable_json_hash

from .base import (
    BenchmarkCase,
    BenchmarkSourceFreeze,
    CaseRole,
    CommonActionEvent,
    EvidenceKind,
    NativeBenchmarkOutcome,
    ProvenanceSurface,
    normalize_effect_state,
)


AGENTHARM_DATASET_REVISION = "e23b3fe60a0da9037314b88e5ee3a0c054970dad"
AGENTHARM_DATASET_URL = "https://huggingface.co/datasets/ai-safety-institute/AgentHarm"
AGENTHARM_RUNNER_REVISION = "a02da4190544ea6b9ca643feed3708d1f7426756"
AGENTHARM_INSPECT_AI_REVISION = "e2dab6dabc98923ca5ee6606bba6fe52655ec185"
AGENTHARM_INSPECT_ROW_SCHEMA_VERSION = "invart.agentharm_inspect_native_row.v0.1"
AGENTHARM_CAPABILITY_CONTROL_SCHEMA_VERSION = "invart.agentharm_capability_control.v0.1"
AGENTHARM_BOUND_ARTIFACT_SCHEMA_VERSION = "invart.agentharm_bound_artifact.v0.1"

_SPLIT_CONTRACTS = {
    "validation": ("inspect_evals/agentharm", "val", "harmful"),
    "test_public": ("inspect_evals/agentharm", "test_public", "harmful"),
    "validation_benign": ("inspect_evals/agentharm_benign", "val", "benign"),
    "test_public_benign": ("inspect_evals/agentharm_benign", "test_public", "benign"),
}


class AgentHarmAdapter:
    benchmark_id = "agentharm"

    def __init__(self, *, split: str) -> None:
        agentharm_split_contract(split)
        self.split = split

    def source_freeze(self) -> BenchmarkSourceFreeze:
        return BenchmarkSourceFreeze(
            benchmark_id=self.benchmark_id,
            source_url=AGENTHARM_DATASET_URL,
            revision=AGENTHARM_DATASET_REVISION,
            license="MIT-with-safety-and-security-use-clause",
            split=self.split,
            allowed_network_destinations=(),
            companion_sources=(
                {
                    "role": "official_runner",
                    "url": "https://github.com/UKGovernmentBEIS/inspect_evals",
                    "revision": AGENTHARM_RUNNER_REVISION,
                },
                {
                    "role": "runner_core",
                    "url": "https://github.com/UKGovernmentBEIS/inspect_ai",
                    "revision": AGENTHARM_INSPECT_AI_REVISION,
                },
            ),
        )

    def enumerate_cases(self, payload: Mapping[str, Any]) -> tuple[BenchmarkCase, ...]:
        if payload.get("split") != self.split:
            raise ValueError("AgentHarm split does not match adapter freeze")
        raw_cases = payload.get("cases")
        if not isinstance(raw_cases, list):
            raise ValueError("AgentHarm cases must be a list")
        cases: list[BenchmarkCase] = []
        for raw in raw_cases:
            if not isinstance(raw, Mapping):
                raise ValueError("AgentHarm case must be an object")
            rubric_rows = raw.get("rubrics") or []
            if not isinstance(rubric_rows, list):
                raise ValueError("AgentHarm rubrics must be a list")
            rubric_ids = [str(item.get("id")) for item in rubric_rows if isinstance(item, Mapping) and item.get("id")]
            default_role = CaseRole.CAPABILITY if self.split.endswith("_benign") else CaseRole.ATTACK
            role = CaseRole(str(raw.get("role") or default_role.value))
            case_id = str(raw.get("id") or "").strip()
            cases.append(
                BenchmarkCase(
                    benchmark_id=self.benchmark_id,
                    case_id=case_id,
                    role=role,
                    comparison_key=str(raw.get("comparison_key")).strip() if raw.get("comparison_key") else None,
                    user_objective=str(raw.get("prompt") or ""),
                    tool_schemas=tuple(raw.get("tools") or ()),
                    capability_profile=raw.get("capability_profile") or {},
                    adapter_metadata={
                        "rubric_ids": rubric_ids,
                        "rubric_hash": stable_json_hash(rubric_rows),
                        "category_hash": stable_json_hash(str(raw.get("category") or "")),
                        "runtime_visibility": "post_hoc_only",
                    },
                )
            )
        return tuple(cases)

    def validate_native_result(self, *, case: BenchmarkCase, artifact: Path) -> NativeBenchmarkOutcome:
        path = Path(artifact).expanduser().resolve()
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("invalid AgentHarm native artifact") from exc
        if not isinstance(payload, dict):
            raise ValueError("AgentHarm native artifact must be an object")
        normalized = validate_agentharm_bound_artifact(payload)
        if normalized.get("case_id") != case.case_id:
            raise ValueError("AgentHarm native artifact identity mismatch")
        if normalized["split"] != self.split:
            raise ValueError("AgentHarm dataset freeze mismatch")
        native_fields = {"refusal", "task_success", "tool_interface_valid", "capability_control_pass", "functional_grader"}
        metrics = {key: normalized[key] for key in sorted(native_fields)}
        metrics["provenance"] = {
            key: value for key, value in normalized.items() if key not in native_fields
        }
        return NativeBenchmarkOutcome(
            benchmark_id=self.benchmark_id,
            case_id=case.case_id,
            artifact_sha256=sha256_file(path, prefixed=True),
            validator_id="agentharm-bound-inspect-bridge-v1",
            native_metrics=metrics,
            source_hash=self.source_freeze().source_hash,
        )

    def join_events(
        self,
        *,
        case: BenchmarkCase,
        records: Sequence[Mapping[str, Any]],
    ) -> tuple[CommonActionEvent, ...]:
        rubric_ids = set(case.adapter_metadata.get("rubric_ids") or [])
        events: list[CommonActionEvent] = []
        for record in records:
            if record.get("case_id") != case.case_id:
                raise ValueError("AgentHarm action record identity mismatch")
            rubric_item = str(record.get("rubric_item_id") or "")
            if rubric_item and rubric_item not in rubric_ids:
                raise ValueError("AgentHarm action references an unknown rubric item")
            effect = normalize_effect_state(record.get("effect"))
            side_effect_ref = str(record.get("side_effect_ref") or "").strip()
            events.append(
                CommonActionEvent(
                    benchmark_id=self.benchmark_id,
                    case_id=case.case_id,
                    action_id=str(record.get("action_id") or ""),
                    tool_name=str(record.get("tool_name") or ""),
                    effect=effect,
                    provenance_surface=ProvenanceSurface.TOOL_ARGUMENTS,
                    evidence_kind=EvidenceKind.SIDE_EFFECT if side_effect_ref else EvidenceKind.ADAPTER_COMPARABLE,
                    authorization_evidence_refs=tuple(record.get("authorization_evidence_refs") or ()),
                    side_effect_evidence_refs=(side_effect_ref,) if side_effect_ref else (),
                    native_event_ref=rubric_item or None,
                )
            )
        return tuple(events)


def classify_agentharm_eligibility(
    native_metrics: Mapping[str, Any],
    *,
    case_role: CaseRole = CaseRole.ATTACK,
) -> dict[str, Any]:
    if case_role is not CaseRole.ATTACK:
        return {"status": "capability_control", "eligible_harmful_denominator": False}
    if native_metrics.get("tool_interface_valid") is not True or native_metrics.get("capability_control_pass") is not True:
        return {"status": "capability_only", "eligible_harmful_denominator": False}
    if native_metrics.get("refusal") is True:
        return {"status": "refused_harmful_task", "eligible_harmful_denominator": True}
    return {"status": "eligible_harmful_task", "eligible_harmful_denominator": True}


def extract_agentharm_inspect_rows(
    payload: Mapping[str, Any],
    *,
    split: str,
    upstream_artifact_hash: str,
) -> tuple[dict[str, Any], ...]:
    """Extract benchmark-owned scores from an ``inspect log dump`` payload.

    This layer intentionally does not infer capability from a harmful task. A
    separately scored benign control must be bound with
    :func:`bind_agentharm_capability_control` before the adapter accepts the row
    as a claimable native artifact.
    """

    expected_task, expected_native_split, task_kind = agentharm_split_contract(split)
    if not str(upstream_artifact_hash).startswith("sha256:"):
        raise ValueError("AgentHarm upstream artifact must be hash-bound")
    if payload.get("status") != "success":
        raise ValueError("AgentHarm Inspect log did not complete successfully")
    eval_payload = payload.get("eval")
    if not isinstance(eval_payload, Mapping):
        raise ValueError("AgentHarm Inspect log is missing eval metadata")
    if eval_payload.get("task") != expected_task:
        raise ValueError("AgentHarm Inspect task does not match split contract")
    task_args = eval_payload.get("task_args")
    if not isinstance(task_args, Mapping) or task_args.get("split") != expected_native_split:
        raise ValueError("AgentHarm Inspect native split does not match adapter split")
    model = _nonempty_string(eval_payload.get("model"), field_name="AgentHarm model")
    refusal_judge = _nonempty_string(task_args.get("refusal_judge"), field_name="AgentHarm refusal judge")
    semantic_judge = _nonempty_string(task_args.get("semantic_judge"), field_name="AgentHarm semantic judge")
    grader_config = {
        "task": expected_task,
        "split": expected_native_split,
        "agent": task_args.get("agent", "default"),
        "agent_kwargs": task_args.get("agent_kwargs") or {},
        "refusal_judge": refusal_judge,
        "semantic_judge": semantic_judge,
        "eval_metadata": eval_payload.get("metadata") or {},
        "scorer_contract": "inspect_evals.agentharm.combined_scorer.v1",
    }
    grader_config_hash = stable_json_hash(grader_config)
    execution_binding = {
        "model": model,
        "agent": task_args.get("agent", "default"),
        "agent_kwargs": task_args.get("agent_kwargs") or {},
        "judge_models": {"refusal": refusal_judge, "semantic": semantic_judge},
        "runner_revision": AGENTHARM_RUNNER_REVISION,
        "inspect_ai_revision": AGENTHARM_INSPECT_AI_REVISION,
        "dataset_revision": AGENTHARM_DATASET_REVISION,
    }
    execution_binding_hash = stable_json_hash(execution_binding)
    results = payload.get("results")
    samples = payload.get("samples")
    if not isinstance(results, Mapping) or not isinstance(samples, list):
        raise ValueError("AgentHarm Inspect log is missing results or samples")
    total_samples = _nonnegative_int(results.get("total_samples"), field_name="total_samples")
    completed_samples = _nonnegative_int(results.get("completed_samples"), field_name="completed_samples")
    if total_samples != len(samples) or completed_samples != total_samples:
        raise ValueError("AgentHarm Inspect log is incomplete")

    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    for sample in samples:
        if not isinstance(sample, Mapping):
            raise ValueError("AgentHarm Inspect sample must be an object")
        case_id = _nonempty_string(sample.get("id"), field_name="AgentHarm case ID")
        epoch = _positive_int(sample.get("epoch", 1), field_name="AgentHarm epoch")
        identity = (case_id, epoch)
        if identity in seen:
            raise ValueError("AgentHarm Inspect log contains duplicate sample identity")
        seen.add(identity)
        if sample.get("error") is not None:
            raise ValueError("AgentHarm Inspect sample contains an execution error")
        functional_grader, refusal, scorer_name = _extract_combined_scorer(sample.get("scores"))
        messages = sample.get("messages")
        if not isinstance(messages, list):
            raise ValueError("AgentHarm Inspect sample messages must be a list")
        proposed_tool_call_ids = {
            str(tool_call.get("id") or "").strip()
            for message in messages
            if isinstance(message, Mapping) and isinstance(message.get("tool_calls"), list)
            for tool_call in message["tool_calls"]
            if isinstance(tool_call, Mapping) and str(tool_call.get("id") or "").strip()
        }
        successful_tool_result_ids = {
            str(message.get("tool_call_id") or "").strip()
            for message in messages
            if isinstance(message, Mapping)
            and message.get("role") == "tool"
            and not message.get("error")
            and str(message.get("tool_call_id") or "").strip()
            and str(message.get("content") or "").strip()
        }
        successful_tool_call_count = len(proposed_tool_call_ids & successful_tool_result_ids)
        sample_metadata = sample.get("metadata")
        if not isinstance(sample_metadata, Mapping):
            raise ValueError("AgentHarm Inspect sample metadata must be an object")
        row = {
            "schema_version": AGENTHARM_INSPECT_ROW_SCHEMA_VERSION,
            "case_id": case_id,
            "epoch": epoch,
            "task_kind": task_kind,
            "model": model,
            "judge_models": {"refusal": refusal_judge, "semantic": semantic_judge},
            "refusal": refusal,
            "task_success": functional_grader == 1.0,
            "functional_grader": functional_grader,
            "proposed_tool_call_count": len(proposed_tool_call_ids),
            "tool_call_count": successful_tool_call_count,
            "scorer_name": scorer_name,
            "sample_metadata_hash": stable_json_hash(dict(sample_metadata)),
            "upstream_artifact_hash": upstream_artifact_hash,
            "runner_revision": AGENTHARM_RUNNER_REVISION,
            "inspect_ai_revision": AGENTHARM_INSPECT_AI_REVISION,
            "dataset_revision": AGENTHARM_DATASET_REVISION,
            "split": split,
            "grader_config_hash": grader_config_hash,
            "execution_binding_hash": execution_binding_hash,
        }
        row["native_row_hash"] = stable_json_hash(row)
        rows.append(row)
    return tuple(rows)


def dump_agentharm_inspect_eval(
    eval_path: Path,
    *,
    inspect_executable: Path,
    timeout_seconds: float = 120.0,
) -> dict[str, Any]:
    """Use Inspect's supported CLI to dump a Zstandard-compressed ``.eval`` log."""

    archive_input = Path(eval_path).expanduser().absolute()
    executable_input = Path(inspect_executable).expanduser().absolute()
    if archive_input.is_symlink():
        raise ValueError("AgentHarm Inspect archive must be a regular non-symlink .eval file")
    if executable_input.is_symlink():
        raise ValueError("Inspect executable must be a regular executable file")
    archive = archive_input.resolve()
    executable = executable_input.resolve()
    if not archive.is_file() or archive.suffix.lower() != ".eval":
        raise ValueError("AgentHarm Inspect archive must be a regular non-symlink .eval file")
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise ValueError("Inspect executable must be a regular executable file")
    if timeout_seconds <= 0:
        raise ValueError("Inspect dump timeout must be positive")
    try:
        completed = subprocess.run(
            [str(executable), "log", "dump", str(archive)],
            capture_output=True,
            text=True,
            timeout=float(timeout_seconds),
            check=False,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("AgentHarm Inspect log dump failed") from exc
    if completed.returncode != 0:
        raise ValueError("AgentHarm Inspect log dump failed")
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError("AgentHarm Inspect log dump did not emit valid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("AgentHarm Inspect log dump must emit a JSON object")
    return {
        "payload": payload,
        "upstream_artifact_hash": sha256_file(archive, prefixed=True),
        "inspect_executable": str(executable),
    }


def agentharm_split_contract(split: str) -> tuple[str, str, str]:
    try:
        return _SPLIT_CONTRACTS[split]
    except KeyError as exc:
        raise ValueError("unsupported AgentHarm split") from exc


def build_agentharm_capability_control(
    benign_rows: Sequence[Mapping[str, Any]],
    *,
    minimum_scored_cases: int,
    minimum_mean_functional_grader: float,
    minimum_tool_use_rate: float,
) -> dict[str, Any]:
    """Build a frozen capability gate from separately scored benign rows."""

    minimum_scored_cases = _positive_int(minimum_scored_cases, field_name="minimum_scored_cases")
    minimum_mean_functional_grader = _unit_interval(
        minimum_mean_functional_grader,
        field_name="minimum_mean_functional_grader",
    )
    minimum_tool_use_rate = _unit_interval(minimum_tool_use_rate, field_name="minimum_tool_use_rate")
    rows = [dict(row) for row in benign_rows]
    if not rows:
        raise ValueError("AgentHarm capability control requires benign rows")
    identities: set[tuple[str, int]] = set()
    scores: list[float] = []
    tool_use_cases = 0
    row_hashes: list[str] = []
    common_binding: dict[str, Any] | None = None
    for row in rows:
        _validate_agentharm_native_row(row, expected_task_kind="benign")
        identity = (str(row.get("case_id") or ""), int(row.get("epoch") or 0))
        if not identity[0] or identity[1] <= 0 or identity in identities:
            raise ValueError("AgentHarm capability control contains invalid or duplicate identities")
        identities.add(identity)
        score = _unit_interval(row.get("functional_grader"), field_name="functional_grader")
        scores.append(score)
        if _nonnegative_int(row.get("tool_call_count"), field_name="tool_call_count") > 0:
            tool_use_cases += 1
        binding = {
            "model": row["model"],
            "judge_models": row["judge_models"],
            "execution_binding_hash": row["execution_binding_hash"],
            "runner_revision": row["runner_revision"],
            "inspect_ai_revision": row["inspect_ai_revision"],
            "dataset_revision": row["dataset_revision"],
            "split": row["split"],
        }
        if common_binding is None:
            common_binding = binding
        elif binding != common_binding:
            raise ValueError("AgentHarm benign rows must share one model and execution binding")
        row_hash = str(row["native_row_hash"])
        row_hashes.append(row_hash)
    assert common_binding is not None
    mean_score = sum(scores) / len(scores)
    full_success_rate = sum(score == 1.0 for score in scores) / len(scores)
    tool_use_rate = tool_use_cases / len(rows)
    tool_interface_valid = len(rows) >= minimum_scored_cases and tool_use_rate >= minimum_tool_use_rate
    capability_control_pass = tool_interface_valid and mean_score >= minimum_mean_functional_grader
    control = {
        "schema_version": AGENTHARM_CAPABILITY_CONTROL_SCHEMA_VERSION,
        "scored_cases": len(rows),
        "minimum_scored_cases": minimum_scored_cases,
        "mean_functional_grader": mean_score,
        "full_task_success_rate": full_success_rate,
        "tool_use_rate": tool_use_rate,
        "minimum_mean_functional_grader": minimum_mean_functional_grader,
        "minimum_tool_use_rate": minimum_tool_use_rate,
        "tool_interface_valid": tool_interface_valid,
        "capability_control_pass": capability_control_pass,
        "benign_row_hashes": sorted(row_hashes),
        "benign_rows": sorted(rows, key=lambda item: (str(item["case_id"]), int(item["epoch"]))),
        **common_binding,
    }
    control["capability_control_hash"] = stable_json_hash(control)
    return control


def bind_agentharm_capability_control(
    native_row: Mapping[str, Any],
    capability_control: Mapping[str, Any],
) -> dict[str, Any]:
    """Create the adapter artifact by binding official score and benign control."""

    row = dict(native_row)
    _validate_agentharm_native_row(row, expected_task_kind="harmful")
    control = dict(capability_control)
    _validate_agentharm_capability_control(control)
    expected_benign_split = f"{row['split']}_benign"
    if control["split"] != expected_benign_split:
        raise ValueError("AgentHarm capability control split is not paired with harmful split")
    for field_name in (
        "model",
        "judge_models",
        "execution_binding_hash",
        "runner_revision",
        "inspect_ai_revision",
        "dataset_revision",
    ):
        if control[field_name] != row[field_name]:
            raise ValueError(f"AgentHarm capability control {field_name} binding mismatch")
    artifact = {
        "schema_version": AGENTHARM_BOUND_ARTIFACT_SCHEMA_VERSION,
        "native_row": row,
        "capability_control": control,
    }
    artifact["artifact_hash"] = stable_json_hash(artifact)
    return artifact


def validate_agentharm_bound_artifact(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and flatten a recomputable AgentHarm evidence bundle."""

    artifact = dict(payload)
    if artifact.get("schema_version") != AGENTHARM_BOUND_ARTIFACT_SCHEMA_VERSION:
        raise ValueError("AgentHarm bound artifact schema mismatch")
    artifact_hash = str(artifact.get("artifact_hash") or "")
    if artifact_hash != stable_json_hash({k: v for k, v in artifact.items() if k != "artifact_hash"}):
        raise ValueError("AgentHarm bound artifact hash mismatch")
    native_row = artifact.get("native_row")
    capability_control = artifact.get("capability_control")
    if not isinstance(native_row, Mapping) or not isinstance(capability_control, Mapping):
        raise ValueError("AgentHarm bound artifact is missing nested evidence")
    expected = bind_agentharm_capability_control(native_row, capability_control)
    if expected != artifact:
        raise ValueError("AgentHarm bound artifact content mismatch")
    row = dict(native_row)
    control = dict(capability_control)
    return {
        "case_id": row["case_id"],
        "epoch": row["epoch"],
        "model": row["model"],
        "judge_models": row["judge_models"],
        "refusal": row["refusal"],
        "task_success": row["task_success"],
        "tool_interface_valid": control["tool_interface_valid"],
        "capability_control_pass": control["capability_control_pass"],
        "functional_grader": row["functional_grader"],
        "upstream_artifact_hash": row["upstream_artifact_hash"],
        "runner_revision": row["runner_revision"],
        "inspect_ai_revision": row["inspect_ai_revision"],
        "dataset_revision": row["dataset_revision"],
        "split": row["split"],
        "grader_config_hash": row["grader_config_hash"],
        "execution_binding_hash": row["execution_binding_hash"],
        "capability_control_hash": control["capability_control_hash"],
        "native_row_hash": row["native_row_hash"],
        "artifact_hash": artifact_hash,
    }


def _extract_combined_scorer(raw_scores: Any) -> tuple[float, bool, str]:
    if not isinstance(raw_scores, Mapping):
        raise ValueError("AgentHarm sample scores must be an object")
    candidates: list[tuple[str, Mapping[str, Any]]] = []
    for name, raw_score in raw_scores.items():
        if not isinstance(raw_score, Mapping):
            continue
        value = raw_score.get("value")
        if isinstance(value, Mapping) and {"score", "refusal"}.issubset(value):
            candidates.append((str(name), value))
    if len(candidates) != 1 or candidates[0][0] != "combined_scorer":
        raise ValueError("AgentHarm sample must contain exactly one official combined_scorer result")
    scorer_name, value = candidates[0]
    functional_grader = _unit_interval(value.get("score"), field_name="AgentHarm native score")
    refusal_value = value.get("refusal")
    if type(refusal_value) not in {int, float} or refusal_value not in {0, 0.0, 1, 1.0}:
        raise ValueError("AgentHarm native score refusal must be exactly 0.0 or 1.0")
    return functional_grader, bool(refusal_value), scorer_name


def _validate_agentharm_native_row(row: Mapping[str, Any], *, expected_task_kind: str) -> None:
    if row.get("schema_version") != AGENTHARM_INSPECT_ROW_SCHEMA_VERSION or row.get("task_kind") != expected_task_kind:
        raise ValueError(f"AgentHarm {expected_task_kind} row schema mismatch")
    row_hash = str(row.get("native_row_hash") or "")
    if row_hash != stable_json_hash({k: v for k, v in row.items() if k != "native_row_hash"}):
        raise ValueError(f"AgentHarm {expected_task_kind} row hash mismatch")
    if type(row.get("refusal")) is not bool or type(row.get("task_success")) is not bool:
        raise ValueError("AgentHarm native row booleans must be literal")
    score = _unit_interval(row.get("functional_grader"), field_name="functional_grader")
    if row["task_success"] is not (score == 1.0):
        raise ValueError("AgentHarm task_success disagrees with functional_grader")
    if row.get("scorer_name") != "combined_scorer":
        raise ValueError("AgentHarm native row scorer is not official")
    expected_split_suffix = "_benign" if expected_task_kind == "benign" else ""
    if row.get("split") not in {f"validation{expected_split_suffix}", f"test_public{expected_split_suffix}"}:
        raise ValueError("AgentHarm native row split mismatch")
    if (
        row.get("runner_revision") != AGENTHARM_RUNNER_REVISION
        or row.get("inspect_ai_revision") != AGENTHARM_INSPECT_AI_REVISION
        or row.get("dataset_revision") != AGENTHARM_DATASET_REVISION
    ):
        raise ValueError("AgentHarm native row source freeze mismatch")
    for field_name in ("upstream_artifact_hash", "grader_config_hash", "execution_binding_hash"):
        if not str(row.get(field_name) or "").startswith("sha256:"):
            raise ValueError(f"AgentHarm native row {field_name} must be hash-bound")
    _nonempty_string(row.get("model"), field_name="AgentHarm model")
    judges = row.get("judge_models")
    if not isinstance(judges, Mapping):
        raise ValueError("AgentHarm judge models must be an object")
    _nonempty_string(judges.get("refusal"), field_name="AgentHarm refusal judge")
    _nonempty_string(judges.get("semantic"), field_name="AgentHarm semantic judge")


def _validate_agentharm_capability_control(control: Mapping[str, Any]) -> None:
    control_hash = str(control.get("capability_control_hash") or "")
    if (
        control.get("schema_version") != AGENTHARM_CAPABILITY_CONTROL_SCHEMA_VERSION
        or control_hash != stable_json_hash({k: v for k, v in control.items() if k != "capability_control_hash"})
        or type(control.get("tool_interface_valid")) is not bool
        or type(control.get("capability_control_pass")) is not bool
    ):
        raise ValueError("AgentHarm capability control is invalid or not hash-bound")
    benign_rows = control.get("benign_rows")
    if not isinstance(benign_rows, list):
        raise ValueError("AgentHarm capability control must retain benign native rows")
    expected = build_agentharm_capability_control(
        benign_rows,
        minimum_scored_cases=_positive_int(
            control.get("minimum_scored_cases"),
            field_name="minimum_scored_cases",
        ),
        minimum_mean_functional_grader=_unit_interval(
            control.get("minimum_mean_functional_grader"),
            field_name="minimum_mean_functional_grader",
        ),
        minimum_tool_use_rate=_unit_interval(
            control.get("minimum_tool_use_rate"),
            field_name="minimum_tool_use_rate",
        ),
    )
    if expected != dict(control):
        raise ValueError("AgentHarm capability control aggregates do not match benign rows")


def _nonempty_string(value: Any, *, field_name: str) -> str:
    normalized = str(value or "").strip()
    if not normalized:
        raise ValueError(f"{field_name} must be nonempty")
    return normalized


def _nonnegative_int(value: Any, *, field_name: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{field_name} must be a nonnegative integer")
    return value


def _positive_int(value: Any, *, field_name: str) -> int:
    parsed = _nonnegative_int(value, field_name=field_name)
    if parsed <= 0:
        raise ValueError(f"{field_name} must be positive")
    return parsed


def _unit_interval(value: Any, *, field_name: str) -> float:
    if type(value) not in {int, float}:
        raise ValueError(f"{field_name} must be a numeric native score")
    parsed = float(value)
    if not math.isfinite(parsed) or parsed < 0.0 or parsed > 1.0:
        raise ValueError(f"{field_name} must be a native score in [0, 1]")
    return parsed


__all__ = [
    "AGENTHARM_CAPABILITY_CONTROL_SCHEMA_VERSION",
    "AGENTHARM_BOUND_ARTIFACT_SCHEMA_VERSION",
    "AGENTHARM_DATASET_REVISION",
    "AGENTHARM_DATASET_URL",
    "AGENTHARM_INSPECT_AI_REVISION",
    "AGENTHARM_INSPECT_ROW_SCHEMA_VERSION",
    "AGENTHARM_RUNNER_REVISION",
    "AgentHarmAdapter",
    "agentharm_split_contract",
    "bind_agentharm_capability_control",
    "build_agentharm_capability_control",
    "classify_agentharm_eligibility",
    "dump_agentharm_inspect_eval",
    "extract_agentharm_inspect_rows",
    "validate_agentharm_bound_artifact",
]
