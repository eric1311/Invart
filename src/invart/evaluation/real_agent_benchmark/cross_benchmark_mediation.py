from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any, Mapping, Sequence

from invart.core.artifacts import sha256_file, stable_json_hash

from .benchmark_adapters.base import (
    ADAPTER_SCHEMA_VERSION,
    BenchmarkCase,
    BenchmarkSourceFreeze,
    CaseRole,
    CommonActionEvent,
    NativeBenchmarkOutcome,
    normalize_effect_state,
    thaw_payload,
)


def build_cross_benchmark_result(
    *,
    source: BenchmarkSourceFreeze,
    case: BenchmarkCase,
    native_artifact: Path,
    native_outcome: NativeBenchmarkOutcome | None,
    events: Sequence[CommonActionEvent],
) -> dict[str, Any]:
    artifact = Path(native_artifact).expanduser().resolve()
    if not artifact.is_file() or native_outcome is None:
        return _blocked_result(source=source, case=case, reason="blocked_missing_native_artifact")
    observed_hash = sha256_file(artifact, prefixed=True)
    if native_outcome.artifact_sha256 != observed_hash:
        raise ValueError("native artifact hash does not match validated outcome")
    if native_outcome.benchmark_id != case.benchmark_id or native_outcome.case_id != case.case_id:
        raise ValueError("native outcome identity does not match case")
    if source.benchmark_id != case.benchmark_id:
        raise ValueError("source benchmark identity does not match case")
    if native_outcome.source_hash != source.source_hash:
        raise ValueError("native outcome source hash does not match source freeze")
    typed_events = tuple(events)
    if any(item.benchmark_id != case.benchmark_id or item.case_id != case.case_id for item in typed_events):
        raise ValueError("event identity does not match case")
    material = {
        "schema_version": ADAPTER_SCHEMA_VERSION,
        "status": "complete",
        "benchmark_id": case.benchmark_id,
        "case_id": case.case_id,
        "case_role": case.role.value,
        "source": source.to_dict(),
        "native_artifact": {"path": str(artifact), "sha256": observed_hash, "validator_id": native_outcome.validator_id},
        "native_outcome": thaw_payload(native_outcome.native_metrics),
        "runtime_policy_projection_hash": stable_json_hash(case.runtime_policy_projection()),
        "events": [item.to_dict() for item in typed_events],
        "evidence_kinds": sorted({item.evidence_kind.value for item in typed_events} | {"native_runtime"}),
        "claim_boundary": (
            "Native metrics remain opaque and benchmark-owned. Common events describe Invart-observed action states; "
            "they do not replace or rescore the native outcome."
        ),
    }
    return {**material, "result_hash": stable_json_hash(material)}


def pair_cases(cases: Sequence[BenchmarkCase]) -> dict[str, Any]:
    grouped: defaultdict[str, dict[CaseRole, list[BenchmarkCase]]] = defaultdict(lambda: defaultdict(list))
    has_pairing_key = False
    for case in cases:
        if case.comparison_key:
            has_pairing_key = True
            grouped[case.comparison_key][case.role].append(case)
    if not has_pairing_key:
        return {"status": "pairing_unavailable", "pairs": [], "reason": "benchmark declares no clean/attack comparison key"}
    pairs: list[dict[str, str]] = []
    for key, roles in sorted(grouped.items()):
        if len(roles[CaseRole.CLEAN]) == 1 and len(roles[CaseRole.ATTACK]) == 1:
            pairs.append({"comparison_key": key, "clean_case_id": roles[CaseRole.CLEAN][0].case_id, "attack_case_id": roles[CaseRole.ATTACK][0].case_id})
    return {
        "status": "paired" if pairs else "no_exact_pair",
        "pairs": pairs,
        "reason": None if pairs else "no comparison key has exactly one clean and one attack case",
    }


def common_events_from_agentdojo_join(join_payload: Mapping[str, Any]) -> tuple[CommonActionEvent, ...]:
    """Project joined AgentDojo calls into the same envelope as newer adapters."""

    events: list[CommonActionEvent] = []
    for row in join_payload.get("events") or []:
        if not isinstance(row, Mapping):
            raise ValueError("AgentDojo joined event must be an object")
        effect = normalize_effect_state(row.get("effect"))
        events.append(
            CommonActionEvent(
                benchmark_id="agentdojo",
                case_id=str(row.get("cell_ref") or ""),
                action_id=str(row.get("event_id") or ""),
                tool_name=str(row.get("tool_name") or ""),
                effect=effect,
                provenance_surface="tool_arguments",
                evidence_kind="adapter_comparable",
                authorization_evidence_refs=tuple(row.get("authorization_evidence_refs") or ()),
                native_event_ref=str(row.get("source_event_id") or "") or None,
            )
        )
    return tuple(events)


def _blocked_result(*, source: BenchmarkSourceFreeze, case: BenchmarkCase, reason: str) -> dict[str, Any]:
    material = {
        "schema_version": ADAPTER_SCHEMA_VERSION,
        "status": reason,
        "benchmark_id": case.benchmark_id,
        "case_id": case.case_id,
        "case_role": case.role.value,
        "source": source.to_dict(),
        "native_artifact": None,
        "native_outcome": None,
        "events": [],
        "evidence_kinds": [],
        "claim_boundary": "No native artifact was validated, so no benchmark score or security effect is claimable.",
    }
    return {**material, "result_hash": stable_json_hash(material)}


__all__ = ["build_cross_benchmark_result", "common_events_from_agentdojo_join", "pair_cases"]
