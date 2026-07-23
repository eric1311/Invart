from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Mapping, Sequence

from invart.core.artifacts import sha256_file, stable_json_hash

from .base import (
    BenchmarkCase,
    BenchmarkSourceFreeze,
    CaseRole,
    CommonActionEvent,
    EffectState,
    EvidenceKind,
    NativeBenchmarkOutcome,
    ProvenanceSurface,
    normalize_effect_state,
)


MCPTOX_SOURCE_URL = "https://github.com/zhiqiangwang4/MCPTox-Benchmark"
MCPTOX_REVISION = "f85189f9ad12504c197c7f920ab818a40657b1fa"


class MCPToxAdapter:
    benchmark_id = "mcptox"

    def __init__(self, *, split: str = "full") -> None:
        self.split = str(split or "").strip()
        if not self.split:
            raise ValueError("MCPTox split must be nonempty")

    def source_freeze(self) -> BenchmarkSourceFreeze:
        return BenchmarkSourceFreeze(
            benchmark_id=self.benchmark_id,
            source_url=MCPTOX_SOURCE_URL,
            revision=MCPTOX_REVISION,
            license="unresolved-no-license-file-at-pinned-revision",
            split=self.split,
            allowed_network_destinations=(),
        )

    def enumerate_cases(self, payload: Mapping[str, Any]) -> tuple[BenchmarkCase, ...]:
        rows = payload.get("cases")
        if not isinstance(rows, list):
            raise ValueError("MCPTox cases must be a list")
        cases: list[BenchmarkCase] = []
        for row in rows:
            if not isinstance(row, Mapping):
                raise ValueError("MCPTox case must be an object")
            role = CaseRole(str(row.get("role") or ""))
            server_hash = str(row.get("server_environment_hash") or "").strip()
            if not server_hash.startswith("sha256:"):
                raise ValueError("MCPTox server environment hash must be frozen")
            pairing_dimensions = row.get("pairing_dimensions")
            if not isinstance(pairing_dimensions, Mapping):
                raise ValueError("MCPTox pairing dimensions must be explicit")
            comparison_key = stable_json_hash(
                {
                    "dimensions": dict(pairing_dimensions),
                    "server_environment_hash": server_hash,
                }
            )
            tool_name = str(row.get("tool_name") or "")
            schema = {
                "name": tool_name,
                "description": str(row.get("tool_description") or ""),
                "parameters": dict(row.get("tool_parameters") or {}),
            }
            cases.append(
                BenchmarkCase(
                    benchmark_id=self.benchmark_id,
                    case_id=str(row.get("id") or ""),
                    role=role,
                    comparison_key=comparison_key,
                    user_objective=str(row.get("user_objective") or ""),
                    tool_schemas=(schema,),
                    capability_profile=row.get("capability_profile") or {},
                    adapter_metadata={
                        "server_id": str(row.get("server_id") or ""),
                        "server_environment_hash": server_hash,
                        "pairing_dimensions_hash": stable_json_hash(dict(pairing_dimensions)),
                        "untrusted_surfaces": ["tool_description"] if role is CaseRole.ATTACK else [],
                    },
                )
            )
        return tuple(cases)

    def validate_native_result(self, *, case: BenchmarkCase, artifact: Path) -> NativeBenchmarkOutcome:
        path = Path(artifact).expanduser().resolve()
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("invalid MCPTox native artifact") from exc
        if not isinstance(payload, dict) or payload.get("case_id") != case.case_id:
            raise ValueError("MCPTox native artifact identity mismatch")
        required = {
            "judge_attack_success",
            "clean_task_success",
            "upstream_record_hash",
            "source_revision",
            "judge_config_hash",
        }
        if not required.issubset(payload):
            raise ValueError("MCPTox native artifact is missing upstream outcome fields")
        if type(payload["judge_attack_success"]) is not bool or type(payload["clean_task_success"]) is not bool:
            raise ValueError("MCPTox outcome fields must be literal booleans")
        if payload["source_revision"] != MCPTOX_REVISION:
            raise ValueError("MCPTox source revision mismatch")
        for field_name in ("upstream_record_hash", "judge_config_hash"):
            if not str(payload[field_name]).startswith("sha256:"):
                raise ValueError(f"MCPTox {field_name} must be hash-bound")
        metrics = {key: payload[key] for key in sorted(required)}
        return NativeBenchmarkOutcome(
            benchmark_id=self.benchmark_id,
            case_id=case.case_id,
            artifact_sha256=sha256_file(path, prefixed=True),
            validator_id="mcptox-aaai-artifact-v1",
            native_metrics=metrics,
            source_hash=self.source_freeze().source_hash,
        )

    def join_events(
        self,
        *,
        case: BenchmarkCase,
        records: Sequence[Mapping[str, Any]],
    ) -> tuple[CommonActionEvent, ...]:
        events: list[CommonActionEvent] = []
        for record in records:
            if record.get("case_id") != case.case_id:
                raise ValueError("MCPTox action record identity mismatch")
            side_effect = str(record.get("side_effect_ref") or "").strip()
            events.append(
                CommonActionEvent(
                    benchmark_id=self.benchmark_id,
                    case_id=case.case_id,
                    action_id=str(record.get("action_id") or ""),
                    tool_name=str(record.get("tool_name") or ""),
                    effect=normalize_effect_state(record.get("effect")),
                    provenance_surface=ProvenanceSurface(str(record.get("provenance_surface") or "")),
                    evidence_kind=EvidenceKind.SIDE_EFFECT if side_effect else EvidenceKind.ADAPTER_COMPARABLE,
                    authorization_evidence_refs=tuple(record.get("authorization_evidence_refs") or ()),
                    side_effect_evidence_refs=(side_effect,) if side_effect else (),
                )
            )
        return tuple(events)


def pair_mcptox_cases(
    cases: Sequence[BenchmarkCase],
    *,
    clean_outcomes: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    grouped: defaultdict[str, dict[CaseRole, list[BenchmarkCase]]] = defaultdict(lambda: defaultdict(list))
    dimension_hashes: defaultdict[str, set[str]] = defaultdict(set)
    for case in cases:
        if case.comparison_key:
            grouped[case.comparison_key][case.role].append(case)
        server_hash = str(case.adapter_metadata.get("server_environment_hash") or "")
        dimensions_hash = str(case.adapter_metadata.get("pairing_dimensions_hash") or "")
        dimension_hashes[dimensions_hash].add(server_hash)
    structural_pairs: list[dict[str, str]] = []
    eligible_pairs: list[dict[str, str]] = []
    capability_failures = 0
    for key, roles in sorted(grouped.items()):
        if len(roles[CaseRole.CLEAN]) != 1 or len(roles[CaseRole.ATTACK]) != 1:
            continue
        clean = roles[CaseRole.CLEAN][0]
        pair = {"comparison_key": key, "clean_case_id": clean.case_id, "attack_case_id": roles[CaseRole.ATTACK][0].case_id}
        structural_pairs.append(pair)
        if clean_outcomes is None:
            continue
        if not clean_outcomes.get(clean.case_id, {}).get("clean_tool_success"):
            capability_failures += 1
            continue
        eligible_pairs.append(pair)
    if clean_outcomes is None and structural_pairs:
        status = "pair_structure_only"
    elif capability_failures and not eligible_pairs:
        status = "capability_only"
    else:
        status = "paired" if eligible_pairs else "no_exact_pair"
    environment_drift = any(len(values) > 1 for values in dimension_hashes.values())
    return {
        "status": status,
        "pairs": structural_pairs,
        "eligible_pairs": eligible_pairs,
        "eligible_security_pairs": len(eligible_pairs),
        "capability_failures": capability_failures,
        "environment_drift": environment_drift,
    }


def classify_mcptox_evidence(
    *,
    native: NativeBenchmarkOutcome,
    events: Sequence[CommonActionEvent],
) -> dict[str, Any]:
    judge_success = native.native_metrics.get("judge_attack_success") is True
    executed = any(
        event.effect is EffectState.EXECUTED and bool(event.side_effect_evidence_refs)
        for event in events
    )
    return {
        "judge_attack_success": judge_success,
        "executed_target_action": executed,
        "strongest_attack_evidence": "side_effect" if executed else "judge" if judge_success else "none",
        "claim_boundary": "Judge success and observed target-side effects are reported separately.",
    }


__all__ = [
    "MCPTOX_REVISION",
    "MCPTOX_SOURCE_URL",
    "MCPToxAdapter",
    "classify_mcptox_evidence",
    "pair_mcptox_cases",
]
