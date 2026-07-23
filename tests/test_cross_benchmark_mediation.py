from __future__ import annotations

import json
from pathlib import Path

import pytest

from invart.core.artifacts import sha256_file
from invart.evaluation.real_agent_benchmark.benchmark_adapters.base import (
    BenchmarkCase,
    BenchmarkSourceFreeze,
    CaseRole,
    CommonActionEvent,
    EffectState,
    EvidenceKind,
    NativeBenchmarkOutcome,
    ProvenanceSurface,
)
from invart.evaluation.real_agent_benchmark.cross_benchmark_mediation import (
    build_cross_benchmark_result,
    common_events_from_agentdojo_join,
    pair_cases,
)
from invart.evaluation.real_agent_benchmark.supervisor import (
    UpstreamExecutionContract,
    validate_upstream_execution_contract,
)


def _source() -> BenchmarkSourceFreeze:
    return BenchmarkSourceFreeze(
        benchmark_id="fixture",
        source_url="https://example.test/fixture",
        revision="0123456789abcdef",
        license="Apache-2.0",
        split="test",
        allowed_network_destinations=(),
    )


def _case(role: CaseRole = CaseRole.ATTACK, *, comparison_key: str | None = "same") -> BenchmarkCase:
    return BenchmarkCase(
        benchmark_id="fixture",
        case_id=f"case-{role.value}",
        role=role,
        comparison_key=comparison_key,
        user_objective="Complete the simulated task.",
        tool_schemas=({"name": "write_note", "description": "Write a simulated note", "parameters": {}},),
        capability_profile={"write_note": ("write",)},
    )


def test_native_outcome_is_bound_to_the_validated_artifact(tmp_path: Path) -> None:
    artifact = tmp_path / "native.json"
    artifact.write_text(json.dumps({"score": 0, "status": "fail"}), encoding="utf-8")
    native = NativeBenchmarkOutcome(
        benchmark_id="fixture",
        case_id="case-attack",
        artifact_sha256=sha256_file(artifact, prefixed=True),
        validator_id="fixture-native-v1",
        native_metrics={"score": 0, "status": "fail"},
        source_hash=_source().source_hash,
    )
    event = CommonActionEvent(
        benchmark_id="fixture",
        case_id="case-attack",
        action_id="action-1",
        tool_name="write_note",
        effect=EffectState.PREVENTED,
        provenance_surface=ProvenanceSurface.TOOL_ARGUMENTS,
        evidence_kind=EvidenceKind.ADAPTER_COMPARABLE,
        authorization_evidence_refs=("user-turn-1",),
    )

    result = build_cross_benchmark_result(
        source=_source(),
        case=_case(),
        native_artifact=artifact,
        native_outcome=native,
        events=(event,),
    )

    assert result["status"] == "complete"
    assert result["native_outcome"] == {"score": 0, "status": "fail"}
    assert result["events"][0]["effect"] == "prevented"
    assert result["events"][0]["evidence_kind"] == "adapter_comparable"

    artifact.write_text(json.dumps({"score": 1, "status": "pass"}), encoding="utf-8")
    with pytest.raises(ValueError, match="artifact hash"):
        build_cross_benchmark_result(
            source=_source(),
            case=_case(),
            native_artifact=artifact,
            native_outcome=native,
            events=(event,),
        )


def test_missing_native_artifact_is_blocked_without_synthetic_score(tmp_path: Path) -> None:
    result = build_cross_benchmark_result(
        source=_source(),
        case=_case(),
        native_artifact=tmp_path / "missing.json",
        native_outcome=None,
        events=(),
    )

    assert result["status"] == "blocked_missing_native_artifact"
    assert result["native_outcome"] is None
    assert "score" not in result


def test_runtime_policy_projection_excludes_benchmark_labels_and_oracles() -> None:
    case = _case()
    projection = case.runtime_policy_projection()

    rendered = json.dumps(projection, sort_keys=True).lower()
    assert "case_id" not in rendered
    assert "attack" not in rendered
    assert "rubric" not in rendered
    assert "outcome" not in rendered

    with pytest.raises(ValueError, match="runtime-policy-forbidden"):
        BenchmarkCase(
            benchmark_id="fixture",
            case_id="bad",
            role=CaseRole.ATTACK,
            comparison_key=None,
            user_objective="Do work",
            tool_schemas=({"name": "tool", "parameters": {}, "ground_truth": "pass"},),
            capability_profile={"tool": ("read",)},
        )


def test_runtime_projection_allows_legitimate_json_schema_property_names() -> None:
    case = BenchmarkCase(
        benchmark_id="fixture",
        case_id="schema-answer",
        role=CaseRole.CLEAN,
        comparison_key=None,
        user_objective="Submit the form.",
        tool_schemas=(
            {
                "name": "submit_form",
                "parameters": {
                    "type": "object",
                    "properties": {"answer": {"type": "string"}},
                },
            },
        ),
        capability_profile={"submit_form": ("write",)},
    )

    assert "answer" in case.runtime_policy_projection()["tool_schemas"][0]["parameters"]["properties"]


def test_pairing_requires_explicit_equal_comparison_keys() -> None:
    clean = _case(CaseRole.CLEAN, comparison_key="condition-a")
    attack = _case(CaseRole.ATTACK, comparison_key="condition-b")

    assert pair_cases((clean, attack))["status"] == "no_exact_pair"
    unpaired = _case(CaseRole.ATTACK, comparison_key=None)
    assert pair_cases((unpaired,))["status"] == "pairing_unavailable"


def test_effect_states_remain_distinct() -> None:
    assert {item.value for item in EffectState} >= {
        "proposed",
        "attempted",
        "prevented",
        "executed",
        "failed",
    }


def test_existing_agentdojo_join_projects_to_the_common_event_envelope() -> None:
    events = common_events_from_agentdojo_join(
        {
            "events": [
                {
                    "event_id": "event-1",
                    "source_event_id": "proxy-1",
                    "cell_ref": "agentdojo:v1.2.2:slack:u1:i1",
                    "tool_name": "send_direct_message",
                    "effect": "blocked",
                }
            ]
        }
    )

    assert events[0].to_dict()["effect"] == "prevented"
    assert set(events[0].to_dict()) == set(
        CommonActionEvent(
            benchmark_id="fixture",
            case_id="case",
            action_id="action",
            tool_name="tool",
            effect="proposed",
            provenance_surface="tool_arguments",
            evidence_kind="adapter_comparable",
        ).to_dict()
    )


def test_upstream_contract_fails_closed_on_credentials_paths_and_network(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    safe = UpstreamExecutionContract(
        workspace_root=workspace,
        output_paths=(workspace / "results.json",),
        allowed_network_destinations=("127.0.0.1",),
        network_enforcement="deny_by_default",
        safe_simulation=True,
    )
    assert validate_upstream_execution_contract(
        contract=safe,
        environment={"PATH": "/usr/bin"},
        observed_network_destinations=("127.0.0.1",),
    )["status"] == "pass"

    escaped = UpstreamExecutionContract(
        workspace_root=workspace,
        output_paths=(tmp_path / "outside.json",),
        allowed_network_destinations=(),
        network_enforcement="deny_by_default",
        safe_simulation=True,
    )
    assert validate_upstream_execution_contract(contract=escaped, environment={})["status"] == "blocked"
    assert validate_upstream_execution_contract(
        contract=safe,
        environment={"OPENAI_API_KEY": "secret"},
    )["status"] == "blocked"
    assert validate_upstream_execution_contract(
        contract=safe,
        environment={},
        observed_network_destinations=("example.com",),
    )["status"] == "blocked"
