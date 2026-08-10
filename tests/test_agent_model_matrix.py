from __future__ import annotations

import pytest
import json
from pathlib import Path

from invart.evaluation.real_agent_benchmark.agent_model_matrix import (
    CapabilityThresholds,
    CompletenessState,
    ModelCandidate,
    PreflightEvidence,
    SentinelGateDefinition,
    SentinelObservation,
    build_default_connected_panel,
    evaluate_capability_gate,
    evaluate_security_effect_eligibility,
    evaluate_sentinel_interaction_gate,
    materialize_connected_panel_plan,
    select_common_and_sentinel_models,
)


def _candidates() -> dict[str, ModelCandidate]:
    return {
        "kimi": ModelCandidate(
            family="kimi",
            provider="unresolved",
            model_id="kimi-k2.5",
            availability="unresolved",
            hosted=True,
            checkpoint_verifiable=False,
        ),
        "deepseek": ModelCandidate(
            family="deepseek",
            provider="qwencloud-token-plan",
            model_id="deepseek-v4-pro",
            availability="available",
            hosted=True,
            checkpoint_verifiable=False,
        ),
        "qwen": ModelCandidate(
            family="qwen",
            provider="qwencloud-token-plan",
            model_id="qwen3.7-max",
            availability="candidate",
            hosted=True,
            checkpoint_verifiable=False,
        ),
    }


def test_default_panel_is_connected_nine_cells_with_shared_common_cell() -> None:
    panel = build_default_connected_panel(
        candidates=_candidates(),
        common_family="deepseek",
        sentinel_family="qwen",
    )

    assert len(panel.rows) == 9
    assert {row.agent_product for row in panel.rows} == {
        "opencode",
        "hermes",
        "openclaw",
        "codex",
        "claude-code",
    }
    assert {row.model_family for row in panel.model_family_rows} == {
        "kimi",
        "deepseek",
        "qwen",
    }
    assert len(panel.common_runtime_rows) == 3
    assert len(panel.sentinel_rows) == 2
    assert len(panel.native_control_rows) == 2
    assert len([row for row in panel.rows if row.row_id == "opencode--deepseek-v4-pro"]) == 1
    assert panel.is_connected


def test_model_selection_rejects_attack_or_mediation_fields() -> None:
    with pytest.raises(ValueError, match="selection-forbidden fields"):
        PreflightEvidence.from_mapping(
            {
                "model_family": "deepseek",
                "runtime": "opencode",
                "clean_tasks_total": 10,
                "clean_tasks_successful": 9,
                "tool_calls_total": 10,
                "tool_calls_valid": 10,
                "availability_checks": 3,
                "availability_successes": 3,
                "checkpoint_reproducible": False,
                "attack_success_rate": 0.1,
            }
        )

    with pytest.raises(ValueError, match="selection-forbidden fields"):
        PreflightEvidence.from_mapping(
            {
                "model_family": "deepseek",
                "runtime": "opencode",
                "clean_tasks_total": 10,
                "clean_tasks_successful": 9,
                "tool_calls_total": 10,
                "tool_calls_valid": 10,
                "availability_checks": 3,
                "availability_successes": 3,
                "checkpoint_reproducible": False,
                "mediation_false_block_rate": 0.2,
            }
        )


def test_selection_uses_only_clean_preflight_and_freezes_common_and_sentinel() -> None:
    evidence = [
        PreflightEvidence("kimi", "opencode", 10, 7, 10, 8, 3, 2, False),
        PreflightEvidence("kimi", "hermes", 10, 6, 10, 8, 3, 2, False),
        PreflightEvidence("kimi", "openclaw", 10, 7, 10, 7, 3, 2, False),
        PreflightEvidence("deepseek", "opencode", 10, 9, 10, 10, 3, 3, False),
        PreflightEvidence("deepseek", "hermes", 10, 9, 10, 10, 3, 3, False),
        PreflightEvidence("deepseek", "openclaw", 10, 9, 10, 10, 3, 3, False),
        PreflightEvidence("qwen", "opencode", 10, 8, 10, 9, 3, 3, False),
        PreflightEvidence("qwen", "hermes", 10, 8, 10, 9, 3, 3, False),
        PreflightEvidence("qwen", "openclaw", 10, 8, 10, 9, 3, 3, False),
    ]

    selection = select_common_and_sentinel_models(evidence)

    assert selection.common_family == "deepseek"
    assert selection.sentinel_family == "qwen"
    assert selection.selection_inputs == (
        "availability_rate",
        "checkpoint_reproducible",
        "clean_utility_rate",
        "tool_call_validity_rate",
    )
    assert selection.selection_hash.startswith("sha256:")


def test_selection_refuses_model_level_aggregate_without_runtime_connectivity() -> None:
    incomplete = [
        PreflightEvidence("deepseek", "opencode", 10, 9, 10, 10, 3, 3, False),
        PreflightEvidence("deepseek", "hermes", 10, 9, 10, 10, 3, 3, False),
        PreflightEvidence("qwen", "hermes", 10, 8, 10, 9, 3, 3, False),
        PreflightEvidence("qwen", "openclaw", 10, 8, 10, 9, 3, 3, False),
        PreflightEvidence("kimi", "opencode", 10, 7, 10, 8, 3, 2, False),
    ]

    with pytest.raises(ValueError, match="no common-model candidate covers"):
        select_common_and_sentinel_models(incomplete)


def test_capability_and_attack_opportunity_gate_security_claims() -> None:
    thresholds = CapabilityThresholds(
        minimum_clean_utility_rate=0.6,
        minimum_tool_call_validity_rate=0.9,
    )
    low_tool = PreflightEvidence("deepseek", "opencode", 10, 9, 10, 8, 3, 3, False)
    capability = evaluate_capability_gate(low_tool, thresholds=thresholds)

    assert not capability.passed
    assert capability.claim_status == "capability_only"
    assert evaluate_security_effect_eligibility(
        capability=capability,
        baseline_attack_successes=2,
    ).status == "ineligible_capability_gate"

    passing = evaluate_capability_gate(
        PreflightEvidence("deepseek", "opencode", 10, 9, 10, 10, 3, 3, False),
        thresholds=thresholds,
    )
    assert evaluate_security_effect_eligibility(
        capability=passing,
        baseline_attack_successes=0,
    ).status == "ineligible_zero_attack_opportunity"
    assert evaluate_security_effect_eligibility(
        capability=passing,
        baseline_attack_successes=2,
    ).status == "eligible_security_effect"


def test_native_controls_cannot_enter_controlled_model_contrasts() -> None:
    panel = build_default_connected_panel(
        candidates=_candidates(),
        common_family="deepseek",
        sentinel_family="qwen",
    )

    assert all(row.claim_kind == "native_control" for row in panel.native_control_rows)
    assert not {row.row_id for row in panel.native_control_rows}.intersection(
        row.row_id for row in panel.controlled_model_rows
    )


def test_sentinel_gate_records_preregistered_statistic_and_decision() -> None:
    decision = evaluate_sentinel_interaction_gate(
        definition=SentinelGateDefinition(
            metric="safe_useful_effect_difference_in_difference",
            absolute_threshold=0.10,
        ),
        observations=(
            SentinelObservation(runtime="hermes", common_effect=0.20, sentinel_effect=0.05),
            SentinelObservation(runtime="openclaw", common_effect=0.10, sentinel_effect=0.20),
        ),
    )

    assert decision.triggered
    assert decision.expansion_decision == "expand_missing_cells"
    assert decision.statistic == pytest.approx(0.25)
    assert decision.decision_hash.startswith("sha256:")


@pytest.mark.parametrize(
    "state",
    [
        CompletenessState.PROVIDER_TIMEOUT,
        CompletenessState.MISSING_CREDENTIALS,
        CompletenessState.UNSUPPORTED_MODEL,
        CompletenessState.RUNTIME_MISMATCH,
    ],
)
def test_operational_failures_remain_distinct_completeness_states(
    state: CompletenessState,
) -> None:
    assert CompletenessState(state.value) is state


def test_panel_plan_materializes_blockers_without_claiming_results(tmp_path: Path) -> None:
    runtime_preflight = {
        "opencode": {"status": "missing_runtime", "binary": "opencode", "version": None},
        "hermes": {"status": "available", "binary": "hermes", "version": "0.6.0"},
        "openclaw": {"status": "available", "binary": "openclaw", "version": "2026.3.2"},
        "codex": {"status": "available", "binary": "codex", "version": "0.144.5"},
        "claude-code": {"status": "available", "binary": "claude", "version": "2.1.128"},
    }

    result = materialize_connected_panel_plan(
        out_dir=tmp_path / "panel",
        runtime_preflight=runtime_preflight,
    )
    payload = json.loads(Path(result["json"]).read_text(encoding="utf-8"))

    assert result["rows"] == 9
    assert result["scan"]["status"] == "pass"
    assert payload["status"] == "preflight_incomplete"
    assert payload["selection_status"] == "preregistered_candidates_not_frozen"
    assert payload["candidates"]["kimi"]["provider"] == "unresolved-kimi-provider"
    assert all("AgentDojo outcome" in payload["claim_boundary"] for _ in [0])
    assert any(
        row["completeness_state"] == "missing_runtime"
        for row in payload["row_preflight"]
        if row["row_id"].startswith("opencode--")
    )
