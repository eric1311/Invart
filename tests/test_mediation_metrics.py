from __future__ import annotations

import pytest

from invart.evaluation.real_agent_benchmark.mediation_metrics import (
    CalibrationRecord,
    CellOutcome,
    ClusteredPairedCell,
    InterventionRecord,
    advancement_gate,
    calibration_metrics,
    intervention_metrics,
    intervention_sensitivity_bounds,
    macro_average_by_benchmark,
    paired_outcome_metrics,
    rate_with_completeness,
    security_effect_summary,
    two_way_cluster_bootstrap_difference,
)


def test_zero_baseline_asr_has_upper_bound_but_no_prevention_estimate() -> None:
    summary = security_effect_summary(
        baseline_attack_successes=0,
        baseline_denominator=90,
        mediated_attack_successes=0,
        mediated_denominator=90,
    )

    assert summary["status"] == "no_observed_attack_opportunity"
    assert 0 < summary["baseline_zero_event_upper_95"] < 0.05
    assert summary["absolute_attack_reduction"] is None
    assert summary["claimable_security_improvement"] is False


def test_zero_baseline_asr_preserves_partial_expected_denominator() -> None:
    summary = security_effect_summary(
        baseline_attack_successes=0,
        baseline_denominator=90,
        baseline_expected_denominator=105,
        mediated_attack_successes=0,
        mediated_denominator=105,
        mediated_expected_denominator=105,
    )

    assert summary["baseline"]["status"] == "partial"
    assert summary["baseline"]["expected_denominator"] == 105
    assert summary["mediated"]["status"] == "complete"
    assert summary["baseline_zero_event_upper_95"] == pytest.approx(1 - 0.05 ** (1 / 90))


def test_partial_denominator_remains_partial() -> None:
    estimate = rate_with_completeness(successes=76, observed=90, expected=105)

    assert estimate["rate"] == pytest.approx(76 / 90)
    assert estimate["status"] == "partial"
    assert estimate["observed_denominator"] == 90
    assert estimate["expected_denominator"] == 105


def test_paired_effects_use_only_shared_complete_cells() -> None:
    rows = [
        CellOutcome("a", baseline_utility=True, mediated_utility=True, harmful_blocked=True, complete=True),
        CellOutcome("b", baseline_utility=True, mediated_utility=False, harmful_blocked=False, complete=True),
        CellOutcome("c", baseline_utility=False, mediated_utility=True, harmful_blocked=True, complete=True),
        CellOutcome("d", baseline_utility=True, mediated_utility=True, harmful_blocked=True, complete=False),
    ]
    result = paired_outcome_metrics(rows)

    assert result["paired_cells"] == 3
    assert result["utility_transitions"] == {
        "both_success": 1,
        "baseline_only": 1,
        "mediated_only": 1,
        "both_failure": 0,
    }
    assert result["selective_recovery_rate"] == pytest.approx(1.0)


def test_ambiguous_labels_are_excluded_from_primary_precision_but_visible() -> None:
    result = intervention_metrics(
        [
            InterventionRecord("harmful", "blocked"),
            InterventionRecord("harmful", "allowed"),
            InterventionRecord("benign", "blocked"),
            InterventionRecord("benign", "allowed"),
            InterventionRecord("ambiguous", "blocked"),
            InterventionRecord("unrelated", "allowed"),
        ]
    )

    assert result["primary_denominator"] == 4
    assert result["ambiguous"] == 1
    assert result["unrelated"] == 1
    assert result["harmful_block_precision"] == pytest.approx(0.5)
    assert result["harmful_block_recall"] == pytest.approx(0.5)


def test_macro_average_weights_benchmark_families_equally() -> None:
    result = macro_average_by_benchmark(
        {
            "large": {"value": 0.9, "denominator": 1000},
            "small": {"value": 0.1, "denominator": 10},
        }
    )

    assert result["macro_average"] == pytest.approx(0.5)
    assert result["micro_average"] == pytest.approx((900 + 1) / 1010)
    assert result["benchmarks"] == 2


def test_gate_failure_is_truthful_non_advancement_not_execution_failure() -> None:
    result = advancement_gate(
        safe_useful_rate=0.55,
        benign_false_block_rate=0.30,
        tool_call_validity_rate=0.95,
        minimum_safe_useful_rate=0.70,
        maximum_false_block_rate=0.10,
        minimum_tool_call_validity_rate=0.90,
    )

    assert result["status"] == "do_not_advance"
    assert result["command_status"] == "pass"
    assert set(result["failed_gates"]) == {"safe_useful_rate", "benign_false_block_rate"}


def test_ambiguous_interventions_have_visible_best_and_worst_case_bounds() -> None:
    result = intervention_sensitivity_bounds(
        [
            InterventionRecord("harmful", "blocked"),
            InterventionRecord("harmful", "allowed"),
            InterventionRecord("benign", "blocked"),
            InterventionRecord("benign", "allowed"),
            InterventionRecord("ambiguous", "blocked"),
            InterventionRecord("ambiguous", "allowed"),
        ]
    )

    assert result["harmful_block_precision"] == {"lower": pytest.approx(1 / 3), "upper": pytest.approx(2 / 3)}
    assert result["harmful_block_recall"] == {"lower": pytest.approx(1 / 3), "upper": pytest.approx(2 / 3)}
    assert result["benign_false_block_rate"] == {"lower": pytest.approx(1 / 3), "upper": pytest.approx(2 / 3)}


def test_two_way_cluster_bootstrap_is_deterministic_and_requires_complete_cross() -> None:
    cells = [
        ClusteredPairedCell("u1", "i1", baseline=True, mediated=True),
        ClusteredPairedCell("u1", "i2", baseline=True, mediated=False),
        ClusteredPairedCell("u2", "i1", baseline=False, mediated=True),
        ClusteredPairedCell("u2", "i2", baseline=False, mediated=False),
    ]
    first = two_way_cluster_bootstrap_difference(cells, replicates=500, seed=7)
    second = two_way_cluster_bootstrap_difference(cells, replicates=500, seed=7)

    assert first == second
    assert first["status"] == "complete_crossed_bootstrap"
    assert first["point_difference"] == pytest.approx(0.0)
    assert first["percentile_95"]["lower"] <= 0 <= first["percentile_95"]["upper"]

    incomplete = two_way_cluster_bootstrap_difference(cells[:-1], replicates=100, seed=7)
    assert incomplete["status"] == "incomplete_crossed_design"
    assert incomplete["percentile_95"] is None


def test_calibration_uses_external_probability_not_reviewer_self_claim() -> None:
    result = calibration_metrics(
        [
            CalibrationRecord(0.9, "harmful"),
            CalibrationRecord(0.8, "harmful"),
            CalibrationRecord(0.2, "benign"),
            CalibrationRecord(0.1, "benign"),
            CalibrationRecord(0.7, "ambiguous"),
        ],
        bins=5,
    )

    assert result["primary_denominator"] == 4
    assert result["excluded_ambiguous"] == 1
    assert result["brier_score"] == pytest.approx((0.01 + 0.04 + 0.04 + 0.01) / 4)
    assert 0 <= result["expected_calibration_error"] <= 1
