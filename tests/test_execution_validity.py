from __future__ import annotations

import pytest

from invart.evaluation.real_agent_benchmark.execution_validity import (
    ExecutionValidityEvidence,
    classify_execution_validity,
    summarize_execution_validity,
)
from invart.evaluation.real_agent_benchmark.provider_budget_gateway import (
    reconcile_gateway_records,
)
from invart.evaluation.real_agent_benchmark.provider_credentials import (
    build_scoped_provider_environment,
)


def _valid_evidence(**overrides: object) -> ExecutionValidityEvidence:
    values: dict[str, object] = {
        "provider_expected": True,
        "provider_ingress_count": 1,
        "provider_forwarded_count": 1,
        "provider_terminal_error_count": 0,
        "orphan_request_ids": (),
        "assistant_message_count": 1,
        "nonempty_assistant_message_count": 1,
        "official_artifact_status": "valid",
        "expected_count": 3,
        "observed_count": 3,
        "hidden_transport_error": False,
        "runtime_resolution_status": "valid_runtime_resolution",
        "clean_capability_passed": True,
        "attack_opportunities": 1,
    }
    values.update(overrides)
    return ExecutionValidityEvidence(**values)


def test_false_zero_transport_fixture_is_technical_invalid() -> None:
    result = classify_execution_validity(
        _valid_evidence(
            provider_ingress_count=0,
            provider_forwarded_count=0,
            provider_terminal_error_count=3,
            assistant_message_count=3,
            nonempty_assistant_message_count=0,
            hidden_transport_error=True,
        ),
        native_outcomes={"utility_successes": 0, "attack_successes": 0},
    )

    assert result["eligibility_status"] == "technical_invalid"
    assert result["technical_valid"] is False
    assert result["security_effect_eligible"] is False
    assert set(result["reasons"]) >= {
        "provider_ingress_missing",
        "provider_forward_missing",
        "assistant_message_empty",
        "hidden_transport_error",
    }
    assert result["native_outcomes"] == {
        "utility_successes": 0,
        "attack_successes": 0,
    }


def test_gateway_reconciliation_detects_orphan_and_terminal_outcomes() -> None:
    records = [
        {"status": "reserved_pending", "gateway_request_id": "req-ok"},
        {"status": "forwarded", "gateway_request_id": "req-ok"},
        {"status": "reserved_pending", "gateway_request_id": "req-orphan"},
        {"status": "transport_failed", "gateway_request_id": "req-failed"},
    ]

    summary = reconcile_gateway_records(records)

    assert summary["ingress_count"] == 3
    assert summary["forwarded_count"] == 1
    assert summary["terminal_error_count"] == 1
    assert summary["pending_without_terminal_request_ids"] == ["req-orphan"]
    assert summary["terminal_without_pending_request_ids"] == ["req-failed"]
    assert summary["orphan_request_ids"] == ["req-failed", "req-orphan"]
    assert summary["terminal_request_ids"] == ["req-failed", "req-ok"]


def test_gateway_reconciliation_rejects_forwarded_receipt_without_reservation() -> None:
    summary = reconcile_gateway_records(
        [{"status": "forwarded", "gateway_request_id": "req-terminal-only"}]
    )

    assert summary["forwarded_count"] == 1
    assert summary["terminal_error_count"] == 0
    assert summary["terminal_without_pending_request_ids"] == [
        "req-terminal-only"
    ]
    assert summary["orphan_request_ids"] == ["req-terminal-only"]


def test_loopback_bypass_is_explicit_in_both_proxy_variable_casings() -> None:
    scoped = build_scoped_provider_environment(
        provider=None,
        include_provider_credentials=False,
        base_env={
            "PATH": "/usr/bin:/bin",
            "NO_PROXY": "corp.internal,127.0.0.1",
            "no_proxy": "legacy.internal",
        },
    )

    assert scoped["NO_PROXY"].split(",") == [
        "corp.internal",
        "127.0.0.1",
        "legacy.internal",
        "localhost",
        "::1",
    ]
    assert scoped["no_proxy"] == scoped["NO_PROXY"]


def test_empty_completion_or_orphan_request_invalidates_parseable_official_json() -> None:
    empty = classify_execution_validity(
        _valid_evidence(nonempty_assistant_message_count=0)
    )
    partially_empty = classify_execution_validity(
        _valid_evidence(
            assistant_message_count=2,
            nonempty_assistant_message_count=1,
        )
    )
    orphan = classify_execution_validity(
        _valid_evidence(orphan_request_ids=("req-orphan",))
    )

    assert empty["eligibility_status"] == "technical_invalid"
    assert "assistant_message_empty" in empty["reasons"]
    assert partially_empty["eligibility_status"] == "technical_invalid"
    assert "assistant_message_empty" in partially_empty["reasons"]
    assert orphan["eligibility_status"] == "technical_invalid"
    assert "orphan_provider_request" in orphan["reasons"]


def test_capability_failure_and_zero_baseline_attacks_are_not_security_effects() -> None:
    capability = classify_execution_validity(
        _valid_evidence(clean_capability_passed=False)
    )
    floor = classify_execution_validity(
        _valid_evidence(attack_opportunities=0)
    )

    assert capability["technical_valid"] is True
    assert capability["eligibility_status"] == "capability_only"
    assert capability["security_effect_eligible"] is False
    assert floor["technical_valid"] is True
    assert floor["eligibility_status"] == "attack_floor"
    assert floor["security_effect_eligible"] is False


def test_runtime_fallback_is_distinct_from_transport_invalidity() -> None:
    result = classify_execution_validity(
        _valid_evidence(runtime_resolution_status="invalid_runtime_resolution")
    )

    assert result["eligibility_status"] == "invalid_runtime_resolution"
    assert result["technical_valid"] is False
    assert result["reasons"] == ["invalid_runtime_resolution"]


def test_validity_summary_keeps_all_denominators_visible() -> None:
    rows = [
        classify_execution_validity(_valid_evidence()),
        classify_execution_validity(_valid_evidence(attack_opportunities=0)),
        classify_execution_validity(_valid_evidence(clean_capability_passed=False)),
        classify_execution_validity(
            _valid_evidence(provider_ingress_count=0, provider_forwarded_count=0)
        ),
    ]

    summary = summarize_execution_validity(rows, expected_rows=5)

    assert summary["expected_rows"] == 5
    assert summary["attempted_rows"] == 4
    assert summary["unattempted_rows"] == 1
    assert summary["unexpected_rows"] == 0
    assert summary["denominator_status"] == "missing_rows"
    assert summary["technical_valid_rows"] == 3
    assert summary["security_effect_eligible_rows"] == 1
    assert summary["eligibility_status_counts"] == {
        "attack_floor": 1,
        "capability_only": 1,
        "security_comparable": 1,
        "technical_invalid": 1,
    }


def test_impossible_evidence_counts_are_rejected() -> None:
    with pytest.raises(ValueError, match="nonempty_assistant_message_count"):
        _valid_evidence(
            assistant_message_count=1,
            nonempty_assistant_message_count=2,
        )
    with pytest.raises(ValueError, match="provider_forwarded_count"):
        _valid_evidence(provider_ingress_count=1, provider_forwarded_count=2)
    with pytest.raises(ValueError, match="expected_rows"):
        summarize_execution_validity([], expected_rows=-1)
