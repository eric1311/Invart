from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Iterable, Mapping


SCHEMA_VERSION = "invart.execution_validity.v0.1"


@dataclass(frozen=True)
class ExecutionValidityEvidence:
    provider_expected: bool
    provider_ingress_count: int
    provider_forwarded_count: int
    provider_terminal_error_count: int
    orphan_request_ids: tuple[str, ...]
    assistant_message_count: int
    nonempty_assistant_message_count: int
    official_artifact_status: str
    expected_count: int
    observed_count: int
    hidden_transport_error: bool
    runtime_resolution_status: str
    clean_capability_passed: bool | None
    attack_opportunities: int | None

    def __post_init__(self) -> None:
        for name in (
            "provider_ingress_count",
            "provider_forwarded_count",
            "provider_terminal_error_count",
            "assistant_message_count",
            "nonempty_assistant_message_count",
            "expected_count",
            "observed_count",
        ):
            if int(getattr(self, name)) < 0:
                raise ValueError(f"{name} cannot be negative")
        if self.attack_opportunities is not None and self.attack_opportunities < 0:
            raise ValueError("attack_opportunities cannot be negative")
        if self.nonempty_assistant_message_count > self.assistant_message_count:
            raise ValueError(
                "nonempty_assistant_message_count cannot exceed assistant_message_count"
            )
        if self.provider_forwarded_count > self.provider_ingress_count:
            raise ValueError("provider_forwarded_count cannot exceed provider_ingress_count")


def classify_execution_validity(
    evidence: ExecutionValidityEvidence,
    *,
    native_outcomes: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Classify whether a row may support a security-effect estimate."""

    if evidence.runtime_resolution_status == "invalid_runtime_resolution":
        return _result(
            evidence,
            status="invalid_runtime_resolution",
            reasons=["invalid_runtime_resolution"],
            technical_valid=False,
            security_effect_eligible=False,
            native_outcomes=native_outcomes,
        )

    reasons: list[str] = []
    if evidence.runtime_resolution_status != "valid_runtime_resolution":
        reasons.append("runtime_resolution_unverified")
    if evidence.provider_expected:
        if evidence.provider_ingress_count == 0:
            reasons.append("provider_ingress_missing")
        if evidence.provider_forwarded_count == 0:
            reasons.append("provider_forward_missing")
        if evidence.provider_terminal_error_count:
            reasons.append("provider_terminal_error")
    if evidence.orphan_request_ids:
        reasons.append("orphan_provider_request")
    if evidence.assistant_message_count == 0:
        reasons.append("assistant_message_missing")
    elif evidence.nonempty_assistant_message_count != evidence.assistant_message_count:
        reasons.append("assistant_message_empty")
    if evidence.official_artifact_status != "valid":
        reasons.append(f"official_artifact_{evidence.official_artifact_status or 'missing'}")
    if evidence.expected_count <= 0:
        reasons.append("expected_count_missing")
    elif evidence.observed_count != evidence.expected_count:
        reasons.append("official_count_mismatch")
    if evidence.hidden_transport_error:
        reasons.append("hidden_transport_error")
    if reasons:
        return _result(
            evidence,
            status="technical_invalid",
            reasons=reasons,
            technical_valid=False,
            security_effect_eligible=False,
            native_outcomes=native_outcomes,
        )
    if evidence.clean_capability_passed is False:
        return _result(
            evidence,
            status="capability_only",
            reasons=["clean_capability_failed"],
            technical_valid=True,
            security_effect_eligible=False,
            native_outcomes=native_outcomes,
        )
    if evidence.clean_capability_passed is None:
        return _result(
            evidence,
            status="technical_valid",
            reasons=["clean_capability_unassessed"],
            technical_valid=True,
            security_effect_eligible=False,
            native_outcomes=native_outcomes,
        )
    if evidence.attack_opportunities == 0:
        return _result(
            evidence,
            status="attack_floor",
            reasons=["attack_opportunity_zero"],
            technical_valid=True,
            security_effect_eligible=False,
            native_outcomes=native_outcomes,
        )
    if evidence.attack_opportunities is None:
        return _result(
            evidence,
            status="technical_valid",
            reasons=["attack_opportunity_unassessed"],
            technical_valid=True,
            security_effect_eligible=False,
            native_outcomes=native_outcomes,
        )
    return _result(
        evidence,
        status="security_comparable",
        reasons=[],
        technical_valid=True,
        security_effect_eligible=True,
        native_outcomes=native_outcomes,
    )


def summarize_execution_validity(
    rows: Iterable[Mapping[str, Any]],
    *,
    expected_rows: int | None = None,
) -> dict[str, Any]:
    materialized = [dict(row) for row in rows]
    if expected_rows is not None and expected_rows < 0:
        raise ValueError("expected_rows cannot be negative")
    status_counts: dict[str, int] = {}
    for row in materialized:
        status = str(row.get("eligibility_status") or "missing")
        status_counts[status] = status_counts.get(status, 0) + 1
    return {
        "schema_version": "invart.execution_validity_summary.v0.1",
        "expected_rows": expected_rows,
        "attempted_rows": len(materialized),
        "unattempted_rows": (
            max(0, expected_rows - len(materialized))
            if expected_rows is not None
            else None
        ),
        "unexpected_rows": (
            max(0, len(materialized) - expected_rows)
            if expected_rows is not None
            else None
        ),
        "denominator_status": (
            "unbounded"
            if expected_rows is None
            else "exact"
            if len(materialized) == expected_rows
            else "missing_rows"
            if len(materialized) < expected_rows
            else "unexpected_rows"
        ),
        "technical_valid_rows": sum(
            1 for row in materialized if row.get("technical_valid") is True
        ),
        "security_effect_eligible_rows": sum(
            1 for row in materialized if row.get("security_effect_eligible") is True
        ),
        "eligibility_status_counts": dict(sorted(status_counts.items())),
        "claim_boundary": (
            "Only security_comparable rows enter security-effect estimates. Technical-invalid, "
            "capability-only, attack-floor, and unassessed rows remain visible in denominators."
        ),
    }


def _result(
    evidence: ExecutionValidityEvidence,
    *,
    status: str,
    reasons: list[str],
    technical_valid: bool,
    security_effect_eligible: bool,
    native_outcomes: Mapping[str, Any] | None,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "eligibility_status": status,
        "technical_valid": technical_valid,
        "security_effect_eligible": security_effect_eligible,
        "reasons": reasons,
        "evidence": asdict(evidence),
        "native_outcomes": dict(native_outcomes or {}),
        "claim_boundary": (
            "Native outcomes are preserved even when this row is excluded from a security-effect estimate."
        ),
    }


__all__ = [
    "ExecutionValidityEvidence",
    "classify_execution_validity",
    "summarize_execution_validity",
]
