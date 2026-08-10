from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from invart.core.artifacts import stable_json_hash

from .tool_capabilities import Capability, ToolCallAssessment


POLICY_DECISION_SCHEMA_VERSION = "invart.mediation_policy_decision.v0.1"
_PROVENANCE_VALUES = {
    "user_instruction",
    "derived_from_user_authorized_source",
    "trusted_observation",
    "untrusted_observation",
    "mixed",
    "unknown",
}


class DecisionEffect(str, Enum):
    ALLOW = "allow"
    ASK = "ask"
    DENY = "deny"


class ProhibitedActionClass(str, Enum):
    """Public, benchmark-independent action classes denied by the safety profile."""

    CREDENTIAL_THEFT = "credential_theft"
    MALWARE_EXECUTION = "malware_execution"
    FRAUD = "fraud"
    TARGETED_HARASSMENT = "targeted_harassment"
    ILLEGAL_DRUG_TRADE = "illegal_drug_trade"
    WEAPON_FACILITATION = "weapon_facilitation"
    PRIVACY_VIOLATION = "privacy_violation"


@dataclass(frozen=True)
class AuthorizationContext:
    action_authorized: bool
    target_authorized: bool
    provenance: str
    evidence_refs: tuple[str, ...]
    prohibited_action_class: ProhibitedActionClass | None = None
    prohibited_action_source: str | None = None

    def __post_init__(self) -> None:
        provenance = str(self.provenance or "").strip()
        if provenance not in _PROVENANCE_VALUES:
            raise ValueError(f"unsupported provenance: {provenance}")
        object.__setattr__(self, "provenance", provenance)
        refs = tuple(sorted({str(ref).strip() for ref in self.evidence_refs if str(ref).strip()}))
        object.__setattr__(self, "evidence_refs", refs)
        action_class = self.prohibited_action_class
        if action_class is not None:
            object.__setattr__(self, "prohibited_action_class", ProhibitedActionClass(action_class))
            source = str(self.prohibited_action_source or "").strip()
            if not source:
                raise ValueError("prohibited_action_source is required")
            lowered = source.lower()
            if any(token in lowered for token in ("benchmark", "agentharm", "rubric", "label", "ground_truth")):
                raise ValueError("prohibited action source must be independent of benchmark labels")
            object.__setattr__(self, "prohibited_action_source", source)
        elif self.prohibited_action_source is not None:
            raise ValueError("prohibited_action_source requires an action class")


@dataclass(frozen=True)
class DeterministicDecision:
    effect: DecisionEffect
    reason_code: str
    evidence_refs: tuple[str, ...]
    critical: bool


@dataclass(frozen=True)
class ReviewerDecision:
    effect: DecisionEffect
    reason_code: str
    evidence_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "effect", DecisionEffect(self.effect))
        reason = str(self.reason_code or "").strip()
        if not reason:
            raise ValueError("reviewer reason_code must be nonempty")
        object.__setattr__(self, "reason_code", reason)
        refs = tuple(sorted({str(ref).strip() for ref in self.evidence_refs if str(ref).strip()}))
        object.__setattr__(self, "evidence_refs", refs)


@dataclass(frozen=True)
class PolicyConfiguration:
    version: str
    prompt_hash: str
    registry_hash: str
    reviewer_threshold: float
    composition_semantics: str = "deny_gt_ask_gt_allow-v1"
    policy_hash: str = field(init=False)

    def __post_init__(self) -> None:
        for name in ("version", "prompt_hash", "registry_hash", "composition_semantics"):
            value = str(getattr(self, name) or "").strip()
            if not value:
                raise ValueError(f"{name} must be nonempty")
            object.__setattr__(self, name, value)
        threshold = float(self.reviewer_threshold)
        if not 0.0 <= threshold <= 1.0:
            raise ValueError("reviewer_threshold must be between zero and one")
        object.__setattr__(self, "reviewer_threshold", threshold)
        object.__setattr__(
            self,
            "policy_hash",
            stable_json_hash(
                {
                    "version": self.version,
                    "prompt_hash": self.prompt_hash,
                    "registry_hash": self.registry_hash,
                    "reviewer_threshold": self.reviewer_threshold,
                    "composition_semantics": self.composition_semantics,
                }
            ),
        )


@dataclass(frozen=True)
class EffectivePolicyDecision:
    effect: DecisionEffect
    reason_codes: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    deterministic_effect: DecisionEffect
    reviewer_effect: DecisionEffect
    policy_hash: str
    decision_hash: str
    schema_version: str = POLICY_DECISION_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "effect": self.effect.value,
            "reason_codes": list(self.reason_codes),
            "evidence_refs": list(self.evidence_refs),
            "deterministic_effect": self.deterministic_effect.value,
            "reviewer_effect": self.reviewer_effect.value,
            "policy_hash": self.policy_hash,
            "decision_hash": self.decision_hash,
        }


def evaluate_deterministic_policy(
    *,
    assessment: ToolCallAssessment,
    authorization: AuthorizationContext,
) -> DeterministicDecision:
    capabilities = assessment.capabilities
    refs = authorization.evidence_refs
    if authorization.prohibited_action_class is not None:
        return DeterministicDecision(
            DecisionEffect.DENY,
            "deterministic_prohibited_action_profile",
            refs,
            critical=True,
        )
    if not assessment.known_tool or Capability.UNKNOWN in capabilities:
        return DeterministicDecision(
            DecisionEffect.ASK,
            "unknown_tool_requires_review",
            refs,
            critical=False,
        )
    if Capability.ATTACK_TARGET in capabilities and not authorization.target_authorized:
        return DeterministicDecision(
            DecisionEffect.DENY,
            "deterministic_known_attack_target",
            refs,
            critical=True,
        )
    untrusted = authorization.provenance in {"untrusted_observation", "mixed", "unknown"}
    if (
        Capability.DATA_EGRESS in capabilities
        and untrusted
        and (not authorization.action_authorized or not authorization.target_authorized)
    ):
        return DeterministicDecision(
            DecisionEffect.DENY,
            "deterministic_critical_egress",
            refs,
            critical=True,
        )
    if Capability.DESTRUCTIVE in capabilities and (
        not authorization.action_authorized or not authorization.target_authorized
    ):
        return DeterministicDecision(
            DecisionEffect.DENY if untrusted else DecisionEffect.ASK,
            "deterministic_destructive_authorization_required",
            refs,
            critical=untrusted,
        )
    effectful = bool(
        capabilities
        & {
            Capability.WRITE,
            Capability.COMMUNICATION,
            Capability.EXTERNAL_NETWORK,
            Capability.DATA_EGRESS,
            Capability.ACCOUNT_MEMBERSHIP_ADMIN,
            Capability.APPROVAL_REQUIRED,
        }
    )
    if effectful and not authorization.action_authorized:
        return DeterministicDecision(
            DecisionEffect.ASK,
            "action_authorization_missing",
            refs,
            critical=False,
        )
    if assessment.target_argument_keys and not authorization.target_authorized:
        return DeterministicDecision(
            DecisionEffect.ASK,
            "target_authorization_missing",
            refs,
            critical=False,
        )
    if effectful and authorization.provenance in {"mixed", "unknown"}:
        return DeterministicDecision(
            DecisionEffect.ASK,
            "provenance_ambiguous",
            refs,
            critical=False,
        )
    return DeterministicDecision(
        DecisionEffect.ALLOW,
        "authorized_effect_with_bound_provenance" if effectful else "read_or_local_effect_allowed",
        refs,
        critical=False,
    )


def compose_policy_decision(
    *,
    policy: PolicyConfiguration,
    deterministic: DeterministicDecision,
    reviewer: ReviewerDecision,
) -> EffectivePolicyDecision:
    rank = {DecisionEffect.ALLOW: 0, DecisionEffect.ASK: 1, DecisionEffect.DENY: 2}
    effect = max((deterministic.effect, reviewer.effect), key=rank.__getitem__)
    reason_codes = tuple(dict.fromkeys((deterministic.reason_code, reviewer.reason_code)))
    evidence_refs = tuple(sorted(set(deterministic.evidence_refs) | set(reviewer.evidence_refs)))
    digest_payload = {
        "policy_hash": policy.policy_hash,
        "effect": effect.value,
        "reason_codes": list(reason_codes),
        "evidence_refs": list(evidence_refs),
        "deterministic_effect": deterministic.effect.value,
        "reviewer_effect": reviewer.effect.value,
        "deterministic_critical": deterministic.critical,
    }
    return EffectivePolicyDecision(
        effect=effect,
        reason_codes=reason_codes,
        evidence_refs=evidence_refs,
        deterministic_effect=deterministic.effect,
        reviewer_effect=reviewer.effect,
        policy_hash=policy.policy_hash,
        decision_hash=stable_json_hash(digest_payload),
    )


__all__ = [
    "AuthorizationContext",
    "DecisionEffect",
    "DeterministicDecision",
    "EffectivePolicyDecision",
    "PolicyConfiguration",
    "ProhibitedActionClass",
    "ReviewerDecision",
    "compose_policy_decision",
    "evaluate_deterministic_policy",
]
