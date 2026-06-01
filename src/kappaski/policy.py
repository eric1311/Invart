from __future__ import annotations

import uuid
from dataclasses import dataclass, replace

from typing import Any

from .models import Finding, Invocation, PolicyDecision, PolicyEvaluation, SemanticReview, TaintState, utc_now
from .rules import highest_severity, is_write_like_action


@dataclass(frozen=True)
class PolicyProfile:
    name: str
    default_policy_mode: str = "advisory"
    reviewer_required: bool = False
    tainted_write_effect: str = "require_approval"
    semantic_medium_effect: str = "audit_only"
    medium_rule_effect: str = "allow"
    high_rule_effect: str = "require_approval"


POLICY_PROFILES: dict[str, PolicyProfile] = {
    "balanced": PolicyProfile(name="balanced"),
    "strict": PolicyProfile(
        name="strict",
        default_policy_mode="managed",
        reviewer_required=True,
        semantic_medium_effect="require_approval",
        medium_rule_effect="require_approval",
    ),
    "audit": PolicyProfile(
        name="audit",
        default_policy_mode="audit",
        tainted_write_effect="audit_only",
        semantic_medium_effect="audit_only",
        medium_rule_effect="audit_only",
        high_rule_effect="audit_only",
    ),
}


def load_policy_profile(name: str | None, config: dict[str, Any] | None = None) -> PolicyProfile:
    if not name:
        profile = POLICY_PROFILES["balanced"]
    else:
        profile = POLICY_PROFILES.get(name, POLICY_PROFILES["balanced"])
    if config:
        profile = _profile_from_config(profile, config)
    return profile


def _profile_from_config(base: PolicyProfile, config: dict[str, Any]) -> PolicyProfile:
    policy = config.get("policy") if isinstance(config.get("policy"), dict) else {}
    kwargs: dict[str, Any] = {}
    if config.get("name"):
        kwargs["name"] = str(config.get("name"))
    if config.get("mode"):
        kwargs["default_policy_mode"] = str(config.get("mode"))
    for field_name in ("tainted_write_effect", "semantic_medium_effect", "medium_rule_effect", "high_rule_effect"):
        if field_name in policy:
            kwargs[field_name] = str(policy[field_name])
    if "reviewer_required" in policy:
        kwargs["reviewer_required"] = bool(policy["reviewer_required"])
    return replace(base, **kwargs) if kwargs else base


POLICY_MODES = {"audit", "advisory", "managed", "ci"}
REVIEW_MODES = {"off", "auto", "always", "required"}
RISK_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def merge_policy(
    invocation: Invocation,
    rule_findings: list[Finding],
    semantic_reviews: list[SemanticReview],
    taint: TaintState,
    *,
    policy_mode: str = "advisory",
    review_mode: str = "auto",
    policy_version: str = "kappaski.policy.v0.2",
    reviewer_failed: bool = False,
    policy_profile: str | None = None,
    policy_profile_config: dict[str, Any] | None = None,
) -> tuple[PolicyEvaluation, PolicyDecision]:
    profile = load_policy_profile(policy_profile, policy_profile_config)
    policy_mode = policy_mode if policy_mode in POLICY_MODES else profile.default_policy_mode
    review_mode = review_mode if review_mode in REVIEW_MODES else "auto"
    if profile.reviewer_required and review_mode == "auto":
        review_mode = "required"
    trace: list[str] = []
    rule_risk = highest_severity(rule_findings)
    review_risk = _highest_review_risk(semantic_reviews)
    final_risk = _max_risk(rule_risk, review_risk)
    effect = "allow"

    if any(finding.severity == "critical" for finding in rule_findings):
        effect = "deny"
        trace.append("deterministic critical finding forced deny")
    elif any(finding.severity == "high" for finding in rule_findings):
        effect = profile.high_rule_effect
        trace.append(f"deterministic high finding uses {profile.name} profile effect {effect}")
    elif any(finding.severity == "medium" for finding in rule_findings) and profile.medium_rule_effect != "allow":
        effect = profile.medium_rule_effect
        trace.append(f"deterministic medium finding uses {profile.name} profile effect {effect}")
    elif any(review.recommended_effect == "deny" and RISK_ORDER.get(review.risk, 0) >= RISK_ORDER["high"] for review in semantic_reviews):
        effect = "deny"
        trace.append("semantic reviewer recommended deny with high-or-critical risk")
    elif any(review.recommended_effect == "deny" for review in semantic_reviews):
        effect = "require_approval"
        trace.append("semantic reviewer recommended deny below high risk; human approval required")
    elif any(review.recommended_effect == "require_approval" for review in semantic_reviews):
        effect = "require_approval"
        trace.append("semantic reviewer recommended approval")
    elif review_risk == "medium":
        effect = profile.semantic_medium_effect
        trace.append(f"semantic medium risk uses {profile.name} profile effect {effect}")

    if taint.is_tainted and is_write_like_action(invocation):
        final_risk = _max_risk(final_risk, "high")
        if effect == "allow":
            effect = profile.tainted_write_effect
            trace.append(f"tainted write-like action uses {profile.name} profile effect {effect}")
        else:
            trace.append("tainted write-like action keeps risk at high or above")

    if reviewer_failed and review_mode == "required" and effect == "allow":
        effect = "require_approval"
        final_risk = _max_risk(final_risk, "medium")
        trace.append("required reviewer failed; approval required")

    if policy_mode == "audit" and effect in {"require_approval", "deny"}:
        if effect == "deny" and any(finding.severity == "critical" for finding in rule_findings):
            trace.append("audit mode cannot downgrade deterministic critical deny")
        else:
            effect = "audit_only"
            trace.append("audit mode records without blocking")

    approval_grade = _approval_grade(effect)
    requires_approval = approval_grade == "require_human"
    reason = trace[-1] if trace else "policy allowed invocation"
    evaluation = PolicyEvaluation(
        evaluation_id=f"eval_{uuid.uuid4().hex[:16]}",
        session_id=invocation.session_id,
        invocation_id=invocation.invocation_id or invocation.event_id,
        policy_version=policy_version,
        policy_mode=policy_mode,
        review_mode=review_mode,
        rule_findings=rule_findings,
        semantic_reviews=semantic_reviews,
        taint_tags=list(invocation.taint_tags),
        capability_grant_id=invocation.capability_grant_id,
        final_effect=effect,
        final_risk=final_risk,
        approval_grade=approval_grade,
        reason=reason,
        decision_trace=trace or ["no findings required escalation"],
        requires_approval=requires_approval,
        evaluated_at=utc_now(),
    )
    decision = PolicyDecision(
        decision_id=f"dec_{invocation.event_id}",
        event_id=invocation.event_id,
        session_id=invocation.session_id,
        timestamp=utc_now(),
        effect=_legacy_effect(effect),
        risk=final_risk,
        matched_rules=[finding.rule_id for finding in rule_findings] + [f"semantic.{cat}" for review in semantic_reviews for cat in review.categories],
        findings=rule_findings,
        reason=reason,
        requires_approval=requires_approval,
        taint_influenced=taint.is_tainted and is_write_like_action(invocation),
        default_policy=policy_version,
    )
    return evaluation, decision


def _highest_review_risk(reviews: list[SemanticReview]) -> str:
    risk = "low"
    for review in reviews:
        risk = _max_risk(risk, review.risk)
    return risk


def _max_risk(left: str, right: str) -> str:
    return left if RISK_ORDER.get(left, 0) >= RISK_ORDER.get(right, 0) else right


def _approval_grade(effect: str) -> str:
    if effect == "deny":
        return "blocked"
    if effect == "require_approval":
        return "require_human"
    if effect == "audit_only":
        return "audit"
    return "auto_approve"


def _legacy_effect(effect: str) -> str:
    if effect == "require_approval":
        return "ask"
    if effect == "audit_only":
        return "allow"
    return effect
