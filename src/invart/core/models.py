from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


Severity = str


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    phase: str
    category: str
    path: str | None = None
    evidence: str | None = None
    recommendation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Asset:
    kind: str
    name: str
    path: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanReport:
    generated_at: str
    target: str
    assets: list[Asset] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    checks: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "target": self.target,
            "assets": [asset.to_dict() for asset in self.assets],
            "findings": [finding.to_dict() for finding in self.findings],
            "checks": self.checks,
            "summary": summarize_findings(self.findings),
        }


@dataclass
class RuntimeEvent:
    type: str
    timestamp: str = field(default_factory=utc_now)
    session_id: str | None = None
    agent: str | None = None
    target: str | None = None
    command: str | None = None
    path: str | None = None
    url: str | None = None
    tool: str | None = None
    skill: str | None = None
    content: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "RuntimeEvent":
        allowed = {
            "type",
            "timestamp",
            "session_id",
            "agent",
            "target",
            "command",
            "path",
            "url",
            "tool",
            "skill",
            "content",
            "metadata",
        }
        values = {key: value for key, value in payload.items() if key in allowed}
        if "type" not in values:
            raise ValueError("runtime event requires a 'type' field")
        if "metadata" not in values or values["metadata"] is None:
            values["metadata"] = {}
        return cls(**values)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Session:
    session_id: str
    started_at: str
    status: str
    target: str
    agent: str | None
    user: str | None
    policy_version: str
    ledger_path: str
    goal: str | None = None
    created_by: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    ended_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Session":
        return cls(
            session_id=str(payload["session_id"]),
            started_at=str(payload.get("started_at", utc_now())),
            status=str(payload.get("status", "active")),
            target=str(payload.get("target", "")),
            agent=payload.get("agent"),
            user=payload.get("user"),
            policy_version=str(payload.get("policy_version", "invart.policy.v0.1")),
            ledger_path=str(payload.get("ledger_path", "")),
            goal=payload.get("goal"),
            created_by=payload.get("created_by"),
            metadata=dict(payload.get("metadata") or {}),
            ended_at=payload.get("ended_at"),
        )


@dataclass
class Invocation:
    event_id: str
    session_id: str
    timestamp: str
    sequence: int
    action_type: str
    actor: str | None = None
    target: str | None = None
    command: str | None = None
    path: str | None = None
    url: str | None = None
    tool: str | None = None
    skill: str | None = None
    payload_summary: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    parent_event_id: str | None = None
    content_hash: str | None = None
    invocation_id: str | None = None
    seq: int | None = None
    adapter: str = "manual"
    operation: str | None = None
    resource_refs: list[dict[str, str]] = field(default_factory=list)
    source: str = "unknown"
    trust_level: str = "unknown"
    input_refs: list[str] = field(default_factory=list)
    output_refs: list[str] = field(default_factory=list)
    taint_tags: list[str] = field(default_factory=list)
    correlation_id: str | None = None
    capability_grant_id: str | None = None
    policy_version: str | None = None
    evidence_refs: list[dict[str, str]] = field(default_factory=list)
    control_mode: str = "advisory"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Invocation":
        return cls(
            event_id=str(payload.get("event_id", payload.get("invocation_id"))),
            session_id=str(payload["session_id"]),
            timestamp=str(payload.get("timestamp", utc_now())),
            sequence=int(payload.get("sequence", payload.get("seq", 0))),
            action_type=str(payload.get("action_type", payload.get("operation", payload.get("type", "unknown")))),
            actor=payload.get("actor"),
            target=payload.get("target"),
            command=payload.get("command"),
            path=payload.get("path"),
            url=payload.get("url"),
            tool=payload.get("tool"),
            skill=payload.get("skill"),
            payload_summary=payload.get("payload_summary"),
            metadata=dict(payload.get("metadata") or {}),
            parent_event_id=payload.get("parent_event_id"),
            content_hash=payload.get("content_hash"),
            invocation_id=str(payload.get("invocation_id", payload.get("event_id"))),
            seq=int(payload.get("seq", payload.get("sequence", 0))),
            adapter=str(payload.get("adapter", "manual")),
            operation=payload.get("operation"),
            resource_refs=[dict(item) for item in payload.get("resource_refs", []) if isinstance(item, dict)],
            source=str(payload.get("source", "unknown")),
            trust_level=str(payload.get("trust_level", "unknown")),
            input_refs=[str(item) for item in payload.get("input_refs", [])],
            output_refs=[str(item) for item in payload.get("output_refs", [])],
            taint_tags=[str(item) for item in payload.get("taint_tags", [])],
            correlation_id=payload.get("correlation_id"),
            capability_grant_id=payload.get("capability_grant_id"),
            policy_version=payload.get("policy_version"),
            evidence_refs=[dict(item) for item in payload.get("evidence_refs", []) if isinstance(item, dict)],
            control_mode=str(payload.get("control_mode", "advisory")),
        )


# Backward-compatible name used by the first proof-generator slice.
ActionEvent = Invocation


@dataclass
class PolicyDecision:
    decision_id: str
    event_id: str
    session_id: str
    timestamp: str
    effect: str
    risk: str
    matched_rules: list[str]
    findings: list[Finding] = field(default_factory=list)
    reason: str = ""
    requires_approval: bool = False
    taint_influenced: bool = False
    default_policy: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["findings"] = [finding.to_dict() for finding in self.findings]
        return payload

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "PolicyDecision":
        return cls(
            decision_id=str(payload["decision_id"]),
            event_id=str(payload["event_id"]),
            session_id=str(payload["session_id"]),
            timestamp=str(payload.get("timestamp", utc_now())),
            effect=str(payload.get("effect", "allow")),
            risk=str(payload.get("risk", "info")),
            matched_rules=[str(item) for item in payload.get("matched_rules", [])],
            findings=[finding_from_dict(item) for item in payload.get("findings", []) if isinstance(item, dict)],
            reason=str(payload.get("reason", "")),
            requires_approval=bool(payload.get("requires_approval", False)),
            taint_influenced=bool(payload.get("taint_influenced", False)),
            default_policy=payload.get("default_policy"),
        )


@dataclass
class ApprovalEvidence:
    approval_id: str
    decision_id: str
    event_id: str
    session_id: str
    status: str
    requested_at: str
    resolved_at: str | None = None
    approver: str | None = None
    reason: str | None = None
    prompt: str | None = None
    expires_at: str | None = None
    context_event_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ApprovalEvidence":
        return cls(
            approval_id=str(payload["approval_id"]),
            decision_id=str(payload["decision_id"]),
            event_id=str(payload["event_id"]),
            session_id=str(payload["session_id"]),
            status=str(payload.get("status", "not_required")),
            requested_at=str(payload.get("requested_at", utc_now())),
            resolved_at=payload.get("resolved_at"),
            approver=payload.get("approver"),
            reason=payload.get("reason"),
            prompt=payload.get("prompt"),
            expires_at=payload.get("expires_at"),
            context_event_ids=[str(item) for item in payload.get("context_event_ids", [])],
        )


@dataclass
class ExecutionOutcome:
    outcome_id: str
    session_id: str
    invocation_id: str
    decision_id: str | None
    status: str
    actor: str | None = None
    reason: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    recorded_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ExecutionOutcome":
        return cls(
            outcome_id=str(payload.get("outcome_id", "")),
            session_id=str(payload.get("session_id", "")),
            invocation_id=str(payload.get("invocation_id", payload.get("event_id", ""))),
            decision_id=payload.get("decision_id"),
            status=str(payload.get("status", "unknown")),
            actor=payload.get("actor"),
            reason=payload.get("reason"),
            metadata=dict(payload.get("metadata") or {}),
            recorded_at=str(payload.get("recorded_at", utc_now())),
        )


@dataclass
class TaintState:
    session_id: str
    is_tainted: bool = False
    level: str = "none"
    sources: list[dict[str, str]] = field(default_factory=list)
    updated_at: str = field(default_factory=utc_now)
    cleared_at: str | None = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "TaintState":
        return cls(
            session_id=str(payload.get("session_id", "")),
            is_tainted=bool(payload.get("is_tainted", False)),
            level=str(payload.get("level", "none")),
            sources=[dict(item) for item in payload.get("sources", []) if isinstance(item, dict)],
            updated_at=str(payload.get("updated_at", utc_now())),
            cleared_at=payload.get("cleared_at"),
            notes=[str(item) for item in payload.get("notes", [])],
        )


@dataclass
class LedgerEntry:
    sequence: int
    entry_id: str
    session_id: str
    timestamp: str
    entry_type: str
    event: dict[str, Any] | None = None
    decision: dict[str, Any] | None = None
    approval: dict[str, Any] | None = None
    outcome: dict[str, Any] | None = None
    taint: dict[str, Any] | None = None
    findings: list[dict[str, Any]] = field(default_factory=list)
    prev_hash: str = ""
    entry_hash: str = ""
    schema_version: str = "invart.ledger.v0.1"
    result: dict[str, Any] | None = None
    reviews: list[dict[str, Any]] = field(default_factory=list)
    evaluation: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "LedgerEntry":
        return cls(
            sequence=int(payload.get("sequence", 0)),
            entry_id=str(payload.get("entry_id", "")),
            session_id=str(payload.get("session_id", "")),
            timestamp=str(payload.get("timestamp", utc_now())),
            entry_type=str(payload.get("entry_type", "action")),
            event=payload.get("event"),
            decision=payload.get("decision"),
            approval=payload.get("approval"),
            outcome=payload.get("outcome"),
            taint=payload.get("taint"),
            findings=[dict(item) for item in payload.get("findings", []) if isinstance(item, dict)],
            prev_hash=str(payload.get("prev_hash", "")),
            entry_hash=str(payload.get("entry_hash", "")),
            schema_version=str(payload.get("schema_version", "invart.ledger.v0.1")),
            result=payload.get("result"),
            reviews=[dict(item) for item in payload.get("reviews", []) if isinstance(item, dict)],
            evaluation=payload.get("evaluation"),
        )


@dataclass
class ProofReport:
    schema_version: str
    generated_at: str
    session: dict[str, Any]
    ledger: dict[str, Any]
    summary: dict[str, Any]
    actions: list[dict[str, Any]]
    policy_decisions: list[dict[str, Any]]
    taint: dict[str, Any]
    findings: list[dict[str, Any]]
    approval_evidence: list[dict[str, Any]] = field(default_factory=list)
    risk_statement: str | None = None
    export_warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ReviewFinding:
    source: str
    category: str
    risk: str
    confidence: float | None
    title: str
    reason: str
    evidence_refs: list[dict[str, str]] = field(default_factory=list)
    recommended_effect: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ReviewFinding":
        return cls(
            source=str(payload.get("source", "semantic")),
            category=str(payload.get("category", "unknown")),
            risk=str(payload.get("risk", "low")),
            confidence=float(payload["confidence"]) if payload.get("confidence") is not None else None,
            title=str(payload.get("title", "Review finding")),
            reason=str(payload.get("reason", "")),
            evidence_refs=[dict(item) for item in payload.get("evidence_refs", []) if isinstance(item, dict)],
            recommended_effect=payload.get("recommended_effect"),
        )


@dataclass
class SemanticReview:
    review_id: str
    session_id: str
    invocation_id: str
    reviewer: str
    model: str | None
    prompt_version: str | None
    input_refs: list[str]
    input_hash: str
    risk: str
    confidence: float
    categories: list[str]
    reason: str
    recommended_effect: str
    findings: list[ReviewFinding] = field(default_factory=list)
    reviewed_at: str = field(default_factory=utc_now)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["findings"] = [finding.to_dict() for finding in self.findings]
        return payload

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "SemanticReview":
        return cls(
            review_id=str(payload.get("review_id", "")),
            session_id=str(payload.get("session_id", "")),
            invocation_id=str(payload.get("invocation_id", payload.get("event_id", ""))),
            reviewer=str(payload.get("reviewer", "heuristic")),
            model=payload.get("model"),
            prompt_version=payload.get("prompt_version"),
            input_refs=[str(item) for item in payload.get("input_refs", [])],
            input_hash=str(payload.get("input_hash", "")),
            risk=str(payload.get("risk", "low")),
            confidence=float(payload.get("confidence", 0.0)),
            categories=[str(item) for item in payload.get("categories", [])],
            reason=str(payload.get("reason", "")),
            recommended_effect=str(payload.get("recommended_effect", "allow")),
            findings=[ReviewFinding.from_dict(item) for item in payload.get("findings", []) if isinstance(item, dict)],
            reviewed_at=str(payload.get("reviewed_at", utc_now())),
            warnings=[str(item) for item in payload.get("warnings", [])],
        )


@dataclass
class PolicyEvaluation:
    evaluation_id: str
    session_id: str
    invocation_id: str
    policy_version: str
    policy_mode: str
    review_mode: str
    rule_findings: list[Finding] = field(default_factory=list)
    semantic_reviews: list[SemanticReview] = field(default_factory=list)
    taint_tags: list[str] = field(default_factory=list)
    capability_grant_id: str | None = None
    final_effect: str = "allow"
    final_risk: str = "low"
    approval_grade: str = "auto_approve"
    reason: str = ""
    decision_trace: list[str] = field(default_factory=list)
    requires_approval: bool = False
    evaluated_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["rule_findings"] = [finding.to_dict() for finding in self.rule_findings]
        payload["semantic_reviews"] = [review.to_dict() for review in self.semantic_reviews]
        return payload

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "PolicyEvaluation":
        return cls(
            evaluation_id=str(payload.get("evaluation_id", "")),
            session_id=str(payload.get("session_id", "")),
            invocation_id=str(payload.get("invocation_id", "")),
            policy_version=str(payload.get("policy_version", "invart.policy.v0.2")),
            policy_mode=str(payload.get("policy_mode", "advisory")),
            review_mode=str(payload.get("review_mode", "auto")),
            rule_findings=[finding_from_dict(item) for item in payload.get("rule_findings", []) if isinstance(item, dict)],
            semantic_reviews=[SemanticReview.from_dict(item) for item in payload.get("semantic_reviews", []) if isinstance(item, dict)],
            taint_tags=[str(item) for item in payload.get("taint_tags", [])],
            capability_grant_id=payload.get("capability_grant_id"),
            final_effect=str(payload.get("final_effect", "allow")),
            final_risk=str(payload.get("final_risk", "low")),
            approval_grade=str(payload.get("approval_grade", "auto_approve")),
            reason=str(payload.get("reason", "")),
            decision_trace=[str(item) for item in payload.get("decision_trace", [])],
            requires_approval=bool(payload.get("requires_approval", False)),
            evaluated_at=str(payload.get("evaluated_at", utc_now())),
        )


def summarize_findings(findings: list[Finding]) -> dict[str, Any]:
    by_severity: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    by_category: dict[str, int] = {}
    for finding in findings:
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
        by_category[finding.category] = by_category.get(finding.category, 0) + 1
    highest = "info"
    for severity in ("critical", "high", "medium", "low", "info"):
        if by_severity.get(severity, 0):
            highest = severity
            break
    return {
        "total_findings": len(findings),
        "highest_severity": highest,
        "by_severity": by_severity,
        "by_category": by_category,
    }


def finding_from_dict(payload: dict[str, Any]) -> Finding:
    return Finding(
        rule_id=str(payload.get("rule_id", "unknown")),
        title=str(payload.get("title", "Unknown finding")),
        severity=str(payload.get("severity", "info")),
        phase=str(payload.get("phase", "runtime")),
        category=str(payload.get("category", "unknown")),
        path=payload.get("path"),
        evidence=payload.get("evidence"),
        recommendation=payload.get("recommendation"),
    )


def display_path(path: Path) -> str:
    try:
        return str(path.expanduser().resolve())
    except OSError:
        return str(path)
