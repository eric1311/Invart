from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from invart.core.artifacts import write_json_artifact
from invart.assurance.postruntime import export_proof_report, verify_proof_report
from invart.core.ledger import load_ledger_entries
from invart.core.models import utc_now
from invart.assurance.coverage import COVERAGE_GRADES

GATE_SCHEMA_VERSION = "invart.gate.v0.5"
GATE_MODES = {"audit", "managed", "ci"}
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class GateFinding:
    check_id: str
    status: str
    severity: str
    title: str
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class GateReport:
    schema_version: str
    generated_at: str
    mode: str
    status: str
    passed: bool
    ledger: str | None
    proof: str | None
    summary: dict[str, Any]
    findings: list[GateFinding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["findings"] = [finding.to_dict() for finding in self.findings]
        return payload


def verify_gate(
    *,
    ledger_path: Path | None = None,
    proof_path: Path | None = None,
    mode: str = "managed",
    output_path: Path | None = None,
    require_closed_session: bool = False,
    coverage_requirements: dict[str, str] | None = None,
) -> dict[str, Any]:
    mode = mode if mode in GATE_MODES else "managed"
    findings: list[GateFinding] = []
    verification = verify_proof_report(proof_path, ledger_path)
    proof = _load_or_derive_proof(proof_path, ledger_path, verification, findings)

    if not verification.get("valid"):
        findings.append(
            GateFinding(
                check_id="proof.verification",
                status="fail",
                severity="critical",
                title="Proof or ledger verification failed",
                detail="The proof cannot be trusted until ledger integrity and proof consistency pass.",
                evidence={"verification": verification},
            )
        )

    if mode == "ci" and proof_path is None:
        findings.append(
            GateFinding(
                check_id="proof.required_in_ci",
                status="fail",
                severity="high",
                title="CI mode requires a proof artifact",
                detail="CI mode should verify the portable proof summary together with the source ledger.",
            )
        )

    if require_closed_session and ledger_path is not None and not _ledger_has_closed_session(ledger_path):
        findings.append(
            GateFinding(
                check_id="session.not_closed",
                status="fail",
                severity="high",
                title="Session is not closed",
                detail="This gate profile requires a closed session before passing.",
            )
        )

    if mode == "ci" and ledger_path is None:
        findings.append(
            GateFinding(
                check_id="ledger.required_in_ci",
                status="fail",
                severity="critical",
                title="CI mode requires the source ledger",
                detail="Proof-only verification cannot recompute the hash chain and is not acceptable for CI gating.",
            )
        )

    if proof:
        findings.extend(_policy_findings(proof, mode))
        findings.extend(_coverage_findings(proof, mode, coverage_requirements or {}))
    else:
        findings.append(
            GateFinding(
                check_id="proof.unavailable",
                status="fail",
                severity="critical",
                title="No proof facts available",
                detail="Gate evaluation requires a proof report or a ledger that can derive one.",
            )
        )

    if any(finding.check_id != "gate.clean" for finding in findings):
        findings = [finding for finding in findings if finding.check_id != "gate.clean"]

    status = _overall_status(findings, mode)
    report = GateReport(
        schema_version=GATE_SCHEMA_VERSION,
        generated_at=utc_now(),
        mode=mode,
        status=status,
        passed=status != "fail",
        ledger=str(ledger_path) if ledger_path else None,
        proof=str(proof_path) if proof_path else None,
        summary=_summary(findings, proof, verification),
        findings=findings,
    ).to_dict()
    if output_path:
        write_json_artifact(output_path, report)
    return report


def _coverage_findings(proof: dict[str, Any], mode: str, requirements: dict[str, str]) -> list[GateFinding]:
    if not requirements:
        return []
    findings: list[GateFinding] = []
    coverage_events = proof.get("coverage", {}).get("events", []) if isinstance(proof.get("coverage"), dict) else []
    if not coverage_events:
        findings.append(
            GateFinding(
                check_id="coverage.missing",
                status="warn" if mode == "audit" else "fail",
                severity="high",
                title="Coverage facts are missing",
                detail="The proof does not contain coverage facts required by this gate profile.",
                evidence={"requirements": requirements},
            )
        )
        return findings
    for item in coverage_events:
        if not isinstance(item, dict):
            continue
        coverage = item.get("coverage") if isinstance(item.get("coverage"), dict) else {}
        grade = coverage.get("coverage_grade") if isinstance(coverage.get("coverage_grade"), dict) else {}
        for dimension, minimum in requirements.items():
            actual = str(grade.get(dimension) or coverage.get(dimension) or "none")
            if _coverage_rank(actual) < _coverage_rank(minimum):
                findings.append(
                    GateFinding(
                        check_id="coverage.gap",
                        status="warn" if mode == "audit" else "fail",
                        severity="high",
                        title="Coverage requirement is not met",
                        detail=f"{dimension} requires at least {minimum}, but event {item.get('event_id')} is {actual}.",
                        evidence={"event_id": item.get("event_id"), "dimension": dimension, "minimum": minimum, "actual": actual},
                    )
                )
    return findings


def _coverage_rank(grade: str) -> int:
    if grade not in COVERAGE_GRADES:
        return 0
    return COVERAGE_GRADES.index(grade)


def _ledger_has_closed_session(ledger_path: Path) -> bool:
    entries, _warnings = load_ledger_entries(ledger_path)
    for entry in entries:
        if entry.entry_type == "session" and entry.event and entry.event.get("type") == "session_end":
            return entry.event.get("status") in {"closed", "aborted"}
    return False


def _load_or_derive_proof(
    proof_path: Path | None,
    ledger_path: Path | None,
    verification: dict[str, Any],
    findings: list[GateFinding],
) -> dict[str, Any] | None:
    if proof_path is not None and proof_path.exists():
        try:
            loaded = json.loads(proof_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            findings.append(
                GateFinding(
                    check_id="proof.json",
                    status="fail",
                    severity="critical",
                    title="Proof JSON is invalid",
                    detail=str(exc),
                )
            )
            return None
        if isinstance(loaded, dict):
            return loaded
        return None
    if ledger_path is not None and ledger_path.exists() and verification.get("hash_chain_valid") is not False:
        return export_proof_report(ledger_path)
    return None


def _policy_findings(proof: dict[str, Any], mode: str) -> list[GateFinding]:
    findings: list[GateFinding] = []
    summary = proof.get("summary", {}) if isinstance(proof.get("summary"), dict) else {}
    ledger = proof.get("ledger", {}) if isinstance(proof.get("ledger"), dict) else {}

    if ledger.get("hash_chain_valid") is not True:
        findings.append(
            GateFinding(
                check_id="ledger.hash_chain",
                status="fail",
                severity="critical",
                title="Ledger hash chain is invalid",
                detail="The source evidence ledger did not verify.",
                evidence={"ledger": ledger},
            )
        )

    approvals = [item for item in proof.get("approval_evidence", []) if isinstance(item, dict)]
    missing = [item for item in approvals if item.get("status") == "missing"]
    rejected = [item for item in approvals if item.get("status") == "rejected"]
    blocked = [item for item in approvals if item.get("status") == "blocked"]
    if missing:
        findings.append(
            GateFinding(
                check_id="approval.missing",
                status="warn" if mode == "audit" else "fail",
                severity="high",
                title="Required approvals are unresolved",
                detail=f"{len(missing)} policy decision(s) require approval but have no approval evidence.",
                evidence={"decision_ids": [item.get("decision_id") for item in missing]},
            )
        )
    if rejected:
        findings.append(
            GateFinding(
                check_id="approval.rejected",
                status="warn" if mode == "audit" else "fail",
                severity="high",
                title="Rejected approvals are present",
                detail=f"{len(rejected)} policy decision(s) were explicitly rejected.",
                evidence={"decision_ids": [item.get("decision_id") for item in rejected]},
            )
        )
    if blocked:
        findings.append(
            GateFinding(
                check_id="policy.blocked",
                status="fail" if mode == "ci" else "warn",
                severity="high",
                title="Policy blocked one or more actions",
                detail=f"{len(blocked)} action(s) were blocked by policy.",
                evidence={"decision_ids": [item.get("decision_id") for item in blocked]},
            )
        )

    high_unresolved_grants = _unresolved_high_risk_capability_grants(proof)
    if high_unresolved_grants:
        findings.append(
            GateFinding(
                check_id="capability_grant.high_risk_unresolved",
                status="warn" if mode == "audit" else "fail",
                severity="high",
                title="High-risk capability grants are unresolved",
                detail=f"{len(high_unresolved_grants)} high-risk adapter/skill capability grant(s) still need approval.",
                evidence={"grants": high_unresolved_grants},
            )
        )

    taint_status = summary.get("taint_status", {}) if isinstance(summary.get("taint_status"), dict) else {}
    decisions = proof.get("policy_decisions", []) if isinstance(proof.get("policy_decisions"), list) else []
    if taint_status.get("is_tainted") and any(decision.get("effect") == "allow" and decision.get("risk") in {"medium", "high", "critical"} for decision in decisions if isinstance(decision, dict)):
        findings.append(
            GateFinding(
                check_id="taint.allowed_risk",
                status="warn" if mode in {"audit", "managed"} else "fail",
                severity="medium",
                title="Tainted session contains allowed risky actions",
                detail="A tainted session allowed at least one medium-or-higher risk action. Review whether this should have required approval.",
            )
        )

    if not findings:
        findings.append(
            GateFinding(
                check_id="gate.clean",
                status="pass",
                severity="info",
                title="Gate checks passed",
                detail="Ledger/proof integrity and policy consumption checks passed for this mode.",
            )
        )
    return findings


def _unresolved_high_risk_capability_grants(proof: dict[str, Any]) -> list[dict[str, Any]]:
    actions = [item for item in proof.get("capability_grants", []) if isinstance(item, dict)]
    decisions = {str(item.get("event_id")): item for item in proof.get("policy_decisions", []) if isinstance(item, dict)}
    approvals = {str(item.get("decision_id")): item for item in proof.get("approval_evidence", []) if isinstance(item, dict)}
    unresolved: list[dict[str, Any]] = []
    for action in actions:
        event_id = str(action.get("event_id") or action.get("invocation_id"))
        decision = decisions.get(event_id)
        if not decision or str(decision.get("risk")) not in {"high", "critical"}:
            continue
        approval = approvals.get(str(decision.get("decision_id")))
        if decision.get("requires_approval") and (not approval or approval.get("status") == "missing"):
            metadata = action.get("metadata", {}) if isinstance(action.get("metadata"), dict) else {}
            surface = metadata.get("capability_surface", {}) if isinstance(metadata.get("capability_surface"), dict) else {}
            unresolved.append(
                {
                    "grant_id": action.get("capability_grant_id") or metadata.get("capability_grant_id"),
                    "source_id": surface.get("source_id"),
                    "decision_id": decision.get("decision_id"),
                    "risk": decision.get("risk"),
                }
            )
    return unresolved


def _overall_status(findings: list[GateFinding], mode: str) -> str:
    if any(finding.status == "fail" for finding in findings):
        return "fail"
    if any(finding.status == "warn" for finding in findings):
        return "warn"
    return "pass"


def _summary(findings: list[GateFinding], proof: dict[str, Any] | None, verification: dict[str, Any]) -> dict[str, Any]:
    by_status: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for finding in findings:
        by_status[finding.status] = by_status.get(finding.status, 0) + 1
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
    proof_summary = proof.get("summary", {}) if isinstance(proof, dict) and isinstance(proof.get("summary"), dict) else {}
    return {
        "findings": len(findings),
        "by_status": by_status,
        "by_severity": by_severity,
        "verification_valid": bool(verification.get("valid")),
        "hash_chain_valid": verification.get("hash_chain_valid"),
        "proof": {
            "total_actions": proof_summary.get("total_actions"),
            "capability_grants": proof_summary.get("capability_grants"),
            "blocked_actions": proof_summary.get("blocked_actions"),
            "approvals": proof_summary.get("approvals", {}),
        },
    }


__all__ = ["GATE_SCHEMA_VERSION", "GateFinding", "GateReport", "verify_gate"]
