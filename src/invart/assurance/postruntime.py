from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from invart.core.artifacts import write_json_artifact
from invart.core.ledger import load_ledger_entries, verify_ledger
from invart.core.models import Finding, ProofReport, finding_from_dict, summarize_findings, utc_now
from invart.governance.identity import accountability_from_ledger
from invart.assurance.path_graph import build_execution_graph


def load_events(event_log: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    if not event_log.exists():
        return events
    with event_log.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                events.append(payload)
    return events


def export_proof_report(ledger_path: Path, output_path: Path | None = None) -> dict[str, Any]:
    entries, warnings = load_ledger_entries(ledger_path)
    integrity = verify_ledger(ledger_path)
    session = _session_summary(entries)
    actions = [dict(entry.event) for entry in entries if entry.entry_type == "action" and entry.event]
    capability_grants = [dict(entry.event) for entry in entries if entry.entry_type == "action" and entry.event and _is_capability_grant(entry.event)]
    decisions = [dict(entry.decision) for entry in entries if entry.decision]
    semantic_reviews = [dict(review) for entry in entries for review in entry.reviews]
    policy_evaluations = [dict(entry.evaluation) for entry in entries if entry.evaluation]
    outcomes = [dict(entry.outcome) for entry in entries if entry.outcome]
    approvals = _approval_summary(entries)
    findings = [
        finding_from_dict(item)
        for entry in entries
        for item in entry.findings
        if isinstance(item, dict)
    ]
    final_taint = _final_taint(entries, session.get("session_id"))
    report = ProofReport(
        schema_version="invart.proof.v0.1",
        generated_at=utc_now(),
        session=session,
        ledger={
            "path": str(ledger_path),
            "entries": integrity["entries"],
            "first_hash": integrity["first_hash"],
            "last_hash": integrity["last_hash"],
            "hash_chain_valid": integrity["valid"],
            "first_violation": integrity["first_violation"],
        },
        summary=_summary(actions, decisions, approvals, findings, final_taint, outcomes),
        actions=actions,
        policy_decisions=decisions,
        taint=final_taint,
        findings=[finding.to_dict() for finding in findings],
        approval_evidence=approvals,
        risk_statement=_risk_statement(integrity["valid"], final_taint, decisions),
        export_warnings=[*warnings, *integrity.get("warnings", [])],
    ).to_dict()
    report["semantic_reviews"] = semantic_reviews
    report["policy_evaluations"] = policy_evaluations
    report["review_warnings"] = [warning for review in semantic_reviews for warning in review.get("warnings", [])]
    report["execution_outcomes"] = outcomes
    report["capability_grants"] = capability_grants
    report["coverage"] = _coverage_summary(entries)
    report["accountability"] = accountability_from_ledger(ledger_path)
    report["path_graph"] = _path_graph_summary(ledger_path)
    if output_path:
        write_json_artifact(output_path, report)
    return report


def verify_proof_report(proof_path: Path | None = None, ledger_path: Path | None = None) -> dict[str, Any]:
    warnings: list[str] = []
    proof: dict[str, Any] | None = None
    if proof_path is not None:
        if not proof_path.exists():
            return {"valid": False, "error": "proof_missing", "warnings": [f"proof not found: {proof_path}"]}
        try:
            loaded = json.loads(proof_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {"valid": False, "error": "proof_invalid_json", "warnings": ["proof JSON could not be parsed"]}
        if not isinstance(loaded, dict):
            return {"valid": False, "error": "proof_not_object", "warnings": ["proof root is not an object"]}
        proof = loaded
        if proof.get("schema_version") != "invart.proof.v0.1":
            warnings.append("unknown or missing proof schema_version")
        if ledger_path is None:
            ledger_value = proof.get("ledger", {}).get("path") if isinstance(proof.get("ledger"), dict) else None
            ledger_path = Path(str(ledger_value)) if ledger_value else None

    if ledger_path is None:
        if proof is None:
            return {"valid": False, "error": "verification_target_missing", "warnings": ["provide --proof, --ledger, or both"]}
        return _verify_proof_only(proof, warnings)

    if not ledger_path.exists():
        return {
            "valid": False,
            "error": "ledger_missing",
            "agent_instruction": "The proof references a ledger that is not available locally. Re-run verification with --ledger, or ask the producer to attach the ledger.jsonl artifact.",
            "warnings": [f"ledger not found: {ledger_path}"],
        }

    integrity = verify_ledger(ledger_path)
    if proof is None:
        return {
            "valid": bool(integrity["valid"]),
            "mode": "ledger",
            "hash_chain_valid": integrity["valid"],
            "last_hash": integrity["last_hash"],
            "warnings": [*warnings, *integrity.get("warnings", [])],
        }

    derived = export_proof_report(ledger_path)
    mismatches = _proof_mismatches(proof, derived)
    return {
        "valid": bool(integrity["valid"]) and not mismatches and not warnings,
        "mode": "proof+ledger",
        "hash_chain_valid": integrity["valid"],
        "last_hash": integrity["last_hash"],
        "mismatches": mismatches,
        "warnings": [*warnings, *integrity.get("warnings", [])],
    }


def _verify_proof_only(proof: dict[str, Any], warnings: list[str]) -> dict[str, Any]:
    required = ["schema_version", "session", "ledger", "summary", "actions", "policy_decisions", "taint", "findings"]
    missing = [key for key in required if key not in proof]
    ledger = proof.get("ledger", {}) if isinstance(proof.get("ledger"), dict) else {}
    if ledger.get("hash_chain_valid") is not True:
        warnings.append("proof reports an invalid or missing ledger hash chain")
    return {
        "valid": not missing and ledger.get("hash_chain_valid") is True and not warnings,
        "mode": "proof",
        "summary_only": True,
        "missing": missing,
        "hash_chain_valid": ledger.get("hash_chain_valid"),
        "last_hash": ledger.get("last_hash"),
        "warnings": [*warnings, "proof-only verification cannot recompute ledger integrity"],
    }


def _proof_mismatches(proof: dict[str, Any], derived: dict[str, Any]) -> list[str]:
    mismatches: list[str] = []
    checks = [
        ("ledger.last_hash", proof.get("ledger", {}).get("last_hash"), derived.get("ledger", {}).get("last_hash")),
        ("ledger.entries", proof.get("ledger", {}).get("entries"), derived.get("ledger", {}).get("entries")),
        ("summary.total_actions", proof.get("summary", {}).get("total_actions"), derived.get("summary", {}).get("total_actions")),
        ("summary.blocked_actions", proof.get("summary", {}).get("blocked_actions"), derived.get("summary", {}).get("blocked_actions")),
        ("taint.is_tainted", proof.get("taint", {}).get("is_tainted"), derived.get("taint", {}).get("is_tainted")),
        ("actions.count", len(proof.get("actions", [])), len(derived.get("actions", []))),
        ("policy_decisions.count", len(proof.get("policy_decisions", [])), len(derived.get("policy_decisions", []))),
        ("findings.count", len(proof.get("findings", [])), len(derived.get("findings", []))),
        ("semantic_reviews.count", len(proof.get("semantic_reviews", [])), len(derived.get("semantic_reviews", []))),
        ("policy_evaluations.count", len(proof.get("policy_evaluations", [])), len(derived.get("policy_evaluations", []))),
        ("execution_outcomes.count", len(proof.get("execution_outcomes", [])), len(derived.get("execution_outcomes", []))),
        ("coverage.events.count", len(proof.get("coverage", {}).get("events", [])), len(derived.get("coverage", {}).get("events", []))),
    ]
    for label, actual, expected in checks:
        if actual != expected:
            mismatches.append(f"{label}: proof={actual!r} ledger={expected!r}")
    return mismatches


def summarize_session(event_log: Path) -> dict[str, Any]:
    entries, _warnings = load_ledger_entries(event_log)
    if entries and any(entry.schema_version == "invart.ledger.v0.1" for entry in entries):
        return export_proof_report(event_log)
    events = load_events(event_log)
    findings = [finding_from_dict(item) for event in events for item in event.get("findings", []) if isinstance(item, dict)]
    event_types: dict[str, int] = {}
    agents: dict[str, int] = {}
    touched_paths: set[str] = set()
    tools: set[str] = set()
    urls: set[str] = set()
    for event in events:
        event_type = str(event.get("type", "unknown"))
        event_types[event_type] = event_types.get(event_type, 0) + 1
        agent = event.get("agent")
        if agent:
            agents[str(agent)] = agents.get(str(agent), 0) + 1
        if event.get("path"):
            touched_paths.add(str(event["path"]))
        if event.get("tool"):
            tools.add(str(event["tool"]))
        if event.get("url"):
            urls.add(str(event["url"]))
    return {
        "generated_at": utc_now(),
        "event_log": str(event_log),
        "summary": {
            "total_events": len(events),
            "event_types": event_types,
            "agents": agents,
            "touched_paths": sorted(touched_paths),
            "tools": sorted(tools),
            "urls": sorted(urls),
            "risks": summarize_findings(findings),
        },
        "findings": [finding.to_dict() for finding in findings],
        "events": events,
    }


def _is_capability_grant(action: dict[str, Any]) -> bool:
    return action.get("type") == "capability_grant" or action.get("action_type") == "capability_grant"


def _coverage_summary(entries: list[Any]) -> dict[str, Any]:
    dimensions = ("preflight_visibility", "runtime_observation", "runtime_enforcement", "postruntime_audit")
    summary: dict[str, dict[str, int]] = {dimension: {} for dimension in dimensions}
    events = []
    for entry in entries:
        event = entry.event or {}
        metadata = event.get("metadata") if isinstance(event, dict) else {}
        coverage = metadata.get("coverage") if isinstance(metadata, dict) else None
        if not isinstance(coverage, dict):
            continue
        grade = coverage.get("coverage_grade") if isinstance(coverage.get("coverage_grade"), dict) else {}
        for dimension in dimensions:
            value = str(grade.get(dimension) or coverage.get(dimension) or "none")
            summary[dimension][value] = summary[dimension].get(value, 0) + 1
        events.append({"event_id": event.get("event_id") or event.get("invocation_id"), "coverage": coverage})
    return {"summary": summary, "events": events}


def _path_graph_summary(ledger_path: Path) -> dict[str, Any]:
    graph = build_execution_graph(ledger_path)
    return {
        "schema_version": graph["schema_version"],
        "summary": graph["summary"],
        "ledger_derived": True,
    }


def _session_summary(entries: list[Any]) -> dict[str, Any]:
    session: dict[str, Any] = {}
    for entry in entries:
        if entry.entry_type == "session" and entry.event:
            event = entry.event
            if event.get("type") == "session_start":
                session.update(
                    {
                        "session_id": event.get("session_id"),
                        "agent": event.get("agent"),
                        "target": event.get("target"),
                        "goal": event.get("goal"),
                        "started_at": event.get("timestamp"),
                        "policy_version": event.get("policy_version"),
                        "user": event.get("user"),
                        "preflight": event.get("preflight"),
                    }
                )
            elif event.get("type") == "session_end":
                session["ended_at"] = event.get("timestamp")
                session["status"] = event.get("status")
    if "session_id" not in session and entries:
        session["session_id"] = entries[0].session_id
    return session


def _approval_summary(entries: list[Any]) -> list[dict[str, Any]]:
    approvals: list[dict[str, Any]] = []
    explicit: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if entry.approval:
            explicit[str(entry.approval.get("decision_id"))] = dict(entry.approval)
    for entry in entries:
        if not entry.decision:
            continue
        decision = entry.decision
        decision_id = str(decision.get("decision_id"))
        if decision_id in explicit:
            approvals.append(explicit[decision_id])
            continue
        status = "not_required"
        if decision.get("requires_approval"):
            status = "missing"
        if decision.get("effect") == "deny":
            status = "blocked"
        approvals.append(
            {
                "approval_id": f"appr_{decision_id}",
                "decision_id": decision_id,
                "event_id": decision.get("event_id"),
                "session_id": decision.get("session_id"),
                "status": status,
                "requested_at": decision.get("timestamp"),
                "resolved_at": None,
                "approver": None,
                "reason": None,
            }
        )
    return approvals


def _final_taint(entries: list[Any], session_id: str | None) -> dict[str, Any]:
    taint: dict[str, Any] = {
        "session_id": session_id or "",
        "is_tainted": False,
        "level": "none",
        "sources": [],
        "updated_at": None,
        "cleared_at": None,
        "notes": [],
    }
    for entry in entries:
        if entry.taint:
            taint = dict(entry.taint)
    return taint


def _summary(
    actions: list[dict[str, Any]],
    decisions: list[dict[str, Any]],
    approvals: list[dict[str, Any]],
    findings: list[Finding],
    taint: dict[str, Any],
    outcomes: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    by_effect: dict[str, int] = {}
    by_risk: dict[str, int] = {}
    for decision in decisions:
        effect = str(decision.get("effect", "unknown"))
        risk = str(decision.get("risk", "unknown"))
        by_effect[effect] = by_effect.get(effect, 0) + 1
        by_risk[risk] = by_risk.get(risk, 0) + 1
    outcomes = outcomes or []
    outcomes_by_status: dict[str, int] = {}
    for outcome in outcomes:
        status = str(outcome.get("status", "unknown"))
        outcomes_by_status[status] = outcomes_by_status.get(status, 0) + 1
    return {
        "total_actions": len(actions),
        "total_events": len(actions),
        "capability_grants": sum(1 for action in actions if _is_capability_grant(action)),
        "decisions_by_effect": by_effect,
        "decisions_by_risk": by_risk,
        "blocked_actions": by_effect.get("deny", 0),
        "approvals": {status: sum(1 for item in approvals if item.get("status") == status) for status in _approval_statuses(approvals)},
        "execution_outcomes": outcomes_by_status,
        "taint_status": {
            "is_tainted": bool(taint.get("is_tainted")),
            "level": taint.get("level", "none"),
            "sources": len(taint.get("sources", [])),
        },
        "risks": summarize_findings(findings),
    }


def _approval_statuses(approvals: list[dict[str, Any]]) -> list[str]:
    statuses = sorted({str(item.get("status", "unknown")) for item in approvals})
    return statuses or ["not_required"]


def _risk_statement(hash_valid: bool, taint: dict[str, Any], decisions: list[dict[str, Any]]) -> str:
    if not hash_valid:
        return "The ledger is incomplete or unverifiable; no clean proof can be asserted."
    if taint.get("is_tainted"):
        return "This session read sensitive resources. Later outbound/write-like actions require review."
    if any(decision.get("effect") == "deny" for decision in decisions):
        return "The ledger is valid and one or more actions were blocked by policy."
    return "No sensitive source was observed before outbound or write-like actions."
