from __future__ import annotations

import hashlib
import json
import os
import subprocess
import uuid
from pathlib import Path
from typing import Any

from .ledger import append_ledger_entry, load_ledger_entries, verify_ledger
from .preflight import preflight_reference, save_preflight
from .models import ActionEvent, ApprovalEvidence, ExecutionOutcome, Finding, LedgerEntry, RuntimeEvent, Session, TaintState, display_path, utc_now
from .policy import merge_policy
from .review import make_reviewer, should_review
from .rules import analyze_runtime_event, highest_severity, updates_taint
from .coverage import default_coverage_for_layer


POLICY_VERSION = "kappaski.policy.v0.2"


def default_session_id() -> str:
    return "ks_" + uuid.uuid4().hex[:12]


def default_session_dir(target: Path, session_id: str) -> Path:
    return target.expanduser().resolve() / ".kappaski" / "sessions" / session_id


def start_session(
    target: Path,
    ledger_path: Path | None = None,
    agent: str | None = None,
    goal: str | None = None,
    session_id: str | None = None,
    preflight_path: Path | None = None,
    create_preflight: bool = True,
) -> Session:
    target = target.expanduser().resolve()
    session_id = session_id or default_session_id()
    if ledger_path is None:
        ledger_path = default_session_dir(target, session_id) / "ledger.jsonl"
    if create_preflight and preflight_path is None:
        preflight = save_preflight(target)
        preflight_path = Path(str(preflight["path"]))
    preflight_ref = preflight_reference(preflight_path)
    existing, _warnings = load_ledger_entries(ledger_path)
    for entry in existing:
        if entry.entry_type == "session" and entry.event and entry.event.get("type") == "session_start":
            event = dict(entry.event)
            return Session(
                session_id=str(event.get("session_id", session_id)),
                started_at=str(event.get("timestamp", utc_now())),
                status="active",
                target=str(event.get("target", target)),
                agent=event.get("agent"),
                user=event.get("user"),
                policy_version=str(event.get("policy_version", POLICY_VERSION)),
                ledger_path=str(ledger_path),
                goal=event.get("goal"),
                created_by=event.get("created_by"),
                metadata=dict(event.get("metadata") or {}),
            )

    session = Session(
        session_id=session_id,
        started_at=utc_now(),
        status="active",
        target=display_path(target),
        agent=agent,
        user=os.environ.get("USER") or os.environ.get("USERNAME"),
        policy_version=POLICY_VERSION,
        ledger_path=str(ledger_path),
        goal=goal,
        created_by="kappaski.cli",
    )
    entry = LedgerEntry(
        sequence=0,
        entry_id=f"led_{uuid.uuid4().hex[:16]}",
        session_id=session.session_id,
        timestamp=session.started_at,
        entry_type="session",
        event={
            "type": "session_start",
            "session_id": session.session_id,
            "timestamp": session.started_at,
            "target": session.target,
            "agent": session.agent,
            "user": session.user,
            "policy_version": session.policy_version,
            "goal": session.goal,
            "created_by": session.created_by,
            "metadata": session.metadata,
            "preflight": preflight_ref,
        },
        result={"status": "active", "preflight": preflight_ref},
    )
    append_ledger_entry(entry, ledger_path)
    return session


def close_session(ledger_path: Path, status: str = "closed") -> LedgerEntry:
    entries, _warnings = load_ledger_entries(ledger_path)
    session_id = _session_id_from_entries(entries)
    final_taint = _taint_from_entries(entries, session_id)
    event = {
        "type": "session_end",
        "session_id": session_id,
        "timestamp": utc_now(),
        "status": status,
        "tainted": final_taint.is_tainted,
        "total_entries": len(entries) + 1,
    }
    entry = LedgerEntry(
        sequence=0,
        entry_id=f"led_{uuid.uuid4().hex[:16]}",
        session_id=session_id,
        timestamp=event["timestamp"],
        entry_type="session",
        event=event,
        taint=final_taint.to_dict(),
        result={"status": status},
    )
    return append_ledger_entry(entry, ledger_path)


def record_approval(
    ledger_path: Path,
    decision_id: str,
    status: str,
    approver: str | None = None,
    reason: str | None = None,
) -> ApprovalEvidence:
    entries, _warnings = load_ledger_entries(ledger_path)
    target_decision: dict[str, Any] | None = None
    for entry in entries:
        if entry.decision and entry.decision.get("decision_id") == decision_id:
            target_decision = dict(entry.decision)
            break
    if target_decision is None:
        raise ValueError(f"decision not found: {decision_id}")
    now = utc_now()
    approval = ApprovalEvidence(
        approval_id=f"appr_{uuid.uuid4().hex[:16]}",
        decision_id=decision_id,
        event_id=str(target_decision.get("event_id")),
        session_id=str(target_decision.get("session_id")),
        status=status,
        requested_at=str(target_decision.get("timestamp", now)),
        resolved_at=now,
        approver=approver,
        reason=reason,
    )
    entry = LedgerEntry(
        sequence=0,
        entry_id=f"led_{uuid.uuid4().hex[:16]}",
        session_id=approval.session_id,
        timestamp=now,
        entry_type="approval",
        approval=approval.to_dict(),
        result={"approval_status": status},
    )
    append_ledger_entry(entry, ledger_path)
    return approval


def record_action(
    event: RuntimeEvent | ActionEvent,
    ledger_path: Path,
    result: dict[str, Any] | None = None,
    review_mode: str = "auto",
    policy_mode: str = "advisory",
    reviewer: str = "heuristic",
    policy_profile: str | None = None,
    policy_profile_config: dict[str, Any] | None = None,
) -> tuple[ActionEvent, Any, TaintState]:
    entries, _warnings = load_ledger_entries(ledger_path)
    session_id = _event_session_id(event) or _session_id_from_entries(entries)
    previous_taint = _taint_from_entries(entries, session_id)
    if isinstance(event, ActionEvent):
        action = event
        event_for_analysis = _runtime_event_from_action(action)
    else:
        action = normalize_action_event(event, session_id, _next_action_sequence(entries))
        event_for_analysis = event
    findings = analyze_runtime_event(event_for_analysis)
    action.taint_tags = _taint_tags(action, findings, previous_taint)
    new_taint = updates_taint(action, findings, previous_taint)
    rule_risk = highest_severity(findings)
    reviews = []
    reviewer_failed = False
    if should_review(action, new_taint, rule_risk, review_mode):
        try:
            reviews.append(make_reviewer(reviewer).review(action, new_taint, findings))
        except Exception:
            reviewer_failed = True
    evaluation, decision = merge_policy(
        action,
        findings,
        reviews,
        new_taint,
        policy_mode=policy_mode,
        review_mode=review_mode,
        policy_version=POLICY_VERSION,
        reviewer_failed=reviewer_failed,
        policy_profile=policy_profile,
        policy_profile_config=policy_profile_config,
    )
    approval_status = "not_required" if not decision.requires_approval else "missing"
    entry_result = {"decision_effect": decision.effect, "approval": approval_status, "approval_grade": evaluation.approval_grade}
    if result:
        entry_result.update(result)
    coverage_layer = str(action.metadata.get("coverage_layer") or action.metadata.get("adapter_layer") or "agent_log")
    if "coverage" not in action.metadata:
        action.metadata["coverage"] = default_coverage_for_layer(coverage_layer).to_dict()
    entry = LedgerEntry(
        sequence=0,
        entry_id=f"led_{uuid.uuid4().hex[:16]}",
        session_id=session_id,
        timestamp=utc_now(),
        entry_type="action",
        event=action.to_dict(),
        decision=decision.to_dict(),
        taint=new_taint.to_dict() if new_taint.to_dict() != previous_taint.to_dict() else None,
        findings=[finding.to_dict() for finding in findings],
        result=entry_result,
        reviews=[review.to_dict() for review in reviews],
        evaluation=evaluation.to_dict(),
    )
    append_ledger_entry(entry, ledger_path)
    return action, decision, new_taint



def explain_decision(ledger_path: Path, decision_id: str | None = None, invocation_id: str | None = None) -> dict[str, Any]:
    entries, warnings = load_ledger_entries(ledger_path)
    action_entry = _find_action_entry(entries, decision_id=decision_id, invocation_id=invocation_id)
    if action_entry is None:
        raise ValueError("decision or invocation not found")
    action_decision = dict(action_entry.decision or {})
    action_event = dict(action_entry.event or {})
    related_outcomes = _outcomes_for(entries, action_decision.get("decision_id"), action_event.get("invocation_id") or action_event.get("event_id"))
    related_approvals = [dict(entry.approval) for entry in entries if entry.approval and entry.approval.get("decision_id") == action_decision.get("decision_id")]
    return {
        "ledger": str(ledger_path),
        "warnings": warnings,
        "invocation": action_event,
        "decision": action_decision,
        "evaluation": dict(action_entry.evaluation or {}),
        "reviews": [dict(review) for review in action_entry.reviews],
        "findings": [dict(finding) for finding in action_entry.findings],
        "taint": dict(action_entry.taint or {}),
        "approval_evidence": related_approvals,
        "outcomes": related_outcomes,
    }


def inspect_invocation_review(ledger_path: Path, invocation_id: str, review_id: str | None = None) -> dict[str, Any]:
    entries, warnings = load_ledger_entries(ledger_path)
    action_entry = _find_action_entry(entries, invocation_id=invocation_id)
    if action_entry is None:
        raise ValueError(f"invocation not found: {invocation_id}")
    reviews = [dict(review) for review in action_entry.reviews]
    if review_id:
        reviews = [review for review in reviews if review.get("review_id") == review_id]
        if not reviews:
            raise ValueError(f"review not found: {review_id}")
    return {
        "ledger": str(ledger_path),
        "warnings": warnings,
        "invocation_id": invocation_id,
        "reviews": reviews,
        "evaluation": dict(action_entry.evaluation or {}),
    }


def record_outcome(
    ledger_path: Path,
    status: str,
    decision_id: str | None = None,
    invocation_id: str | None = None,
    actor: str | None = None,
    reason: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> ExecutionOutcome:
    entries, _warnings = load_ledger_entries(ledger_path)
    action_entry = _find_action_entry(entries, decision_id=decision_id, invocation_id=invocation_id)
    if action_entry is None:
        raise ValueError("decision or invocation not found")
    action_event = dict(action_entry.event or {})
    action_decision = dict(action_entry.decision or {})
    resolved_invocation = str(action_event.get("invocation_id") or action_event.get("event_id"))
    resolved_decision = str(action_decision.get("decision_id")) if action_decision.get("decision_id") else None
    outcome = ExecutionOutcome(
        outcome_id=f"out_{uuid.uuid4().hex[:16]}",
        session_id=action_entry.session_id,
        invocation_id=resolved_invocation,
        decision_id=resolved_decision,
        status=status,
        actor=actor,
        reason=reason,
        metadata=dict(metadata or {}),
    )
    entry = LedgerEntry(
        sequence=0,
        entry_id=f"led_{uuid.uuid4().hex[:16]}",
        session_id=outcome.session_id,
        timestamp=outcome.recorded_at,
        entry_type="outcome",
        outcome=outcome.to_dict(),
        result={"outcome_status": status, "decision_id": resolved_decision, "invocation_id": resolved_invocation},
    )
    append_ledger_entry(entry, ledger_path)
    return outcome

def append_event(event: RuntimeEvent, event_log: Path) -> list[Finding]:
    _action, decision, _taint = record_action(event, event_log, review_mode="off", policy_mode="advisory")
    return list(decision.findings)


def analyze_event_payload(payload: dict[str, Any], session_id: str | None = None) -> tuple[RuntimeEvent, list[Finding]]:
    if session_id and "session_id" not in payload:
        payload = dict(payload)
        payload["session_id"] = session_id
    event = RuntimeEvent.from_dict(payload)
    return event, analyze_runtime_event(event)


def run_shell_with_audit(
    command: list[str],
    event_log: Path,
    agent: str | None = None,
    target: str | None = None,
    session_id: str | None = None,
    review_mode: str = "auto",
    policy_mode: str = "advisory",
    reviewer: str = "heuristic",
    policy_profile: str | None = None,
    policy_profile_config: dict[str, Any] | None = None,
) -> int:
    event = RuntimeEvent(type="shell", session_id=session_id, agent=agent, target=target, command=" ".join(command))
    _action, decision, _taint = record_action(event, event_log, review_mode=review_mode, policy_mode=policy_mode, reviewer=reviewer, policy_profile=policy_profile, policy_profile_config=policy_profile_config)
    if decision.effect != "allow":
        record_action(
            RuntimeEvent(
                type="shell_blocked",
                session_id=session_id,
                agent=agent,
                target=target,
                command=" ".join(command),
                metadata={"reason": decision.reason},
            ),
            event_log,
            result={"blocked": True, "decision_effect": decision.effect},
            review_mode=review_mode,
            policy_mode=policy_mode,
            reviewer=reviewer,
            policy_profile=policy_profile,
        )
        return 126
    completed = subprocess.run(command, check=False)
    record_action(
        RuntimeEvent(
            type="shell_exit",
            session_id=session_id,
            agent=agent,
            target=target,
            command=" ".join(command),
            metadata={"exit_code": completed.returncode},
        ),
        event_log,
        result={"exit_code": completed.returncode},
        review_mode=review_mode,
        policy_mode=policy_mode,
        reviewer=reviewer,
        policy_profile=policy_profile,
    )
    return completed.returncode


def normalize_action_event(event: RuntimeEvent, session_id: str, sequence: int) -> ActionEvent:
    content_hash = hashlib.sha256(event.content.encode("utf-8")).hexdigest() if event.content else None
    metadata = dict(event.metadata)
    if event.content is not None and "raw_content" not in metadata:
        metadata["raw_content"] = event.content
    invocation_id = f"inv_{uuid.uuid4().hex[:16]}"
    operation = str(metadata.get("operation", event.type))
    return ActionEvent(
        event_id=invocation_id,
        invocation_id=invocation_id,
        session_id=session_id,
        timestamp=event.timestamp,
        sequence=sequence,
        seq=sequence,
        action_type=event.type,
        operation=operation,
        actor=event.agent or metadata.get("actor"),
        adapter=str(metadata.get("adapter", "manual")),
        target=event.target,
        command=event.command,
        path=event.path,
        url=event.url,
        tool=event.tool,
        skill=event.skill,
        payload_summary=_payload_summary(event),
        metadata=metadata,
        content_hash=content_hash,
        resource_refs=_resource_refs(event),
        source=str(metadata.get("source", "unknown")),
        trust_level=str(metadata.get("trust_level", "unknown")),
        input_refs=[str(item) for item in metadata.get("input_refs", [])] if isinstance(metadata.get("input_refs", []), list) else [],
        output_refs=[str(item) for item in metadata.get("output_refs", [])] if isinstance(metadata.get("output_refs", []), list) else [],
        taint_tags=[str(item) for item in metadata.get("taint_tags", [])] if isinstance(metadata.get("taint_tags", []), list) else [],
        correlation_id=metadata.get("correlation_id"),
        capability_grant_id=metadata.get("capability_grant_id"),
        policy_version=str(metadata.get("policy_version", POLICY_VERSION)),
        evidence_refs=_evidence_refs(event, content_hash),
        control_mode=str(metadata.get("control_mode", "advisory")),
    )


def _taint_tags(action: ActionEvent, findings: list[Finding], previous_taint: TaintState) -> list[str]:
    tags = set(action.taint_tags)
    if previous_taint.is_tainted:
        tags.add("tainted_session")
    for finding in findings:
        if finding.category in {"secrets", "ssh-key", "ssh-config", "cloud-credentials", "cluster-credentials"}:
            tags.add("sensitive_read")
            tags.add("credential")
        if finding.category in {"prompt-injection", "goal-hijack", "hidden-instruction"}:
            tags.add("external_instruction")
        if finding.category == "data-theft":
            tags.add("exfiltration_attempt")
        if finding.category == "network":
            tags.add("outbound")
        if finding.category == "mcp":
            tags.add("mcp_high_risk")
    return sorted(tags)



def _find_action_entry(entries: list[LedgerEntry], decision_id: str | None = None, invocation_id: str | None = None) -> LedgerEntry | None:
    for entry in entries:
        if entry.entry_type != "action":
            continue
        decision = entry.decision or {}
        event = entry.event or {}
        if decision_id and decision.get("decision_id") == decision_id:
            return entry
        if invocation_id and (event.get("invocation_id") == invocation_id or event.get("event_id") == invocation_id):
            return entry
    return None


def _outcomes_for(entries: list[LedgerEntry], decision_id: Any, invocation_id: Any) -> list[dict[str, Any]]:
    outcomes: list[dict[str, Any]] = []
    for entry in entries:
        if not entry.outcome:
            continue
        outcome = dict(entry.outcome)
        if decision_id and outcome.get("decision_id") == decision_id:
            outcomes.append(outcome)
        elif invocation_id and outcome.get("invocation_id") == invocation_id:
            outcomes.append(outcome)
    return outcomes

def _resource_refs(event: RuntimeEvent) -> list[dict[str, str]]:
    refs: list[dict[str, str]] = []
    if event.path:
        refs.append({"kind": "file", "value": event.path})
    if event.url:
        refs.append({"kind": "url", "value": event.url})
    if event.command:
        refs.append({"kind": "command", "value": event.command})
    if event.tool:
        refs.append({"kind": "tool", "value": event.tool})
    if event.skill:
        refs.append({"kind": "skill", "value": event.skill})
    return refs


def _evidence_refs(event: RuntimeEvent, content_hash: str | None) -> list[dict[str, str]]:
    refs: list[dict[str, str]] = []
    if content_hash:
        refs.append({"kind": "content_hash", "sha256": content_hash})
    if event.command:
        refs.append({"kind": "payload_summary", "value": _payload_summary(event) or ""})
    return refs


def _payload_summary(event: RuntimeEvent) -> str | None:
    if event.content is not None:
        digest = hashlib.sha256(event.content.encode("utf-8")).hexdigest()
        return f"content length={len(event.content)} sha256={digest}"
    value = event.command or event.path or event.url or event.tool or event.skill or event.content
    if value is None:
        return None
    compact = " ".join(str(value).split())
    if len(compact) <= 240:
        return compact
    return compact[:237] + "..."


def _runtime_event_from_action(action: ActionEvent) -> RuntimeEvent:
    return RuntimeEvent(
        type=action.action_type,
        timestamp=action.timestamp,
        session_id=action.session_id,
        agent=action.actor,
        target=action.target,
        command=action.command,
        path=action.path,
        url=action.url,
        tool=action.tool,
        skill=action.skill,
        content=None,
        metadata=action.metadata,
    )


def _event_session_id(event: RuntimeEvent | ActionEvent) -> str | None:
    if isinstance(event, ActionEvent):
        return event.session_id
    return event.session_id


def _next_action_sequence(entries: list[LedgerEntry]) -> int:
    actions = [entry for entry in entries if entry.entry_type == "action" and entry.event]
    return len(actions) + 1


def _session_id_from_entries(entries: list[LedgerEntry]) -> str:
    for entry in entries:
        if entry.session_id:
            return entry.session_id
    return default_session_id()


def _taint_from_entries(entries: list[LedgerEntry], session_id: str) -> TaintState:
    taint = TaintState(session_id=session_id)
    for entry in entries:
        if entry.taint:
            taint = TaintState.from_dict(entry.taint)
    return taint


__all__ = [
    "POLICY_VERSION",
    "append_event",
    "analyze_event_payload",
    "close_session",
    "explain_decision",
    "inspect_invocation_review",
    "record_action",
    "record_approval",
    "record_outcome",
    "run_shell_with_audit",
    "start_session",
    "verify_ledger",
]
