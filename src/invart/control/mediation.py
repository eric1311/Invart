from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from invart.assurance.coverage import CoverageRecord, default_coverage_for_layer
from invart.core.ledger import append_ledger_entry, load_ledger_entries
from invart.core.models import LedgerEntry, RuntimeEvent, utc_now
from invart.control.runtime import record_action, record_approval, record_outcome
from invart.control.rules import analyze_runtime_event


MEDIATION_SCHEMA_VERSION = "invart.mediation.v0.22"


@dataclass(frozen=True)
class MediationRequest:
    mediation_id: str
    session_id: str
    surface: str
    event: dict[str, Any]
    mode: str
    requested_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class MediationDecision:
    mediation_id: str
    effect: str
    risk: str
    reason: str
    coverage: dict[str, Any]
    decided_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class MediationOutcome:
    mediation_id: str
    status: str
    recorded_at: str = field(default_factory=utc_now)
    actor: str | None = None
    reason: str | None = None
    invocation_id: str | None = None
    decision_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def mediate_event(
    ledger_path: Path,
    *,
    session_id: str,
    surface: str,
    event: dict[str, Any],
    mode: str = "managed",
    simulate_failure: bool = False,
) -> dict[str, Any]:
    mediation_id = "med_" + uuid.uuid4().hex[:16]
    payload = dict(event)
    metadata = dict(payload.get("metadata") or {})
    metadata["mediation_id"] = mediation_id
    metadata["mediation_surface"] = surface
    metadata["coverage"] = _coverage_for(surface, simulate_failure=simulate_failure).to_dict()
    payload["metadata"] = metadata
    payload.setdefault("session_id", session_id)
    request = MediationRequest(mediation_id=mediation_id, session_id=session_id, surface=surface, event=payload, mode=mode)
    effect, risk, reason = _decide(payload, mode=mode, simulate_failure=simulate_failure)
    decision = MediationDecision(mediation_id=mediation_id, effect=effect, risk=risk, reason=reason, coverage=metadata["coverage"])
    runtime_event = RuntimeEvent.from_dict(payload)
    action, policy_decision, _taint = record_action(runtime_event, ledger_path, review_mode="off", policy_mode="managed" if mode == "managed" else "advisory")
    status = _outcome_status(effect)
    outcome = MediationOutcome(
        mediation_id=mediation_id,
        status=status,
        invocation_id=action.invocation_id,
        decision_id=policy_decision.decision_id,
        reason=reason,
    )
    if status in {"blocked", "fail_open_alert"}:
        record_outcome(
            ledger_path,
            "blocked" if status == "blocked" else "failed",
            decision_id=policy_decision.decision_id,
            invocation_id=action.invocation_id,
            actor="invart-mediation",
            reason=reason,
            metadata={"mediation_id": mediation_id, "mediation_status": status},
        )
    _append_mediation_entry(ledger_path, session_id=session_id, request=request, decision=decision, outcome=outcome)
    return {"schema_version": MEDIATION_SCHEMA_VERSION, "request": request.to_dict(), "decision": decision.to_dict(), "outcome": outcome.to_dict()}


def resolve_mediation(ledger_path: Path, *, mediation_id: str, actor: str, status: str, reason: str) -> dict[str, Any]:
    if status not in {"approved", "rejected"}:
        raise ValueError("mediation resolution status must be approved or rejected")
    entries, _warnings = load_ledger_entries(ledger_path)
    record = _find_mediation(entries, mediation_id)
    if not record:
        raise ValueError(f"mediation not found: {mediation_id}")
    outcome_payload = record["outcome"]
    decision_id = outcome_payload.get("decision_id")
    if decision_id:
        record_approval(ledger_path, str(decision_id), status, approver=actor, reason=reason)
    resolved = MediationOutcome(
        mediation_id=mediation_id,
        status="resumed" if status == "approved" else "blocked",
        actor=actor,
        reason=reason,
        invocation_id=outcome_payload.get("invocation_id"),
        decision_id=decision_id,
    )
    entry = LedgerEntry(
        sequence=0,
        entry_id="led_" + uuid.uuid4().hex[:16],
        session_id=str(record.get("session_id") or ""),
        timestamp=resolved.recorded_at,
        entry_type="mediation",
        event={"type": "mediation_resolution", "schema_version": MEDIATION_SCHEMA_VERSION, "mediation_id": mediation_id},
        result={"request": record["request"], "decision": record["decision"], "outcome": resolved.to_dict()},
    )
    append_ledger_entry(entry, ledger_path)
    return {"schema_version": MEDIATION_SCHEMA_VERSION, "outcome": resolved.to_dict()}


def replay_mediation(ledger_path: Path) -> dict[str, Any]:
    entries, warnings = load_ledger_entries(ledger_path)
    events = []
    summary: dict[str, int] = {}
    for entry in entries:
        if entry.entry_type != "mediation" or not isinstance(entry.result, dict):
            continue
        outcome = entry.result.get("outcome") if isinstance(entry.result.get("outcome"), dict) else {}
        status = str(outcome.get("status", "unknown"))
        summary[status] = summary.get(status, 0) + 1
        events.append({"sequence": entry.sequence, "request": entry.result.get("request"), "decision": entry.result.get("decision"), "outcome": outcome})
    return {"schema_version": "invart.mediation_replay.v0.22", "ledger": str(ledger_path), "warnings": warnings, "summary": summary, "events": events}


def _append_mediation_entry(
    ledger_path: Path,
    *,
    session_id: str,
    request: MediationRequest,
    decision: MediationDecision,
    outcome: MediationOutcome,
) -> None:
    entry = LedgerEntry(
        sequence=0,
        entry_id="led_" + uuid.uuid4().hex[:16],
        session_id=session_id,
        timestamp=outcome.recorded_at,
        entry_type="mediation",
        event={"type": "mediation", "schema_version": MEDIATION_SCHEMA_VERSION, "mediation_id": request.mediation_id},
        result={"request": request.to_dict(), "decision": decision.to_dict(), "outcome": outcome.to_dict()},
    )
    append_ledger_entry(entry, ledger_path)


def _decide(event: dict[str, Any], *, mode: str, simulate_failure: bool) -> tuple[str, str, str]:
    if simulate_failure:
        return "fail_open_alert", "critical", "mediation surface failed; fail-open critical alert recorded"
    findings = analyze_runtime_event(RuntimeEvent.from_dict(event))
    if any(item.severity == "critical" for item in findings):
        return "deny", "critical", "deterministic critical finding denied"
    if event.get("metadata", {}).get("tainted") or any(item.severity == "high" for item in findings):
        return "require_approval", "high", "high-risk or tainted action paused for approval"
    if mode == "audit":
        return "audit", "low", "audit mode recorded action without interruption"
    return "allow", "low", "low-risk action allowed"


def _outcome_status(effect: str) -> str:
    if effect == "require_approval":
        return "paused"
    if effect == "deny":
        return "blocked"
    if effect == "fail_open_alert":
        return "fail_open_alert"
    if effect == "audit":
        return "audit"
    return "allowed"


def _coverage_for(surface: str, *, simulate_failure: bool) -> CoverageRecord:
    if simulate_failure:
        return CoverageRecord(runtime_observation="observed", postruntime_audit="observed", observed_by=[surface], degraded_reason="mediation surface failed open")
    layer = {
        "command": "shell_wrapper",
        "file": "rust_shim",
        "file-write": "rust_shim",
        "network": "native_hook",
        "env": "native_hook",
        "mcp": "mcp_broker",
        "native_hook": "native_hook",
        "wrapper": "shell_wrapper",
    }.get(surface, "agent_log")
    return default_coverage_for_layer(layer)


def _find_mediation(entries: list[LedgerEntry], mediation_id: str) -> dict[str, Any] | None:
    for entry in entries:
        if entry.entry_type != "mediation" or not isinstance(entry.result, dict):
            continue
        decision = entry.result.get("decision") if isinstance(entry.result.get("decision"), dict) else {}
        if decision.get("mediation_id") == mediation_id:
            return {"session_id": entry.session_id, **entry.result}
    return None


__all__ = ["mediate_event", "replay_mediation", "resolve_mediation", "MediationRequest", "MediationDecision", "MediationOutcome"]
