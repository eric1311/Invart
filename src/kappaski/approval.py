from __future__ import annotations

from pathlib import Path
from typing import Any

from .ledger import load_ledger_entries
from .runtime import record_approval


def list_approval_items(ledger_path: Path, status: str | None = None) -> dict[str, Any]:
    entries, warnings = load_ledger_entries(ledger_path)
    explicit = {str(entry.approval.get("decision_id")): dict(entry.approval) for entry in entries if entry.approval}
    items: list[dict[str, Any]] = []
    for entry in entries:
        if entry.entry_type != "action" or not entry.decision:
            continue
        decision = dict(entry.decision)
        event = dict(entry.event or {})
        evaluation = dict(entry.evaluation or {})
        approval = explicit.get(str(decision.get("decision_id")))
        approval_status = "not_required"
        if approval:
            approval_status = str(approval.get("status", "unknown"))
        elif decision.get("effect") == "deny":
            approval_status = "blocked"
        elif decision.get("requires_approval"):
            approval_status = "missing"
        if status and approval_status != status:
            continue
        metadata = event.get("metadata", {}) if isinstance(event.get("metadata"), dict) else {}
        surface = metadata.get("capability_surface", {}) if isinstance(metadata.get("capability_surface"), dict) else {}
        items.append({
            "decision_id": decision.get("decision_id"),
            "invocation_id": event.get("invocation_id") or event.get("event_id"),
            "action_type": event.get("action_type") or event.get("type"),
            "risk": decision.get("risk"),
            "effect": decision.get("effect"),
            "reason": decision.get("reason"),
            "approval_status": approval_status,
            "approval": approval,
            "capability_source_id": surface.get("source_id"),
            "capability_kind": surface.get("kind"),
            "recommended_next_action": _next_action(approval_status),
            "resource_refs": event.get("resource_refs", []),
        })
    return {
        "ledger": str(ledger_path),
        "warnings": warnings,
        "summary": _summary(items),
        "approvals": items,
    }


def approve_items(ledger_path: Path, *, decision_id: str | None = None, all_missing: bool = False, approver: str | None = None, reason: str | None = None, status: str = "approved") -> dict[str, Any]:
    if all_missing and not reason:
        raise ValueError("--all approval requires a reason")
    if not all_missing and not decision_id:
        raise ValueError("approval requires --decision or --all")
    inbox = list_approval_items(ledger_path, status="missing" if all_missing else None)
    targets = []
    if all_missing:
        targets = [item for item in inbox["approvals"] if item["approval_status"] == "missing"]
    else:
        targets = [item for item in inbox["approvals"] if item["decision_id"] == decision_id]
    if not targets:
        raise ValueError("no matching approval decisions found")
    records = []
    for item in targets:
        records.append(record_approval(ledger_path, str(item["decision_id"]), status, approver=approver, reason=reason).to_dict())
    return {
        "ledger": str(ledger_path),
        "status": status,
        "resolved": len(records),
        "approvals": records,
    }


def _next_action(status: str) -> str:
    if status == "missing":
        return "approve_or_reject"
    if status == "blocked":
        return "inspect_blocked_policy"
    if status == "rejected":
        return "do_not_execute"
    return "none"


def _summary(items: list[dict[str, Any]]) -> dict[str, Any]:
    by_status: dict[str, int] = {}
    by_risk: dict[str, int] = {}
    for item in items:
        by_status[str(item.get("approval_status"))] = by_status.get(str(item.get("approval_status")), 0) + 1
        by_risk[str(item.get("risk"))] = by_risk.get(str(item.get("risk")), 0) + 1
    return {"total": len(items), "by_status": by_status, "by_risk": by_risk}


__all__ = ["list_approval_items", "approve_items"]
