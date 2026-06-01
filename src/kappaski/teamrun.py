from __future__ import annotations

import json
import html
import uuid
from pathlib import Path
from typing import Any

from .artifacts import write_html_artifact, write_json_artifact
from .ledger import append_ledger_entry, load_ledger_entries, verify_ledger
from .models import LedgerEntry, utc_now


def create_teamrun(name: str, users: list[str], agents: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
        "schema_version": "kappaski.teamrun.v0.12",
        "teamrun_id": "tr_" + uuid.uuid4().hex[:16],
        "name": name,
        "users": users,
        "agents": agents or [],
        "created_at": utc_now(),
    }


def declare_agent_identity(agent_id: str, declared_by: str, adapter_facts: dict[str, Any] | None = None) -> dict[str, Any]:
    adapter_facts = dict(adapter_facts or {})
    inconsistent = bool(adapter_facts.get("agent_id") and adapter_facts.get("agent_id") != agent_id)
    return {
        "schema_version": "kappaski.agent_identity.v0.12",
        "agent_id": agent_id,
        "declared_by": declared_by,
        "adapter_facts": adapter_facts,
        "consistent": not inconsistent,
        "warnings": ["declared agent identity differs from adapter/session facts"] if inconsistent else [],
    }


def create_handoff(source_agent: str, target_agent: str, resource_refs: list[dict[str, str]], *, taint_mode: str = "resource-reference", session_tainted: bool = False) -> dict[str, Any]:
    if taint_mode not in {"resource-reference", "session-wide"}:
        raise ValueError("taint_mode must be resource-reference or session-wide")
    inherited = session_tainted if taint_mode == "session-wide" else any(ref.get("tainted") == "true" for ref in resource_refs)
    return {
        "schema_version": "kappaski.handoff.v0.12",
        "handoff_id": "ho_" + uuid.uuid4().hex[:16],
        "source_agent": source_agent,
        "target_agent": target_agent,
        "resource_refs": resource_refs,
        "taint_inheritance": {"mode": taint_mode, "inherited": inherited},
        "created_at": utc_now(),
    }


def create_blackboard_entry(teamrun: str, author: str, content: str, resource_refs: list[str] | None = None) -> dict[str, Any]:
    return {
        "schema_version": "kappaski.blackboard.v0.12",
        "blackboard_id": "bb_" + uuid.uuid4().hex[:16],
        "teamrun": teamrun,
        "author": author,
        "content": content,
        "resource_refs": resource_refs or [],
        "created_at": utc_now(),
    }


def delegate_grant(source_agent: str, target_agent: str, parent_scope: str, delegate_scope: str) -> dict[str, Any]:
    parent = _scope_set(parent_scope)
    delegate = _scope_set(delegate_scope)
    allowed = delegate.issubset(parent)
    if not allowed:
        raise ValueError("delegated grant must be restrict-only")
    return {
        "schema_version": "kappaski.grant_delegation.v0.12",
        "grant_delegation_id": "gd_" + uuid.uuid4().hex[:16],
        "source_agent": source_agent,
        "target_agent": target_agent,
        "parent_scope": sorted(parent),
        "delegate_scope": sorted(delegate),
        "restrict_only": True,
        "created_at": utc_now(),
    }


def append_teamrun_fact(ledger_path: Path, entry_type: str, payload: dict[str, Any]) -> dict[str, Any]:
    session_id = _session_id_from_ledger(ledger_path)
    entry = LedgerEntry(
        sequence=0,
        entry_id="led_" + uuid.uuid4().hex[:16],
        session_id=session_id,
        timestamp=utc_now(),
        entry_type=entry_type,
        event={"type": entry_type, **payload},
        result=payload,
    )
    appended = append_ledger_entry(entry, ledger_path)
    return {"record": payload, "entry": appended.to_dict()}


def export_teamrun_proof(ledger_path: Path, output_path: Path | None = None) -> dict[str, Any]:
    entries, warnings = load_ledger_entries(ledger_path)
    facts = {
        "teamruns": [entry.result for entry in entries if entry.entry_type == "teamrun" and entry.result],
        "agent_identities": [entry.result for entry in entries if entry.entry_type == "agent_identity" and entry.result],
        "blackboard_entries": [entry.result for entry in entries if entry.entry_type == "blackboard" and entry.result],
        "handoffs": [entry.result for entry in entries if entry.entry_type == "handoff" and entry.result],
        "grant_delegations": [entry.result for entry in entries if entry.entry_type == "grant_delegation" and entry.result],
    }
    proof = {
        "schema_version": "kappaski.teamrun_proof.v0.12",
        "generated_at": utc_now(),
        "ledger": str(ledger_path),
        "warnings": warnings,
        "summary": {
            "teamruns": len(facts["teamruns"]),
            "agent_identities": len(facts["agent_identities"]),
            "blackboard_entries": len(facts["blackboard_entries"]),
            "handoffs": len(facts["handoffs"]),
            "grant_delegations": len(facts["grant_delegations"]),
        },
        "facts": facts,
    }
    if output_path:
        write_json_artifact(output_path, proof)
    return proof


def export_teamrun_aggregate(ledger_paths: list[Path], output_path: Path | None = None) -> dict[str, Any]:
    proofs = [export_teamrun_proof(path) for path in ledger_paths]
    aggregate_facts = {
        "teamruns": [],
        "agent_identities": [],
        "blackboard_entries": [],
        "handoffs": [],
        "grant_delegations": [],
    }
    verification = []
    warnings: list[str] = []
    for path, proof in zip(ledger_paths, proofs):
        verified = verify_ledger(path)
        verification.append({"ledger": str(path), "valid": bool(verified.get("valid")), "warnings": verified.get("warnings", [])})
        warnings.extend(str(item) for item in proof.get("warnings", []))
        facts = proof.get("facts", {}) if isinstance(proof.get("facts"), dict) else {}
        for key in aggregate_facts:
            aggregate_facts[key].extend(dict(item, ledger=str(path)) for item in facts.get(key, []) if isinstance(item, dict))
    aggregate = {
        "schema_version": "kappaski.teamrun_aggregate.v0.12",
        "generated_at": utc_now(),
        "ledgers": [str(path) for path in ledger_paths],
        "ledger_verification": verification,
        "warnings": warnings,
        "summary": {
            "ledgers": len(ledger_paths),
            "valid_ledgers": sum(1 for item in verification if item.get("valid")),
            "teamruns": len(aggregate_facts["teamruns"]),
            "agent_identities": len(aggregate_facts["agent_identities"]),
            "blackboard_entries": len(aggregate_facts["blackboard_entries"]),
            "handoffs": len(aggregate_facts["handoffs"]),
            "grant_delegations": len(aggregate_facts["grant_delegations"]),
        },
        "facts": aggregate_facts,
    }
    if output_path:
        write_json_artifact(output_path, aggregate)
    return aggregate


def export_teamrun_timeline_html(ledger_paths: list[Path], output_path: Path) -> dict[str, Any]:
    aggregate = export_teamrun_aggregate(ledger_paths)
    rows: list[dict[str, Any]] = []
    for fact_type, items in aggregate.get("facts", {}).items():
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            rows.append(
                {
                    "timestamp": str(item.get("created_at") or item.get("reviewed_at") or ""),
                    "type": fact_type[:-1] if fact_type.endswith("s") else fact_type,
                    "ledger": str(item.get("ledger", "")),
                    "actor": str(item.get("author") or item.get("source_agent") or item.get("declared_by") or ""),
                    "summary": _timeline_summary(fact_type, item),
                }
            )
    rows.sort(key=lambda item: item["timestamp"])
    html_rows = "\n".join(
        "<tr>"
        f"<td>{html.escape(row['timestamp'])}</td>"
        f"<td>{html.escape(row['type'])}</td>"
        f"<td>{html.escape(row['actor'])}</td>"
        f"<td>{html.escape(row['summary'])}</td>"
        f"<td><code>{html.escape(row['ledger'])}</code></td>"
        "</tr>"
        for row in rows
    )
    document = f"""<!doctype html><html><head><meta charset="utf-8"><title>TeamRun Timeline</title><style>
body{{font-family:Inter,Arial,sans-serif;margin:0;background:#f7f7f4;color:#1f2933}}.wrap{{max-width:1100px;margin:0 auto;padding:40px 24px}}table{{width:100%;border-collapse:collapse;background:#fff;border:1px solid #ddd8cc}}td,th{{border-bottom:1px solid #e6e0d4;padding:10px;text-align:left;vertical-align:top}}code{{background:#17202a;color:#eef4f8;padding:2px 5px;border-radius:4px}}</style></head><body><main class="wrap"><h1>TeamRun Timeline</h1><p>Multi-ledger TeamRun, handoff, blackboard, identity, and grant facts.</p><table><tr><th>Time</th><th>Type</th><th>Actor</th><th>Summary</th><th>Ledger</th></tr>{html_rows}</table></main></body></html>"""
    write_html_artifact(output_path, document)
    return {
        "schema_version": "kappaski.teamrun_timeline.v0.12",
        "status": "pass",
        "output": str(output_path),
        "summary": {"ledgers": len(ledger_paths), "events": len(rows)},
    }


def _timeline_summary(fact_type: str, item: dict[str, Any]) -> str:
    if fact_type == "teamruns":
        return f"TeamRun {item.get('name')} users={','.join(str(user) for user in item.get('users', []))}"
    if fact_type == "handoffs":
        return f"handoff {item.get('source_agent')} -> {item.get('target_agent')}"
    if fact_type == "blackboard_entries":
        return str(item.get("content", ""))
    if fact_type == "agent_identities":
        return f"identity {item.get('agent_id')} consistent={item.get('consistent')}"
    if fact_type == "grant_delegations":
        return f"grant {item.get('source_agent')} -> {item.get('target_agent')}"
    return json.dumps(item, ensure_ascii=False, sort_keys=True)[:240]


def _scope_set(value: str) -> set[str]:
    return {item.strip() for item in value.split(",") if item.strip()}


def _session_id_from_ledger(ledger_path: Path) -> str:
    entries, _warnings = load_ledger_entries(ledger_path)
    for entry in entries:
        if entry.session_id:
            return entry.session_id
    return "teamrun"
