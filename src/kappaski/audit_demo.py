from __future__ import annotations

import html
import json
import uuid
from pathlib import Path
from typing import Any

from .ledger import append_ledger_entry
from .models import LedgerEntry, utc_now
from .gate import verify_gate
from .models import RuntimeEvent
from .postruntime import export_proof_report
from .replay import export_replay_html
from .runtime import close_session, record_action, start_session
from .claude_adapter import run_claude_code_adapter


def run_enterprise_audit_demo(out_dir: Path) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    ledger = out_dir / "ledger.jsonl"
    proof_path = out_dir / "proof.json"
    replay_path = out_dir / "replay.html"
    audit_json_path = out_dir / "audit-report.json"
    audit_html_path = out_dir / "audit-report.html"

    session = start_session(
        out_dir,
        ledger,
        agent="multi-agent-demo",
        goal="Enterprise runtime audit demo: secret leak and unsafe deletion",
        session_id="ks_v014_enterprise_audit",
        create_preflight=False,
    )

    events = [
        RuntimeEvent(
            type="file_read",
            session_id=session.session_id,
            path="/repo/.env",
            metadata={"scenario": "secret_leak", "resource": "credential_file"},
        ),
        RuntimeEvent(
            type="content",
            session_id=session.session_id,
            content="Agent prepared deployment note containing OPENAI_API_KEY=sk-demo-secret-value before posting externally.",
            metadata={
                "scenario": "secret_leak",
                "raw_content": "OPENAI_API_KEY=sk-demo-secret-value\nTARGET=https://external.example/upload",
                "raw_content_note": "folded demo credential evidence; synthetic but shaped like a real secret leak case",
            },
        ),
        RuntimeEvent(
            type="network",
            session_id=session.session_id,
            url="https://external.example/upload",
            metadata={"scenario": "secret_leak", "method": "POST"},
        ),
        RuntimeEvent(
            type="shell",
            session_id=session.session_id,
            command="rm -rf .",
            metadata={"scenario": "unsafe_deletion", "resource": "workspace"},
        ),
    ]
    for event in events:
        record_action(event, ledger, review_mode="off", policy_mode="managed", policy_profile="strict")

    close_session(ledger)
    proof = export_proof_report(ledger, proof_path)
    gate = verify_gate(ledger_path=ledger, proof_path=proof_path, mode="managed")
    replay = export_replay_html(ledger, replay_path, gate_mode="managed", include_raw=True)
    audit = build_enterprise_audit_report(proof, gate, replay, ledger, proof_path, replay_path)
    audit_json_path.write_text(json.dumps(audit, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    audit_html_path.write_text(render_enterprise_audit_html(audit, proof), encoding="utf-8")
    return {
        "schema_version": "kappaski.enterprise_audit_demo.v0.14",
        "ledger": str(ledger),
        "proof": str(proof_path),
        "replay": str(replay_path),
        "audit_json": str(audit_json_path),
        "audit_report": str(audit_html_path),
        "summary": audit["summary"],
    }


def run_enterprise_audit_live_adapter_demo(out_dir: Path) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / "workspace"
    target.mkdir(parents=True, exist_ok=True)
    hooks = out_dir / "claude-hooks.jsonl"
    hooks.write_text(
        json.dumps({"type": "file_read", "path": str(target / ".env"), "metadata": {"scenario": "secret_leak", "source": "claude_code_hook", "trust_level": "trusted"}}, ensure_ascii=False) + "\n" +
        json.dumps({"type": "content", "content": "Agent prepared note containing OPENAI_API_KEY=sk-demo-secret-value before external post.", "metadata": {"scenario": "secret_leak", "raw_content": "OPENAI_API_KEY=sk-demo-secret-value\nTARGET=https://external.example/upload", "raw_content_note": "folded demo credential evidence from adapter hook"}}, ensure_ascii=False) + "\n" +
        json.dumps({"type": "network", "url": "https://external.example/upload", "metadata": {"scenario": "secret_leak", "method": "POST", "source": "claude_code_hook"}}, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    blocked_marker = target / "should_not_exist"
    adapter = run_claude_code_adapter(
        target=target,
        command=["sh", "-c", f"touch {blocked_marker}; rm -rf ."],
        hook_events=hooks,
        out_dir=out_dir / "adapter-artifacts",
        session_id="ks_v014_live_adapter_audit",
        create_preflight=False,
        enforcement="file-write",
    )
    ledger = Path(adapter["ledger"])
    proof_path = Path(adapter["proof"])
    replay_path = out_dir / "replay.html"
    audit_json_path = out_dir / "audit-report.json"
    audit_html_path = out_dir / "audit-report.html"
    proof = json.loads(proof_path.read_text(encoding="utf-8"))
    gate = verify_gate(ledger_path=ledger, proof_path=proof_path, mode="managed")
    replay = export_replay_html(ledger, replay_path, gate_mode="managed", include_raw=True)
    audit = build_enterprise_audit_report(proof, gate, replay, ledger, proof_path, replay_path)
    audit["demo_mode"] = "live_adapter_enforced"
    audit["adapter"] = adapter
    audit["summary"]["blocked_before_execution"] = blocked_marker.exists() is False and adapter.get("status") == "blocked"
    audit_json_path.write_text(json.dumps(audit, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    audit_html_path.write_text(render_enterprise_audit_html(audit, proof), encoding="utf-8")
    return {
        "schema_version": "kappaski.enterprise_audit_demo.v0.14",
        "mode": "live_adapter_enforced",
        "ledger": str(ledger),
        "proof": str(proof_path),
        "replay": str(replay_path),
        "audit_json": str(audit_json_path),
        "audit_report": str(audit_html_path),
        "adapter": adapter,
        "summary": audit["summary"],
    }


def build_enterprise_audit_report(
    proof: dict[str, Any],
    gate: dict[str, Any],
    replay: dict[str, Any],
    ledger_path: Path,
    proof_path: Path,
    replay_path: Path,
) -> dict[str, Any]:
    actions = [item for item in proof.get("actions", []) if isinstance(item, dict)]
    decisions = [item for item in proof.get("policy_decisions", []) if isinstance(item, dict)]
    findings = []
    scenarios: set[str] = set()
    for action in actions:
        event = action.get("event", {}) if isinstance(action.get("event"), dict) else action
        metadata = event.get("metadata", {}) if isinstance(event.get("metadata"), dict) else {}
        if metadata.get("scenario"):
            scenarios.add(str(metadata["scenario"]))
    for decision in decisions:
        decision_findings = decision.get("findings", []) if isinstance(decision.get("findings"), list) else []
        for finding in decision_findings:
            if isinstance(finding, dict):
                findings.append(finding)

    critical_or_high = sum(1 for item in findings if item.get("severity") in {"critical", "high"})
    approval_required = sum(1 for item in decisions if item.get("effect") in {"ask", "require_approval"})
    denied = sum(1 for item in decisions if item.get("effect") == "deny")
    return {
        "schema_version": "kappaski.enterprise_audit.v0.14",
        "audience": "enterprise_security_team",
        "risk_scenarios": sorted(scenarios),
        "summary": {
            "total_actions": proof.get("summary", {}).get("total_actions", len(actions)),
            "critical_or_high_findings": critical_or_high,
            "approval_required": approval_required,
            "denied": denied,
            "gate_status": gate.get("status"),
        },
        "artifacts": {
            "ledger": str(ledger_path),
            "proof": str(proof_path),
            "replay": str(replay_path),
            "replay_actions": replay.get("actions"),
        },
        "security_findings": findings,
        "recommended_controls": [
            "Keep deterministic critical rules above LLM reviewer downgrade authority.",
            "Require approval before tainted content can reach external network sinks.",
            "Treat destructive workspace deletion as deny or explicit break-glass only.",
        ],
    }


def render_enterprise_audit_html(audit: dict[str, Any], proof: dict[str, Any]) -> str:
    esc = html.escape
    summary = audit.get("summary", {})
    findings = audit.get("security_findings", [])
    rows = "".join(
        f"<tr><td>{esc(str(item.get('severity', 'unknown')))}</td><td>{esc(str(item.get('rule_id', 'unknown')))}</td><td>{esc(str(item.get('title', '')))}</td><td>{esc(str(item.get('recommendation', '')))}</td></tr>"
        for item in findings
        if isinstance(item, dict)
    )
    controls = "".join(f"<li>{esc(str(item))}</li>" for item in audit.get("recommended_controls", []))
    raw = esc(json.dumps(proof, ensure_ascii=False, indent=2, sort_keys=True))
    scenarios = ", ".join(esc(str(item)) for item in audit.get("risk_scenarios", []))
    return f'''<!doctype html><html><head><meta charset="utf-8"><title>Enterprise Runtime Audit</title><style>body{{font-family:Inter,Arial,sans-serif;margin:0;background:#f7f7f4;color:#1f2933}}.wrap{{max-width:1100px;margin:0 auto;padding:40px 24px}}.section{{background:#fff;border:1px solid #ddd8cc;border-radius:8px;padding:20px;margin:16px 0}}.grid{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}}.metric{{border:1px solid #e6e0d4;border-radius:8px;padding:14px;background:#faf9f5}}.metric b{{font-size:28px;display:block}}table{{width:100%;border-collapse:collapse}}td,th{{border-bottom:1px solid #e6e0d4;padding:10px;text-align:left;vertical-align:top}}pre{{background:#17202a;color:#eef4f8;padding:16px;border-radius:8px;overflow:auto;max-height:420px}}@media(max-width:760px){{.grid{{grid-template-columns:1fr 1fr}}}}</style></head><body><main class="wrap"><h1>Enterprise Runtime Audit</h1><p>Security-team-facing report for the Kappaski v0.14 demo. It demonstrates runtime control-plane coverage for secret leak and unsafe deletion workflows.</p><section class="section"><h2>Executive Summary</h2><div class="grid"><div class="metric"><span>Actions</span><b>{esc(str(summary.get('total_actions')))}</b></div><div class="metric"><span>High/Critical</span><b>{esc(str(summary.get('critical_or_high_findings')))}</b></div><div class="metric"><span>Approvals</span><b>{esc(str(summary.get('approval_required')))}</b></div><div class="metric"><span>Denied</span><b>{esc(str(summary.get('denied')))}</b></div></div><p>Scenarios: {scenarios}</p></section><section class="section"><h2>Security Findings</h2><table><tr><th>Severity</th><th>Rule</th><th>Finding</th><th>Recommendation</th></tr>{rows}</table></section><section class="section"><h2>Controls</h2><ul>{controls}</ul></section><section class="section"><h2>Raw Evidence</h2><details><summary>Show folded proof evidence</summary><pre>{raw}</pre></details></section></main></body></html>'''


def record_audit_signoff(
    ledger_path: Path,
    *,
    actor: str,
    status: str,
    reason: str,
    report_path: Path | None = None,
) -> dict[str, Any]:
    if status not in {"approved", "rejected", "needs_followup"}:
        raise ValueError("audit signoff status must be approved, rejected, or needs_followup")
    if not actor:
        raise ValueError("audit signoff requires actor")
    if not reason:
        raise ValueError("audit signoff requires reason")
    signoff = {
        "schema_version": "kappaski.audit_signoff.v0.14",
        "signoff_id": "aso_" + uuid.uuid4().hex[:16],
        "actor": actor,
        "status": status,
        "reason": reason,
        "report_path": str(report_path) if report_path else None,
        "recorded_at": utc_now(),
    }
    entry = LedgerEntry(
        sequence=0,
        entry_id="led_" + uuid.uuid4().hex[:16],
        session_id=_session_id_from_ledger(ledger_path),
        timestamp=utc_now(),
        entry_type="audit_signoff",
        event={"type": "audit_signoff", **signoff},
        result=signoff,
    )
    appended = append_ledger_entry(entry, ledger_path)
    return {"signoff": signoff, "entry": appended.to_dict()}


def _session_id_from_ledger(ledger_path: Path) -> str:
    from .ledger import load_ledger_entries

    entries, _warnings = load_ledger_entries(ledger_path)
    for entry in entries:
        if entry.session_id:
            return entry.session_id
    return "audit_signoff"


__all__ = [
    "run_enterprise_audit_demo",
    "run_enterprise_audit_live_adapter_demo",
    "build_enterprise_audit_report",
    "render_enterprise_audit_html",
    "record_audit_signoff",
]
