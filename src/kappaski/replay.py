from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from .gate import verify_gate
from .postruntime import export_proof_report
from .models import utc_now


def export_replay_html(ledger_path: Path, output_path: Path, *, gate_mode: str = "managed", case_path: Path | None = None, include_raw: bool = True) -> dict[str, Any]:
    proof = export_proof_report(ledger_path)
    gate = verify_gate(ledger_path=ledger_path, mode=gate_mode)
    case = _load_case(case_path)
    html_doc = _render(proof, gate, case, include_raw=include_raw)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html_doc, encoding="utf-8")
    return {
        "replay": str(output_path),
        "ledger": str(ledger_path),
        "gate_status": gate.get("status"),
        "actions": proof.get("summary", {}).get("total_actions"),
        "capability_grants": proof.get("summary", {}).get("capability_grants"),
        "case": case.get("instance_id") if case else None,
    }


def _load_case(case_path: Path | None) -> dict[str, Any]:
    if not case_path or not case_path.exists():
        return {}
    payload = json.loads(case_path.read_text(encoding="utf-8"))
    if isinstance(payload, dict) and payload.get("cases"):
        return dict(payload["cases"][0])
    return dict(payload) if isinstance(payload, dict) else {}


def _render(proof: dict[str, Any], gate: dict[str, Any], case: dict[str, Any], *, include_raw: bool) -> str:
    session = proof.get("session", {})
    summary = proof.get("summary", {})
    actions = proof.get("actions", [])
    approvals = proof.get("approval_evidence", [])
    decisions = {str(item.get("event_id")): item for item in proof.get("policy_decisions", []) if isinstance(item, dict)}
    rows = []
    for action in actions:
        event_id = str(action.get("event_id") or action.get("invocation_id"))
        decision = decisions.get(event_id, {})
        metadata = action.get("metadata") if isinstance(action.get("metadata"), dict) else {}
        coverage = metadata.get("coverage") if isinstance(metadata.get("coverage"), dict) else {}
        coverage_grade = coverage.get("coverage_grade") if isinstance(coverage.get("coverage_grade"), dict) else {}
        observed_by = ", ".join(str(item) for item in coverage.get("observed_by", []))
        enforced_by = ", ".join(str(item) for item in coverage.get("enforced_by", []))
        runtime_observation = coverage_grade.get("runtime_observation") or coverage.get("runtime_observation")
        runtime_enforcement = coverage_grade.get("runtime_enforcement") or coverage.get("runtime_enforcement")
        summary_value = action.get("payload_summary") or action.get("command") or action.get("path") or action.get("url") or action.get("skill") or action.get("tool")
        rows.append(f"<tr><td>{esc(action.get('seq') or action.get('sequence'))}</td><td>{esc(action.get('action_type') or action.get('type'))}</td><td>{esc(decision.get('risk'))}</td><td>{esc(decision.get('effect'))}</td><td>{esc(runtime_observation)}</td><td>{esc(runtime_enforcement)}</td><td>{esc(observed_by)}</td><td>{esc(enforced_by)}</td><td>{esc(summary_value)}</td></tr>")
    raw_block = ""
    if include_raw:
        raw_block = f"<section><h2>Raw Proof</h2><details><summary>Show raw proof JSON</summary><pre>{esc(json.dumps(proof, ensure_ascii=False, indent=2))}</pre></details></section>"
    case_block = ""
    if case:
        case_block = f"<section><h2>Real Case Context</h2><div class='cards'><div><b>{esc(case.get('instance_id'))}</b><p>{esc(case.get('repo'))}</p><p>{esc(case.get('problem_statement'))}</p></div></div></section>"
    approval_rows = "".join(f"<tr><td>{esc(item.get('decision_id'))}</td><td>{esc(item.get('status'))}</td><td>{esc(item.get('approver'))}</td><td>{esc(item.get('reason'))}</td></tr>" for item in approvals)
    return f"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Kappaski Replay</title><style>body{{font:14px/1.55 -apple-system,BlinkMacSystemFont,Segoe UI,Arial,sans-serif;margin:0;background:#f6f8fb;color:#172033}}header{{background:#0f172a;color:white;padding:32px 40px}}main{{max-width:1180px;margin:0 auto;padding:28px 22px}}section{{background:white;border:1px solid #dfe5ef;border-radius:12px;padding:18px;margin:16px 0}}table{{width:100%;border-collapse:collapse}}td,th{{border-bottom:1px solid #e5e7eb;padding:8px;text-align:left;vertical-align:top}}th{{background:#f1f5f9}}pre{{white-space:pre-wrap;background:#0f172a;color:#e2e8f0;padding:14px;border-radius:10px;overflow:auto}}.pill{{display:inline-block;border-radius:999px;padding:3px 8px;background:#e0ecff;color:#1d4ed8;font-weight:650}}.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px}}</style></head><body><header><span class='pill'>Kappaski Replay</span><h1>Runtime Replay Report</h1><p>Generated {esc(utc_now())}</p></header><main><section><h2>Session</h2><div class='cards'><div><b>Session</b><p>{esc(session.get('session_id'))}</p></div><div><b>Agent</b><p>{esc(session.get('agent'))}</p></div><div><b>Goal</b><p>{esc(session.get('goal'))}</p></div><div><b>Gate</b><p>{esc(gate.get('status'))}</p></div></div></section>{case_block}<section><h2>Summary</h2><pre>{esc(json.dumps(summary, ensure_ascii=False, indent=2))}</pre></section><section><h2>Coverage</h2><pre>{esc(json.dumps(proof.get('coverage', {}), ensure_ascii=False, indent=2))}</pre></section><section><h2>Timeline</h2><table><tr><th>Seq</th><th>Action</th><th>Risk</th><th>Effect</th><th>Observed</th><th>Enforced</th><th>Observed By</th><th>Enforced By</th><th>Summary</th></tr>{''.join(rows)}</table></section><section><h2>Approvals</h2><table><tr><th>Decision</th><th>Status</th><th>Approver</th><th>Reason</th></tr>{approval_rows}</table></section><section><h2>Gate Findings</h2><pre>{esc(json.dumps(gate.get('findings', []), ensure_ascii=False, indent=2))}</pre></section>{raw_block}</main></body></html>"""


def esc(value: Any) -> str:
    return html.escape("" if value is None else str(value))


__all__ = ["export_replay_html"]
