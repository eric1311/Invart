from __future__ import annotations

import html
from pathlib import Path
from typing import Any

from invart.assurance.evidence_bundle import export_evidence_bundle
from invart.core.artifacts import relative_href, write_html_artifact, write_json_artifact
from invart.core.ledger import load_ledger_entries
from invart.core.models import LedgerEntry, utc_now


SCHEMA_VERSION = "invart.layer_runtime_workflow.v0.9.6"
LAYERS = (
    ("L1", "Execution Surface"),
    ("L2", "Runtime Fact Model"),
    ("L3", "Decision Plane"),
    ("L4", "Mediation Plane"),
    ("L5", "Evidence Plane"),
)
STAGES = ("before-runtime", "during-runtime", "after-runtime")


def export_layer_runtime_workflow(ledger_path: Path, out_dir: Path, *, profile: dict[str, Any] | None = None) -> dict[str, Any]:
    ledger_path = ledger_path.expanduser().resolve()
    out_dir = out_dir.expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    entries, warnings = load_ledger_entries(ledger_path)
    bundle = export_evidence_bundle(ledger_path, out_dir / "evidence", profile=profile or {"name": "layer-runtime-workflow", "mode": "managed"})
    artifacts = {
        **bundle["artifacts"],
        "evidence_manifest": bundle["manifest_path"],
        "workflow_json": str(out_dir / "layer-runtime-workflow.json"),
        "workflow_html": str(out_dir / "layer-runtime-workflow.html"),
    }
    matrix = _runtime_effect_matrix(artifacts)
    timeline = _layer_timeline(entries, artifacts)
    operations = _operation_guide(artifacts)
    report = {
        "schema_version": SCHEMA_VERSION,
        "status": "pass",
        "generated_at": utc_now(),
        "ledger": str(ledger_path),
        "warnings": warnings,
        "runtime_effect_matrix": matrix,
        "layer_timeline": timeline,
        "operations": operations,
        "artifacts": artifacts,
        "summary": {
            "entries": len(entries),
            "actions": sum(1 for entry in entries if entry.entry_type == "action"),
            "decisions": sum(1 for entry in entries if entry.decision),
            "outcomes": sum(1 for entry in entries if entry.outcome),
            "layers": len(LAYERS),
            "stages": len(STAGES),
        },
        "claim_boundary": "Layer workflow is derived from the ledger and generated artifacts; it does not add facts outside the ledger fact source.",
    }
    write_json_artifact(Path(artifacts["workflow_json"]), report)
    write_html_artifact(Path(artifacts["workflow_html"]), _render_workflow_html(report))
    return report


def _runtime_effect_matrix(artifacts: dict[str, str]) -> list[dict[str, Any]]:
    rows = {
        ("before-runtime", "L1"): ("Execution Surface", "Identify launchers, hooks, wrapper, MCP, skill, command, file, and network surfaces.", artifacts["path_graph_html"]),
        ("before-runtime", "L2"): ("Runtime Fact Model", "Confirm the ledger path, session facts, identity/grant facts, resources, and credential boundary.", artifacts["ledger"]),
        ("before-runtime", "L3"): ("Decision Plane", "Inspect policy profile and path-aware rules before interpreting actions.", artifacts["path_policy"]),
        ("before-runtime", "L4"): ("Mediation Plane", "Check whether the run was only observed, mediated, or enforced before side effects.", artifacts["coverage"]),
        ("before-runtime", "L5"): ("Evidence Plane", "Record the evidence bundle manifest and hash contract.", artifacts["evidence_manifest"]),
        ("during-runtime", "L1"): ("Execution Surface", "Map each action to its surface: shell, file, network, tool, skill, MCP, hook, or wrapper.", artifacts["path_graph_json"]),
        ("during-runtime", "L2"): ("Runtime Fact Model", "Read invocations, taint state, resources, decisions, approvals, and outcomes as ledger entries.", artifacts["proof"]),
        ("during-runtime", "L3"): ("Decision Plane", "Explain why policy allowed, requested approval, denied, or marked a path critical.", artifacts["path_policy"]),
        ("during-runtime", "L4"): ("Mediation Plane", "Inspect allow/audit/paused/blocked/enforced/fail-open outcomes without mixing coverage grades.", artifacts["replay"]),
        ("during-runtime", "L5"): ("Evidence Plane", "Use replay and coverage artifacts to show what Invart observed or controlled during execution.", artifacts["coverage"]),
        ("after-runtime", "L1"): ("Execution Surface", "Review uncovered or degraded execution surfaces as follow-up control gaps.", artifacts["coverage"]),
        ("after-runtime", "L2"): ("Runtime Fact Model", "Keep the ledger as the fact source for reconstruction and dispute resolution.", artifacts["ledger"]),
        ("after-runtime", "L3"): ("Decision Plane", "Use path graph and policy report to explain why the run was safe, paused, or blocked.", artifacts["path_graph_html"]),
        ("after-runtime", "L4"): ("Mediation Plane", "Verify approvals, outcomes, and gate findings after the run.", artifacts["audit_json"]),
        ("after-runtime", "L5"): ("Evidence Plane", "Share the portable proof, audit report, and manifest with reviewers.", artifacts["audit_html"]),
    }
    return [
        {
            "stage": stage,
            "layer": layer,
            "layer_name": layer_name,
            "effect": effect,
            "artifact": artifact,
        }
        for stage in STAGES
        for layer, _label in LAYERS
        for layer_name, effect, artifact in [rows[(stage, layer)]]
    ]


def _layer_timeline(entries: list[LedgerEntry], artifacts: dict[str, str]) -> list[dict[str, Any]]:
    actions = [entry for entry in entries if entry.entry_type == "action"]
    decisions = [entry for entry in entries if entry.decision]
    approvals = [entry for entry in entries if entry.entry_type == "approval"]
    outcomes = [entry for entry in entries if entry.outcome]
    sessions = [entry for entry in entries if entry.entry_type == "session"]
    first_action = _first_action_summary(actions)
    return [
        {
            "stage": "before-runtime",
            "layer": "L1",
            "layer_name": "Execution Surface",
            "operator_question": "Which runtime surface will the agent use?",
            "invart_observation": f"{len(actions)} action surface(s) are reconstructable from the ledger.",
            "artifact": artifacts["path_graph_html"],
        },
        {
            "stage": "during-runtime",
            "layer": "L2",
            "layer_name": "Runtime Fact Model",
            "operator_question": "What happened, and what resource did it touch?",
            "invart_observation": first_action,
            "artifact": artifacts["proof"],
        },
        {
            "stage": "during-runtime",
            "layer": "L3",
            "layer_name": "Decision Plane",
            "operator_question": "Why was it allowed, paused, or blocked?",
            "invart_observation": f"{len(decisions)} decision record(s) and {len(approvals)} approval record(s) are available.",
            "artifact": artifacts["path_policy"],
        },
        {
            "stage": "during-runtime",
            "layer": "L4",
            "layer_name": "Mediation Plane",
            "operator_question": "Did Invart only observe, mediate, or enforce?",
            "invart_observation": f"{len(outcomes)} outcome record(s) exist; coverage report preserves observed/mediated/enforced distinctions.",
            "artifact": artifacts["coverage"],
        },
        {
            "stage": "after-runtime",
            "layer": "L5",
            "layer_name": "Evidence Plane",
            "operator_question": "What should a reviewer open after the run?",
            "invart_observation": f"{len(sessions)} session boundary record(s) plus proof, replay, graph, audit, and manifest are exported.",
            "artifact": artifacts["audit_html"],
        },
    ]


def _operation_guide(artifacts: dict[str, str]) -> list[dict[str, str]]:
    return [
        {"layer": "L1", "command": "invart pre-runtime --target . --save", "artifact": artifacts["path_graph_html"], "purpose": "Inventory surfaces before runtime."},
        {"layer": "L2", "command": "invart runtime record-event --ledger ledger.jsonl --event '{...}'", "artifact": artifacts["ledger"], "purpose": "Persist normalized runtime facts."},
        {"layer": "L3", "command": "invart policy check-path --ledger ledger.jsonl --out path-policy.json", "artifact": artifacts["path_policy"], "purpose": "Explain path-aware policy decisions."},
        {"layer": "L4", "command": "invart mediation inspect --ledger ledger.jsonl", "artifact": artifacts["replay"], "purpose": "Inspect mediation outcomes and approval state."},
        {"layer": "L5", "command": "invart runtime layers --ledger ledger.jsonl --out-dir .invart/layers", "artifact": artifacts["evidence_manifest"], "purpose": "Export reviewable evidence package."},
    ]


def _first_action_summary(actions: list[LedgerEntry]) -> str:
    if not actions:
        return "No action entries were found; only session/evidence boundaries can be reported."
    event = actions[0].event or {}
    touched = event.get("command") or event.get("path") or event.get("url") or event.get("tool") or event.get("skill") or event.get("action_type")
    return f"First action {event.get('invocation_id') or event.get('event_id')} touched {touched}."


def _render_workflow_html(report: dict[str, Any]) -> str:
    base = Path(report["artifacts"]["workflow_html"]).parent
    matrix_rows = _render_matrix_rows(report["runtime_effect_matrix"], base)
    timeline_rows = "".join(
        "<tr>"
        f"<td>{html.escape(item['layer'])} {html.escape(item['layer_name'])}</td>"
        f"<td>{html.escape(item['stage'])}</td>"
        f"<td>{html.escape(item['operator_question'])}</td>"
        f"<td>{html.escape(item['invart_observation'])}</td>"
        f"<td><a href=\"{relative_href(base, Path(item['artifact']))}\">{html.escape(Path(item['artifact']).name)}</a></td>"
        "</tr>"
        for item in report["layer_timeline"]
    )
    operation_rows = "".join(
        "<tr>"
        f"<td>{html.escape(item['layer'])}</td>"
        f"<td><code>{html.escape(item['command'])}</code></td>"
        f"<td>{html.escape(item['purpose'])}</td>"
        f"<td><a href=\"{relative_href(base, Path(item['artifact']))}\">{html.escape(Path(item['artifact']).name)}</a></td>"
        "</tr>"
        for item in report["operations"]
    )
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Invart Layer Runtime Workflow</title><style>body{{font-family:Inter,Arial,sans-serif;margin:0;background:#f7f8fb;color:#172033}}header{{background:#0f172a;color:white;padding:36px 44px}}main{{max-width:1180px;margin:0 auto;padding:28px 24px}}section{{background:white;border:1px solid #dfe5ef;border-radius:8px;padding:18px;margin:16px 0}}table{{width:100%;border-collapse:collapse}}th,td{{border-bottom:1px solid #e5e7eb;padding:9px;text-align:left;vertical-align:top}}code{{background:#eef2f7;padding:2px 5px;border-radius:5px}}a{{color:#2563eb;text-decoration:none}}</style></head><body><header><h1>Invart Layer Runtime Workflow</h1><p>Runtime operation view for before-runtime, during-runtime, after-runtime across L1-L5.</p></header><main><section><h2>Runtime Effect Matrix</h2><p>Observed, mediated, and enforced are not interchangeable.</p><table><tr><th>Layer</th><th>Before runtime</th><th>During runtime</th><th>After runtime</th></tr>{matrix_rows}</table></section><section><h2>Layer Timeline</h2><table><tr><th>Layer</th><th>Stage</th><th>Question</th><th>Invart observation</th><th>Artifact</th></tr>{timeline_rows}</table></section><section><h2>Operator Commands</h2><table><tr><th>Layer</th><th>Command</th><th>Purpose</th><th>Artifact</th></tr>{operation_rows}</table></section><section><h2>Claim Boundary</h2><p>{html.escape(report['claim_boundary'])}</p></section></main></body></html>"""


def _render_matrix_rows(matrix: list[dict[str, Any]], base: Path) -> str:
    by_layer: dict[str, dict[str, dict[str, Any]]] = {}
    for item in matrix:
        by_layer.setdefault(item["layer"], {})[item["stage"]] = item
    rows = []
    for layer, layer_name in LAYERS:
        cells = []
        for stage in STAGES:
            item = by_layer[layer][stage]
            cells.append(
                f"<td>{html.escape(item['effect'])}<br><a href=\"{relative_href(base, Path(item['artifact']))}\">{html.escape(Path(item['artifact']).name)}</a></td>"
            )
        rows.append(f"<tr><th>{html.escape(layer)} {html.escape(layer_name)}</th>{''.join(cells)}</tr>")
    return "".join(rows)


__all__ = ["export_layer_runtime_workflow"]
