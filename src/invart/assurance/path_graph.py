from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from invart.core.artifacts import write_html_artifact, write_json_artifact
from invart.core.ledger import load_ledger_entries
from invart.core.models import utc_now


GRAPH_SCHEMA_VERSION = "invart.execution_graph.v0.20"


def build_execution_graph(ledger_path: Path) -> dict[str, Any]:
    entries, warnings = load_ledger_entries(ledger_path)
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    taint_source_invocations: list[str] = []
    session_id = entries[0].session_id if entries else ""

    def node(node_id: str, kind: str, label: str, **attrs: Any) -> None:
        nodes.setdefault(node_id, {"id": node_id, "kind": kind, "label": label, **attrs})

    def edge(source: str, target: str, kind: str, **attrs: Any) -> None:
        item = {"source": source, "target": target, "kind": kind, **attrs}
        if item not in edges:
            edges.append(item)

    for entry in entries:
        if entry.entry_type == "session" and entry.event:
            event = entry.event
            sid = str(event.get("session_id") or entry.session_id)
            session_id = sid
            node(f"session:{sid}", "session", sid, status=event.get("status"), goal=event.get("goal"))
            if event.get("agent"):
                node(f"agent:{event.get('agent')}", "agent", str(event.get("agent")))
                edge(f"agent:{event.get('agent')}", f"session:{sid}", "runs_session")
        elif entry.entry_type == "identity" and entry.event:
            event = entry.event
            sid = str(event.get("session_id") or entry.session_id or session_id)
            node(f"session:{sid}", "session", sid)
            principal = event.get("principal") if isinstance(event.get("principal"), dict) else {}
            agent = event.get("agent_identity") if isinstance(event.get("agent_identity"), dict) else {}
            if principal.get("principal_id"):
                pid = str(principal["principal_id"])
                node(f"principal:{pid}", "principal", pid, **principal)
                edge(f"principal:{pid}", f"session:{sid}", "created_by")
            if agent.get("agent_id"):
                aid = str(agent["agent_id"])
                node(f"agent:{aid}", "agent", aid, **agent)
                if principal.get("principal_id"):
                    edge(f"principal:{principal['principal_id']}", f"agent:{aid}", "declares_agent")
                edge(f"agent:{aid}", f"session:{sid}", "acts_in")
            for grant in event.get("capability_grants", []) if isinstance(event.get("capability_grants"), list) else []:
                if not isinstance(grant, dict) or not grant.get("grant_id"):
                    continue
                gid = str(grant["grant_id"])
                node(f"grant:{gid}", "grant", gid, **grant)
                if principal.get("principal_id"):
                    edge(f"principal:{principal['principal_id']}", f"grant:{gid}", "issues_grant")
                if agent.get("agent_id"):
                    edge(f"grant:{gid}", f"agent:{agent['agent_id']}", "authorizes")
        elif entry.entry_type == "action" and entry.event:
            action = entry.event
            inv = str(action.get("invocation_id") or action.get("event_id"))
            node(f"invocation:{inv}", "invocation", action.get("payload_summary") or action.get("action_type") or inv, **_compact(action))
            edge(f"session:{entry.session_id}", f"invocation:{inv}", "has_invocation")
            if action.get("capability_grant_id"):
                gid = str(action["capability_grant_id"])
                node(f"grant:{gid}", "grant", gid)
                edge(f"grant:{gid}", f"invocation:{inv}", "uses_grant")
            for resource in _resources(action):
                node(resource["id"], "resource", resource["label"], kind_detail=resource["kind"])
                edge(f"invocation:{inv}", resource["id"], resource["edge_kind"])
            if action.get("taint_tags"):
                node(f"taint:{inv}", "taint", ",".join(str(item) for item in action.get("taint_tags", [])), tags=list(action.get("taint_tags", [])))
                edge(f"invocation:{inv}", f"taint:{inv}", "taints")
            if any(str(tag) == "tainted_session" for tag in action.get("taint_tags", [])):
                for source_inv in taint_source_invocations:
                    edge(f"invocation:{source_inv}", f"invocation:{inv}", "taints")
            if entry.taint and entry.taint.get("is_tainted"):
                for source in entry.taint.get("sources", []):
                    if isinstance(source, dict) and source.get("event_id"):
                        src = str(source["event_id"])
                        if src not in taint_source_invocations:
                            taint_source_invocations.append(src)
            if entry.decision:
                did = str(entry.decision.get("decision_id"))
                node(f"decision:{did}", "decision", str(entry.decision.get("effect")), **entry.decision)
                edge(f"invocation:{inv}", f"decision:{did}", "decided_by")
        elif entry.entry_type == "approval" and entry.approval:
            approval = entry.approval
            aid = str(approval.get("approval_id"))
            node(f"approval:{aid}", "approval", str(approval.get("status")), **approval)
            if approval.get("decision_id"):
                edge(f"decision:{approval['decision_id']}", f"approval:{aid}", "approved_by")
        elif entry.entry_type == "outcome" and entry.outcome:
            outcome = entry.outcome
            oid = str(outcome.get("outcome_id"))
            node(f"outcome:{oid}", "outcome", str(outcome.get("status")), **outcome)
            if outcome.get("invocation_id"):
                edge(f"invocation:{outcome['invocation_id']}", f"outcome:{oid}", "produces")
        elif entry.entry_type in {"teamrun", "handoff"} and entry.event:
            event = entry.event
            if event.get("type") == "handoff":
                source = str(event.get("source_agent"))
                target = str(event.get("target_agent"))
                node(f"agent:{source}", "agent", source)
                node(f"agent:{target}", "agent", target)
                edge(f"agent:{source}", f"agent:{target}", "handoff_to")

    return {
        "schema_version": GRAPH_SCHEMA_VERSION,
        "generated_at": utc_now(),
        "ledger": str(ledger_path),
        "warnings": warnings,
        "nodes": sorted(nodes.values(), key=lambda item: item["id"]),
        "edges": sorted(edges, key=lambda item: (item["source"], item["target"], item["kind"])),
        "summary": {
            "nodes": len(nodes),
            "edges": len(edges),
            "sessions": sum(1 for item in nodes.values() if item["kind"] == "session"),
            "invocations": sum(1 for item in nodes.values() if item["kind"] == "invocation"),
            "taint_nodes": sum(1 for item in nodes.values() if item["kind"] == "taint"),
        },
    }


def query_execution_graph(graph: dict[str, Any], *, target_id: str, direction: str = "upstream") -> dict[str, Any]:
    target = _resolve_node_id(graph, target_id)
    reverse = direction == "upstream"
    adjacency: dict[str, list[dict[str, Any]]] = {}
    for edge in graph.get("edges", []):
        if not isinstance(edge, dict):
            continue
        source = str(edge.get("source"))
        dest = str(edge.get("target"))
        key = dest if reverse else source
        adjacency.setdefault(key, []).append(edge)
    seen = {target}
    queue = [target]
    used_edges: list[dict[str, Any]] = []
    while queue:
        current = queue.pop(0)
        for edge in adjacency.get(current, []):
            nxt = str(edge.get("source") if reverse else edge.get("target"))
            used_edges.append(edge)
            if nxt not in seen:
                seen.add(nxt)
                queue.append(nxt)
    return {
        "schema_version": "invart.execution_graph_query.v0.20",
        "direction": direction,
        "target": target,
        "reachable_node_ids": sorted(_strip_prefix(item) for item in seen),
        "edges": used_edges,
    }


def export_execution_graph_json(ledger_path: Path, output_path: Path) -> dict[str, Any]:
    graph = build_execution_graph(ledger_path)
    write_json_artifact(output_path, graph)
    return {"status": "pass", "output": str(output_path), "summary": graph["summary"]}


def export_execution_graph_html(ledger_path: Path, output_path: Path) -> dict[str, Any]:
    graph = build_execution_graph(ledger_path)
    rows = "".join(
        f"<tr><td>{esc(node['id'])}</td><td>{esc(node['kind'])}</td><td>{esc(node['label'])}</td></tr>"
        for node in graph["nodes"]
    )
    edge_rows = "".join(
        f"<tr><td>{esc(edge['source'])}</td><td>{esc(edge['kind'])}</td><td>{esc(edge['target'])}</td></tr>"
        for edge in graph["edges"]
    )
    doc = f"""<!doctype html><html><head><meta charset='utf-8'><title>Execution Path Graph</title><style>body{{font-family:Inter,Arial,sans-serif;margin:0;background:#f7f8fb;color:#172033}}main{{max-width:1180px;margin:0 auto;padding:32px 24px}}table{{width:100%;border-collapse:collapse;background:white;border:1px solid #dfe5ef;margin:16px 0}}td,th{{border-bottom:1px solid #dfe5ef;padding:8px;text-align:left}}th{{background:#f1f5f9}}pre{{background:#0f172a;color:#e2e8f0;padding:14px;border-radius:8px;overflow:auto}}</style></head><body><main><h1>Execution Path Graph</h1><p>Ledger-derived Agent-BOM-like graph. The ledger remains the source of truth.</p><pre>{esc(json.dumps(graph['summary'], ensure_ascii=False, indent=2))}</pre><h2>Nodes</h2><table><tr><th>ID</th><th>Kind</th><th>Label</th></tr>{rows}</table><h2>Edges</h2><table><tr><th>Source</th><th>Kind</th><th>Target</th></tr>{edge_rows}</table></main></body></html>"""
    write_html_artifact(output_path, doc)
    return {"status": "pass", "output": str(output_path), "summary": graph["summary"]}


def _resources(action: dict[str, Any]) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    action_type = str(action.get("action_type") or action.get("type") or "")
    if action.get("path"):
        result.append({"id": "resource:file:" + str(action["path"]), "kind": "file", "label": str(action["path"]), "edge_kind": "writes" if "write" in action_type or action_type == "delete" else "reads"})
    if action.get("url"):
        result.append({"id": "resource:url:" + str(action["url"]), "kind": "url", "label": str(action["url"]), "edge_kind": "egresses_to"})
    if action.get("command"):
        result.append({"id": "resource:command:" + str(action["command"]), "kind": "command", "label": str(action["command"]), "edge_kind": "executes"})
    if action.get("tool"):
        result.append({"id": "resource:tool:" + str(action["tool"]), "kind": "tool", "label": str(action["tool"]), "edge_kind": "calls_tool"})
    if action.get("skill"):
        result.append({"id": "resource:skill:" + str(action["skill"]), "kind": "skill", "label": str(action["skill"]), "edge_kind": "loads_skill"})
    return result


def _compact(payload: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in payload.items() if key in {"action_type", "seq", "source", "trust_level", "capability_grant_id"}}


def _resolve_node_id(graph: dict[str, Any], target_id: str) -> str:
    node_ids = {str(item.get("id")) for item in graph.get("nodes", []) if isinstance(item, dict)}
    if target_id in node_ids:
        return target_id
    for prefix in ("invocation:", "decision:", "approval:", "outcome:", "resource:file:", "resource:url:"):
        candidate = prefix + target_id
        if candidate in node_ids:
            return candidate
    return target_id


def _strip_prefix(node_id: str) -> str:
    return node_id.split(":", 1)[1] if ":" in node_id else node_id


def esc(value: Any) -> str:
    return html.escape("" if value is None else str(value))


__all__ = [
    "build_execution_graph",
    "export_execution_graph_html",
    "export_execution_graph_json",
    "query_execution_graph",
]
