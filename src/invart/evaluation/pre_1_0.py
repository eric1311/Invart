from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from invart.core.artifacts import relative_href, write_html_artifact, write_json_artifact
from invart.surfaces.native import native_capability_matrix, unmanaged_agent_inventory
from invart.evaluation.pre_v1 import run_pre_v1_control_plane_demo
from invart.evaluation.real_world_cases import run_real_world_risk_demo


SCHEMA_VERSION = "invart.pre_1_0_final_demo.v0.45"


def run_pre_1_0_final_demo(out_dir: Path, *, external_evidence_manifest: Path | None = None) -> dict[str, Any]:
    out_dir = out_dir.expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    surface_root = out_dir / "agent-surfaces"
    _write_demo_surfaces(surface_root)
    matrix = native_capability_matrix(surface_root)
    unmanaged = unmanaged_agent_inventory(surface_root)
    matrix_path = out_dir / "vendor-matrix.json"
    unmanaged_path = out_dir / "unmanaged-inventory.json"
    write_json_artifact(matrix_path, matrix)
    write_json_artifact(unmanaged_path, unmanaged)
    risk_demo = run_real_world_risk_demo(out_dir / "real-world-risk-demo")
    pre_v1_demo = run_pre_v1_control_plane_demo(out_dir / "pre-v1-demo")
    external = _external_status(external_evidence_manifest)
    entrypoint = out_dir / "pre-1.0-final-demo.html"
    runtime_effect_matrix = _runtime_effect_matrix(
        entrypoint=entrypoint,
        vendor_matrix=matrix_path,
        unmanaged_inventory=unmanaged_path,
        risk_demo=risk_demo,
        pre_v1_demo=pre_v1_demo,
        external=external,
    )
    report = {
        "schema_version": SCHEMA_VERSION,
        "status": "pass",
        "artifacts": {
            "entrypoint": str(entrypoint),
            "vendor_matrix": str(matrix_path),
            "unmanaged_inventory": str(unmanaged_path),
            "real_world_demo": risk_demo,
            "pre_v1_demo": pre_v1_demo,
            "external_evidence": external,
        },
        "runtime_effect_matrix": runtime_effect_matrix,
        "summary": {
            "vendor_agents": matrix["summary"]["agents"],
            "unmanaged_findings": unmanaged["summary"]["findings"],
            "external_validation": external["status"],
        },
        "claim_boundary": "Pre-1.0 final demo links local product artifacts and optional external evidence status; it does not claim external validation unless a valid manifest is attached.",
    }
    write_html_artifact(entrypoint, _render_final_demo_html(report))
    return report


def _runtime_effect_matrix(
    *,
    entrypoint: Path,
    vendor_matrix: Path,
    unmanaged_inventory: Path,
    risk_demo: dict[str, Any],
    pre_v1_demo: dict[str, Any],
    external: dict[str, Any],
) -> list[dict[str, Any]]:
    pre_v1_artifacts = pre_v1_demo["artifacts"]
    risk_entry = Path(risk_demo["artifacts"]["html"])
    rows = [
        ("before-runtime", "L1", "Execution Surface", "Agent config, skills, MCP, wrappers, launchers, and unmanaged surfaces are discovered.", vendor_matrix),
        ("before-runtime", "L2", "Runtime Fact Model", "Session identity, principal, credential boundary, and grants are prepared as ledger facts.", pre_v1_artifacts["ledger"]),
        ("before-runtime", "L3", "Decision Plane", "Policy profile and deterministic critical boundaries are visible before action.", pre_v1_artifacts["path_policy"]),
        ("before-runtime", "L4", "Mediation Plane", "Managed launch path distinguishes covered and weakly covered surfaces before execution.", unmanaged_inventory),
        ("before-runtime", "L5", "Evidence Plane", "The demo entrypoint records the claim boundary and artifact map.", entrypoint),
        ("during-runtime", "L1", "Execution Surface", "Agent-like file, network, shell, content, and skill/tool actions enter observed surfaces.", risk_entry),
        ("during-runtime", "L2", "Runtime Fact Model", "Invocations record resource, taint, identity, coverage, and outcome facts.", pre_v1_artifacts["proof"]),
        ("during-runtime", "L3", "Decision Plane", "Path-aware policy reconstructs risky chains such as secret read to network sink.", pre_v1_artifacts["path_policy"]),
        ("during-runtime", "L4", "Mediation Plane", "Actions are allowed, audited, paused, denied, or enforced without conflating coverage levels.", pre_v1_artifacts["replay"]),
        ("during-runtime", "L5", "Evidence Plane", "Coverage and replay show observed / mediated / enforced as separate claims.", pre_v1_artifacts["coverage_report"]),
        ("after-runtime", "L1", "Execution Surface", "Surface inventory remains available for coverage gap review.", vendor_matrix),
        ("after-runtime", "L2", "Runtime Fact Model", "The ledger remains the fact source for all reconstructed actions.", pre_v1_artifacts["ledger"]),
        ("after-runtime", "L3", "Decision Plane", "Path graph explains why a decision was allowed, paused, or blocked.", pre_v1_artifacts["path_graph"]),
        ("after-runtime", "L4", "Mediation Plane", "Gate output shows approval and enforcement gaps without overstating control.", pre_v1_artifacts["proof"]),
        ("after-runtime", "L5", "Evidence Plane", f"Audit and optional external evidence status are reviewable; external status is {external.get('status')}.", pre_v1_artifacts["audit_report"]),
    ]
    return [
        {
            "stage": stage,
            "layer": layer,
            "layer_name": layer_name,
            "effect": effect,
            "artifact": str(artifact),
        }
        for stage, layer, layer_name, effect, artifact in rows
    ]


def _write_demo_surfaces(root: Path) -> None:
    (root / ".claude").mkdir(parents=True, exist_ok=True)
    (root / ".claude" / "settings.json").write_text(json.dumps({"hooks": {"PreToolUse": []}, "mcpServers": {"fs": {}}}), encoding="utf-8")
    (root / ".codex").mkdir(parents=True, exist_ok=True)
    (root / ".codex" / "config.toml").write_text("[hooks]\npre_tool_use = 'invart bridge native --agent codex'\n", encoding="utf-8")
    (root / ".cursor").mkdir(parents=True, exist_ok=True)
    (root / ".cursor" / "mcp.json").write_text(json.dumps({"mcpServers": {"local": {}}}), encoding="utf-8")
    (root / "hermes.json").write_text(json.dumps({"mcp": {"safe_env": True}}), encoding="utf-8")


def _external_status(manifest_path: Path | None) -> dict[str, Any]:
    if not manifest_path:
        return {
            "status": "external_pending",
            "evidence_level": "not_attached",
            "claim_boundary": "No external/live benchmark evidence manifest was attached.",
        }
    from invart.evaluation.external_evidence import verify_external_evidence

    verified = verify_external_evidence(manifest_path)
    return {
        "status": "attached" if verified["status"] == "pass" else "invalid",
        "manifest_path": str(manifest_path),
        "verify": verified,
        "evidence_level": verified.get("evidence_level"),
    }


def _render_final_demo_html(report: dict[str, Any]) -> str:
    base = Path(report["artifacts"]["entrypoint"]).parent
    matrix = relative_href(base, Path(report["artifacts"]["vendor_matrix"]))
    unmanaged = relative_href(base, Path(report["artifacts"]["unmanaged_inventory"]))
    risk_entry = relative_href(base, Path(report["artifacts"]["real_world_demo"]["artifacts"]["html"]))
    pre_v1_artifacts = report["artifacts"]["pre_v1_demo"]["artifacts"]
    pre_v1_audit = relative_href(base, Path(pre_v1_artifacts["audit_report"]))
    pre_v1_replay = relative_href(base, Path(pre_v1_artifacts["replay"]))
    pre_v1_graph = relative_href(base, Path(pre_v1_artifacts["path_graph"]))
    actions = _action_rows(pre_v1_artifacts)
    effect_matrix = _effect_matrix_rows(report["runtime_effect_matrix"], base)
    external = report["artifacts"]["external_evidence"]
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Invart Pre-1.0 Final Demo</title>
  <style>
    body{{font-family:Inter,Arial,sans-serif;margin:0;background:#f7f8fb;color:#172033}}
    header{{background:#0f172a;color:white;padding:42px 48px}}main{{max-width:1120px;margin:0 auto;padding:28px 24px}}
    section{{background:white;border:1px solid #dfe5ef;border-radius:10px;padding:18px;margin:14px 0}}
    table{{width:100%;border-collapse:collapse}}th,td{{border-bottom:1px solid #e5eaf2;padding:9px;text-align:left;vertical-align:top}}
    code{{background:#eef2f7;padding:2px 5px;border-radius:5px}}a{{color:#2563eb;text-decoration:none}}
  </style>
</head>
<body>
<header><h1>Invart Pre-1.0 Final Demo</h1><p>One entrypoint for before-runtime inventory, during-runtime Invart actions, after-runtime audit, and external validation status.</p></header>
<main>
  <section><h2>Entrypoints</h2><ul>
    <li><a href="{matrix}">vendor-matrix.json</a></li>
    <li><a href="{unmanaged}">unmanaged-inventory.json</a></li>
    <li><a href="{risk_entry}">real-world risk demo</a></li>
    <li><a href="{pre_v1_audit}">audit report</a> · <a href="{pre_v1_replay}">replay</a> · <a href="{pre_v1_graph}">path graph</a></li>
  </ul></section>
  <section><h2>Runtime Effect Matrix</h2><p>Before runtime, during runtime, and after runtime are shown against the five control layers. Coverage labels are truthful: observed / mediated / enforced are separate claims.</p><table><tr><th>Layer</th><th>Before runtime</th><th>During runtime</th><th>After runtime</th></tr>{effect_matrix}</table></section>
  <section><h2>Invart actions</h2><table><tr><th>Action</th><th>Evidence</th><th>Meaning</th></tr>{actions}</table></section>
  <section><h2>External validation</h2><p>Status: <code>{html.escape(str(external.get("status")))}</code></p><p>{html.escape(str(external.get("claim_boundary") or external.get("evidence_level") or ""))}</p></section>
  <section><h2>Claim boundary</h2><p>{html.escape(report["claim_boundary"])}</p></section>
</main>
</body>
</html>"""


def _effect_matrix_rows(matrix: list[dict[str, Any]], base: Path) -> str:
    by_layer: dict[str, dict[str, dict[str, Any]]] = {}
    for item in matrix:
        by_layer.setdefault(item["layer"], {})[item["stage"]] = item
    labels = {
        "L1": "L1 Execution Surface",
        "L2": "L2 Runtime Fact Model",
        "L3": "L3 Decision Plane",
        "L4": "L4 Mediation Plane",
        "L5": "L5 Evidence Plane",
    }
    stages = ["before-runtime", "during-runtime", "after-runtime"]
    rows = []
    for layer in ["L1", "L2", "L3", "L4", "L5"]:
        cells = []
        for stage in stages:
            item = by_layer[layer][stage]
            href = relative_href(base, Path(item["artifact"]))
            cells.append(f"<td>{html.escape(item['effect'])}<br><a href=\"{href}\">{html.escape(Path(item['artifact']).name)}</a></td>")
        rows.append(f"<tr><th>{labels[layer]}</th>{''.join(cells)}</tr>")
    return "".join(rows)


def _action_rows(pre_v1_artifacts: dict[str, Any]) -> str:
    rows = [
        ("identity binding", "proof.json", "principal, agent, credential boundary, and grants are visible"),
        ("path policy", "path_graph.json", "secret read to network sink can be reconstructed"),
        ("coverage gate", "coverage.html", "observed, mediated, and enforced states are not conflated"),
        ("audit report", "audit-report.html", "security reviewer can answer who/what/why/outcome"),
    ]
    return "".join(
        f"<tr><td>{html.escape(name)}</td><td><code>{html.escape(evidence)}</code></td><td>{html.escape(meaning)}</td></tr>"
        for name, evidence, meaning in rows
    )
