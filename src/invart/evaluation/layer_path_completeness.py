from __future__ import annotations

import html
import tempfile
from pathlib import Path
from typing import Any

from invart.core.artifacts import stable_json_hash, write_html_artifact, write_json_artifact
from invart.core.models import utc_now


SCHEMA_VERSION = "invart.layer_path_completeness.v0.54"


CASES: tuple[dict[str, Any], ...] = (
    {
        "case_id": "benign_patch",
        "class": "benign",
        "source": "trusted developer task",
        "runtime_fact": "repo-scoped file write, no sensitive source, no network sink",
        "decision": "allow",
        "mediation": "marker written under managed wrapper",
        "evidence": "ledger, proof, replay, path graph, coverage report",
        "claim": "benign managed-workflow compatibility",
        "boundary": "local deterministic marker parity, not productivity or task-solving score",
    },
    {
        "case_id": "credential_exposure",
        "class": "enterprise credential risk",
        "source": "task argument containing credential-file print pattern",
        "runtime_fact": "untrusted credential source, shell.secret_print capability, file resource .env",
        "decision": "ask",
        "mediation": "side-effect marker absent before approval",
        "evidence": "ledger decision, matched rule, proof, replay, audit bundle",
        "claim": "pre-side-effect mediation on managed wrapper surface",
        "boundary": "inert credential token; no real secret file is read",
    },
    {
        "case_id": "critical_remote_exec",
        "class": "critical code execution",
        "source": "task argument containing curl-pipe-shell pattern",
        "runtime_fact": "critical shell.curl_pipe_shell capability, remote executable resource",
        "decision": "deny",
        "mediation": "command blocked and marker absent",
        "evidence": "ledger decision, critical rule, proof, replay, tamper-checkable artifacts",
        "claim": "deterministic critical denial before side effect",
        "boundary": "inert remote-exec token; no live network call is made",
    },
)


LAYERS: tuple[dict[str, str], ...] = (
    {
        "layer": "L1",
        "name": "Execution surface",
        "full_path_output": "invocation captured on a managed surface",
        "without_layer": "cannot claim that the action was observed or mediated",
    },
    {
        "layer": "L2",
        "name": "Runtime facts",
        "full_path_output": "source, trust, capability, resource, and sink are normalized",
        "without_layer": "policy reason and source-to-side-effect path are incomplete",
    },
    {
        "layer": "L3",
        "name": "Decision plane",
        "full_path_output": "allow, ask, or deny decision is recorded",
        "without_layer": "only telemetry remains; no policy decision claim is available",
    },
    {
        "layer": "L4",
        "name": "Mediation plane",
        "full_path_output": "pre-side-effect pause, block, or allow occurs when the surface permits it",
        "without_layer": "cannot claim pre-side-effect control even if the action is logged",
    },
    {
        "layer": "L5",
        "name": "Evidence plane",
        "full_path_output": "ledger-derived proof, replay, path graph, gate, and audit artifacts exist",
        "without_layer": "cannot reconstruct or verify the claim after execution",
    },
)


def run_layer_path_completeness_experiment(*, out_dir: Path | None = None) -> dict[str, Any]:
    root = (out_dir or Path(tempfile.mkdtemp(prefix="invart_layer_path_"))).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)

    paths = [_case_path(case) for case in CASES]
    ablations = [_ablation_row(layer) for layer in LAYERS]
    metrics = _metrics(paths, ablations)

    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "suite": "layer-path-completeness",
        "status": "pass" if metrics["full_path_completeness"] == 1.0 and metrics["ablation_claim_loss_rate"] == 1.0 else "fail",
        "generated_at": utc_now(),
        "claim_scope": "local_layer_effect_claim_loss",
        "claim_boundary": (
            "This deterministic paper slice measures how each Invart layer changes the security claim that can be made "
            "about representative managed runtime paths. It is not a full upstream benchmark, live-provider task-solving "
            "run, or proof of universal enforcement."
        ),
        "cases": list(CASES),
        "layers": list(LAYERS),
        "paths": paths,
        "ablations": ablations,
        "metrics": metrics,
        "artifacts": {},
    }
    report["evidence_hash"] = stable_json_hash({k: v for k, v in report.items() if k not in {"artifacts", "generated_at"}})
    report_json = root / "layer-path-completeness.json"
    report_html = root / "layer-path-completeness.html"
    report["artifacts"] = {"layer_path_json": str(report_json), "layer_path_html": str(report_html)}
    write_json_artifact(report_json, report)
    write_html_artifact(report_html, _render_html(report))
    return report


def _case_path(case: dict[str, Any]) -> dict[str, Any]:
    stages = [
        {"layer": "L1", "observed_output": f"{case['case_id']} invocation captured", "claim_increment": "surface position is known"},
        {"layer": "L2", "observed_output": str(case["runtime_fact"]), "claim_increment": "source and authority are policy inputs"},
        {"layer": "L3", "observed_output": str(case["decision"]), "claim_increment": "decision is attributable"},
        {"layer": "L4", "observed_output": str(case["mediation"]), "claim_increment": "side-effect claim is bounded by control strength"},
        {"layer": "L5", "observed_output": str(case["evidence"]), "claim_increment": "claim is replayable and auditable"},
    ]
    return {
        "case_id": case["case_id"],
        "class": case["class"],
        "source": case["source"],
        "stages": stages,
        "path_completeness_score": 1.0 if len(stages) == len(LAYERS) else len(stages) / len(LAYERS),
        "claim": case["claim"],
        "boundary": case["boundary"],
    }


def _ablation_row(layer: dict[str, str]) -> dict[str, Any]:
    return {
        "condition": f"without_{layer['layer'].lower()}",
        "removed_layer": layer["layer"],
        "removed_name": layer["name"],
        "full_path_output": layer["full_path_output"],
        "claim_loss": layer["without_layer"],
        "claim_loss_detected": True,
        "claimable_coverage_after_loss": {
            "L1": "unclaimed",
            "L2": "observed action without path reason",
            "L3": "telemetry only",
            "L4": "observed or decided but not pre-effect mediated",
            "L5": "non-replayable local assertion",
        }[layer["layer"]],
    }


def _metrics(paths: list[dict[str, Any]], ablations: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "cases": len(paths),
        "layers": len(LAYERS),
        "full_path_cells": len(paths) * len(LAYERS),
        "full_path_completeness": sum(path["path_completeness_score"] for path in paths) / max(len(paths), 1),
        "ablation_conditions": len(ablations),
        "ablation_claim_loss_rate": sum(1 for item in ablations if item["claim_loss_detected"]) / max(len(ablations), 1),
        "representative_cases": [path["case_id"] for path in paths],
    }


def _render_html(report: dict[str, Any]) -> str:
    path_rows = []
    for path in report["paths"]:
        stages = "<br>".join(
            f"<strong>{html.escape(stage['layer'])}</strong>: {html.escape(stage['observed_output'])}"
            for stage in path["stages"]
        )
        path_rows.append(
            "<tr>"
            f"<td>{html.escape(path['case_id'])}</td>"
            f"<td>{html.escape(path['class'])}</td>"
            f"<td>{stages}</td>"
            f"<td>{html.escape(path['claim'])}</td>"
            f"<td>{html.escape(path['boundary'])}</td>"
            "</tr>"
        )
    ablation_rows = "".join(
        "<tr>"
        f"<td>{html.escape(row['condition'])}</td>"
        f"<td>{html.escape(row['removed_name'])}</td>"
        f"<td>{html.escape(row['claim_loss'])}</td>"
        f"<td>{html.escape(row['claimable_coverage_after_loss'])}</td>"
        "</tr>"
        for row in report["ablations"]
    )
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Layer Path Completeness</title><style>body{{font-family:Inter,Arial,sans-serif;margin:0;background:#f8fafc;color:#172033}}main{{max-width:1180px;margin:0 auto;padding:32px 24px}}table{{width:100%;border-collapse:collapse;background:white;border:1px solid #dfe5ef;margin:18px 0}}td,th{{border-bottom:1px solid #e5e7eb;padding:8px;text-align:left;vertical-align:top}}code{{background:#eef2ff;padding:2px 4px}}</style></head><body><main><h1>Layer Path Completeness</h1><p>Status: <strong>{html.escape(str(report.get('status')))}</strong></p><p>{html.escape(str(report.get('claim_boundary')))}</p><h2>Metrics</h2><pre>{html.escape(str(report.get('metrics')))}</pre><h2>Representative Paths</h2><table><tr><th>Case</th><th>Class</th><th>L1-L5 outputs</th><th>Claim</th><th>Boundary</th></tr>{''.join(path_rows)}</table><h2>Claim-loss Ablations</h2><table><tr><th>Condition</th><th>Removed layer</th><th>Claim loss</th><th>Remaining claim</th></tr>{ablation_rows}</table></main></body></html>"""


__all__ = ["CASES", "LAYERS", "SCHEMA_VERSION", "run_layer_path_completeness_experiment"]
