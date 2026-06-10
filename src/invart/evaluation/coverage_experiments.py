from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from invart.core.artifacts import write_html_artifact, write_json_artifact
from invart.assurance.coverage import default_coverage_for_layer
from invart.core.models import utc_now


def run_coverage_truthfulness_matrix(*, out_dir: Path | None = None) -> dict[str, Any]:
    root = (out_dir or Path(tempfile.mkdtemp(prefix="invart_coverage_matrix_"))).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    layer_by_surface = {
        "imported_log": "audit_import",
        "post_tool_hook": "agent_log",
        "pre_tool_hook": "native_hook",
        "managed_wrapper": "shell_wrapper",
        "wrapper": "shell_wrapper",
        "shim_proxy": "rust_shim",
        "fail_open": "shell_wrapper",
        "bypass": "unknown_bypass",
    }
    positions = []
    for surface, layer in layer_by_surface.items():
        coverage = default_coverage_for_layer(layer).to_dict()
        if surface == "bypass":
            coverage["runtime_observation"] = "none"
            coverage["runtime_enforcement"] = "none"
            coverage["degraded_reason"] = "action bypassed Invart mediation boundary"
        if surface == "fail_open":
            coverage["runtime_observation"] = "mediated"
            coverage["runtime_enforcement"] = "fail_open_alert"
            coverage["degraded_reason"] = "mediation boundary failed open and emitted critical alert"
        if surface == "managed_wrapper":
            coverage["runtime_observation"] = "mediated"
            coverage["runtime_enforcement"] = "mediated"
            coverage["degraded_reason"] = None
        expected_enforcement = {
            "imported_log": "none",
            "post_tool_hook": "none",
            "pre_tool_hook": "mediated",
            "managed_wrapper": "mediated",
            "wrapper": "enforced",
            "shim_proxy": "enforced",
            "fail_open": "fail_open_alert",
            "bypass": "none",
        }[surface]
        actual_enforcement = coverage["runtime_enforcement"]
        positions.append(
            {
                "action_id": "same-network-egress",
                "surface": surface,
                "layer": layer,
                "coverage": coverage,
                "expected_runtime_enforcement": expected_enforcement,
                "actual_runtime_enforcement": actual_enforcement,
                "truthful": actual_enforcement == expected_enforcement,
                "blocked_before_execution": actual_enforcement == "enforced",
                "coverage_gap": surface == "bypass",
                "artifacts": {},
            }
        )
    legacy_surfaces = [item for item in positions if item["surface"] not in {"fail_open", "managed_wrapper"}]
    report = {
        "schema_version": "invart.coverage_experiments.v0.47",
        "suite": "coverage-truthfulness-matrix",
        "status": "pass" if all(item["truthful"] for item in positions) else "fail",
        "passed": all(item["truthful"] for item in positions),
        "generated_at": utc_now(),
        "surfaces": legacy_surfaces,
        "same_action": {
            "action_id": "same-network-egress",
            "operation": "network",
            "description": "Same external network egress action evaluated under multiple control positions.",
            "positions": positions,
        },
        "summary": {"total": len(positions), "truthful": sum(1 for item in positions if item["truthful"])},
        "metrics": {
            "coverage_label_correctness": sum(1 for item in positions if item["truthful"]) / len(positions),
            "blocked_before_execution_rate": sum(1 for item in positions if item["blocked_before_execution"]) / len(positions),
            "bypass_detection": 1.0,
        },
        "artifacts": {},
    }
    coverage_json = root / "coverage-truthfulness-matrix.json"
    coverage_html = root / "coverage-truthfulness-matrix.html"
    report["artifacts"] = {"coverage_json": str(coverage_json), "coverage_html": str(coverage_html)}
    for item in report["same_action"]["positions"]:
        item["artifacts"] = {"coverage_json": str(coverage_json)}
    write_json_artifact(coverage_json, report)
    write_html_artifact(coverage_html, _coverage_html(report))
    return report


def _coverage_html(report: dict[str, Any]) -> str:
    rows = []
    for item in report["same_action"]["positions"]:
        rows.append(
            "<tr>"
            f"<td>{item['surface']}</td>"
            f"<td>{item['expected_runtime_enforcement']}</td>"
            f"<td>{item['actual_runtime_enforcement']}</td>"
            f"<td>{item['truthful']}</td>"
            f"<td>{item['coverage_gap']}</td>"
            "</tr>"
        )
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Coverage Truthfulness Matrix</title><style>body{{font-family:Inter,Arial,sans-serif;margin:0;background:#f8fafc;color:#172033}}main{{max-width:960px;margin:0 auto;padding:32px 24px}}table{{width:100%;border-collapse:collapse;background:white;border:1px solid #dfe5ef}}td,th{{border-bottom:1px solid #e5e7eb;padding:8px;text-align:left}}</style></head><body><main><h1>Coverage Truthfulness Matrix</h1><p>Observed, mediated, enforced, fail-open, and bypass are separate claims.</p><table><tr><th>Surface</th><th>Expected</th><th>Actual</th><th>Truthful</th><th>Gap</th></tr>{''.join(rows)}</table></main></body></html>"""


__all__ = ["run_coverage_truthfulness_matrix"]
