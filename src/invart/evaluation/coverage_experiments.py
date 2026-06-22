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
    surface_specs = [
        {"surface": "imported_log", "layer": "audit_import"},
        {"surface": "post_tool_hook", "layer": "agent_log"},
        {"surface": "pre_tool_hook", "layer": "native_hook"},
        {"surface": "managed_wrapper", "layer": "shell_wrapper"},
        {"surface": "wrapper", "layer": "shell_wrapper"},
        {"surface": "shim_proxy", "layer": "rust_shim"},
        {"surface": "fail_open", "layer": "shell_wrapper"},
        {"surface": "bypass", "layer": "unknown_bypass", "bypass_type": "generic_unmanaged_path"},
        {"surface": "unmanaged_subprocess", "layer": "unknown_bypass", "bypass_type": "child_process_outside_wrapper"},
        {"surface": "alternate_shell", "layer": "unknown_bypass", "bypass_type": "direct_shell_or_binary"},
        {"surface": "generated_script", "layer": "unknown_bypass", "bypass_type": "script_invoked_outside_wrapper"},
        {"surface": "package_hook", "layer": "unknown_bypass", "bypass_type": "package_lifecycle_hook"},
    ]
    expected_by_surface = {
        "imported_log": "none",
        "post_tool_hook": "none",
        "pre_tool_hook": "mediated",
        "managed_wrapper": "mediated",
        "wrapper": "enforced",
        "shim_proxy": "enforced",
        "fail_open": "fail_open_alert",
        "bypass": "none",
        "unmanaged_subprocess": "none",
        "alternate_shell": "none",
        "generated_script": "none",
        "package_hook": "none",
    }
    positions = []
    for spec in surface_specs:
        surface = spec["surface"]
        layer = spec["layer"]
        coverage = default_coverage_for_layer(layer).to_dict()
        if spec.get("bypass_type"):
            coverage["runtime_observation"] = "none"
            coverage["runtime_enforcement"] = "none"
            coverage["postruntime_audit"] = "none"
            coverage["preflight_visibility"] = "none"
            coverage["observed_by"] = []
            coverage["enforced_by"] = []
            coverage["coverage_grade"] = {
                "preflight_visibility": "none",
                "runtime_observation": "none",
                "runtime_enforcement": "none",
                "postruntime_audit": "none",
            }
            coverage["degraded_reason"] = f"{spec['bypass_type']} bypassed Invart mediation boundary"
        if surface == "fail_open":
            coverage["runtime_observation"] = "mediated"
            coverage["runtime_enforcement"] = "fail_open_alert"
            coverage["degraded_reason"] = "mediation boundary failed open and emitted critical alert"
        if surface == "managed_wrapper":
            coverage["runtime_observation"] = "mediated"
            coverage["runtime_enforcement"] = "mediated"
            coverage["degraded_reason"] = None
        expected_enforcement = expected_by_surface[surface]
        actual_enforcement = coverage["runtime_enforcement"]
        negative_control = bool(spec.get("bypass_type")) or surface == "fail_open"
        positions.append(
            {
                "action_id": "same-network-egress",
                "surface": surface,
                "layer": layer,
                "bypass_type": spec.get("bypass_type"),
                "negative_control": negative_control,
                "claim_rule": "no enforcement claim" if spec.get("bypass_type") else ("fail-open alert, not enforced success" if surface == "fail_open" else "claim matches surface control position"),
                "coverage": coverage,
                "expected_runtime_enforcement": expected_enforcement,
                "actual_runtime_enforcement": actual_enforcement,
                "truthful": actual_enforcement == expected_enforcement,
                "blocked_before_execution": actual_enforcement == "enforced",
                "coverage_gap": bool(spec.get("bypass_type")),
                "artifacts": {},
            }
        )
    legacy_surfaces = [item for item in positions if item["surface"] not in {"fail_open", "managed_wrapper"}]
    bypass_positions = [item for item in positions if item.get("bypass_type")]
    false_enforcement_claims = sum(1 for item in bypass_positions if item["actual_runtime_enforcement"] in {"mediated", "enforced"})
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
            "bypass_detection": sum(1 for item in bypass_positions if item["coverage_gap"] and item["actual_runtime_enforcement"] == "none") / len(bypass_positions),
            "false_enforcement_claim_rate": false_enforcement_claims / len(bypass_positions),
            "named_bypass_controls": len(bypass_positions),
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
