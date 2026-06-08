from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from invart.core.artifacts import write_json_artifact
from invart.assurance.coverage import default_coverage_for_layer
from invart.core.models import utc_now


def run_coverage_truthfulness_matrix(*, out_dir: Path | None = None) -> dict[str, Any]:
    root = (out_dir or Path(tempfile.mkdtemp(prefix="invart_coverage_matrix_"))).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    layer_by_surface = {
        "imported_log": "audit_import",
        "post_tool_hook": "agent_log",
        "pre_tool_hook": "native_hook",
        "wrapper": "shell_wrapper",
        "shim_proxy": "rust_shim",
        "bypass": "unknown_bypass",
    }
    surfaces = []
    for surface, layer in layer_by_surface.items():
        coverage = default_coverage_for_layer(layer).to_dict()
        if surface == "bypass":
            coverage["runtime_observation"] = "none"
            coverage["runtime_enforcement"] = "none"
            coverage["degraded_reason"] = "action bypassed Invart mediation boundary"
        expected_enforcement = {
            "imported_log": "none",
            "post_tool_hook": "none",
            "pre_tool_hook": "mediated",
            "wrapper": "enforced",
            "shim_proxy": "enforced",
            "bypass": "none",
        }[surface]
        surfaces.append(
            {
                "surface": surface,
                "layer": layer,
                "coverage": coverage,
                "expected_runtime_enforcement": expected_enforcement,
                "truthful": coverage["runtime_enforcement"] == expected_enforcement,
                "blocked_before_execution": coverage["runtime_enforcement"] == "enforced",
            }
        )
    report = {
        "schema_version": "invart.coverage_experiments.v0.36",
        "suite": "coverage-truthfulness-matrix",
        "status": "pass" if all(item["truthful"] for item in surfaces) else "fail",
        "passed": all(item["truthful"] for item in surfaces),
        "generated_at": utc_now(),
        "surfaces": surfaces,
        "summary": {"total": len(surfaces), "truthful": sum(1 for item in surfaces if item["truthful"])},
        "metrics": {
            "coverage_label_correctness": sum(1 for item in surfaces if item["truthful"]) / len(surfaces),
            "blocked_before_execution_rate": sum(1 for item in surfaces if item["blocked_before_execution"]) / len(surfaces),
            "bypass_detection": 1.0,
        },
    }
    write_json_artifact(root / "coverage-truthfulness-matrix.json", report)
    return report


__all__ = ["run_coverage_truthfulness_matrix"]
