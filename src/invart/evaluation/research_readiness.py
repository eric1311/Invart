from __future__ import annotations

import html
import json
import tempfile
from pathlib import Path
from typing import Any

from invart.core.artifacts import stable_json_hash, write_html_artifact, write_json_artifact
from invart.core.models import utc_now
from invart.evaluation.paper_tables import REQUIRED_TABLE_IDS, validate_paper_table_bundle


SCHEMA_VERSION = "invart.research_readiness.v0.51"


def verify_research_readiness(
    out_dir: Path | None = None,
    *,
    paper_tables: Path | None = None,
    coverage: Path | None = None,
    reviewer: Path | None = None,
    audit: Path | None = None,
    product_matrix: Path | None = None,
    external_evidence: Path | None = None,
    require_external_validation: bool = False,
) -> dict[str, Any]:
    root = (out_dir or Path(tempfile.mkdtemp(prefix="invart_research_ready_"))).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    expected = {
        "paper_tables": paper_tables,
        "coverage": coverage,
        "reviewer": reviewer,
        "audit": audit,
        "product_matrix": product_matrix,
    }
    missing = [name for name, path in expected.items() if path is None or not path.exists()]
    checks: dict[str, Any] = {}
    if paper_tables and paper_tables.exists():
        checks["paper_tables"] = _check_paper_tables(_load_json(paper_tables))
    else:
        checks["paper_tables"] = _missing_check("paper_tables")
    if coverage and coverage.exists():
        checks["coverage_truthfulness"] = _check_coverage(_load_json(coverage))
    else:
        checks["coverage_truthfulness"] = _missing_check("coverage")
    if reviewer and reviewer.exists():
        checks["reviewer_ablation"] = _check_reviewer(_load_json(reviewer))
    else:
        checks["reviewer_ablation"] = _missing_check("reviewer")
    if audit and audit.exists():
        checks["audit_reconstruction"] = _check_audit(_load_json(audit))
    else:
        checks["audit_reconstruction"] = _missing_check("audit")
    if product_matrix and product_matrix.exists():
        checks["product_control_matrix"] = _check_product_matrix(_load_json(product_matrix))
    else:
        checks["product_control_matrix"] = _missing_check("product_matrix")
    checks["external_validation"] = _check_external(external_evidence, require_external_validation=require_external_validation)
    failed = [name for name, payload in checks.items() if payload.get("status") == "fail"]
    skipped_required = [
        name
        for name, payload in checks.items()
        if name != "external_validation" and payload.get("status") == "skipped"
    ]
    research_ready = not failed and not skipped_required and not missing
    if require_external_validation and checks["external_validation"]["status"] != "pass":
        research_ready = False
    state = "research_ready" if research_ready else "research_incomplete"
    report_json = root / "research-readiness-report.json"
    report_html = root / "research-readiness-report.html"
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "status": "pass" if research_ready else "fail",
        "state": state,
        "generated_at": utc_now(),
        "missing": missing,
        "checks": checks,
        "summary": {
            "checks": len(checks),
            "failed": len(failed),
            "missing": len(missing),
            "external_required": require_external_validation,
        },
        "claim_boundary": "research_ready means local paper evidence artifacts are complete and internally consistent. It does not claim final external benchmark validation unless an external evidence manifest verifies.",
        "artifacts": {"report_json": str(report_json), "report_html": str(report_html)},
        "evidence_hash": "",
    }
    report["evidence_hash"] = stable_json_hash({"checks": checks, "missing": missing, "state": state})
    write_json_artifact(report_json, report)
    write_html_artifact(report_html, _research_html(report))
    return report


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _missing_check(name: str) -> dict[str, Any]:
    return {"status": "fail", "reason": f"missing {name} artifact"}


def _check_paper_tables(payload: dict[str, Any]) -> dict[str, Any]:
    validation = validate_paper_table_bundle(payload)
    table_ids = {table.get("table_id") for table in payload.get("tables", []) if isinstance(table, dict)}
    missing_tables = sorted(set(REQUIRED_TABLE_IDS) - table_ids)
    return {
        "status": "pass" if validation.get("status") == "pass" and not missing_tables else "fail",
        "validation": validation,
        "tables": sorted(table_ids),
        "missing_tables": missing_tables,
    }


def _check_coverage(payload: dict[str, Any]) -> dict[str, Any]:
    correctness = payload.get("metrics", {}).get("coverage_label_correctness")
    same_action = payload.get("same_action", {})
    positions = {item.get("surface"): item for item in same_action.get("positions", []) if isinstance(item, dict)}
    ok = (
        payload.get("status") == "pass"
        and correctness == 1.0
        and positions.get("imported_log", {}).get("actual_runtime_enforcement") == "none"
        and positions.get("managed_wrapper", {}).get("actual_runtime_enforcement") == "mediated"
        and positions.get("shim_proxy", {}).get("actual_runtime_enforcement") == "enforced"
        and positions.get("fail_open", {}).get("actual_runtime_enforcement") != "enforced"
    )
    return {
        "status": "pass" if ok else "fail",
        "coverage_label_correctness": correctness,
        "same_action_positions": sorted(positions),
    }


def _check_reviewer(payload: dict[str, Any]) -> dict[str, Any]:
    modes = payload.get("modes", {})
    selective = modes.get("selective", {})
    always = modes.get("always_on", {})
    async_audit = modes.get("async_audit", {})
    ok = (
        payload.get("status") == "pass"
        and payload.get("critical_non_downgradable") is True
        and selective.get("reviewer_call_rate", 1) < always.get("reviewer_call_rate", 0)
        and selective.get("estimated_tokens", 0) > 0
        and selective.get("estimated_cost_usd", -1) >= 0
        and async_audit.get("changes_policy_outcome") is False
        and payload.get("redaction", {}).get("raw_secret_persisted") is False
    )
    return {
        "status": "pass" if ok else "fail",
        "selective_call_rate": selective.get("reviewer_call_rate"),
        "always_on_call_rate": always.get("reviewer_call_rate"),
        "estimated_cost_usd": selective.get("estimated_cost_usd"),
    }


def _check_audit(payload: dict[str, Any]) -> dict[str, Any]:
    metrics = payload.get("metrics", {})
    ok = (
        payload.get("status") == "pass"
        and metrics.get("audit_reconstruction_success") == 1.0
        and metrics.get("tamper_detection_rate") == 1.0
        and metrics.get("missing_field_rate", 0) > 0
    )
    return {"status": "pass" if ok else "fail", "metrics": metrics}


def _check_product_matrix(payload: dict[str, Any]) -> dict[str, Any]:
    baselines = {item.get("baseline"): item for item in payload.get("baselines", []) if isinstance(item, dict)}
    plugin = baselines.get("plugin_only", {})
    managed = baselines.get("invart_managed_launcher", {})
    ok = (
        payload.get("status") == "pass"
        and payload.get("summary", {}).get("products", 0) >= 4
        and plugin.get("supports_mediation") is False
        and plugin.get("coverage_grade") in {"observed", "vendor_owned"}
        and managed.get("supports_mediation") is True
        and managed.get("coverage_grade") == "mediated"
    )
    return {"status": "pass" if ok else "fail", "products": payload.get("summary", {}).get("products"), "baselines": sorted(baselines)}


def _check_external(path: Path | None, *, require_external_validation: bool) -> dict[str, Any]:
    if not path:
        status = "fail" if require_external_validation else "skipped"
        return {
            "status": status,
            "reason": "no external evidence manifest attached",
            "required": require_external_validation,
        }
    if not path.exists():
        return {"status": "fail", "reason": "external evidence manifest path does not exist", "path": str(path)}
    payload = _load_json(path)
    status = "pass" if payload.get("status") == "pass" else "fail"
    return {"status": status, "manifest": str(path), "kind": payload.get("kind"), "evidence_level": payload.get("evidence_level")}


def _research_html(report: dict[str, Any]) -> str:
    rows = []
    for name, payload in report["checks"].items():
        rows.append(
            "<tr>"
            f"<td>{html.escape(name)}</td>"
            f"<td>{html.escape(str(payload.get('status')))}</td>"
            f"<td><pre>{html.escape(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))}</pre></td>"
            "</tr>"
        )
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Research Readiness Gate</title><style>body{{font-family:Inter,Arial,sans-serif;margin:0;background:#f8fafc;color:#172033}}main{{max-width:1120px;margin:0 auto;padding:32px 24px}}table{{width:100%;border-collapse:collapse;background:white;border:1px solid #dfe5ef}}td,th{{border-bottom:1px solid #e5e7eb;padding:8px;text-align:left;vertical-align:top}}pre{{white-space:pre-wrap;margin:0;font-size:12px}}</style></head><body><main><h1>Research Readiness Gate</h1><p>Status: <strong>{html.escape(str(report.get("status")))}</strong> · State: <strong>{html.escape(str(report.get("state")))}</strong></p><table><tr><th>Check</th><th>Status</th><th>Details</th></tr>{''.join(rows)}</table></main></body></html>"""


__all__ = ["verify_research_readiness"]
