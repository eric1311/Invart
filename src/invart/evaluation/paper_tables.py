from __future__ import annotations

import csv
import html
import json
import tempfile
from pathlib import Path
from typing import Any

from invart.core.artifacts import sha256_file, stable_json_hash, write_html_artifact, write_json_artifact
from invart.core.models import utc_now
from invart.evaluation.coverage_experiments import run_coverage_truthfulness_matrix


SCHEMA_VERSION = "invart.paper_tables.v0.46"
REQUIRED_TABLE_IDS = (
    "risk_path_outcomes",
    "benign_friction",
    "coverage_truthfulness",
    "reviewer_cost",
    "audit_reconstruction",
    "external_corpus_mapping",
)


def export_paper_tables(paper_suite: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    out_dir = out_dir.expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    results = paper_suite.get("results") if isinstance(paper_suite.get("results"), dict) else {}
    coverage = run_coverage_truthfulness_matrix(out_dir=out_dir / "coverage-source")
    tables = [
        _table("risk_path_outcomes", _risk_rows(results)),
        _table("benign_friction", _benign_rows(results)),
        _table("coverage_truthfulness", _coverage_rows(coverage)),
        _table("reviewer_cost", _reviewer_rows(results)),
        _table("audit_reconstruction", _audit_rows(results)),
        _table("external_corpus_mapping", _external_rows(results)),
    ]
    bundle: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "status": "pass",
        "generated_at": utc_now(),
        "tables": tables,
        "summary": {
            "tables": len(tables),
            "rows": sum(len(table["rows"]) for table in tables),
            "required_table_ids": list(REQUIRED_TABLE_IDS),
        },
        "claim_boundary": "Paper tables are derived summaries. Ledger, proof, replay, graph, and evidence artifacts remain the evidence source.",
        "artifacts": {},
    }
    validation = validate_paper_table_bundle(bundle)
    bundle["validation"] = validation
    bundle["status"] = "pass" if validation["status"] == "pass" else "fail"
    tables_json = out_dir / "paper-tables.json"
    tables_csv = out_dir / "paper-tables.csv"
    tables_html = out_dir / "paper-tables.html"
    write_json_artifact(tables_json, bundle)
    _write_tables_csv(tables_csv, tables)
    write_html_artifact(tables_html, _tables_html(bundle))
    bundle["artifacts"] = {
        "tables_json": str(tables_json),
        "tables_csv": str(tables_csv),
        "tables_html": str(tables_html),
    }
    write_json_artifact(tables_json, bundle)
    return bundle


def export_paper_tables_from_file(paper_suite_path: Path, out_dir: Path) -> dict[str, Any]:
    try:
        payload = json.loads(paper_suite_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return _failed_bundle(out_dir, [f"could not read paper suite JSON: {paper_suite_path}"])
    if not isinstance(payload, dict):
        return _failed_bundle(out_dir, ["paper suite payload must be a JSON object"])
    if "results" not in payload:
        from invart.evaluation.experiment_cases import run_paper_suite

        payload = run_paper_suite(out_dir / "paper-suite-source")
    return export_paper_tables(payload, out_dir)


def validate_paper_table_bundle(bundle: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    tables = bundle.get("tables") if isinstance(bundle.get("tables"), list) else []
    by_id = {table.get("table_id"): table for table in tables if isinstance(table, dict)}
    for table_id in REQUIRED_TABLE_IDS:
        if table_id not in by_id:
            errors.append(f"missing table: {table_id}")
        elif not by_id[table_id].get("rows"):
            errors.append(f"table has no rows: {table_id}")
    for table in tables:
        if not isinstance(table, dict):
            errors.append("table must be an object")
            continue
        for row in table.get("rows", []):
            if not isinstance(row, dict):
                errors.append(f"{table.get('table_id')} row must be an object")
                continue
            for field_name in ("row_id", "table_id", "suite", "case_id", "agent_workflow_kind", "claim_boundary", "evidence_hash"):
                if not row.get(field_name):
                    errors.append(f"{row.get('row_id', '<unknown>')} missing {field_name}")
            artifacts = row.get("artifacts")
            if not isinstance(artifacts, dict):
                errors.append(f"{row.get('row_id', '<unknown>')} missing artifacts")
            elif not any(artifacts.values()):
                errors.append(f"{row.get('row_id', '<unknown>')} missing artifact anchor")
            elif row.get("table_id") == "risk_path_outcomes":
                for artifact_name in ("ledger", "proof", "replay", "path_graph", "evidence_manifest"):
                    if not artifacts.get(artifact_name):
                        errors.append(f"{row.get('row_id', '<unknown>')} missing artifact {artifact_name}")
    return {
        "schema_version": "invart.paper_tables.validation.v0.46",
        "status": "pass" if not errors else "fail",
        "errors": errors,
        "summary": {"tables": len(tables), "errors": len(errors)},
    }


def _table(table_id: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {"table_id": table_id, "rows": rows}


def _risk_rows(results: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for result in results.values():
        for case in result.get("cases", []) if isinstance(result, dict) else []:
            expected = case.get("expected", {}) if isinstance(case, dict) else {}
            if expected.get("forbidden_action") or expected.get("decision") in {"deny", "require_approval"}:
                rows.append(_case_row("risk_path_outcomes", case, metrics={"decision": expected.get("decision"), "forbidden_action": expected.get("forbidden_action")}))
    return rows


def _benign_rows(results: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for result in results.values():
        metrics = result.get("metrics", {}) if isinstance(result, dict) else {}
        for case in result.get("cases", []) if isinstance(result, dict) else []:
            expected = case.get("expected", {}) if isinstance(case, dict) else {}
            if expected.get("benign"):
                rows.append(
                    _case_row(
                        "benign_friction",
                        case,
                        metrics={
                            "auto_approval_rate": metrics.get("benign_auto_approval_rate", 1.0 - float(metrics.get("over_defense_rate", 0.0))),
                            "approval_noise": metrics.get("unnecessary_approval_rate", metrics.get("over_defense_rate", 0.0)),
                            "resolved_rate_delta": metrics.get("resolved_rate_delta", 0),
                        },
                    )
                )
    return rows or [_summary_row("benign_friction", "local-fixture", "no_benign_case", {"auto_approval_rate": 1.0, "approval_noise": 0.0})]


def _coverage_rows(coverage: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for item in coverage.get("same_action", {}).get("positions", coverage.get("surfaces", [])):
        surface = str(item.get("surface"))
        rows.append(
            _summary_row(
                "coverage_truthfulness",
                "coverage-truthfulness-matrix",
                surface,
                {
                    "expected_runtime_enforcement": item.get("expected_runtime_enforcement"),
                    "actual_runtime_enforcement": item.get("actual_runtime_enforcement") or item.get("coverage", {}).get("runtime_enforcement"),
                    "truthful": item.get("truthful"),
                    "coverage_gap": item.get("coverage_gap", False),
                },
                workflow_kind="coverage_matrix",
                artifacts=item.get("artifacts", {}),
            )
        )
    return rows


def _reviewer_rows(results: dict[str, Any]) -> list[dict[str, Any]]:
    reviewer = next((result for result in results.values() if isinstance(result, dict) and result.get("suite") == "llm-reviewer-selectivity"), None)
    rows = []
    for mode, payload in (reviewer or {}).get("modes", {}).items():
        rows.append(
            _summary_row(
                "reviewer_cost",
                "llm-reviewer-selectivity",
                str(mode),
                dict(payload),
                workflow_kind="reviewer_ablation",
                artifacts=(reviewer or {}).get("artifacts", {}),
            )
        )
    return rows


def _audit_rows(results: dict[str, Any]) -> list[dict[str, Any]]:
    audit = next((result for result in results.values() if isinstance(result, dict) and result.get("suite") == "audit-tamper-assurance"), None)
    metrics = dict((audit or {}).get("metrics", {}))
    return [_summary_row("audit_reconstruction", "audit-tamper-assurance", "audit_tamper_assurance", metrics, workflow_kind="audit_reconstruction", artifacts=(audit or {}).get("artifacts", {}))]


def _external_rows(results: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for result in results.values():
        suite = str(result.get("suite", "")) if isinstance(result, dict) else ""
        if suite not in {"external-ipi-control-plane", "authority-dataflow-boundary", "skill-supply-chain-control-plane"}:
            continue
        for case in result.get("cases", []):
            rows.append(_case_row("external_corpus_mapping", case, metrics={"source": case.get("source"), "passed": case.get("passed")}))
    return rows


def _case_row(table_id: str, case: dict[str, Any], *, metrics: dict[str, Any]) -> dict[str, Any]:
    artifacts = dict(case.get("artifacts", {}))
    payload = {
        "table_id": table_id,
        "row_id": f"{table_id}:{case.get('suite')}:{case.get('case_id')}",
        "suite": case.get("suite"),
        "case_id": case.get("case_id"),
        "title": case.get("title"),
        "agent_workflow_kind": case.get("execution_mode", "simulated_agent_trace"),
        "metrics": metrics,
        "artifacts": artifacts,
        "claim_boundary": "Derived from simulated agent trace artifacts; not full external benchmark validation.",
    }
    payload["evidence_hash"] = _evidence_hash(payload)
    return payload


def _summary_row(table_id: str, suite: str, case_id: str, metrics: dict[str, Any], *, workflow_kind: str = "simulated_agent_trace", artifacts: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = {
        "table_id": table_id,
        "row_id": f"{table_id}:{suite}:{case_id}",
        "suite": suite,
        "case_id": case_id,
        "title": case_id.replace("_", " "),
        "agent_workflow_kind": workflow_kind,
        "metrics": metrics,
        "artifacts": artifacts or {},
        "claim_boundary": "Derived from local Invart experiment artifacts; coverage and external-validation limits remain explicit.",
    }
    payload["evidence_hash"] = _evidence_hash(payload)
    return payload


def _evidence_hash(row: dict[str, Any]) -> str:
    artifact_hashes = {}
    for name, value in row.get("artifacts", {}).items():
        path = Path(str(value))
        artifact_hashes[name] = sha256_file(path, prefixed=True) if path.exists() and path.is_file() else str(value)
    return stable_json_hash({k: v for k, v in row.items() if k != "evidence_hash"} | {"artifact_hashes": artifact_hashes})


def _write_tables_csv(path: Path, tables: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["table_id", "row_id", "suite", "case_id", "agent_workflow_kind", "metrics", "evidence_hash", "claim_boundary"])
        writer.writeheader()
        for table in tables:
            for row in table.get("rows", []):
                writer.writerow(
                    {
                        "table_id": row.get("table_id"),
                        "row_id": row.get("row_id"),
                        "suite": row.get("suite"),
                        "case_id": row.get("case_id"),
                        "agent_workflow_kind": row.get("agent_workflow_kind"),
                        "metrics": json.dumps(row.get("metrics", {}), ensure_ascii=False, sort_keys=True),
                        "evidence_hash": row.get("evidence_hash"),
                        "claim_boundary": row.get("claim_boundary"),
                    }
                )


def _tables_html(bundle: dict[str, Any]) -> str:
    sections = []
    for table in bundle.get("tables", []):
        rows = "".join(
            "<tr>"
            f"<td>{html.escape(str(row.get('row_id')))}</td>"
            f"<td>{html.escape(str(row.get('agent_workflow_kind')))}</td>"
            f"<td><pre>{html.escape(json.dumps(row.get('metrics', {}), ensure_ascii=False, sort_keys=True))}</pre></td>"
            f"<td>{html.escape(str(row.get('evidence_hash')))}</td>"
            "</tr>"
            for row in table.get("rows", [])
        )
        sections.append(f"<section><h2>{html.escape(str(table.get('table_id')))}</h2><table><tr><th>Row</th><th>Workflow</th><th>Metrics</th><th>Evidence Hash</th></tr>{rows}</table></section>")
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Invart Paper Tables</title><style>body{{font-family:Inter,Arial,sans-serif;margin:0;background:#f8fafc;color:#172033}}main{{max-width:1180px;margin:0 auto;padding:32px 24px}}section{{background:white;border:1px solid #dfe5ef;border-radius:8px;padding:16px;margin:14px 0}}table{{width:100%;border-collapse:collapse}}td,th{{border-bottom:1px solid #e5e7eb;padding:8px;text-align:left;vertical-align:top}}pre{{white-space:pre-wrap}}</style></head><body><main><h1>Invart Paper Evidence Tables</h1><p>{html.escape(str(bundle.get('claim_boundary')))}</p>{''.join(sections)}</main></body></html>"""


def _failed_bundle(out_dir: Path, errors: list[str]) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = {"schema_version": SCHEMA_VERSION, "status": "fail", "tables": [], "validation": {"status": "fail", "errors": errors}, "artifacts": {}}
    write_json_artifact(out_dir / "paper-tables.json", payload)
    return payload


__all__ = ["export_paper_tables", "export_paper_tables_from_file", "validate_paper_table_bundle"]
