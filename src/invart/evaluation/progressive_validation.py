from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from invart.core.artifacts import sha256_file, stable_json_hash, write_html_artifact, write_json_artifact
from invart.evaluation.external_evidence import import_external_evidence, verify_external_evidence


SCHEMA_VERSION = "invart.progressive_validation.v0.45"
MANIFEST_KIND = "progressive_validation"
EVIDENCE_LEVEL = "external_progressive_sample"
DEFAULT_PUBLIC_RISK_CATALOG = Path("benchmarks/fixtures/public-risk-sources.v2026-06-02.json")
STAGE_LIMITS = {"smoke": 1, "sample": 3, "scale": 10}
DEFAULT_CATEGORIES = ("public-risk-catalog",)
SUPPORTED_CATEGORIES = ("public-risk-catalog", "external-corpus-snapshot", "swe-bench")


def run_progressive_validation(
    *,
    out_dir: Path,
    stage: str = "smoke",
    categories: list[str] | None = None,
    max_cases: int | None = None,
    public_risk_catalog: Path | None = None,
    snapshot_path: Path | None = None,
    swe_report_path: Path | None = None,
    swe_instance_results_path: Path | None = None,
    swe_predictions_path: Path | None = None,
    swe_logs_path: Path | None = None,
    swe_run_id: str = "invart_progressive_sample",
) -> dict[str, Any]:
    out_dir = out_dir.expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    limit = _stage_limit(stage, max_cases=max_cases)
    selected = list(categories or DEFAULT_CATEGORIES)
    invalid = [category for category in selected if category not in SUPPORTED_CATEGORIES]
    category_reports: dict[str, Any] = {}
    if invalid:
        for category in invalid:
            category_reports[category] = _failed_category(category, f"unsupported category: {category}", stage, limit)
    for category in selected:
        if category in invalid:
            continue
        category_dir = out_dir / category
        if category == "public-risk-catalog":
            category_reports[category] = validate_public_risk_catalog_sample(
                public_risk_catalog or DEFAULT_PUBLIC_RISK_CATALOG,
                category_dir,
                stage=stage,
                limit=limit,
            )
        elif category == "external-corpus-snapshot":
            if snapshot_path is None:
                category_reports[category] = _failed_category(category, "--snapshot is required", stage, limit)
            else:
                category_reports[category] = validate_external_corpus_snapshot_sample(
                    snapshot_path,
                    category_dir,
                    stage=stage,
                    limit=limit,
                )
        elif category == "swe-bench":
            if not all((swe_report_path, swe_instance_results_path, swe_predictions_path, swe_logs_path)):
                category_reports[category] = _failed_category(
                    category,
                    "--swe-report, --swe-instance-results, --swe-predictions, and --swe-logs are required",
                    stage,
                    limit,
                )
            else:
                category_reports[category] = validate_swe_bench_progressive_sample(
                    report_path=swe_report_path,  # type: ignore[arg-type]
                    instance_results_path=swe_instance_results_path,  # type: ignore[arg-type]
                    predictions_path=swe_predictions_path,  # type: ignore[arg-type]
                    logs_path=swe_logs_path,  # type: ignore[arg-type]
                    out_dir=category_dir,
                    run_id=swe_run_id,
                    stage=stage,
                    limit=limit,
                )
    checks = {
        "categories_selected": bool(selected),
        "all_categories_pass": all(report.get("status") == "pass" for report in category_reports.values()),
        "final_ready_not_eligible": all(report.get("final_ready_eligible") is False for report in category_reports.values()),
    }
    status = "pass" if all(checks.values()) else "fail"
    manifest_path = out_dir / "progressive-validation-manifest.json"
    report_html = out_dir / "progressive-validation-report.html"
    manifest: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "kind": MANIFEST_KIND,
        "status": status,
        "stage": stage,
        "limit": limit,
        "evidence_level": EVIDENCE_LEVEL,
        "final_ready_eligible": False,
        "categories": selected,
        "checks": checks,
        "summary": {
            "categories": len(category_reports),
            "passed": sum(1 for report in category_reports.values() if report.get("status") == "pass"),
            "failed": sum(1 for report in category_reports.values() if report.get("status") != "pass"),
            "final_ready_eligible": False,
        },
        "category_reports": {
            category: {
                "status": report.get("status"),
                "evidence_level": report.get("evidence_level"),
                "final_ready_eligible": report.get("final_ready_eligible"),
                "summary": report.get("summary", {}),
                "artifacts": report.get("artifacts", {}),
                "errors": report.get("errors", []),
            }
            for category, report in category_reports.items()
        },
        "claim_boundary": "Progressive validation samples debug evidence pipelines; it is not final external validation and cannot satisfy final_ready.",
        "manifest_path": str(manifest_path),
        "report_html": str(report_html),
    }
    manifest["manifest_hash"] = stable_json_hash({k: v for k, v in manifest.items() if k not in {"manifest_hash", "manifest_path", "report_html"}})
    write_json_artifact(manifest_path, manifest)
    write_html_artifact(report_html, _progressive_html(manifest))
    return {
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "stage": stage,
        "limit": limit,
        "evidence_level": EVIDENCE_LEVEL,
        "final_ready_eligible": False,
        "categories": category_reports,
        "checks": checks,
        "summary": manifest["summary"],
        "artifacts": {"manifest": str(manifest_path), "report_html": str(report_html)},
        "claim_boundary": manifest["claim_boundary"],
    }


def validate_public_risk_catalog_sample(catalog_path: Path, out_dir: Path, *, stage: str, limit: int) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    catalog_path = catalog_path.expanduser().resolve()
    payload = _load_json(catalog_path)
    errors: list[str] = []
    if payload is None:
        errors.append("public risk catalog must be a JSON object")
        return _category_report("public-risk-catalog", "fail", stage, limit, errors=errors)
    sources = payload.get("sources") if isinstance(payload.get("sources"), list) else []
    sampled = sources[:limit]
    if not sampled:
        errors.append("public risk catalog has no sources")
    if not payload.get("claim_boundary"):
        errors.append("public risk catalog missing required field: claim_boundary")
    for source in sampled:
        if not isinstance(source, dict):
            errors.append("source must be an object")
            continue
        for field in ("source_id", "url", "before_signal", "during_signal", "after_signal", "mapped_trajectory"):
            if not source.get(field):
                errors.append(f"source {source.get('source_id', '<unknown>')} missing required field: {field}")
        trajectory = source.get("mapped_trajectory")
        if not isinstance(trajectory, list) or len(trajectory) < 3:
            errors.append(f"source {source.get('source_id', '<unknown>')} mapped_trajectory must include pre/during/after steps")
    sample_path = out_dir / "public-risk-catalog-sample.json"
    write_json_artifact(
        sample_path,
        {
            "schema_version": "invart.public_risk_catalog_sample.v0.45",
            "source_catalog": str(catalog_path),
            "source_catalog_hash": sha256_file(catalog_path, prefixed=True) if catalog_path.exists() else None,
            "stage": stage,
            "limit": limit,
            "sources": sampled,
        },
    )
    return _category_report(
        "public-risk-catalog",
        "pass" if not errors else "fail",
        stage,
        limit,
        errors=errors,
        summary={"available_sources": len(sources), "sampled_sources": len(sampled)},
        artifacts={"sample": str(sample_path)},
    )


def validate_external_corpus_snapshot_sample(snapshot_path: Path, out_dir: Path, *, stage: str, limit: int) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    snapshot_path = snapshot_path.expanduser().resolve()
    payload = _load_json(snapshot_path)
    if payload is None:
        return _category_report("external-corpus-snapshot", "fail", stage, limit, errors=["snapshot must be a JSON object"])
    cases = payload.get("cases") if isinstance(payload.get("cases"), list) else []
    sampled_cases = cases[:limit]
    sampled_snapshot = dict(payload, cases=sampled_cases)
    sampled_snapshot_path = out_dir / "sampled-external-corpus-snapshot.json"
    write_json_artifact(sampled_snapshot_path, sampled_snapshot)
    imported = import_external_evidence(sampled_snapshot_path, out_dir / "imported")
    verified = verify_external_evidence(Path(imported["manifest_path"])) if imported.get("manifest_path") else {"status": "fail", "errors": imported.get("errors", [])}
    errors = list(imported.get("errors", [])) + list(verified.get("errors", []))
    status = "pass" if imported.get("status") == "pass" and verified.get("status") == "pass" else "fail"
    return _category_report(
        "external-corpus-snapshot",
        status,
        stage,
        limit,
        errors=errors,
        summary={"available_cases": len(cases), "sampled_cases": len(sampled_cases)},
        artifacts={
            "sampled_snapshot": str(sampled_snapshot_path),
            "import_manifest": imported.get("manifest_path"),
        },
    )


def validate_swe_bench_progressive_sample(
    *,
    report_path: Path,
    instance_results_path: Path,
    predictions_path: Path,
    logs_path: Path,
    out_dir: Path,
    run_id: str,
    stage: str,
    limit: int,
) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_path.expanduser().resolve()
    instance_results_path = instance_results_path.expanduser().resolve()
    predictions_path = predictions_path.expanduser().resolve()
    logs_path = logs_path.expanduser().resolve()
    report = _load_json(report_path) or {}
    rows = _load_jsonl(instance_results_path)
    total = int(report.get("total_instances") or 0)
    submitted = int(report.get("submitted_instances") or 0)
    completed = int(report.get("completed_instances") or 0)
    errors_count = int(report.get("error_instances") or 0)
    completed_ids = [str(item) for item in report.get("completed_ids", [])] if isinstance(report.get("completed_ids"), list) else []
    row_ids = [str(item.get("instance_id")) for item in rows if item.get("instance_id")]
    checks = {
        "official_report_present": report_path.exists() and bool(report),
        "instance_results_present": instance_results_path.exists() and bool(rows),
        "predictions_present": predictions_path.exists(),
        "logs_present": logs_path.exists(),
        "sample_size_positive": total > 0,
        "sample_size_within_limit": 0 < total <= limit,
        "submitted_equals_total": submitted == total and total > 0,
        "completed_equals_submitted": completed == submitted and submitted > 0,
        "error_instances_zero": errors_count == 0,
        "instance_results_complete": len(rows) == completed and completed > 0,
        "completed_ids_match_instance_results": not completed_ids or sorted(completed_ids) == sorted(row_ids),
    }
    status = "pass" if all(checks.values()) else "fail"
    sample_report_path = out_dir / "swe-bench-progressive-sample.json"
    sample_report = {
        "schema_version": "invart.swe_bench_progressive_sample.v0.45",
        "status": status,
        "stage": stage,
        "limit": limit,
        "run_id": run_id,
        "evidence_level": EVIDENCE_LEVEL,
        "final_ready_eligible": False,
        "checks": checks,
        "summary": {"total_instances": total, "completed_instances": completed, "rows": len(rows)},
        "artifacts": {
            "official_report": str(report_path),
            "instance_results": str(instance_results_path),
            "predictions": str(predictions_path),
            "logs": str(logs_path),
        },
        "hashes": {
            "official_report": sha256_file(report_path, prefixed=True) if report_path.exists() else None,
            "instance_results": sha256_file(instance_results_path, prefixed=True) if instance_results_path.exists() else None,
            "predictions": sha256_file(predictions_path, prefixed=True) if predictions_path.exists() else None,
            "logs": _hash_path(logs_path) if logs_path.exists() else None,
        },
        "claim_boundary": "This is a progressive SWE-Bench sample for debugging the evidence pipeline; it cannot satisfy full external validation.",
    }
    write_json_artifact(sample_report_path, sample_report)
    return _category_report(
        "swe-bench",
        status,
        stage,
        limit,
        errors=[key for key, value in checks.items() if value is False],
        summary=sample_report["summary"],
        artifacts={"sample_report": str(sample_report_path), **sample_report["artifacts"]},
    )


def _stage_limit(stage: str, *, max_cases: int | None) -> int:
    if stage not in STAGE_LIMITS:
        raise ValueError(f"unsupported progressive validation stage: {stage}")
    if max_cases is not None:
        return max(1, max_cases)
    return STAGE_LIMITS[stage]


def _category_report(
    category: str,
    status: str,
    stage: str,
    limit: int,
    *,
    errors: list[str] | None = None,
    summary: dict[str, Any] | None = None,
    artifacts: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "category": category,
        "status": status,
        "stage": stage,
        "limit": limit,
        "evidence_level": EVIDENCE_LEVEL,
        "final_ready_eligible": False,
        "summary": summary or {},
        "artifacts": artifacts or {},
        "errors": errors or [],
        "claim_boundary": "Progressive samples are debugging evidence and cannot satisfy final_ready.",
    }


def _failed_category(category: str, error: str, stage: str, limit: int) -> dict[str, Any]:
    return _category_report(category, "fail", stage, limit, errors=[error])


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    return loaded if isinstance(loaded, dict) else None


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            loaded = json.loads(line)
            if isinstance(loaded, dict):
                rows.append(loaded)
    except json.JSONDecodeError:
        return []
    return rows


def _hash_path(path: Path) -> str:
    if path.is_file():
        return sha256_file(path, prefixed=True)
    import hashlib

    parts = []
    for child in sorted(item for item in path.rglob("*") if item.is_file()):
        parts.append(f"{child.relative_to(path)}:{sha256_file(child, prefixed=True)}")
    return f"sha256:{hashlib.sha256(chr(10).join(parts).encode('utf-8')).hexdigest()}"


def _progressive_html(manifest: dict[str, Any]) -> str:
    rows = []
    for category, report in manifest["category_reports"].items():
        rows.append(
            "<tr>"
            f"<td>{html.escape(category)}</td>"
            f"<td>{html.escape(str(report.get('status')))}</td>"
            f"<td>{html.escape(str(report.get('evidence_level')))}</td>"
            f"<td>{html.escape(json.dumps(report.get('summary', {}), ensure_ascii=False, sort_keys=True))}</td>"
            "</tr>"
        )
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Invart Progressive External Validation</title><style>body{{font-family:Inter,Arial,sans-serif;margin:0;background:#f8fafc;color:#172033}}main{{max-width:1040px;margin:0 auto;padding:34px 24px}}section{{background:white;border:1px solid #dfe5ef;border-radius:8px;padding:16px;margin:14px 0}}table{{width:100%;border-collapse:collapse}}td,th{{border-bottom:1px solid #e5e7eb;padding:9px;text-align:left;vertical-align:top}}code,pre{{font-family:SFMono-Regular,Consolas,monospace}}pre{{background:#0f172a;color:#e2e8f0;padding:14px;border-radius:8px;overflow:auto}}</style></head><body><main><h1>Invart Progressive External Validation</h1><section><p>Status: <strong>{html.escape(str(manifest.get('status')))}</strong></p><p>Stage: <code>{html.escape(str(manifest.get('stage')))}</code>; limit: <code>{html.escape(str(manifest.get('limit')))}</code></p><p>{html.escape(str(manifest.get('claim_boundary')))}</p></section><section><h2>Categories</h2><table><tr><th>Category</th><th>Status</th><th>Evidence Level</th><th>Summary</th></tr>{''.join(rows)}</table></section><section><h2>Manifest</h2><pre>{html.escape(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True))}</pre></section></main></body></html>"""


__all__ = [
    "DEFAULT_PUBLIC_RISK_CATALOG",
    "EVIDENCE_LEVEL",
    "MANIFEST_KIND",
    "SCHEMA_VERSION",
    "SUPPORTED_CATEGORIES",
    "run_progressive_validation",
    "validate_external_corpus_snapshot_sample",
    "validate_public_risk_catalog_sample",
    "validate_swe_bench_progressive_sample",
]
