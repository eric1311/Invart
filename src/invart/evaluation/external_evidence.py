from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from invart.core.artifacts import sha256_file, stable_json_hash, write_json_artifact


MANIFEST_SCHEMA_VERSION = "invart.external_evidence_manifest.v0.44"


def import_external_evidence(snapshot_path: Path, out_dir: Path) -> dict[str, Any]:
    snapshot_path = snapshot_path.expanduser().resolve()
    out_dir = out_dir.expanduser().resolve()
    errors: list[str] = []
    payload = _load_json(snapshot_path)
    if payload is None:
        errors.append("snapshot must be a JSON object")
        return _failed_import(snapshot_path, out_dir, errors)
    for field in ("source", "source_url", "version", "cases"):
        if not payload.get(field):
            errors.append(f"missing required field: {field}")
    cases = payload.get("cases") if isinstance(payload.get("cases"), list) else []
    if not cases:
        errors.append("cases must be a non-empty list")
    normalized_cases = []
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            errors.append(f"case {index} must be an object")
            continue
        for field in ("case_id", "title", "trust", "capability", "resource", "sink", "expected", "agent_trace"):
            if field not in case:
                errors.append(f"case {case.get('case_id', index)} missing required field: {field}")
        expected = case.get("expected")
        if not isinstance(expected, dict) or not expected.get("decision"):
            errors.append(f"case {case.get('case_id', index)} expected decision is required")
        if not isinstance(case.get("agent_trace"), list) or not case.get("agent_trace"):
            errors.append(f"case {case.get('case_id', index)} agent_trace must be non-empty")
        normalized_cases.append(dict(case, source=payload.get("source")))
    if errors:
        return _failed_import(snapshot_path, out_dir, errors)
    out_dir.mkdir(parents=True, exist_ok=True)
    cases_path = out_dir / "normalized-cases.json"
    write_json_artifact(cases_path, {"cases": normalized_cases})
    manifest_path = out_dir / "external-evidence-manifest.json"
    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "kind": "corpus_snapshot",
        "status": "pass",
        "source": payload["source"],
        "source_url": payload["source_url"],
        "version": payload["version"],
        "license": payload.get("license", "unknown"),
        "evidence_level": "pinned_upstream_snapshot",
        "snapshot_path": str(snapshot_path),
        "snapshot_hash": sha256_file(snapshot_path, prefixed=True),
        "normalized_cases_path": str(cases_path),
        "normalized_cases_hash": sha256_file(cases_path, prefixed=True),
        "summary": {"cases": len(normalized_cases)},
        "claim_boundary": "Imported external corpus snapshots are evidence seeds; Invart ledger remains the fact source after cases are executed.",
        "manifest_path": str(manifest_path),
    }
    write_json_artifact(manifest_path, manifest)
    return manifest


def attach_swe_bench_full_evidence(
    *,
    report_path: Path,
    instance_results_path: Path,
    predictions_path: Path,
    logs_path: Path,
    out_dir: Path,
    run_id: str,
    expected_total_instances: int = 2294,
    invart_mode: str = "managed",
) -> dict[str, Any]:
    report_path = report_path.expanduser().resolve()
    instance_results_path = instance_results_path.expanduser().resolve()
    predictions_path = predictions_path.expanduser().resolve()
    logs_path = logs_path.expanduser().resolve()
    out_dir = out_dir.expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    report = _load_json(report_path) or {}
    rows = _load_jsonl(instance_results_path)
    total = int(report.get("total_instances") or 0)
    submitted = int(report.get("submitted_instances") or 0)
    completed = int(report.get("completed_instances") or 0)
    errors = int(report.get("error_instances") or 0)
    completed_ids = [str(item) for item in report.get("completed_ids", [])] if isinstance(report.get("completed_ids"), list) else []
    row_ids = [str(item.get("instance_id")) for item in rows if isinstance(item, dict) and item.get("instance_id")]
    checks = {
        "official_report_present": report_path.exists() and bool(report),
        "instance_results_present": instance_results_path.exists() and bool(rows),
        "predictions_present": predictions_path.exists(),
        "logs_present": logs_path.exists(),
        "expected_total_instances_match": total == expected_total_instances,
        "submitted_equals_total": submitted == total and total > 0,
        "completed_equals_submitted": completed == submitted and submitted > 0,
        "error_instances_zero": errors == 0,
        "instance_results_complete": len(rows) == completed and completed > 0,
        "completed_ids_match_instance_results": not completed_ids or sorted(completed_ids) == sorted(row_ids),
        "predictions_hash_present": predictions_path.exists(),
    }
    checks["all_instances_complete"] = all(
        checks[key]
        for key in (
            "expected_total_instances_match",
            "submitted_equals_total",
            "completed_equals_submitted",
            "error_instances_zero",
            "instance_results_complete",
            "completed_ids_match_instance_results",
        )
    )
    status = "pass" if all(checks.values()) else "fail"
    manifest_path = out_dir / "swe-bench-full-evidence-manifest.json"
    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "kind": "swe_bench_full",
        "status": status,
        "source": "SWE-Bench",
        "source_url": "https://www.swebench.com/",
        "run_id": run_id,
        "evidence_level": "external_live_run",
        "invart_mode": invart_mode,
        "expected_total_instances": expected_total_instances,
        "checks": checks,
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
        "summary": {"total_instances": total, "completed_instances": completed, "rows": len(rows)},
        "claim_boundary": "This manifest verifies attached official full SWE-Bench artifacts; it does not rerun the heavy benchmark.",
        "manifest_path": str(manifest_path),
    }
    manifest["manifest_hash"] = stable_json_hash({k: v for k, v in manifest.items() if k not in {"manifest_hash", "manifest_path"}})
    write_json_artifact(manifest_path, manifest)
    return manifest


def verify_external_evidence(manifest_path: Path) -> dict[str, Any]:
    manifest_path = manifest_path.expanduser().resolve()
    manifest = _load_json(manifest_path)
    errors: list[str] = []
    if manifest is None:
        return {"schema_version": "invart.external_evidence_verify.v0.44", "status": "fail", "errors": ["manifest must be a JSON object"], "manifest_path": str(manifest_path)}
    progressive_schema = "invart.progressive_validation.v0.45"
    if manifest.get("schema_version") not in {MANIFEST_SCHEMA_VERSION, progressive_schema}:
        errors.append("unsupported manifest schema_version")
    kind = manifest.get("kind")
    if kind == "corpus_snapshot":
        _verify_file_hash(manifest.get("snapshot_path"), manifest.get("snapshot_hash"), "snapshot_hash", errors)
        _verify_file_hash(manifest.get("normalized_cases_path"), manifest.get("normalized_cases_hash"), "normalized_cases_hash", errors)
        cases_path = Path(str(manifest.get("normalized_cases_path", "")))
        cases_payload = _load_json(cases_path) or {}
        cases = cases_payload.get("cases") if isinstance(cases_payload.get("cases"), list) else []
        if len(cases) != int(manifest.get("summary", {}).get("cases") or -1):
            errors.append("case count does not match manifest summary")
    elif kind == "swe_bench_full":
        artifacts = manifest.get("artifacts", {}) if isinstance(manifest.get("artifacts"), dict) else {}
        hashes = manifest.get("hashes", {}) if isinstance(manifest.get("hashes"), dict) else {}
        for key in ("official_report", "instance_results", "predictions"):
            _verify_file_hash(artifacts.get(key), hashes.get(key), f"hashes.{key}", errors)
        logs = artifacts.get("logs")
        if logs and Path(str(logs)).exists() and hashes.get("logs") != _hash_path(Path(str(logs))):
            errors.append("hashes.logs does not match logs artifact")
        if manifest.get("status") != "pass":
            errors.append("attached SWE-Bench evidence manifest did not pass its own checks")
    elif kind == "progressive_validation":
        expected_hash = stable_json_hash(
            {k: v for k, v in manifest.items() if k not in {"manifest_hash", "manifest_path", "report_html"}}
        )
        if manifest.get("manifest_hash") != expected_hash:
            errors.append("manifest_hash does not match progressive validation manifest")
        if manifest.get("status") != "pass":
            errors.append("progressive validation manifest did not pass its own checks")
        if manifest.get("evidence_level") != "external_progressive_sample":
            errors.append("progressive validation evidence_level must be external_progressive_sample")
        if manifest.get("final_ready_eligible") is not False:
            errors.append("progressive validation manifest must not be final_ready eligible")
    else:
        errors.append(f"unknown manifest kind: {kind}")
    status = "pass" if not errors else "fail"
    return {
        "schema_version": "invart.external_evidence_verify.v0.44",
        "status": status,
        "manifest_path": str(manifest_path),
        "kind": kind,
        "evidence_level": manifest.get("evidence_level"),
        "summary": manifest.get("summary", {}),
        "claim_boundary": manifest.get("claim_boundary"),
        "errors": errors,
    }


def _failed_import(snapshot_path: Path, out_dir: Path, errors: list[str]) -> dict[str, Any]:
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "kind": "corpus_snapshot",
        "status": "fail",
        "snapshot_path": str(snapshot_path),
        "out_dir": str(out_dir),
        "errors": errors,
    }


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


def _verify_file_hash(path_value: Any, expected: Any, label: str, errors: list[str]) -> None:
    if not path_value:
        errors.append(f"{label} path missing")
        return
    path = Path(str(path_value))
    if not path.exists():
        errors.append(f"{label} artifact missing")
        return
    if sha256_file(path, prefixed=True) != expected:
        errors.append(f"{label} does not match artifact")


def _hash_path(path: Path) -> str:
    import hashlib

    if path.is_file():
        return sha256_file(path, prefixed=True)
    parts = []
    for child in sorted(item for item in path.rglob("*") if item.is_file()):
        parts.append(f"{child.relative_to(path)}:{sha256_file(child, prefixed=True)}")
    joined = "\n".join(parts)
    return f"sha256:{hashlib.sha256(joined.encode('utf-8')).hexdigest()}"
