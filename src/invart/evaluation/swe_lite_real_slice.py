from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from invart.core.artifacts import sha256_file, stable_json_hash, write_html_artifact, write_json_artifact


SCHEMA_VERSION = "invart.swe_bench_lite_real_slice.v0.1"


def build_swe_bench_lite_real_slice_summary(
    *,
    rows_path: Path,
    report_path: Path,
    instance_results_path: Path,
    predictions_path: Path,
    logs_path: Path,
    out_dir: Path,
) -> dict[str, Any]:
    rows_path = rows_path.expanduser().resolve()
    report_path = report_path.expanduser().resolve()
    instance_results_path = instance_results_path.expanduser().resolve()
    predictions_path = predictions_path.expanduser().resolve()
    logs_path = logs_path.expanduser().resolve()
    out_dir = out_dir.expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    rows_payload = _load_json(rows_path)
    report = _load_json(report_path)
    instance_results = _load_jsonl(instance_results_path)
    predictions = _load_jsonl(predictions_path)
    row_items = rows_payload.get("rows") if isinstance(rows_payload.get("rows"), list) else []
    rows = [_row_payload(item) for item in row_items if isinstance(_row_payload(item), dict)]
    rows_by_id = {str(row.get("instance_id")): row for row in rows if row.get("instance_id")}
    result_ids = [str(item.get("instance_id")) for item in instance_results if item.get("instance_id")]
    prediction_ids = [str(item.get("instance_id")) for item in predictions if item.get("instance_id")]
    completed_ids = [str(item) for item in report.get("completed_ids", [])] if isinstance(report.get("completed_ids"), list) else []
    log_ids = sorted(path.stem for path in logs_path.glob("*.log")) if logs_path.is_dir() else []

    checks = {
        "rows_present": bool(rows),
        "rows_total_declared": int(rows_payload.get("num_rows_total") or 0) >= len(rows),
        "report_present": bool(report),
        "instance_results_present": bool(instance_results),
        "predictions_present": bool(predictions),
        "logs_present": logs_path.exists() and bool(log_ids),
        "completed_matches_rows": sorted(completed_ids) == sorted(rows_by_id),
        "instance_results_match_rows": sorted(result_ids) == sorted(rows_by_id),
        "predictions_match_rows": sorted(prediction_ids) == sorted(rows_by_id),
        "logs_match_rows": sorted(log_ids) == sorted(rows_by_id),
        "error_instances_zero": int(report.get("error_instances") or 0) == 0,
    }
    repos: dict[str, int] = {}
    for row in rows:
        repo = str(row.get("repo") or "unknown")
        repos[repo] = repos.get(repo, 0) + 1
    summary = {
        "schema_version": SCHEMA_VERSION,
        "status": "pass" if all(checks.values()) else "fail",
        "source": "SWE-bench/SWE-bench_Lite Hugging Face rows API",
        "source_url": rows_payload.get("source_url") or report.get("source_url"),
        "rows_path": _display_path(rows_path),
        "report_path": _display_path(report_path),
        "instance_results_path": _display_path(instance_results_path),
        "predictions_path": _display_path(predictions_path),
        "logs_path": _display_path(logs_path),
        "hashes": {
            "rows": sha256_file(rows_path, prefixed=True) if rows_path.exists() else None,
            "report": sha256_file(report_path, prefixed=True) if report_path.exists() else None,
            "instance_results": sha256_file(instance_results_path, prefixed=True) if instance_results_path.exists() else None,
            "predictions": sha256_file(predictions_path, prefixed=True) if predictions_path.exists() else None,
            "logs": _hash_logs(logs_path) if logs_path.exists() else None,
        },
        "checks": checks,
        "summary": {
            "rows_total": int(rows_payload.get("num_rows_total") or 0),
            "rows_fetched": len(rows),
            "completed_instances": int(report.get("completed_instances") or 0),
            "error_instances": int(report.get("error_instances") or 0),
            "resolved_instances": int(report.get("resolved_instances") or 0),
            "unresolved_instances": int(report.get("unresolved_instances") or 0),
            "prediction_rows": len(predictions),
            "instance_result_rows": len(instance_results),
            "log_files": len(log_ids),
            "repos": dict(sorted(repos.items())),
            "instance_ids": sorted(rows_by_id),
        },
        "claim_boundary": (
            "This artifact validates a real SWE-Bench Lite rows slice and attached local metadata/prediction/log "
            "artifacts for evidence-pipeline completeness. It is not an official SWE-Bench grading run, resolved-rate "
            "claim, or provider task-solving result."
        ),
    }
    summary["summary_hash"] = stable_json_hash(summary)
    summary_path = out_dir / "summary.json"
    html_path = out_dir / "summary.html"
    write_json_artifact(summary_path, summary)
    write_html_artifact(html_path, _summary_html(summary))
    summary["artifacts"] = {"summary_json": _display_path(summary_path), "summary_html": _display_path(html_path)}
    write_json_artifact(summary_path, summary)
    return summary


def _row_payload(item: dict[str, Any]) -> dict[str, Any]:
    row = item.get("row")
    return row if isinstance(row, dict) else item


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    loaded = json.loads(path.read_text(encoding="utf-8"))
    return loaded if isinstance(loaded, dict) else {}


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        loaded = json.loads(line)
        if isinstance(loaded, dict):
            rows.append(loaded)
    return rows


def _hash_logs(path: Path) -> str:
    import hashlib

    parts = []
    if path.is_file():
        return sha256_file(path, prefixed=True)
    for item in sorted(path.glob("*.log")):
        parts.append(f"{item.name}:{sha256_file(item, prefixed=True)}")
    return "sha256:" + hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()


def _display_path(path: Path) -> str:
    try:
        return str(path.relative_to(Path.cwd()))
    except ValueError:
        return str(path)


def _summary_html(summary: dict[str, Any]) -> str:
    checks = "".join(
        f"<tr><td>{html.escape(key)}</td><td>{'pass' if value else 'fail'}</td></tr>"
        for key, value in summary.get("checks", {}).items()
    )
    instances = "".join(f"<li>{html.escape(item)}</li>" for item in summary.get("summary", {}).get("instance_ids", []))
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>SWE-Bench Lite Real Slice</title>
<style>body{{font-family:Inter,Arial,sans-serif;margin:32px;color:#172033}}table{{border-collapse:collapse}}td,th{{border:1px solid #d6dde8;padding:6px 8px;text-align:left}}th{{background:#f3f6fb}}</style></head>
<body><h1>SWE-Bench Lite Real Slice</h1>
<p>Status: <strong>{html.escape(str(summary.get("status")))}</strong></p>
<p>{html.escape(str(summary.get("claim_boundary")))}</p>
<h2>Summary</h2><pre>{html.escape(json.dumps(summary.get("summary", {}), ensure_ascii=False, indent=2, sort_keys=True))}</pre>
<h2>Checks</h2><table><tr><th>Check</th><th>Status</th></tr>{checks}</table>
<h2>Instances</h2><ul>{instances}</ul></body></html>"""


__all__ = ["SCHEMA_VERSION", "build_swe_bench_lite_real_slice_summary"]
