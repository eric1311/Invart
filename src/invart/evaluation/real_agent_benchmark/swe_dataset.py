from __future__ import annotations

import json
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from invart.core.artifacts import sha256_file, write_json_artifact
from invart.core.models import utc_now


SWE_VERIFIED_DATASET = "SWE-bench/SWE-bench_Verified"
DATASETS_SERVER_ROWS_URL = "https://datasets-server.huggingface.co/rows"


def swe_instance_ids_from_manifest(manifest: dict[str, Any]) -> list[str]:
    ids: list[str] = []
    for case in manifest.get("cases", []):
        if not isinstance(case, dict) or case.get("family") != "swe_bench_verified":
            continue
        ref = str(case.get("benchmark_case_ref") or "")
        instance_id = ref.rsplit(":", 1)[-1] if ":" in ref else ref
        if instance_id and instance_id not in ids:
            ids.append(instance_id)
    return ids


def export_swe_bench_verified_instance_rows(
    *,
    instance_ids: list[str],
    out_dir: Path,
    dataset: str = SWE_VERIFIED_DATASET,
    config: str = "default",
    split: str = "test",
    rows_json: Path | None = None,
    page_size: int = 100,
    max_rows: int = 1000,
) -> dict[str, Any]:
    root = out_dir.expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    wanted = [item for item in instance_ids if item]
    rows, source = _load_rows(
        dataset=dataset,
        config=config,
        split=split,
        rows_json=rows_json,
        page_size=page_size,
        max_rows=max_rows,
        wanted=set(wanted),
    )
    by_id: dict[str, dict[str, Any]] = {}
    for row in rows:
        instance = _normalize_row(row)
        instance_id = str(instance.get("instance_id") or "")
        if instance_id in wanted:
            by_id[instance_id] = instance

    artifacts: dict[str, str] = {}
    missing = [instance_id for instance_id in wanted if instance_id not in by_id]
    for instance_id in wanted:
        instance = by_id.get(instance_id)
        if instance is None:
            continue
        wrapped = {
            "schema_version": "invart.p0_swe_official_instance_row.v0.1",
            "generated_at": utc_now(),
            "dataset": dataset,
            "config": config,
            "split": split,
            "source": source,
            "row": instance,
            "claim_boundary": (
                "This file is a copied official SWE-Bench dataset row used to prepare an agent workspace. "
                "It is not a grader result and does not establish resolved/unresolved status."
            ),
        }
        target = root / f"{instance_id}.json"
        write_json_artifact(target, wrapped)
        artifacts[instance_id] = str(target)

    report = {
        "schema_version": "invart.p0_swe_instance_export.v0.1",
        "generated_at": utc_now(),
        "status": "pass" if not missing else "fail",
        "dataset": dataset,
        "config": config,
        "split": split,
        "source": source,
        "requested_instance_ids": wanted,
        "exported_instance_ids": sorted(artifacts),
        "missing_instance_ids": missing,
        "artifacts": artifacts,
        "source_rows_json_sha256": sha256_file(rows_json.expanduser().resolve(), prefixed=True) if rows_json else None,
        "claim_boundary": (
            "SWE instance export only materializes official dataset rows for later workspace preparation. "
            "Benchmark utility claims still require the official SWE-Bench harness report."
        ),
    }
    write_json_artifact(root / "p0_swe_instance_export.json", report)
    return report


def export_swe_bench_verified_instances_from_manifest(
    *,
    manifest: dict[str, Any],
    out_dir: Path,
    dataset: str = SWE_VERIFIED_DATASET,
    config: str = "default",
    split: str = "test",
    rows_json: Path | None = None,
    page_size: int = 100,
    max_rows: int = 1000,
) -> dict[str, Any]:
    return export_swe_bench_verified_instance_rows(
        instance_ids=swe_instance_ids_from_manifest(manifest),
        out_dir=out_dir,
        dataset=dataset,
        config=config,
        split=split,
        rows_json=rows_json,
        page_size=page_size,
        max_rows=max_rows,
    )


def _load_rows(
    *,
    dataset: str,
    config: str,
    split: str,
    rows_json: Path | None,
    page_size: int,
    max_rows: int,
    wanted: set[str],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if rows_json is not None:
        resolved = rows_json.expanduser().resolve()
        payload = json.loads(resolved.read_text(encoding="utf-8"))
        rows = payload.get("rows", payload) if isinstance(payload, dict) else payload
        if not isinstance(rows, list):
            raise ValueError("--rows-json must contain a list or an object with a rows list")
        return [row for row in rows if isinstance(row, dict)], {"kind": "local_rows_json", "path": str(resolved)}

    collected: list[dict[str, Any]] = []
    offset = 0
    total: int | None = None
    while offset < max_rows:
        url = DATASETS_SERVER_ROWS_URL + "?" + urllib.parse.urlencode(
            {
                "dataset": dataset,
                "config": config,
                "split": split,
                "offset": offset,
                "length": page_size,
            }
        )
        with urllib.request.urlopen(url, timeout=60) as response:
            payload = json.load(response)
        page = payload.get("rows", [])
        if not isinstance(page, list) or not page:
            break
        collected.extend(row for row in page if isinstance(row, dict))
        total = int(payload.get("num_rows_total") or total or len(collected))
        found = {str(_normalize_row(row).get("instance_id") or "") for row in collected}
        if wanted.issubset(found):
            break
        offset += page_size
        if total is not None and offset >= total:
            break
    return collected, {
        "kind": "huggingface_datasets_server",
        "url": DATASETS_SERVER_ROWS_URL,
        "dataset": dataset,
        "config": config,
        "split": split,
        "rows_scanned": len(collected),
        "total_rows": total,
    }


def _normalize_row(row: dict[str, Any]) -> dict[str, Any]:
    nested = row.get("row")
    if isinstance(nested, dict):
        return dict(nested)
    return dict(row)
