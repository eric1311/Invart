from __future__ import annotations

from typing import Any


def summarize_side_effect_records(records: list[dict[str, Any]]) -> dict[str, Any]:
    detected = [record for record in records if record.get("side_effect_detected") is True]
    sources: set[str] = set()
    for record in records:
        source = record.get("ground_truth_source")
        if source:
            sources.add(str(source))
        for item in record.get("ground_truth_sources") or []:
            sources.add(str(item))
    return {
        "schema_version": "invart.p0_side_effect_summary.v0.1",
        "records": len(records),
        "detected": len(detected),
        "unchanged": len(records) - len(detected),
        "ground_truth_sources": sorted(sources),
    }
