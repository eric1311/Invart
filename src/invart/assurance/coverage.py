from __future__ import annotations

from dataclasses import dataclass, field
import html
import json
from pathlib import Path
from typing import Any

from invart.core.artifacts import write_html_artifact

COVERAGE_GRADES = ("none", "declared", "observed", "mediated", "enforced")


def _rank(grade: str) -> int:
    if grade not in COVERAGE_GRADES:
        raise ValueError(f"unknown coverage grade: {grade}")
    return COVERAGE_GRADES.index(grade)


def _stronger(left: str, right: str) -> str:
    return left if _rank(left) >= _rank(right) else right


@dataclass
class CoverageRecord:
    preflight_visibility: str = "none"
    runtime_observation: str = "none"
    runtime_enforcement: str = "none"
    postruntime_audit: str = "none"
    observed_by: list[str] = field(default_factory=list)
    enforced_by: list[str] = field(default_factory=list)
    degraded_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "preflight_visibility": self.preflight_visibility,
            "runtime_observation": self.runtime_observation,
            "runtime_enforcement": self.runtime_enforcement,
            "postruntime_audit": self.postruntime_audit,
            "observed_by": list(self.observed_by),
            "enforced_by": list(self.enforced_by),
            "coverage_grade": {
                "preflight_visibility": self.preflight_visibility,
                "runtime_observation": self.runtime_observation,
                "runtime_enforcement": self.runtime_enforcement,
                "postruntime_audit": self.postruntime_audit,
            },
            "degraded_reason": self.degraded_reason,
        }


def default_coverage_for_layer(layer: str) -> CoverageRecord:
    if layer in {"native_hook", "native_plugin", "mcp_broker"}:
        return CoverageRecord(
            preflight_visibility="declared",
            runtime_observation="mediated",
            runtime_enforcement="mediated",
            postruntime_audit="observed",
            observed_by=[layer],
        )
    if layer in {"shell_wrapper", "rust_shim", "sandbox"}:
        return CoverageRecord(
            preflight_visibility="observed",
            runtime_observation="mediated",
            runtime_enforcement="enforced",
            postruntime_audit="observed",
            enforced_by=[layer],
        )
    if layer in {"agent_log", "audit_import"}:
        return CoverageRecord(runtime_observation="observed", postruntime_audit="observed", observed_by=[layer])
    return CoverageRecord(degraded_reason=f"unknown coverage layer: {layer}")


def merge_coverage_records(records: list[CoverageRecord]) -> CoverageRecord:
    merged = CoverageRecord()
    for record in records:
        merged.preflight_visibility = _stronger(merged.preflight_visibility, record.preflight_visibility)
        merged.runtime_observation = _stronger(merged.runtime_observation, record.runtime_observation)
        merged.runtime_enforcement = _stronger(merged.runtime_enforcement, record.runtime_enforcement)
        merged.postruntime_audit = _stronger(merged.postruntime_audit, record.postruntime_audit)
        for source in record.observed_by:
            if source not in merged.observed_by:
                merged.observed_by.append(source)
        for source in record.enforced_by:
            if source not in merged.enforced_by:
                merged.enforced_by.append(source)
        if record.degraded_reason and not merged.degraded_reason:
            merged.degraded_reason = record.degraded_reason
    return merged


def coverage_meets_requirement(record: CoverageRecord, requirements: dict[str, str]) -> bool:
    for dimension, minimum in requirements.items():
        actual = getattr(record, dimension)
        if _rank(actual) < _rank(minimum):
            return False
    return True


def evaluate_coverage_gate(coverage: dict[str, Any], *, profile: dict[str, Any] | None = None) -> dict[str, Any]:
    profile = profile or {}
    mode = str(profile.get("mode") or "audit")
    allow_unmanaged = bool(profile.get("allow_unmanaged", True))
    profile_coverage = profile.get("coverage") if isinstance(profile.get("coverage"), dict) else {}
    required_runtime = str(
        profile.get("required_runtime_enforcement")
        or profile.get("runtime_enforcement")
        or ("mediated" if profile_coverage.get("require_runtime_mediation") else "none")
    )
    runtime_layer = coverage.get("runtime") if isinstance(coverage.get("runtime"), dict) else {}
    actual_runtime = str(
        coverage.get("runtime_enforcement")
        or runtime_layer.get("enforcement")
        or runtime_layer.get("runtime_enforcement")
        or "none"
    )
    actual_observation = str(
        coverage.get("runtime_observation")
        or runtime_layer.get("observation")
        or runtime_layer.get("runtime_observation")
        or "none"
    )
    findings: list[dict[str, Any]] = []
    failure_status = "warn" if mode in {"audit", "advisory"} else "fail"
    unmanaged_detected = bool(coverage.get("unmanaged_detected")) or actual_runtime == "unmanaged" or actual_observation == "unmanaged"
    if unmanaged_detected and not allow_unmanaged:
        findings.append(
            {
                "check_id": "coverage.unmanaged_detected",
                "severity": "high" if failure_status == "fail" else "medium",
                "effect": "fail" if failure_status == "fail" else "warn",
                "message": "unmanaged agent surface detected",
            }
        )
    if required_runtime != "none":
        if actual_runtime == "unmanaged" or actual_observation == "unmanaged":
            findings.append(
                {
                    "check_id": "coverage.runtime_unmanaged",
                    "severity": "high" if failure_status == "fail" else "medium",
                    "effect": "fail" if failure_status == "fail" else "warn",
                    "required": required_runtime,
                    "actual": actual_runtime,
                    "message": "runtime path is unmanaged and cannot satisfy mediated coverage requirements",
                }
            )
            meets = False
        elif actual_runtime == "vendor_owned":
            meets = False
        elif actual_runtime in COVERAGE_GRADES and required_runtime in COVERAGE_GRADES:
            meets = _rank(actual_runtime) >= _rank(required_runtime)
        else:
            meets = False
        if not meets:
            findings.append(
                {
                    "check_id": "coverage.runtime_enforcement_insufficient",
                    "severity": "high" if failure_status == "fail" else "medium",
                    "effect": "fail" if failure_status == "fail" else "warn",
                    "required": required_runtime,
                    "actual": actual_runtime,
                    "message": "runtime enforcement coverage is below profile requirement",
                }
            )
    status = "pass"
    if findings:
        status = "fail" if any(item["effect"] == "fail" for item in findings) else "warn"
    return {
        "schema_version": "invart.coverage_gate.v0.43",
        "status": status,
        "mode": mode,
        "coverage": dict(coverage),
        "profile": dict(profile),
        "findings": findings,
        "summary": {"findings": len(findings)},
    }


def export_coverage_html_report(proof_path: Path, output_path: Path) -> dict[str, Any]:
    proof = json.loads(proof_path.read_text(encoding="utf-8"))
    coverage = proof.get("coverage", {}) if isinstance(proof.get("coverage"), dict) else {}
    summary = coverage.get("summary", {}) if isinstance(coverage.get("summary"), dict) else {}
    events = coverage.get("events", []) if isinstance(coverage.get("events"), list) else []
    dimensions = ("preflight_visibility", "runtime_observation", "runtime_enforcement", "postruntime_audit")
    rows = []
    for dimension in dimensions:
        bucket = summary.get(dimension, {}) if isinstance(summary.get(dimension), dict) else {}
        cells = "".join(f"<td>{html.escape(str(bucket.get(grade, 0)))}</td>" for grade in COVERAGE_GRADES)
        rows.append(f"<tr><th>{html.escape(dimension)}</th>{cells}</tr>")
    event_rows = "".join(
        "<tr>"
        f"<td>{html.escape(str(item.get('invocation_id', '')))}</td>"
        f"<td>{html.escape(str(item.get('runtime_observation', '')))}</td>"
        f"<td>{html.escape(str(item.get('runtime_enforcement', '')))}</td>"
        f"<td>{html.escape(', '.join(str(x) for x in item.get('observed_by', [])))}</td>"
        f"<td>{html.escape(', '.join(str(x) for x in item.get('enforced_by', [])))}</td>"
        "</tr>"
        for item in events
        if isinstance(item, dict)
    )
    grade_headers = "".join(f"<th>{html.escape(grade)}</th>" for grade in COVERAGE_GRADES)
    document = f"""<!doctype html><html><head><meta charset="utf-8"><title>Coverage Matrix</title><style>
body{{font-family:Inter,Arial,sans-serif;margin:0;background:#f7f7f4;color:#1f2933}}.wrap{{max-width:1100px;margin:0 auto;padding:40px 24px}}table{{width:100%;border-collapse:collapse;background:#fff;border:1px solid #ddd8cc;margin:16px 0}}td,th{{border-bottom:1px solid #e6e0d4;padding:10px;text-align:left}}code{{background:#17202a;color:#eef4f8;padding:2px 5px;border-radius:4px}}</style></head><body><main class="wrap"><h1>Coverage Matrix</h1><p>Proof-derived visibility, observation, enforcement, and audit coverage.</p><table><tr><th>Dimension</th>{grade_headers}</tr>{''.join(rows)}</table><h2>Events</h2><table><tr><th>Invocation</th><th>runtime_observation</th><th>runtime_enforcement</th><th>Observed By</th><th>Enforced By</th></tr>{event_rows}</table></main></body></html>"""
    write_html_artifact(output_path, document)
    return {
        "schema_version": "invart.coverage_html.v0.18",
        "status": "pass",
        "proof": str(proof_path),
        "output": str(output_path),
        "summary": {"events": len(events)},
    }
