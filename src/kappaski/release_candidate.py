from __future__ import annotations

import html
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from .artifacts import write_html_artifact, write_json_artifact
from .evidence_bundle import export_evidence_bundle, verify_evidence_bundle
from .pre_v1 import run_pre_v1_control_plane_demo
from .roadmap import verify_roadmap_coverage
from .models import utc_now


RC_SCHEMA_VERSION = "kappaski.release_candidate.v0.40"
DEFAULT_RC_BENCHMARKS = (
    "v0.25-adapter-runtime-integration",
    "v0.26-policy-as-code",
    "v0.27-enterprise-evidence-export",
    "v0.28-harness-expansion",
    "v0.30-control-plane-experiment-runner",
    "v0.31-external-ipi-control-plane",
    "v0.32-authority-dataflow-boundary",
    "v0.33-swebench-friction-control-plane",
    "v0.34-skill-supply-chain-control-plane",
    "v0.35-secure-coding-gate",
    "v0.36-coverage-truthfulness-matrix",
    "v0.37-llm-reviewer-selectivity",
    "v0.38-audit-tamper-assurance",
    "v0.39-paper-ready-experiment-suite",
    "v0.40-swe-bench-full-validation-contract",
    "pre-v1-control-plane",
)
DEFAULT_REQUIRED_DOCS = (
    "docs/v0.25-adapter-runtime-integration.html",
    "docs/v0.26-policy-as-code.html",
    "docs/v0.27-enterprise-evidence-export.html",
    "docs/v0.28-benchmark-harness-expansion.html",
    "docs/v0.29-release-candidate-gate.html",
    "docs/v0.30-experiment-case-runner.html",
    "docs/v0.31-external-ipi-control-plane.html",
    "docs/v0.32-authority-dataflow-boundary.html",
    "docs/v0.33-swebench-friction-track.html",
    "docs/v0.34-skill-supply-chain-track.html",
    "docs/v0.35-secure-coding-gate.html",
    "docs/v0.36-coverage-truthfulness-matrix.html",
    "docs/v0.37-llm-reviewer-selectivity.html",
    "docs/v0.38-audit-tamper-assurance.html",
    "docs/v0.39-paper-ready-experiment-suite.html",
    "docs/v0.40-swe-bench-full-validation-contract.html",
    "docs/roadmap.html",
    "docs/user-guide.html",
    "docs/architecture.html",
    "docs/full-product-readiness.html",
    "docs/implementation-audit-v0.1-v0.39.html",
)


def verify_release_candidate(
    out_dir: Path,
    *,
    run_pytest: bool = True,
    required_docs: list[Path] | None = None,
    benchmark_suites: list[str] | None = None,
) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    checks: dict[str, Any] = {}
    checks["pytest"] = _run_pytest() if run_pytest else {"status": "skipped", "reason": "disabled by caller"}
    docs = required_docs or [Path(item) for item in DEFAULT_REQUIRED_DOCS]
    checks["docs"] = _check_docs(docs)
    roadmap = verify_roadmap_coverage(require_full=True)
    checks["roadmap_full"] = {"status": "pass" if roadmap.get("passed") else "fail", "report": roadmap}
    claim_findings = roadmap.get("claim_integrity_findings", [])
    checks["claim_integrity"] = {
        "status": "pass" if not claim_findings else "fail",
        "summary": {"findings": len(claim_findings)},
        "findings": claim_findings,
    }
    external_validation = verify_roadmap_coverage(require_external_validation=True)
    external_gaps = external_validation.get("external_validation_gaps", [])
    checks["external_validation"] = {
        "status": "pass" if not external_gaps else "skipped",
        "summary": {"gaps": len(external_gaps)},
        "reason": "external/live benchmark validation is optional for local RC and must not be reported as completed when it was not run",
        "gaps": [
            {
                "version": item.get("version"),
                "capability_id": item.get("capability_id"),
                "external_validation": item.get("external_validation"),
                "evidence_level": item.get("evidence_level"),
                "next_step": item.get("next_step"),
            }
            for item in external_gaps
        ],
    }
    checks["benchmarks"] = _run_benchmarks(list(benchmark_suites or DEFAULT_RC_BENCHMARKS))
    demo = run_pre_v1_control_plane_demo(out_dir / "demo")
    evidence = export_evidence_bundle(Path(demo["artifacts"]["ledger"]), out_dir / "evidence", profile={"name": "rc", "mode": "managed"})
    evidence_verify = verify_evidence_bundle(Path(evidence["manifest_path"]))
    checks["artifact_completeness"] = {
        "status": "pass" if demo.get("status") == "pass" and evidence_verify.get("status") == "pass" else "fail",
        "demo": demo,
        "evidence": evidence,
        "evidence_verify": evidence_verify,
    }
    status = "pass" if all(item.get("status") in {"pass", "skipped"} for item in checks.values()) and checks["docs"]["status"] == "pass" and checks["roadmap_full"]["status"] == "pass" and checks["benchmarks"]["status"] == "pass" and checks["artifact_completeness"]["status"] == "pass" else "fail"
    report = {
        "schema_version": RC_SCHEMA_VERSION,
        "status": status,
        "generated_at": utc_now(),
        "checks": checks,
        "summary": {
            "checks": len(checks),
            "failed": sum(1 for item in checks.values() if item.get("status") == "fail"),
            "skipped": sum(1 for item in checks.values() if item.get("status") == "skipped"),
        },
        "artifacts": {},
    }
    report_json = out_dir / "release-candidate-report.json"
    report_html = out_dir / "release-candidate-report.html"
    report["artifacts"] = {"report_json": str(report_json), "report_html": str(report_html)}
    write_json_artifact(report_json, report)
    write_html_artifact(report_html, _rc_html(report))
    return report


def _run_pytest() -> dict[str, Any]:
    env = dict(os.environ)
    env["PYTHONPATH"] = "src" + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", "-q"],
        check=False,
        cwd=str(Path.cwd()),
        env=env,
        capture_output=True,
        text=True,
    )
    return {
        "status": "pass" if completed.returncode == 0 else "fail",
        "returncode": completed.returncode,
        "stdout_tail": completed.stdout[-4000:],
        "stderr_tail": completed.stderr[-4000:],
    }


def _check_docs(required_docs: list[Path]) -> dict[str, Any]:
    missing = [str(path) for path in required_docs if not path.exists()]
    return {"status": "pass" if not missing else "fail", "required": [str(path) for path in required_docs], "missing": missing}


def _run_benchmarks(suites: list[str]) -> dict[str, Any]:
    from .evals import run_benchmark

    results = []
    for suite in suites:
        try:
            result = run_benchmark(suite)
        except Exception as exc:
            results.append({"suite": suite, "status": "fail", "error": str(exc)})
            continue
        passed = result.get("passed") is True or result.get("summary", {}).get("passed") == result.get("summary", {}).get("total")
        results.append({"suite": suite, "status": "pass" if passed else "fail", "result": result})
    failed = sum(1 for item in results if item["status"] != "pass")
    return {"status": "pass" if failed == 0 else "fail", "results": results, "summary": {"total": len(results), "failed": failed}}


def _rc_html(report: dict[str, Any]) -> str:
    sections = "".join(
        f"<section><h2>{html.escape(name)}</h2><pre>{html.escape(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))}</pre></section>"
        for name, payload in report.get("checks", {}).items()
    )
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Kappaski v0.40 RC Gate</title><style>body{{font-family:Inter,Arial,sans-serif;margin:0;background:#f8fafc;color:#172033}}main{{max-width:1160px;margin:0 auto;padding:34px 24px}}section{{background:#fff;border:1px solid #dce4ef;border-radius:8px;padding:16px;margin:14px 0}}pre{{background:#111827;color:#e5e7eb;padding:14px;border-radius:8px;overflow:auto}}.status{{font-weight:700}}</style></head><body><main><h1>Kappaski v0.40 Release Candidate Gate</h1><p class="status">Status: {html.escape(str(report.get("status")))}</p>{sections}</main></body></html>"""


__all__ = ["verify_release_candidate"]
