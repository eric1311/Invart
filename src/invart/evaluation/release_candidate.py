from __future__ import annotations

import html
import json
import os
import shutil
import struct
import subprocess
import sys
from pathlib import Path
from typing import Any

from invart.core.artifacts import write_html_artifact, write_json_artifact
from invart.assurance.evidence_bundle import export_evidence_bundle, verify_evidence_bundle
from invart.evaluation.external_evidence import verify_external_evidence
from invart.evaluation.pre_1_0 import run_pre_1_0_final_demo
from invart.evaluation.pre_v1 import run_pre_v1_control_plane_demo
from invart.evaluation.roadmap import verify_roadmap_coverage
from invart.core.models import utc_now


RC_SCHEMA_VERSION = "invart.release_candidate.v0.45"
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
    "v0.41-unmanaged-agent-inventory",
    "v0.42-managed-launcher-migration",
    "v0.43-enterprise-coverage-gate",
    "v0.44-external-evidence-and-swebench",
    "v0.45-final-demo-and-rc-gate",
    "progressive-external-validation",
    "pre-v1-control-plane",
)
DEFAULT_REQUIRED_DOCS = (
    "README.md",
    "LICENSE",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "CHANGELOG.md",
    "docs/README.md",
    "docs/index.md",
    "docs/product.md",
    "docs/quickstart.md",
    "docs/concepts.md",
    "docs/cli-reference.md",
    "docs/api-sdk.md",
    "docs/examples.md",
    "docs/runtime-effect-demo.md",
    "docs/architecture.md",
    "docs/evaluation.md",
    "docs/open-source-boundary.md",
    "docs/release-history.md",
    "docs/html/index.html",
    "docs/html/product.html",
    "docs/html/quickstart.html",
    "docs/html/concepts.html",
    "docs/html/cli-reference.html",
    "docs/html/api-sdk.html",
    "docs/html/examples.html",
    "docs/html/runtime-effect-demo.html",
    "docs/html/architecture.html",
    "docs/html/evaluation.html",
    "docs/html/open-source-boundary.html",
    "docs/html/release-history.html",
    "docs/html/style.css",
)
DEFAULT_REQUIRED_BRAND_ASSETS = {
    "assets/brand/png-from-original/invart-logo-original-master-1774x887.png": (1774, 887),
    "assets/brand/png-from-original/invart-logo-horizontal-1600x800.png": (1600, 800),
    "assets/brand/png-from-original/invart-logo-docs-header-1200x400.png": (1200, 400),
    "assets/brand/png-from-original/invart-logo-og-1600x900.png": (1600, 900),
    "assets/brand/png-from-original/invart-logo-square-preview-1024x1024.png": (1024, 1024),
    "assets/brand/png-from-original/invart-mark-from-original-512x512.png": (512, 512),
    "assets/brand/png-from-original/invart-mark-from-original-64x64.png": (64, 64),
}


def verify_release_candidate(
    out_dir: Path,
    *,
    run_pytest: bool = True,
    required_docs: list[Path] | None = None,
    benchmark_suites: list[str] | None = None,
    final: bool = False,
    require_external_validation: bool = False,
    external_evidence_manifest: Path | None = None,
) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    checks: dict[str, Any] = {}
    checks["pytest"] = _run_pytest() if run_pytest else {"status": "skipped", "reason": "disabled by caller"}
    docs = required_docs or [Path(item) for item in DEFAULT_REQUIRED_DOCS]
    checks["docs"] = _check_docs(docs)
    checks["brand_assets"] = _check_brand_assets(DEFAULT_REQUIRED_BRAND_ASSETS)
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
    final_readiness = _final_readiness(
        out_dir,
        final=final,
        require_external_validation=require_external_validation,
        external_evidence_manifest=external_evidence_manifest,
        checks=checks,
    )
    checks.update(final_readiness["checks"])
    local_checks_pass = (
        all(item.get("status") in {"pass", "skipped"} for item in checks.values())
        and checks["docs"]["status"] == "pass"
        and checks["roadmap_full"]["status"] == "pass"
        and checks["benchmarks"]["status"] == "pass"
        and checks["artifact_completeness"]["status"] == "pass"
    )
    external_required_missing = require_external_validation and not final_readiness["final_readiness"].get("external_final_eligible")
    status = "pass" if local_checks_pass and not external_required_missing else "fail"
    report = {
        "schema_version": RC_SCHEMA_VERSION,
        "status": status,
        "generated_at": utc_now(),
        "checks": checks,
        "final_readiness": final_readiness["final_readiness"],
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


def _final_readiness(
    out_dir: Path,
    *,
    final: bool,
    require_external_validation: bool,
    external_evidence_manifest: Path | None,
    checks: dict[str, Any],
) -> dict[str, Any]:
    if external_evidence_manifest:
        external_evidence = verify_external_evidence(external_evidence_manifest)
    else:
        external_evidence = {
            "schema_version": "invart.external_evidence_verify.v0.44",
            "status": "skipped",
            "reason": "no external evidence manifest was attached",
            "evidence_level": "not_attached",
        }
    external_final_eligible = _external_evidence_final_eligible(external_evidence)
    final_checks: dict[str, Any] = {"external_evidence": external_evidence}
    if final:
        final_demo = run_pre_1_0_final_demo(out_dir / "final-demo", external_evidence_manifest=external_evidence_manifest)
        final_checks["final_demo"] = {
            "status": "pass" if final_demo.get("status") == "pass" else "fail",
            "report": final_demo,
        }
    local_failures = [
        name
        for name, payload in checks.items()
        if payload.get("status") == "fail"
    ] + [
        name
        for name, payload in final_checks.items()
        if payload.get("status") == "fail"
    ]
    if final and external_final_eligible and not local_failures:
        state = "final_ready"
    elif final:
        state = "external_pending" if not external_final_eligible else "local_gate_failed"
    else:
        state = "local_rc_ready" if not local_failures else "local_gate_failed"
    if require_external_validation and not external_final_eligible:
        state = "external_pending"
    final_readiness = {
        "schema_version": "invart.final_readiness.v0.45",
        "state": state,
        "final_mode": final,
        "requires_external_validation": require_external_validation,
        "external_evidence_status": external_evidence.get("status"),
        "external_evidence_kind": external_evidence.get("kind"),
        "external_evidence_level": external_evidence.get("evidence_level"),
        "external_final_eligible": external_final_eligible,
        "local_failures": local_failures,
        "claim_boundary": "Invart only reports final_ready when local RC checks pass and an attached external_live_run SWE-Bench full evidence manifest verifies.",
    }
    return {"checks": final_checks, "final_readiness": final_readiness}


def _external_evidence_final_eligible(external_evidence: dict[str, Any]) -> bool:
    return (
        external_evidence.get("status") == "pass"
        and external_evidence.get("kind") == "swe_bench_full"
        and external_evidence.get("evidence_level") == "external_live_run"
    )


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
    command = [sys.executable, "-m", "pytest", "-q"]
    if completed.returncode != 0 and "No module named pytest" in completed.stderr and shutil.which("uv"):
        command = ["uv", "run", "--with", "pytest", "pytest", "-q"]
        completed = subprocess.run(
            command,
            check=False,
            cwd=str(Path.cwd()),
            env=env,
            capture_output=True,
            text=True,
        )
    return {
        "status": "pass" if completed.returncode == 0 else "fail",
        "command": command,
        "returncode": completed.returncode,
        "stdout_tail": completed.stdout[-4000:],
        "stderr_tail": completed.stderr[-4000:],
    }


def _check_docs(required_docs: list[Path]) -> dict[str, Any]:
    missing = [str(path) for path in required_docs if not path.exists()]
    return {"status": "pass" if not missing else "fail", "required": [str(path) for path in required_docs], "missing": missing}


def _check_brand_assets(required_assets: dict[str, tuple[int, int]]) -> dict[str, Any]:
    checked: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []
    for raw_path, expected_dimensions in required_assets.items():
        path = Path(raw_path)
        item: dict[str, Any] = {
            "path": raw_path,
            "expected_dimensions": list(expected_dimensions),
        }
        if not path.exists():
            item["status"] = "missing"
            failed.append(item)
            checked.append(item)
            continue
        try:
            actual_dimensions = _png_dimensions(path)
        except Exception as exc:
            item["status"] = "invalid"
            item["error"] = str(exc)
            failed.append(item)
            checked.append(item)
            continue
        item["actual_dimensions"] = list(actual_dimensions)
        item["status"] = "pass" if actual_dimensions == expected_dimensions else "dimension_mismatch"
        if item["status"] != "pass":
            failed.append(item)
        checked.append(item)
    return {
        "status": "pass" if not failed else "fail",
        "checked": checked,
        "failed": failed,
    }


def _png_dimensions(path: Path) -> tuple[int, int]:
    with path.open("rb") as handle:
        signature = handle.read(8)
        if signature != b"\x89PNG\r\n\x1a\n":
            raise ValueError("not a PNG file")
        length = struct.unpack(">I", handle.read(4))[0]
        chunk_type = handle.read(4)
        if length != 13 or chunk_type != b"IHDR":
            raise ValueError("missing PNG IHDR")
        return struct.unpack(">II", handle.read(8))


def _run_benchmarks(suites: list[str]) -> dict[str, Any]:
    from invart.evaluation.evals import run_benchmark

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
    final = report.get("final_readiness", {})
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Invart Pre-1.0 RC Gate</title><style>body{{font-family:Inter,Arial,sans-serif;margin:0;background:#f8fafc;color:#172033}}main{{max-width:1160px;margin:0 auto;padding:34px 24px}}section{{background:#fff;border:1px solid #dce4ef;border-radius:8px;padding:16px;margin:14px 0}}pre{{background:#111827;color:#e5e7eb;padding:14px;border-radius:8px;overflow:auto}}.status{{font-weight:700}}</style></head><body><main><h1>Invart Pre-1.0 Release Candidate Gate</h1><p class="status">Status: {html.escape(str(report.get("status")))}</p><p>Final readiness: <strong>{html.escape(str(final.get("state", "unknown")))}</strong></p>{sections}</main></body></html>"""


__all__ = ["verify_release_candidate"]
