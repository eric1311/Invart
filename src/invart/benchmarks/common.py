from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from invart.evaluation.experiment_cases import run_experiment_suite, run_paper_suite



def _run_paper_ready_experiment_benchmark() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="invart_v039_") as tmp:
        return run_direct_experiment_benchmark(run_paper_suite(Path(tmp) / "paper"), "v0.39-paper-ready-experiment-suite")



def run_experiment_benchmark(experiment_suite: str, benchmark_suite: str) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix=f"invart_{benchmark_suite}_") as tmp:
        result = run_experiment_suite(experiment_suite, out_dir=Path(tmp) / "run")
        return run_direct_experiment_benchmark(result, benchmark_suite)


def run_direct_experiment_benchmark(result: dict[str, Any], benchmark_suite: str) -> dict[str, Any]:
    passed = result.get("status") == "pass" or result.get("passed") is True
    summary = result.get("summary", {}) if isinstance(result.get("summary"), dict) else {}
    return {
        "suite": benchmark_suite,
        "passed": passed,
        "summary": {
            "total": int(summary.get("total", 1)) if summary else 1,
            "passed": int(summary.get("passed", 1 if passed else 0)) if summary else (1 if passed else 0),
            "failed": int(summary.get("failed", 0 if passed else 1)) if summary else (0 if passed else 1),
        },
        "metrics": result.get("metrics", {}),
        "result": result,
    }


def _suite_result(suite: str, checks: dict[str, bool], artifacts: dict[str, Any] | None = None) -> dict[str, Any]:
    passed = sum(1 for value in checks.values() if value)
    total = len(checks)
    return {"suite": suite, "passed": passed == total, "summary": {"passed": passed, "total": total, "failed": total - passed}, "checks": checks, "artifacts": artifacts or {}}



__all__ = ["run_direct_experiment_benchmark", "run_experiment_benchmark", "_run_paper_ready_experiment_benchmark", "_suite_result"]
