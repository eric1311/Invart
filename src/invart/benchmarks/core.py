from __future__ import annotations

from typing import Any

from .registry import benchmark_runner_registry
from .semantic import BenchmarkCase, run_semantic_benchmark


def run_benchmark(suite: str = "v0.2-semantic", *, reviewer: str = "heuristic", policy_profile: str = "balanced") -> dict[str, Any]:
    runner = benchmark_runner_registry().get(suite)
    if runner is not None:
        return runner()
    if suite != "v0.2-semantic":
        raise ValueError(f"unknown benchmark suite: {suite}")
    return run_semantic_benchmark(suite, reviewer=reviewer, policy_profile=policy_profile)


__all__ = ["BenchmarkCase", "run_benchmark"]
