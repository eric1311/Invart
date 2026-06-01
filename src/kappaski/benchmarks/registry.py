"""Benchmark runner registry façade.

The concrete benchmark implementations live in ``kappaski.benchmarks.core``;
this module gives future suites a stable place to grow without expanding the
legacy ``kappaski.evals`` façade.
"""

from __future__ import annotations

from typing import Any, Callable

from .core import _benchmark_runner_registry


def benchmark_runner_registry() -> dict[str, Callable[[], dict[str, Any]]]:
    return _benchmark_runner_registry()


__all__ = ["benchmark_runner_registry"]
