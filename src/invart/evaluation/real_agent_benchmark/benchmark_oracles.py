from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path
from typing import Any, Mapping, Sequence

from invart.core.artifacts import sha256_file, stable_json_dumps, stable_json_hash, write_json_artifact

from .mediation_adjudication import GroundTruthCall
from .provider_run_control import scan_provider_artifact_tree, secure_provider_artifact_tree


AGENTDOJO_GROUND_TRUTH_SCHEMA_VERSION = "invart.agentdojo_ground_truth_export.v0.1"


def extract_agentdojo_ground_truth(
    *,
    official_python: Path,
    benchmark_version: str,
    suite: str,
    user_task_ids: Sequence[str] = (),
    injection_task_ids: Sequence[str] = (),
    helper_script: Path | None = None,
    timeout: float = 120.0,
) -> dict[str, Any]:
    # Preserve a virtual environment's Python symlink path. Resolving it to the
    # base interpreter discards pyvenv.cfg discovery and therefore its packages.
    python = Path(official_python).expanduser().absolute()
    helper = (
        Path(helper_script).expanduser().resolve()
        if helper_script is not None
        else Path(__file__).with_name("agentdojo_ground_truth_helper.py").resolve()
    )
    if not python.is_file() or not os.access(python, os.X_OK):
        raise ValueError("official AgentDojo Python must be an executable file")
    if not helper.is_file():
        raise ValueError("AgentDojo ground-truth helper is missing")
    command = [
        str(python),
        str(helper),
        "--benchmark-version",
        str(benchmark_version),
        "--suite",
        str(suite),
    ]
    for task_id in user_task_ids:
        command.extend(("--user-task", str(task_id)))
    for task_id in injection_task_ids:
        command.extend(("--injection-task", str(task_id)))
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
        env={"PATH": os.environ.get("PATH", ""), "PYTHONUTF8": "1"},
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip().splitlines()[-1:] or ["no stderr"]
        raise RuntimeError(f"AgentDojo ground-truth extraction failed: {detail[0]}")
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError("AgentDojo ground-truth helper returned invalid JSON") from exc
    _validate_ground_truth_payload(
        payload,
        benchmark_version=str(benchmark_version),
        suite=str(suite),
    )
    payload["extractor"] = {
        "helper_name": helper.name,
        "helper_sha256": sha256_file(helper, prefixed=True),
        "transport": "isolated_official_python_subprocess",
        "environment": "minimal_no_provider_credentials",
    }
    payload["artifact_hash"] = stable_json_hash(payload)
    return payload


def export_agentdojo_ground_truth(
    *,
    output_dir: Path,
    official_python: Path,
    benchmark_version: str,
    suite: str,
    user_task_ids: Sequence[str] = (),
    injection_task_ids: Sequence[str] = (),
    timeout: float = 120.0,
) -> dict[str, Any]:
    payload = extract_agentdojo_ground_truth(
        official_python=official_python,
        benchmark_version=benchmark_version,
        suite=suite,
        user_task_ids=user_task_ids,
        injection_task_ids=injection_task_ids,
        timeout=timeout,
    )
    root = Path(output_dir)
    root.mkdir(parents=True, exist_ok=True)
    artifact = write_json_artifact(root / "agentdojo_ground_truth.json", payload)
    secure_provider_artifact_tree(root)
    scan = scan_provider_artifact_tree(root)
    if scan["status"] != "pass":
        raise RuntimeError("AgentDojo ground-truth artifact failed safety scan")
    return {
        "status": "exported",
        "cells": len(payload["cells"]),
        "artifact_hash": payload["artifact_hash"],
        "artifact": str(artifact),
        "scan": scan,
    }


def ground_truth_calls_for_cell(
    payload: Mapping[str, Any], *, cell_ref: str
) -> tuple[tuple[GroundTruthCall, ...], tuple[GroundTruthCall, ...]]:
    cells = payload.get("cells")
    if not isinstance(cells, list):
        raise ValueError("ground-truth payload cells must be a list")
    matches = [cell for cell in cells if isinstance(cell, Mapping) and cell.get("cell_ref") == cell_ref]
    if len(matches) != 1:
        raise ValueError("ground-truth cell_ref must resolve uniquely")
    cell = matches[0]
    return (
        _typed_ground_truth_calls(cell.get("user_ground_truth"), owner="user"),
        _typed_ground_truth_calls(cell.get("injection_ground_truth"), owner="injection"),
    )


def _validate_ground_truth_payload(
    payload: Any, *, benchmark_version: str, suite: str
) -> None:
    if not isinstance(payload, dict):
        raise ValueError("AgentDojo ground-truth payload must be an object")
    if payload.get("schema_version") != AGENTDOJO_GROUND_TRUTH_SCHEMA_VERSION:
        raise ValueError("unsupported AgentDojo ground-truth schema")
    benchmark = payload.get("benchmark")
    if not isinstance(benchmark, Mapping) or benchmark.get("family") != "agentdojo":
        raise ValueError("ground-truth payload is not AgentDojo")
    if benchmark.get("benchmark_version") != benchmark_version:
        raise ValueError("ground-truth benchmark version mismatch")
    if benchmark.get("suite") != suite:
        raise ValueError("ground-truth suite mismatch")
    cells = payload.get("cells")
    if not isinstance(cells, list) or not cells:
        raise ValueError("ground-truth payload has no cells")
    refs = [cell.get("cell_ref") for cell in cells if isinstance(cell, Mapping)]
    if len(refs) != len(cells) or len(set(refs)) != len(refs):
        raise ValueError("ground-truth cell references must be present and unique")


def _typed_ground_truth_calls(value: Any, *, owner: str) -> tuple[GroundTruthCall, ...]:
    if not isinstance(value, list):
        raise ValueError(f"{owner} ground truth must be a list")
    calls: list[GroundTruthCall] = []
    for item in value:
        if not isinstance(item, Mapping) or item.get("owner") != owner:
            raise ValueError(f"invalid {owner} ground-truth call")
        calls.append(
            GroundTruthCall(
                owner=owner,
                sequence_index=item["sequence_index"],
                tool_name=item["tool_name"],
                arguments=item["arguments"],
                placeholder_arguments=item.get("placeholder_arguments"),
                is_sink=bool(item.get("is_sink")),
            )
        )
    return tuple(calls)


__all__ = [
    "export_agentdojo_ground_truth",
    "extract_agentdojo_ground_truth",
    "ground_truth_calls_for_cell",
]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Export post-hoc AgentDojo ground truth.")
    parser.add_argument("--official-python", type=Path, required=True)
    parser.add_argument("--benchmark-version", required=True)
    parser.add_argument("--suite", required=True)
    parser.add_argument("--user-task", action="append", default=[])
    parser.add_argument("--injection-task", action="append", default=[])
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=120.0)
    args = parser.parse_args(argv)
    result = export_agentdojo_ground_truth(
        output_dir=args.output_dir,
        official_python=args.official_python,
        benchmark_version=args.benchmark_version,
        suite=args.suite,
        user_task_ids=args.user_task,
        injection_task_ids=args.injection_task,
        timeout=args.timeout,
    )
    print(stable_json_dumps(result), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
