"""Standalone AgentDojo oracle extractor executed by the isolated official Python.

Keep this file import-light: it is invoked by path so the official environment does not
need to import the Invart package or its dependencies.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
from typing import Any


SCHEMA_VERSION = "invart.agentdojo_ground_truth_export.v0.1"


def _call_rows(calls: list[Any], *, owner: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for index, call in enumerate(calls):
        payload = call.model_dump(mode="json")
        rows.append(
            {
                "owner": owner,
                "sequence_index": index,
                "tool_name": payload["function"],
                "arguments": payload["args"],
                "placeholder_arguments": payload.get("placeholder_args"),
                "is_sink": index == len(calls) - 1,
            }
        )
    return rows


def _stable_hash(payload: Any) -> str:
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def extract(
    *,
    benchmark_version: str,
    suite_name: str,
    user_task_ids: tuple[str, ...] = (),
    injection_task_ids: tuple[str, ...] = (),
) -> dict[str, Any]:
    from agentdojo.task_suite.load_suites import get_suite

    suite = get_suite(benchmark_version, suite_name)
    users = tuple(user_task_ids) or tuple(sorted(suite.user_tasks))
    injections = tuple(injection_task_ids) or tuple(sorted(suite.injection_tasks))
    cells: list[dict[str, Any]] = []
    for user_task_id in users:
        user_task = suite.get_user_task_by_id(user_task_id)
        for injection_task_id in injections:
            injection_task = suite.get_injection_task_by_id(injection_task_id)
            environment = suite.load_and_inject_default_environment({})
            task_environment = user_task.init_environment(environment)
            pre_environment = task_environment.model_copy(deep=True)
            user_calls = user_task.ground_truth(pre_environment.model_copy(deep=True))
            injection_calls = injection_task.ground_truth(pre_environment.model_copy(deep=True))
            cells.append(
                {
                    "cell_ref": (
                        f"agentdojo:{benchmark_version}:{suite_name}:"
                        f"{user_task_id}:{injection_task_id}"
                    ),
                    "user_task_id": user_task_id,
                    "injection_task_id": injection_task_id,
                    "user_prompt": str(user_task.PROMPT),
                    "injection_goal": str(injection_task.GOAL),
                    "user_ground_truth": _call_rows(user_calls, owner="user"),
                    "injection_ground_truth": _call_rows(injection_calls, owner="injection"),
                }
            )
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "benchmark": {
            "family": "agentdojo",
            "benchmark_version": benchmark_version,
            "suite": suite_name,
            "package_version": importlib.metadata.version("agentdojo"),
        },
        "cells": cells,
        "claim_boundary": (
            "This is a post-hoc export of AgentDojo's native user and injection ground-truth calls. "
            "It must never be disclosed to the runtime policy or reviewer. Official utility and attack "
            "success remain owned by AgentDojo's native oracle."
        ),
    }
    payload["ground_truth_hash"] = _stable_hash(payload)
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--benchmark-version", required=True)
    parser.add_argument("--suite", required=True)
    parser.add_argument("--user-task", action="append", default=[])
    parser.add_argument("--injection-task", action="append", default=[])
    args = parser.parse_args(argv)
    payload = extract(
        benchmark_version=args.benchmark_version,
        suite_name=args.suite,
        user_task_ids=tuple(args.user_task),
        injection_task_ids=tuple(args.injection_task),
    )
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
