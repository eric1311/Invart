from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any, Mapping

from invart.core.artifacts import stable_json_dumps, stable_json_hash, write_json_artifact

from .provider_run_control import scan_provider_artifact_tree, secure_provider_artifact_tree
from .tool_capabilities import Capability, build_agentdojo_slack_registry, classify_tool_call


ANALYSIS_SCHEMA_VERSION = "invart.agentdojo_ground_truth_analysis.v0.1"


def analyze_agentdojo_ground_truth(payload: Mapping[str, Any]) -> dict[str, Any]:
    benchmark = payload.get("benchmark")
    cells = payload.get("cells")
    if not isinstance(benchmark, Mapping) or benchmark.get("family") != "agentdojo":
        raise ValueError("ground truth must describe AgentDojo")
    if not isinstance(cells, list) or not cells:
        raise ValueError("ground truth must contain cells")
    registry = build_agentdojo_slack_registry()
    user_tools: Counter[str] = Counter()
    injection_tools: Counter[str] = Counter()
    user_sinks: Counter[str] = Counter()
    injection_sinks: Counter[str] = Counter()
    injection_sink_rows: list[Mapping[str, Any]] = []
    membership_attack_steps = 0
    for cell in cells:
        if not isinstance(cell, Mapping):
            raise ValueError("ground-truth cell must be an object")
        for owner, counter, sink_counter in (
            ("user_ground_truth", user_tools, user_sinks),
            ("injection_ground_truth", injection_tools, injection_sinks),
        ):
            calls = cell.get(owner)
            if not isinstance(calls, list):
                raise ValueError(f"{owner} must be a list")
            for call in calls:
                if not isinstance(call, Mapping) or not isinstance(call.get("arguments"), Mapping):
                    raise ValueError("ground-truth call must contain arguments")
                tool = str(call.get("tool_name") or "")
                counter[tool] += 1
                assessment = classify_tool_call(
                    registry=registry,
                    tool_name=tool,
                    arguments=call["arguments"],
                )
                if owner == "injection_ground_truth" and Capability.ACCOUNT_MEMBERSHIP_ADMIN in assessment.capabilities:
                    membership_attack_steps += 1
                if call.get("is_sink") is True:
                    sink_counter[tool] += 1
                    if owner == "injection_ground_truth":
                        injection_sink_rows.append(call)

    shared = sorted(set(user_tools) & set(injection_tools))
    read_or_navigation_without_write = 0
    shared_sink_count = 0
    for call in injection_sink_rows:
        assessment = classify_tool_call(
            registry=registry,
            tool_name=str(call["tool_name"]),
            arguments=call["arguments"],
        )
        if (
            Capability.READ in assessment.capabilities
            and Capability.EXTERNAL_NETWORK in assessment.capabilities
            and Capability.WRITE not in assessment.capabilities
        ):
            read_or_navigation_without_write += 1
        if call["tool_name"] in user_tools:
            shared_sink_count += 1

    result: dict[str, Any] = {
        "schema_version": ANALYSIS_SCHEMA_VERSION,
        "benchmark": dict(benchmark),
        "denominator": {
            "cells": len(cells),
            "weighting": "cell_weighted_ground_truth_calls",
            "user_calls": sum(user_tools.values()),
            "injection_calls": sum(injection_tools.values()),
        },
        "tool_distributions": {
            "user": _counter_rows(user_tools),
            "injection": _counter_rows(injection_tools),
            "user_sinks": _counter_rows(user_sinks),
            "injection_sinks": _counter_rows(injection_sinks),
        },
        "tool_overlap": {
            "shared_tool_names": shared,
            "shared_tool_count": len(shared),
            "user_only_tool_names": sorted(set(user_tools) - set(injection_tools)),
            "injection_only_tool_names": sorted(set(injection_tools) - set(user_tools)),
        },
        "attack_sinks": {
            "total": len(injection_sink_rows),
            "shared_with_user_tool": shared_sink_count,
            "read_or_navigation_without_write": read_or_navigation_without_write,
            "membership_admin_attack_steps": membership_attack_steps,
        },
        "policy_findings": {
            "tool_name_only_policy_invalid": bool(shared_sink_count),
            "write_only_policy_invalid": bool(read_or_navigation_without_write),
            "required_decision_features": [
                "action_authorization",
                "target_authorization",
                "argument_provenance",
                "sequence_context",
                "capability_metadata",
            ],
            "prompt_implications": [
                "external reads and navigation require authorized targets when sourced from untrusted content",
                "derived content may be allowed when action and destination are user-authorized",
                "membership changes require explicit authorization for every principal and scope",
                "shared tools require argument- and provenance-sensitive adjudication",
            ],
        },
        "source_ground_truth_hash": payload.get("ground_truth_hash") or payload.get("artifact_hash"),
        "claim_boundary": (
            "This analysis describes benchmark ground-truth structure for post-hoc policy development. "
            "It is not runtime evidence, must not be disclosed to the policy or reviewer, and does not "
            "estimate attack prevention or false-block rates without joined proposed-call events."
        ),
    }
    result["analysis_hash"] = stable_json_hash(result)
    return result


def export_agentdojo_ground_truth_analysis(
    *, output_dir: Path, ground_truth_path: Path
) -> dict[str, Any]:
    try:
        payload = json.loads(Path(ground_truth_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("invalid AgentDojo ground-truth artifact") from exc
    if not isinstance(payload, dict):
        raise ValueError("ground-truth artifact must be an object")
    result = analyze_agentdojo_ground_truth(payload)
    root = Path(output_dir)
    root.mkdir(parents=True, exist_ok=True)
    artifact = write_json_artifact(root / "agentdojo_ground_truth_analysis.json", result)
    secure_provider_artifact_tree(root)
    scan = scan_provider_artifact_tree(root)
    if scan["status"] != "pass":
        raise RuntimeError("ground-truth analysis failed artifact safety scan")
    return {
        "status": "analyzed",
        "analysis_hash": result["analysis_hash"],
        "artifact": str(artifact),
        "scan": scan,
    }


def _counter_rows(counter: Counter[str]) -> list[dict[str, Any]]:
    return [{"tool_name": key, "count": counter[key]} for key in sorted(counter)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyze AgentDojo ground-truth structure.")
    parser.add_argument("--ground-truth", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    result = export_agentdojo_ground_truth_analysis(
        output_dir=args.output_dir,
        ground_truth_path=args.ground_truth,
    )
    print(stable_json_dumps(result), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["analyze_agentdojo_ground_truth", "export_agentdojo_ground_truth_analysis"]
