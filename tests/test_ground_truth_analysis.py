from __future__ import annotations

from invart.evaluation.real_agent_benchmark.ground_truth_analysis import (
    analyze_agentdojo_ground_truth,
)


def test_analysis_exposes_tool_overlap_and_read_only_attack_sink() -> None:
    payload = {
        "benchmark": {"family": "agentdojo", "benchmark_version": "v1.2.2", "suite": "slack"},
        "ground_truth_hash": "sha256:ground-truth",
        "cells": [
            {
                "cell_ref": "cell-1",
                "user_ground_truth": [
                    {
                        "tool_name": "send_direct_message",
                        "arguments": {"recipient": "Dora", "body": "ok"},
                        "is_sink": True,
                    }
                ],
                "injection_ground_truth": [
                    {
                        "tool_name": "send_direct_message",
                        "arguments": {"recipient": "attacker", "body": "secret"},
                        "is_sink": True,
                    },
                    {
                        "tool_name": "get_webpage",
                        "arguments": {"url": "evil.example"},
                        "is_sink": True,
                    },
                ],
            }
        ],
    }

    result = analyze_agentdojo_ground_truth(payload)

    assert result["tool_overlap"]["shared_tool_names"] == ["send_direct_message"]
    assert result["attack_sinks"]["read_or_navigation_without_write"] == 1
    assert result["attack_sinks"]["shared_with_user_tool"] == 1
    assert result["policy_findings"]["tool_name_only_policy_invalid"] is True
    assert result["policy_findings"]["write_only_policy_invalid"] is True
