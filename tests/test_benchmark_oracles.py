from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from invart.evaluation.real_agent_benchmark.benchmark_oracles import (
    extract_agentdojo_ground_truth,
    ground_truth_calls_for_cell,
)


def _fake_helper(path: Path, *, version: str = "v1.2.2") -> Path:
    payload = {
        "schema_version": "invart.agentdojo_ground_truth_export.v0.1",
        "benchmark": {
            "family": "agentdojo",
            "benchmark_version": version,
            "suite": "slack",
            "package_version": "0.1.35",
        },
        "cells": [
            {
                "cell_ref": f"agentdojo:{version}:slack:user_task_1:injection_task_1",
                "user_task_id": "user_task_1",
                "injection_task_id": "injection_task_1",
                "user_ground_truth": [
                    {
                        "owner": "user",
                        "sequence_index": 0,
                        "tool_name": "send_channel_message",
                        "arguments": {"channel": "project", "body": "ok"},
                        "placeholder_arguments": None,
                        "is_sink": True,
                    }
                ],
                "injection_ground_truth": [
                    {
                        "owner": "injection",
                        "sequence_index": 0,
                        "tool_name": "send_direct_message",
                        "arguments": {"recipient": "attacker", "body": "secret"},
                        "placeholder_arguments": {"recipient": "attacker", "body": "$content"},
                        "is_sink": True,
                    }
                ],
            }
        ],
        "ground_truth_hash": "sha256:fake",
        "claim_boundary": "post-hoc only",
    }
    path.write_text(
        "import json\n"
        f"print(json.dumps({payload!r}))\n",
        encoding="utf-8",
    )
    return path


def test_official_ground_truth_wrapper_validates_and_builds_typed_calls(tmp_path: Path) -> None:
    payload = extract_agentdojo_ground_truth(
        official_python=Path(sys.executable),
        helper_script=_fake_helper(tmp_path / "helper.py"),
        benchmark_version="v1.2.2",
        suite="slack",
        user_task_ids=("user_task_1",),
        injection_task_ids=("injection_task_1",),
        timeout=5,
    )

    user, injection = ground_truth_calls_for_cell(
        payload,
        cell_ref="agentdojo:v1.2.2:slack:user_task_1:injection_task_1",
    )
    assert user[0].owner == "user"
    assert user[0].tool_name == "send_channel_message"
    assert injection[0].owner == "injection"
    assert injection[0].placeholder_arguments == {
        "recipient": "attacker",
        "body": "$content",
    }
    assert injection[0].is_sink is True


def test_official_ground_truth_wrapper_rejects_version_mismatch(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="benchmark version"):
        extract_agentdojo_ground_truth(
            official_python=Path(sys.executable),
            helper_script=_fake_helper(tmp_path / "helper.py", version="v1.2"),
            benchmark_version="v1.2.2",
            suite="slack",
            timeout=5,
        )
