from __future__ import annotations

from invart.evaluation.real_agent_benchmark.provider_smoke import (
    run_qwencloud_compatibility_smoke,
)


def test_qwencloud_tool_smoke_reports_conformance_without_response_content() -> None:
    secret = "sk-sp-test-smoke-secret-1234567890"

    def transport(**_kwargs):
        return {
            "id": "chatcmpl-smoke",
            "model": "deepseek-v4-pro",
            "choices": [
                {
                    "finish_reason": "tool_calls",
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call-1",
                                "type": "function",
                                "function": {
                                    "name": "lookup_weather",
                                    "arguments": '{"city":"Beijing"}',
                                },
                            }
                        ],
                    },
                }
            ],
            "usage": {"prompt_tokens": 12, "completion_tokens": 8, "total_tokens": 20},
        }

    result = run_qwencloud_compatibility_smoke(
        model="deepseek-v4-pro",
        environment={"DASHSCOPE_TP_API_KEY": secret},
        tool_probe=True,
        transport=transport,
    )

    assert result["status"] == "pass"
    assert result["provider"] == "qwencloud-token-plan"
    assert result["model"] == "deepseek-v4-pro"
    assert result["tool_call_conformance"] == {
        "expected": True,
        "valid_calls": 1,
        "tool_names": ["lookup_weather"],
    }
    assert "choices" not in result
    assert "response" not in result
    assert secret not in repr(result)


def test_qwencloud_tool_smoke_fails_when_model_returns_only_text() -> None:
    def transport(**_kwargs):
        return {
            "model": "deepseek-v4-pro",
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {"role": "assistant", "content": "I would call the tool."},
                }
            ],
        }

    result = run_qwencloud_compatibility_smoke(
        model="deepseek-v4-pro",
        environment={"DASHSCOPE_TP_API_KEY": "test-secret"},
        tool_probe=True,
        transport=transport,
    )

    assert result["status"] == "fail_tool_conformance"
    assert result["tool_call_conformance"]["valid_calls"] == 0
