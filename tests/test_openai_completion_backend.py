from __future__ import annotations

import json

import pytest

from invart.evaluation.real_agent_benchmark.agent_backends import (
    OpenAICompatibleCompletionBackend,
)
from invart.evaluation.real_agent_benchmark.agent_runtime_manifest import (
    ClaimKind,
    QWENCLOUD_TOKEN_PLAN,
    build_runtime_manifest,
    completion_backend_request,
)


def _manifest():
    request = completion_backend_request(
        requested_provider="qwencloud-token-plan",
        requested_model="deepseek-v4-pro",
        agent_product="opencode",
        low_level_runtime="agentdojo-fixed-loop",
        evidence_kind=ClaimKind.COMPLETION_BACKEND,
    )
    return build_runtime_manifest(request=request, provider_profile=QWENCLOUD_TOKEN_PLAN)


def test_openai_backend_forwards_allowlisted_request_and_returns_valid_receipt() -> None:
    secret = "sk-sp-test-completion-secret-1234567890"
    observed: dict[str, object] = {}

    def transport(*, url, headers, body, timeout):
        observed.update(url=url, headers=headers, body=json.loads(body), timeout=timeout)
        return {
            "id": "chatcmpl-test",
            "model": "deepseek-v4-pro",
            "choices": [{"message": {"role": "assistant", "content": "ok"}}],
            "usage": {"prompt_tokens": 3, "completion_tokens": 1, "total_tokens": 4},
        }

    backend = OpenAICompatibleCompletionBackend(
        manifest=_manifest(),
        environment={"DASHSCOPE_TP_API_KEY": secret},
        transport=transport,
        timeout=12.0,
    )
    result = backend.complete(
        {
            "model": "caller-alias-must-not-win",
            "messages": [{"role": "user", "content": "hello"}],
            "temperature": 0,
            "tools": [{"type": "function", "function": {"name": "lookup", "parameters": {}}}],
            "unsupported_private_field": "drop-me",
        }
    )

    assert observed["url"] == (
        "https://token-plan.cn-beijing.maas.aliyuncs.com/compatible-mode/v1/chat/completions"
    )
    assert observed["headers"] == {
        "Authorization": f"Bearer {secret}",
        "Content-Type": "application/json",
    }
    assert observed["body"] == {
        "model": "deepseek-v4-pro",
        "messages": [{"role": "user", "content": "hello"}],
        "temperature": 0,
        "tools": [{"type": "function", "function": {"name": "lookup", "parameters": {}}}],
    }
    assert observed["timeout"] == 12.0
    assert result.validation.valid is True
    assert result.receipt.resolved_model == "deepseek-v4-pro"
    assert result.response["usage"]["total_tokens"] == 4
    assert secret not in repr(result)


def test_openai_backend_fails_closed_without_provider_credential() -> None:
    called = False

    def transport(**_kwargs):
        nonlocal called
        called = True
        return {}

    backend = OpenAICompatibleCompletionBackend(
        manifest=_manifest(),
        environment={},
        transport=transport,
    )

    with pytest.raises(RuntimeError, match="DASHSCOPE_TP_API_KEY"):
        backend.complete({"messages": [{"role": "user", "content": "hello"}]})
    assert called is False


def test_openai_backend_invalidates_silent_model_fallback_and_redacts_echoes() -> None:
    secret = "sk-sp-test-echo-secret-1234567890"

    def transport(**_kwargs):
        return {
            "model": "fallback-model",
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": f"Authorization: Bearer {secret}",
                    }
                }
            ],
        }

    backend = OpenAICompatibleCompletionBackend(
        manifest=_manifest(),
        environment={"DASHSCOPE_TP_API_KEY": secret},
        transport=transport,
    )
    result = backend.complete({"messages": [{"role": "user", "content": "hello"}]})

    assert result.validation.valid is False
    assert result.validation.status == "invalid_runtime_resolution"
    assert "model_mismatch" in result.validation.reasons
    assert secret not in json.dumps(result.response)
    assert result.response["choices"][0]["message"]["content"] == "Authorization: Bearer <redacted>"


def test_openai_backend_refuses_unapproved_live_provider_transport() -> None:
    backend = OpenAICompatibleCompletionBackend(
        manifest=_manifest(),
        environment={"DASHSCOPE_TP_API_KEY": "test-secret"},
    )

    with pytest.raises(RuntimeError, match="approval-bound budget ledger"):
        backend.complete({"messages": [{"role": "user", "content": "hello"}]})
