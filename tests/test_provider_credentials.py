from __future__ import annotations

import os
import sys

import pytest

from invart.evaluation.real_agent_benchmark.provider_credentials import (
    assert_no_secret_argv,
    build_scoped_provider_environment,
    provider_credential_options,
    redact_provider_secrets,
)
from invart.surfaces.supervision import supervise_process_group


def test_qwencloud_credentials_are_provider_scoped(monkeypatch: pytest.MonkeyPatch) -> None:
    token_plan_secret = "sk-sp-token-plan-test-secret-1234567890"
    monkeypatch.setenv("DASHSCOPE_TP_API_KEY", token_plan_secret)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-unrelated-secret-1234567890")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-unrelated-secret-1234567890")
    monkeypatch.setenv("UNRELATED_SERVICE_TOKEN", "unrelated-token-secret")

    scoped = build_scoped_provider_environment(
        provider="qwencloud-token-plan",
        base_env=os.environ,
    )

    assert scoped["DASHSCOPE_TP_API_KEY"] == token_plan_secret
    assert "OPENAI_API_KEY" not in scoped
    assert "ANTHROPIC_API_KEY" not in scoped
    assert "UNRELATED_SERVICE_TOKEN" not in scoped
    assert scoped.get("PATH")

    options = provider_credential_options("opencode", provider="qwencloud-token-plan")
    assert options == [
        {
            "name": "DASHSCOPE_TP_API_KEY",
            "kind": "provider_api_key",
            "present": True,
            "secret_material": True,
        }
    ]
    assert token_plan_secret not in repr(options)


def test_scoped_process_env_excludes_unrelated_keys_and_redacts_output() -> None:
    token_plan_secret = "sk-sp-token-plan-output-secret-1234567890"
    unrelated_secret = "sk-unrelated-output-secret-1234567890"
    base_env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", ""),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "DASHSCOPE_TP_API_KEY": token_plan_secret,
        "OPENAI_API_KEY": unrelated_secret,
    }
    scoped = build_scoped_provider_environment(
        provider="qwencloud-token-plan",
        base_env=base_env,
    )
    command = [
        sys.executable,
        "-c",
        (
            "import os; "
            "print('qwen=' + os.environ.get('DASHSCOPE_TP_API_KEY', 'missing')); "
            "print('openai=' + os.environ.get('OPENAI_API_KEY', 'missing'))"
        ),
    ]

    result = supervise_process_group(
        command,
        env=scoped,
        redactions=[token_plan_secret],
    )

    assert result["returncode"] == 0
    assert token_plan_secret not in result["stdout"]
    assert "qwen=<redacted>" in result["stdout"]
    assert "openai=missing" in result["stdout"]
    assert unrelated_secret not in repr(result)


def test_credentials_only_environment_cannot_override_fixed_runtime_paths() -> None:
    scoped = build_scoped_provider_environment(
        provider="qwencloud-token-plan",
        agent="opencode",
        base_env={
            "DASHSCOPE_TP_API_KEY": "tp-secret",
            "PYTHONPATH": "relative-src-that-must-not-be-merged",
            "PATH": "/provider/path-that-must-not-be-merged",
        },
        include_passthrough=False,
    )

    assert scoped == {
        "DASHSCOPE_TP_API_KEY": "tp-secret",
        "NO_PROXY": "localhost,127.0.0.1,::1",
        "no_proxy": "localhost,127.0.0.1,::1",
    }


def test_secret_values_are_rejected_in_argv_and_redacted_from_text() -> None:
    secret = "sk-sp-token-plan-argv-secret-1234567890"

    with pytest.raises(ValueError, match="secret material"):
        assert_no_secret_argv(
            ["client", "--api-key", secret],
            secret_values=[secret],
        )

    text = f"Authorization: Bearer {secret}\nDASHSCOPE_TP_API_KEY={secret}"
    redacted = redact_provider_secrets(text, secret_values=[secret])
    assert secret not in redacted
    assert "Authorization: Bearer <redacted>" in redacted
    assert "DASHSCOPE_TP_API_KEY=<redacted>" in redacted
