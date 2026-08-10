from __future__ import annotations

import json
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from invart.core.artifacts import stable_json_hash
from invart.evaluation.real_agent_benchmark.agent_backends import (
    CommandSpec,
    build_claude_code_command,
    build_codex_command,
    build_hermes_command,
    build_openclaw_command,
    build_opencode_command,
    build_opencode_provider_config,
    write_opencode_isolated_config,
)
from invart.evaluation.real_agent_benchmark.agent_runtime_manifest import (
    ClaimKind,
    ExecutionContract,
    QWENCLOUD_TOKEN_PLAN,
    RuntimeReceipt,
    RuntimeRequest,
    build_runtime_manifest,
    hash_runtime_state_tree,
    validate_runtime_receipt,
)


def _request(
    *,
    agent_product: str = "opencode",
    low_level_runtime: str = "opencode-run",
    execution_contract: ExecutionContract = ExecutionContract.NATIVE_RUNTIME,
    evidence_kind: ClaimKind = ClaimKind.NATIVE_RUNTIME,
) -> RuntimeRequest:
    return RuntimeRequest(
        requested_provider="qwencloud-token-plan",
        requested_model="deepseek-v4-pro",
        agent_product=agent_product,
        low_level_runtime=low_level_runtime,
        execution_contract=execution_contract,
        evidence_kind=evidence_kind,
    )


def test_qwencloud_token_plan_profile_is_hosted_deployment_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DASHSCOPE_TP_API_KEY", "credential-value-must-never-be-read")

    payload = QWENCLOUD_TOKEN_PLAN.to_dict()

    assert payload == {
        "profile_id": "qwencloud-token-plan",
        "base_url": "https://token-plan.cn-beijing.maas.aliyuncs.com/compatible-mode/v1",
        "credential_env_name": "DASHSCOPE_TP_API_KEY",
        "preferred_model": "deepseek-v4-pro",
        "hosted": True,
        "checkpoint_verifiable": False,
        "attribution_scope": "hosted_deployment_stack",
    }
    assert "credential-value-must-never-be-read" not in json.dumps(payload)


def test_opencode_command_is_noninteractive_model_explicit_json_and_cwd_bound(tmp_path: Path) -> None:
    command = build_opencode_command(request=_request(), prompt="do the task", cwd=tmp_path)

    assert command.argv == (
        "opencode",
        "run",
        "--pure",
        "--model",
        "qwencloud-token-plan/deepseek-v4-pro",
        "--format",
        "json",
        "--dir",
        str(tmp_path.resolve()),
        "do the task",
    )
    assert command.cwd == str(tmp_path.resolve())
    assert command.output_format == "json_events"
    assert command.credential_env_names == ("DASHSCOPE_TP_API_KEY",)


def test_opencode_isolated_config_uses_env_reference_not_secret(tmp_path: Path) -> None:
    secret = "dashscope-secret-must-not-be-serialized"
    request = _request()
    config_path = tmp_path / "isolated" / "opencode.json"

    written = write_opencode_isolated_config(
        path=config_path,
        request=request,
        provider_profile=QWENCLOUD_TOKEN_PLAN,
    )
    payload = json.loads(written.read_text(encoding="utf-8"))
    command = build_opencode_command(
        request=request,
        prompt="do the task",
        cwd=tmp_path,
        provider_profile=QWENCLOUD_TOKEN_PLAN,
        config_path=written,
    )

    assert payload == build_opencode_provider_config(
        request=request,
        provider_profile=QWENCLOUD_TOKEN_PLAN,
    )
    assert payload["provider"]["qwencloud-token-plan"]["options"]["apiKey"] == (
        "{env:DASHSCOPE_TP_API_KEY}"
    )
    assert payload["plugin"] == []
    assert payload["mcp"] == {}
    assert payload["instructions"] == []
    assert written.stat().st_mode & 0o077 == 0
    assert command.environment_overrides == (("OPENCODE_CONFIG", str(written)),)
    assert secret not in json.dumps(payload)


def test_hermes_command_is_single_query_quiet_and_home_is_metadata(tmp_path: Path) -> None:
    request = _request(agent_product="hermes", low_level_runtime="hermes-agent-loop")
    isolated_home = tmp_path / "home"

    command = build_hermes_command(
        request=request,
        prompt="do the task",
        cwd=tmp_path,
        isolated_home=isolated_home,
    )

    assert command.argv == (
        "hermes",
        "chat",
        "--query",
        "do the task",
        "--quiet",
        "--model",
        "deepseek-v4-pro",
    )
    assert command.environment_overrides == (("HOME", str(isolated_home.resolve())),)
    assert "--home" not in command.argv
    assert "--provider" not in command.argv
    assert command.runtime_resolution_source == "isolated_config_and_runtime_receipt"


def test_openclaw_command_keeps_model_resolution_out_of_cli_arguments(tmp_path: Path) -> None:
    request = _request(agent_product="openclaw", low_level_runtime="openclaw-embedded")

    command = build_openclaw_command(
        request=request,
        prompt="do the task",
        cwd=tmp_path,
        agent_id="benchmark-agent",
        session_id="session-007",
    )

    assert command.argv == (
        "openclaw",
        "agent",
        "--local",
        "--json",
        "--agent",
        "benchmark-agent",
        "--session-id",
        "session-007",
        "--message",
        "do the task",
    )
    assert "deepseek-v4-pro" not in command.argv
    assert "qwencloud-token-plan" not in command.argv
    assert command.runtime_resolution_source == "manifest_and_runtime_receipt"


def test_codex_and_claude_code_commands_match_existing_compatibility_bridge(tmp_path: Path) -> None:
    codex = build_codex_command(prompt="do the task", cwd=tmp_path)
    claude = build_claude_code_command(prompt="do the task", cwd=tmp_path)

    assert codex.argv == (
        "codex",
        "--ask-for-approval",
        "never",
        "exec",
        "--cd",
        str(tmp_path.resolve()),
        "--sandbox",
        "workspace-write",
        "do the task",
    )
    assert claude.argv == (
        "claude",
        "--print",
        "--permission-mode",
        "bypassPermissions",
        "--output-format",
        "text",
        "--max-budget-usd",
        "2",
        "do the task",
    )


def test_manifest_is_frozen_and_hashes_only_stable_public_state() -> None:
    manifest = build_runtime_manifest(
        request=_request(),
        provider_profile=QWENCLOUD_TOKEN_PLAN,
        profile_name="comparable-clean",
        agent_version="opencode-test",
        runtime_version="runtime-test",
        tool_allowlist=("read", "write"),
        memory_hashes=(),
        skill_hashes=(),
    )

    expected_hash = stable_json_hash(manifest.to_dict(include_hash=False))
    assert manifest.manifest_hash == expected_hash
    assert manifest.to_dict()["request"] == {
        "requested_provider": "qwencloud-token-plan",
        "requested_model": "deepseek-v4-pro",
        "agent_product": "opencode",
        "low_level_runtime": "opencode-run",
        "execution_contract": "native_runtime",
        "evidence_kind": "native_runtime",
    }
    assert manifest.to_dict()["provider_profile"]["attribution_scope"] == "hosted_deployment_stack"
    with pytest.raises(FrozenInstanceError):
        manifest.profile_name = "native-realistic"  # type: ignore[misc]


def test_completion_backend_contract_cannot_claim_native_runtime() -> None:
    with pytest.raises(ValueError, match="completion_backend.*native_runtime"):
        _request(
            execution_contract=ExecutionContract.COMPLETION_BACKEND,
            evidence_kind=ClaimKind.NATIVE_RUNTIME,
        )


def test_claim_kinds_keep_evidence_boundaries_distinct() -> None:
    assert {kind.value for kind in ClaimKind} == {
        "completion_backend",
        "native_runtime",
        "native_control",
        "observe_only",
    }


@pytest.mark.parametrize(
    ("changed_field", "changed_value", "expected_reason"),
    [
        ("resolved_provider", "unexpected-provider", "provider_mismatch"),
        ("resolved_model", "unexpected-model", "model_mismatch"),
        ("resolved_agent_product", "codex", "agent_product_mismatch"),
        ("resolved_low_level_runtime", "codex-app-server", "low_level_runtime_mismatch"),
    ],
)
def test_runtime_receipt_mismatch_invalidates_resolution(
    changed_field: str,
    changed_value: str,
    expected_reason: str,
) -> None:
    manifest = build_runtime_manifest(request=_request(), provider_profile=QWENCLOUD_TOKEN_PLAN)
    values = {
        "resolved_provider": "qwencloud-token-plan",
        "resolved_model": "deepseek-v4-pro",
        "resolved_agent_product": "opencode",
        "resolved_low_level_runtime": "opencode-run",
    }
    values[changed_field] = changed_value

    result = validate_runtime_receipt(manifest, RuntimeReceipt(**values))

    assert result.valid is False
    assert result.status == "invalid_runtime_resolution"
    assert expected_reason in result.reasons


def test_undeclared_fallback_invalidates_runtime_resolution() -> None:
    manifest = build_runtime_manifest(request=_request(), provider_profile=QWENCLOUD_TOKEN_PLAN)
    receipt = RuntimeReceipt(
        resolved_provider="qwencloud-token-plan",
        resolved_model="deepseek-v4-pro",
        resolved_agent_product="opencode",
        resolved_low_level_runtime="opencode-run",
        fallback_used=True,
        fallback_id="provider-default",
    )

    result = validate_runtime_receipt(manifest, receipt)

    assert result.valid is False
    assert result.status == "invalid_runtime_resolution"
    assert "undeclared_fallback" in result.reasons


def test_matching_receipt_is_valid_and_contains_no_credential_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DASHSCOPE_TP_API_KEY", "credential-value-must-never-be-read")
    manifest = build_runtime_manifest(request=_request(), provider_profile=QWENCLOUD_TOKEN_PLAN)
    receipt = RuntimeReceipt(
        resolved_provider="qwencloud-token-plan",
        resolved_model="deepseek-v4-pro",
        resolved_agent_product="opencode",
        resolved_low_level_runtime="opencode-run",
    )

    result = validate_runtime_receipt(manifest, receipt)
    serialized = json.dumps(
        {
            "manifest": manifest.to_dict(),
            "receipt": receipt.to_dict(),
            "validation": result.to_dict(),
        }
    )

    assert result.valid is True
    assert result.status == "valid_runtime_resolution"
    assert result.reasons == ()
    assert "credential-value-must-never-be-read" not in serialized


def test_command_metadata_rejects_credential_value_overrides(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="credential values cannot be environment overrides"):
        CommandSpec(
            agent_product="opencode",
            argv=("opencode", "run", "task"),
            cwd=str(tmp_path),
            output_format="text",
            environment_overrides=(("DASHSCOPE_TP_API_KEY", "must-not-serialize"),),
        )


def test_comparable_clean_rejects_declared_memory_or_skill_state() -> None:
    with pytest.raises(ValueError, match="cannot declare memory or skill state"):
        build_runtime_manifest(
            request=_request(),
            provider_profile=QWENCLOUD_TOKEN_PLAN,
            profile_name="comparable-clean",
            memory_hashes=("sha256:undeclared-memory",),
        )


def test_runtime_state_change_invalidates_bound_receipt(tmp_path: Path) -> None:
    isolated_home = tmp_path / "home"
    isolated_home.mkdir()
    initial_hash = hash_runtime_state_tree(isolated_home)
    manifest = build_runtime_manifest(
        request=_request(agent_product="hermes", low_level_runtime="hermes-agent-loop"),
        provider_profile=QWENCLOUD_TOKEN_PLAN,
        profile_state_hash=initial_hash,
    )
    (isolated_home / "memory.md").write_text("unexpected task-specific memory", encoding="utf-8")
    changed_hash = hash_runtime_state_tree(isolated_home)

    validation = validate_runtime_receipt(
        manifest,
        RuntimeReceipt(
            resolved_provider="qwencloud-token-plan",
            resolved_model="deepseek-v4-pro",
            resolved_agent_product="hermes",
            resolved_low_level_runtime="hermes-agent-loop",
            resolved_profile_state_hash=changed_hash,
        ),
    )

    assert initial_hash != changed_hash
    assert validation.valid is False
    assert "profile_state_mismatch" in validation.reasons


def test_state_bound_manifest_requires_state_hash_in_receipt(tmp_path: Path) -> None:
    initial_hash = hash_runtime_state_tree(tmp_path)
    manifest = build_runtime_manifest(
        request=_request(agent_product="openclaw", low_level_runtime="openclaw-embedded"),
        provider_profile=QWENCLOUD_TOKEN_PLAN,
        profile_state_hash=initial_hash,
    )

    validation = validate_runtime_receipt(
        manifest,
        RuntimeReceipt(
            resolved_provider="qwencloud-token-plan",
            resolved_model="deepseek-v4-pro",
            resolved_agent_product="openclaw",
            resolved_low_level_runtime="openclaw-embedded",
        ),
    )

    assert "profile_state_receipt_missing" in validation.reasons
