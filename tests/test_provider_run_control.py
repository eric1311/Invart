from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from invart.evaluation.real_agent_benchmark.agent_runtime_manifest import (
    ClaimKind,
    QWENCLOUD_TOKEN_PLAN,
    RuntimeRequest,
    build_runtime_manifest,
)
from invart.evaluation.real_agent_benchmark.provider_run_control import (
    ProviderBudgetLedger,
    create_provider_approval_packet,
    load_provider_approval_packet,
    scan_provider_artifact_tree,
    secure_provider_artifact_tree,
    write_provider_approval_packet,
)


def _manifest():
    return build_runtime_manifest(
        request=RuntimeRequest(
            requested_provider="qwencloud-token-plan",
            requested_model="deepseek-v4-pro",
            agent_product="opencode",
            low_level_runtime="agentdojo-fixed-loop",
            execution_contract="completion_backend",
            evidence_kind=ClaimKind.COMPLETION_BACKEND,
        ),
        provider_profile=QWENCLOUD_TOKEN_PLAN,
    )


def _approval(*, now: datetime, max_calls: int = 2, max_tokens: int = 1000):
    manifest = _manifest()
    return create_provider_approval_packet(
        approval_id="approval-test-001",
        approved_by="user",
        approved_at=now,
        expires_at=now + timedelta(hours=1),
        manifest_hash=manifest.manifest_hash,
        provider="qwencloud-token-plan",
        endpoint=QWENCLOUD_TOKEN_PLAN.base_url,
        model_ids=("deepseek-v4-pro",),
        max_calls=max_calls,
        max_total_tokens=max_tokens,
        purpose="bounded compatibility and benchmark preflight",
    )


def test_budget_ledger_binds_manifest_provider_model_expiry_and_budget(tmp_path: Path) -> None:
    now = datetime(2026, 7, 19, 12, 0, tzinfo=timezone.utc)
    manifest = _manifest()
    approval = _approval(now=now)
    ledger = ProviderBudgetLedger(approval=approval, state_path=tmp_path / "budget.json")

    validation = ledger.validate_scope(manifest=manifest, at=now)
    assert validation["status"] == "valid_provider_approval_scope"
    assert not (tmp_path / "budget.json").exists()

    first = ledger.reserve(
        manifest=manifest,
        maximum_tokens=400,
        at=now,
        request_id="gateway-request-1",
    )
    second = ledger.reserve(
        manifest=manifest,
        maximum_tokens=600,
        at=now,
        request_id="gateway-request-2",
    )

    assert first["call_index"] == 1
    assert second["remaining_calls"] == 0
    assert second["remaining_tokens"] == 0
    assert first["request_id"] == "gateway-request-1"
    assert (tmp_path / "budget.json").stat().st_mode & 0o077 == 0
    assert json.loads((tmp_path / "budget.json").read_text())["approval_hash"] == approval.approval_hash
    with pytest.raises(RuntimeError, match="call budget exhausted"):
        ledger.reserve(manifest=manifest, maximum_tokens=1, at=now)


def test_budget_ledger_fails_closed_on_scope_mismatch_and_expiry(tmp_path: Path) -> None:
    now = datetime(2026, 7, 19, 12, 0, tzinfo=timezone.utc)
    manifest = _manifest()
    approval = _approval(now=now)
    mismatched = build_runtime_manifest(
        request=RuntimeRequest(
            requested_provider="qwencloud-token-plan",
            requested_model="qwen3.7-max",
            agent_product="opencode",
            low_level_runtime="agentdojo-fixed-loop",
            execution_contract="completion_backend",
            evidence_kind="completion_backend",
        ),
        provider_profile=QWENCLOUD_TOKEN_PLAN,
    )
    ledger = ProviderBudgetLedger(approval=approval, state_path=tmp_path / "budget.json")

    with pytest.raises(RuntimeError, match="manifest hash mismatch"):
        ledger.reserve(manifest=mismatched, maximum_tokens=10, at=now)
    with pytest.raises(RuntimeError, match="approval expired"):
        ledger.reserve(manifest=manifest, maximum_tokens=10, at=now + timedelta(hours=2))


def test_recursive_artifact_scan_detects_nested_secret_patterns_and_permissions(tmp_path: Path) -> None:
    secret = "dashscope-test-secret-123456"
    nested = tmp_path / "nested"
    nested.mkdir()
    leaked = nested / "trace.jsonl"
    leaked.write_text(
        f'{{"env":"DASHSCOPE_TP_API_KEY={secret}","header":"Authorization: Bearer another-secret"}}',
        encoding="utf-8",
    )
    leaked.chmod(0o644)

    report = scan_provider_artifact_tree(tmp_path, secret_values=(secret,))

    assert report["status"] == "fail"
    assert report["scanned_files"] == 1
    assert {item["kind"] for item in report["secret_matches"]} >= {
        "exact_secret_value",
        "authorization_bearer",
        "secret_assignment",
    }
    assert report["permission_violations"]
    assert secret not in json.dumps(report)


def test_secure_artifact_tree_makes_nested_artifacts_owner_only(tmp_path: Path) -> None:
    nested = tmp_path / "nested"
    nested.mkdir()
    script = nested / "reproduce.sh"
    script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    script.chmod(0o755)
    data = nested / "result.json"
    data.write_text("{}", encoding="utf-8")
    data.chmod(0o644)

    secure_provider_artifact_tree(tmp_path)
    report = scan_provider_artifact_tree(tmp_path)

    assert report["status"] == "pass"
    assert os.access(script, os.X_OK)
    assert script.stat().st_mode & 0o777 == 0o700
    assert data.stat().st_mode & 0o777 == 0o600


def test_approval_packet_round_trips_only_when_hash_and_permissions_match(tmp_path: Path) -> None:
    approval = _approval(
        now=datetime(2026, 7, 19, 12, 0, tzinfo=timezone.utc),
        max_calls=3,
        max_tokens=1000,
    )
    path = tmp_path / "approval.json"
    path.write_text(json.dumps(approval.to_dict()), encoding="utf-8")
    path.chmod(0o600)

    loaded = load_provider_approval_packet(path)
    assert loaded.approval_hash == approval.approval_hash

    payload = json.loads(path.read_text())
    payload["max_calls"] = 4
    path.write_text(json.dumps(payload), encoding="utf-8")
    path.chmod(0o600)
    with pytest.raises(ValueError, match="hash"):
        load_provider_approval_packet(path)


def test_approval_and_budget_state_reject_symlinks(tmp_path: Path) -> None:
    now = datetime(2026, 7, 19, 12, 0, tzinfo=timezone.utc)
    approval = _approval(now=now)
    real_approval = tmp_path / "real-approval.json"
    real_approval.write_text(json.dumps(approval.to_dict()), encoding="utf-8")
    real_approval.chmod(0o600)
    approval_link = tmp_path / "approval-link.json"
    approval_link.symlink_to(real_approval)
    with pytest.raises(ValueError, match="non-symlink"):
        load_provider_approval_packet(approval_link)

    real_state = tmp_path / "real-budget.json"
    real_state.write_text("{}", encoding="utf-8")
    real_state.chmod(0o600)
    state_link = tmp_path / "budget-link.json"
    state_link.symlink_to(real_state)
    with pytest.raises(ValueError, match="must not be a symlink"):
        ProviderBudgetLedger(approval=approval, state_path=state_link)


def test_approval_writer_is_owner_only_and_refuses_overwrite(tmp_path: Path) -> None:
    approval = _approval(now=datetime(2026, 7, 19, 12, 0, tzinfo=timezone.utc))
    path = write_provider_approval_packet(tmp_path / "control" / "approval.json", approval)

    assert path.stat().st_mode & 0o077 == 0
    assert load_provider_approval_packet(path).approval_hash == approval.approval_hash
    with pytest.raises(FileExistsError):
        write_provider_approval_packet(path, approval)
