from __future__ import annotations

import json
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from invart.evaluation.real_agent_benchmark.agent_backends import (
    build_opencode_provider_config,
)
from invart.evaluation.real_agent_benchmark.agent_runtime_manifest import (
    QWENCLOUD_TOKEN_PLAN,
    build_runtime_manifest,
    native_runtime_request,
)
from invart.evaluation.real_agent_benchmark.provider_budget_gateway import (
    GatewayUpstreamResponse,
    ProviderBudgetGateway,
    reconcile_gateway_records,
    start_provider_budget_gateway,
)
from invart.evaluation.real_agent_benchmark.provider_run_control import (
    ProviderBudgetLedger,
    create_provider_approval_packet,
)


def _manifest():
    request = native_runtime_request(
        requested_provider="qwencloud-token-plan",
        requested_model="deepseek-v4-pro",
        agent_product="opencode",
        low_level_runtime="opencode-run-via-budget-gateway",
    )
    return build_runtime_manifest(
        request=request,
        provider_profile=QWENCLOUD_TOKEN_PLAN,
        profile_name="comparable-clean",
        agent_version="1.18.3",
        runtime_version="provider-budget-gateway-v0.1",
    )


def _gateway(tmp_path: Path, *, transport):
    manifest = _manifest()
    now = datetime.now(timezone.utc)
    approval = create_provider_approval_packet(
        approval_id="opencode-gateway-test",
        approved_by="user",
        approved_at=now - timedelta(minutes=1),
        expires_at=now + timedelta(hours=1),
        manifest_hash=manifest.manifest_hash,
        provider="qwencloud-token-plan",
        endpoint=QWENCLOUD_TOKEN_PLAN.base_url,
        model_ids=("deepseek-v4-pro",),
        max_calls=2,
        max_total_tokens=1024,
        purpose="bounded OpenCode gateway test",
    )
    ledger = ProviderBudgetLedger(
        approval=approval,
        state_path=tmp_path / "budget.json",
    )
    return ProviderBudgetGateway(
        manifest=manifest,
        budget_ledger=ledger,
        environment={"DASHSCOPE_TP_API_KEY": "real-secret-must-not-leak"},
        log_path=tmp_path / "gateway" / "requests.jsonl",
        maximum_tokens_per_call=512,
        transport=transport,
    )


def test_gateway_reserves_budget_and_preserves_stream_protocol_without_logging_prompt(
    tmp_path: Path,
) -> None:
    observed: dict[str, object] = {}

    def transport(*, url, headers, body, timeout):
        observed.update(url=url, headers=dict(headers), body=json.loads(body), timeout=timeout)
        return GatewayUpstreamResponse(
            status=200,
            content_type="text/event-stream",
            chunks=(b"data: {\"id\":\"one\"}\n\n", b"data: [DONE]\n\n"),
        )

    gateway = _gateway(tmp_path, transport=transport)
    result = gateway.forward(
        {
            "model": "deepseek-v4-pro",
            "messages": [{"role": "user", "content": "private prompt content"}],
            "stream": True,
            "max_tokens": 256,
        }
    )

    assert result.status == 200
    assert result.content_type == "text/event-stream"
    assert b"".join(result.chunks).endswith(b"data: [DONE]\n\n")
    assert observed["body"]["messages"][0]["content"] == "private prompt content"
    assert observed["headers"]["Authorization"] == "Bearer real-secret-must-not-leak"
    budget = json.loads((tmp_path / "budget.json").read_text())
    assert budget["calls_reserved"] == 1
    assert budget["tokens_reserved"] == 256
    log_path = tmp_path / "gateway" / "requests.jsonl"
    serialized = log_path.read_text()
    assert "private prompt content" not in serialized
    assert "real-secret-must-not-leak" not in serialized
    records = [json.loads(line) for line in serialized.splitlines()]
    assert [item["status"] for item in records] == ["reserved_pending", "forwarded"]
    assert records[0]["gateway_request_id"] == records[1]["gateway_request_id"]
    assert records[1]["request_hash"].startswith("sha256:")
    assert log_path.stat().st_mode & 0o077 == 0


def test_gateway_rejects_model_mismatch_and_clamps_per_call_overage(
    tmp_path: Path,
) -> None:
    forwarded: dict[str, object] = {}

    def transport(**kwargs):
        forwarded.update(body=json.loads(kwargs["body"]))
        return GatewayUpstreamResponse(200, "application/json", (b"{}",))

    gateway = _gateway(tmp_path, transport=transport)

    with pytest.raises(ValueError, match="model"):
        gateway.forward(
            {
                "model": "qwen3.7-max",
                "messages": [{"role": "user", "content": "hello"}],
                "max_tokens": 10,
            }
        )
    result = gateway.forward(
        {
            "model": "deepseek-v4-pro",
            "messages": [{"role": "user", "content": "hello"}],
            "max_tokens": 513,
        }
    )
    assert forwarded["body"]["max_tokens"] == 512
    assert result.record["requested_maximum_tokens"] == 513
    assert result.record["maximum_tokens"] == 512
    assert result.record["token_limit_clamped"] is True
    assert json.loads((tmp_path / "budget.json").read_text())["tokens_reserved"] == 512


def test_opencode_loopback_config_contains_no_provider_credential_reference() -> None:
    request = _manifest().request
    payload = build_opencode_provider_config(
        request=request,
        provider_profile=QWENCLOUD_TOKEN_PLAN,
        local_gateway_base_url="http://127.0.0.1:43123/v1",
    )
    options = payload["provider"]["qwencloud-token-plan"]["options"]

    assert options["baseURL"] == "http://127.0.0.1:43123/v1"
    assert options["apiKey"] == "invart-local-loopback-non-secret"
    assert "DASHSCOPE_TP_API_KEY" not in json.dumps(payload)

    with pytest.raises(ValueError, match="loopback"):
        build_opencode_provider_config(
            request=request,
            provider_profile=QWENCLOUD_TOKEN_PLAN,
            local_gateway_base_url="https://external.example/v1",
        )


def test_loopback_http_request_reaches_gateway_and_reconciles_terminal_receipt(
    tmp_path: Path,
) -> None:
    def transport(**_kwargs):
        return GatewayUpstreamResponse(
            200,
            "application/json",
            (b'{"choices":[{"message":{"role":"assistant","content":"OK"}}]}',),
        )

    gateway = _gateway(tmp_path, transport=transport)
    server, thread, port = start_provider_budget_gateway(gateway=gateway)
    try:
        request = urllib.request.Request(
            f"http://127.0.0.1:{port}/v1/chat/completions",
            data=json.dumps(
                {
                    "model": "deepseek-v4-pro",
                    "messages": [{"role": "user", "content": "reply OK"}],
                    "max_tokens": 16,
                }
            ).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            assert response.status == 200
            assert json.loads(response.read())["choices"][0]["message"]["content"] == "OK"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    records = [
        json.loads(line)
        for line in gateway.log_path.read_text(encoding="utf-8").splitlines()
    ]
    reconciliation = reconcile_gateway_records(records)
    assert reconciliation["ingress_count"] == 1
    assert reconciliation["forwarded_count"] == 1
    assert reconciliation["terminal_error_count"] == 0
    assert reconciliation["pending_without_terminal_request_ids"] == []
    assert reconciliation["terminal_without_pending_request_ids"] == []
    assert reconciliation["orphan_request_ids"] == []
