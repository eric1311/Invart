from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from typing import Any

from invart.core.artifacts import stable_json_hash, write_json_artifact
from invart.core.models import utc_now

from .agentdojo_cli_proxy import AgentDojoCliProxy, start_budgeted_opencode_runtime
from .provider_credentials import provider_secret_values
from .provider_run_control import scan_provider_artifact_tree, secure_provider_artifact_tree


SMOKE_SCHEMA_VERSION = "invart.opencode_native_provider_smoke.v0.1"


def run_opencode_native_smoke(
    *,
    out_dir: Path,
    provider: str,
    model_id: str,
    agent_version: str,
    approval_path: Path,
    budget_state_path: Path,
    maximum_tokens_per_call: int = 4096,
    timeout: float = 120.0,
) -> dict[str, Any]:
    root = out_dir.expanduser().absolute()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    root.chmod(0o700)
    runtime = start_budgeted_opencode_runtime(
        provider=provider,
        model_id=model_id,
        agent_version=agent_version,
        approval_path=approval_path,
        budget_state_path=budget_state_path,
        control_dir=root / "control",
        maximum_tokens_per_call=maximum_tokens_per_call,
        timeout=timeout,
    )
    try:
        proxy = AgentDojoCliProxy(
            agent="opencode",
            model_id="invart-opencode-native-smoke",
            mode="baseline_agent",
            case_id="opencode-native-provider-smoke",
            cwd=root / "workspace",
            log_dir=root / "proxy-log",
            timeout=timeout,
            policy_variant="V0",
            agent_runtime_manifest=runtime.manifest,
            opencode_config_path=runtime.config_path,
            provider_gateway_log_path=runtime.gateway_log_path,
        )
        response = proxy.complete(
            {
                "model": "invart-opencode-native-smoke",
                "messages": [
                    {
                        "role": "user",
                        "content": "Do not call a tool. Reply with exactly OK and no other text.",
                    }
                ],
            }
        )
    finally:
        runtime.close()
    content = str(response["choices"][0]["message"]["content"] or "").strip()
    call_records = _read_jsonl(root / "proxy-log" / "p0_agentdojo_proxy_calls.jsonl")
    gateway_records = _read_jsonl(root / "control" / "provider_gateway_requests.jsonl")
    terminal_gateway_records = [
        item
        for item in gateway_records
        if item.get("status") in {
            "forwarded",
            "transport_failed",
            "rejected_before_reservation",
        }
    ]
    pending_ids = {
        str(item.get("gateway_request_id") or "")
        for item in gateway_records
        if item.get("status") == "reserved_pending" and item.get("gateway_request_id")
    }
    terminal_ids = {
        str(item.get("gateway_request_id") or "")
        for item in terminal_gateway_records
        if item.get("gateway_request_id")
    }
    orphan_pending_ids = sorted(pending_ids - terminal_ids)
    forwarded_records = [
        item for item in terminal_gateway_records if item.get("status") == "forwarded"
    ]
    returncodes = [
        item.get("supervision", {}).get("returncode")
        for item in call_records
        if isinstance(item.get("supervision"), dict)
    ]
    passed = bool(
        content == "OK"
        and call_records
        and forwarded_records
        and not orphan_pending_ids
        and all(code == 0 for code in returncodes)
        and all(item.get("status") == "forwarded" for item in terminal_gateway_records)
    )
    payload = {
        "schema_version": SMOKE_SCHEMA_VERSION,
        "generated_at": utc_now(),
        "status": "pass" if passed else "fail",
        "agent": "opencode",
        "agent_version": agent_version,
        "provider": provider,
        "model": model_id,
        "runtime_manifest": runtime.manifest.to_dict(),
        "response_hash": stable_json_hash({"response": content}),
        "response_chars": len(content),
        "exact_ok": content == "OK",
        "proxy_calls": len(call_records),
        "provider_gateway_calls": len(forwarded_records),
        "provider_gateway_records": len(gateway_records),
        "provider_gateway_statuses": [
            str(item.get("status") or "") for item in terminal_gateway_records
        ],
        "provider_gateway_orphan_pending_ids": orphan_pending_ids,
        "returncodes": returncodes,
        "budget_state_present": budget_state_path.expanduser().absolute().is_file(),
        "claim_boundary": (
            "This is a bounded native OpenCode/provider compatibility smoke. It is not AgentDojo "
            "utility, attack success, mediation-effect, or cross-agent evidence."
        ),
    }
    write_json_artifact(root / "opencode_native_smoke.json", payload)
    secure_provider_artifact_tree(root)
    scan = scan_provider_artifact_tree(
        root,
        secret_values=provider_secret_values(provider=provider, agent="opencode"),
    )
    payload["artifact_scan"] = scan
    payload["ephemeral_runtime_state_removed"] = not (
        root / "control" / "runtime-home"
    ).exists()
    payload["status"] = "pass" if passed and scan.get("status") == "pass" else "fail"
    write_json_artifact(root / "opencode_native_smoke.json", payload)
    secure_provider_artifact_tree(root)
    return payload


def finalize_opencode_native_smoke_artifact(
    *,
    out_dir: Path,
    provider: str,
) -> dict[str, Any]:
    root = out_dir.expanduser().absolute()
    artifact_path = root / "opencode_native_smoke.json"
    if not artifact_path.is_file():
        raise ValueError("OpenCode smoke artifact is missing")
    payload = json.loads(artifact_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("schema_version") != SMOKE_SCHEMA_VERSION:
        raise ValueError("OpenCode smoke artifact schema is invalid")
    state_dir = root / "control" / "runtime-home"
    if state_dir.is_symlink():
        raise ValueError("OpenCode ephemeral runtime state must not be a symlink")
    if state_dir.exists():
        shutil.rmtree(state_dir)
    secure_provider_artifact_tree(root)
    scan = scan_provider_artifact_tree(
        root,
        secret_values=provider_secret_values(provider=provider, agent="opencode"),
    )
    functional_pass = bool(
        payload.get("exact_ok") is True
        and int(payload.get("provider_gateway_calls") or 0) >= 1
        and not payload.get("provider_gateway_orphan_pending_ids")
        and payload.get("returncodes")
        and all(code == 0 for code in payload["returncodes"])
        and all(status == "forwarded" for status in payload.get("provider_gateway_statuses", []))
    )
    payload["artifact_scan"] = scan
    payload["ephemeral_runtime_state_removed"] = not state_dir.exists()
    payload["status"] = "pass" if functional_pass and scan.get("status") == "pass" else "fail"
    payload["finalized_at"] = utc_now()
    write_json_artifact(artifact_path, payload)
    secure_provider_artifact_tree(root)
    return payload


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            records.append(payload)
    return records


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run one approval-bound native OpenCode smoke.")
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--provider", default="qwencloud-token-plan")
    parser.add_argument("--model", default="deepseek-v4-pro")
    parser.add_argument("--agent-version", required=True)
    parser.add_argument("--approval", required=True)
    parser.add_argument("--budget-state", required=True)
    parser.add_argument("--maximum-tokens-per-call", type=int, default=4096)
    parser.add_argument("--timeout", type=float, default=120.0)
    args = parser.parse_args(argv)
    payload = run_opencode_native_smoke(
        out_dir=Path(args.out_dir),
        provider=args.provider,
        model_id=args.model,
        agent_version=args.agent_version,
        approval_path=Path(args.approval),
        budget_state_path=Path(args.budget_state),
        maximum_tokens_per_call=args.maximum_tokens_per_call,
        timeout=args.timeout,
    )
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if payload.get("status") == "pass" else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
