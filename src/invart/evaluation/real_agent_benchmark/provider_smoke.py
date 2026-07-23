from __future__ import annotations

import argparse
import json
import os
from typing import Any, Callable, Mapping, Optional

from invart.core.artifacts import stable_json_hash

from .agent_backends import OpenAICompatibleCompletionBackend
from .agent_runtime_manifest import (
    ClaimKind,
    QWENCLOUD_TOKEN_PLAN,
    build_runtime_manifest,
    completion_backend_request,
)


SMOKE_SCHEMA_VERSION = "invart.provider_compatibility_smoke.v0.1"


def run_qwencloud_compatibility_smoke(
    *,
    model: str = "deepseek-v4-pro",
    environment: Mapping[str, str] | None = None,
    tool_probe: bool = False,
    transport: Optional[Callable[..., dict[str, Any]]] = None,
    timeout: float = 120.0,
) -> dict[str, Any]:
    request = completion_backend_request(
        requested_provider=QWENCLOUD_TOKEN_PLAN.profile_id,
        requested_model=model,
        agent_product="provider-smoke",
        low_level_runtime="openai-compatible-chat-completions",
        evidence_kind=ClaimKind.COMPLETION_BACKEND,
    )
    manifest = build_runtime_manifest(request=request, provider_profile=QWENCLOUD_TOKEN_PLAN)
    backend = OpenAICompatibleCompletionBackend(
        manifest=manifest,
        environment=environment or os.environ,
        transport=transport,
        timeout=timeout,
        bounded_compatibility_probe=True,
    )
    completion = backend.complete(_smoke_request(tool_probe=tool_probe))
    choices = completion.response.get("choices")
    first_choice = choices[0] if isinstance(choices, list) and choices and isinstance(choices[0], dict) else {}
    message = first_choice.get("message") if isinstance(first_choice.get("message"), dict) else {}
    valid_tool_names = _valid_tool_call_names(message.get("tool_calls"))
    expected_tool_names = ["lookup_weather"] if tool_probe else []
    if not completion.validation.valid:
        status = "invalid_runtime_resolution"
    elif tool_probe and valid_tool_names != expected_tool_names:
        status = "fail_tool_conformance"
    else:
        status = "pass"
    usage = completion.response.get("usage") if isinstance(completion.response.get("usage"), dict) else {}
    return {
        "schema_version": SMOKE_SCHEMA_VERSION,
        "status": status,
        "provider": request.requested_provider,
        "model": request.requested_model,
        "endpoint_class": "token_plan_openai_compatible",
        "attribution_scope": manifest.attribution_scope,
        "checkpoint_model_family_claimable": manifest.checkpoint_model_family_claimable,
        "manifest_hash": manifest.manifest_hash,
        "request_hash": completion.request_hash,
        "response_hash": stable_json_hash(completion.response),
        "runtime_resolution": completion.validation.to_dict(),
        "finish_reason": first_choice.get("finish_reason"),
        "content_present": bool(message.get("content")),
        "tool_call_conformance": {
            "expected": tool_probe,
            "valid_calls": len(valid_tool_names),
            "tool_names": valid_tool_names,
        },
        "usage": {
            key: usage.get(key)
            for key in ("prompt_tokens", "completion_tokens", "total_tokens")
            if key in usage
        },
        "claim_boundary": (
            "This is a single hosted-provider compatibility probe. It is not AgentDojo utility, attack, "
            "native-agent-runtime, or Invart security-effect evidence."
        ),
    }


def _smoke_request(*, tool_probe: bool) -> dict[str, Any]:
    if not tool_probe:
        return {
            "messages": [
                {"role": "user", "content": "Reply with exactly OK."},
            ],
        }
    return {
        "messages": [
            {
                "role": "user",
                "content": "Call lookup_weather exactly once for Beijing. Do not answer in prose.",
            }
        ],
        "tools": [
            {
                "type": "function",
                "function": {
                    "name": "lookup_weather",
                    "description": "Look up weather for one city.",
                    "parameters": {
                        "type": "object",
                        "properties": {"city": {"type": "string"}},
                        "required": ["city"],
                        "additionalProperties": False,
                    },
                },
            }
        ],
    }


def _valid_tool_call_names(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    names: list[str] = []
    for call in value:
        if not isinstance(call, dict):
            continue
        function = call.get("function")
        if not isinstance(function, dict) or not str(function.get("name") or "").strip():
            continue
        arguments = function.get("arguments")
        try:
            parsed = json.loads(arguments) if isinstance(arguments, str) else arguments
        except json.JSONDecodeError:
            continue
        if not isinstance(parsed, dict):
            continue
        names.append(str(function["name"]))
    return names


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run one bounded QwenCloud compatibility probe.")
    parser.add_argument("--model", default=QWENCLOUD_TOKEN_PLAN.preferred_model)
    parser.add_argument("--tool-probe", action="store_true")
    parser.add_argument("--timeout", type=float, default=120.0)
    args = parser.parse_args(argv)
    try:
        result = run_qwencloud_compatibility_smoke(
            model=args.model,
            tool_probe=args.tool_probe,
            timeout=args.timeout,
        )
    except Exception as exc:
        result = {
            "schema_version": SMOKE_SCHEMA_VERSION,
            "status": "blocked",
            "provider": QWENCLOUD_TOKEN_PLAN.profile_id,
            "model": args.model,
            "error_type": type(exc).__name__,
            "error": str(exc),
            "claim_boundary": "No compatibility result is claimable from a blocked provider probe.",
        }
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] == "pass" else 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
