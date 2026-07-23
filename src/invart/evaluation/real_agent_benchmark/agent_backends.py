from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Optional
from urllib import error as urllib_error
from urllib import request as urllib_request

from invart.core.artifacts import stable_json_hash

from .agent_runtime_manifest import (
    ProviderProfile,
    RuntimeManifest,
    RuntimeReceipt,
    RuntimeReceiptValidation,
    RuntimeRequest,
    provider_profile_for_id,
    validate_runtime_receipt,
)
from .provider_credentials import redact_provider_secrets
from .provider_run_control import ProviderBudgetLedger


_SERIALIZABLE_ENVIRONMENT_METADATA = frozenset({"HOME", "OPENCODE_CONFIG"})
_OPENAI_FORWARD_FIELDS = (
    "messages",
    "temperature",
    "top_p",
    "max_tokens",
    "tools",
    "tool_choice",
    "response_format",
    "seed",
    "stop",
    "parallel_tool_calls",
)


def _maximum_completion_tokens(payload: Mapping[str, Any]) -> int:
    value = payload.get("max_tokens")
    if value is None:
        return 4096
    tokens = int(value)
    if tokens <= 0:
        raise ValueError("max_tokens must be positive")
    return tokens


@dataclass(frozen=True)
class BackendCompletion:
    response: dict[str, Any]
    receipt: RuntimeReceipt
    validation: RuntimeReceiptValidation
    request_hash: str
    budget_reservation: Optional[dict[str, Any]] = None


class OpenAICompatibleCompletionBackend:
    """Dependency-free hosted completion transport with immutable resolution evidence."""

    def __init__(
        self,
        *,
        manifest: RuntimeManifest,
        environment: Mapping[str, str],
        transport: Optional[Callable[..., dict[str, Any]]] = None,
        timeout: float = 120.0,
        budget_ledger: Optional[ProviderBudgetLedger] = None,
        bounded_compatibility_probe: bool = False,
    ) -> None:
        if manifest.provider_profile is None:
            raise ValueError("OpenAI-compatible backend requires a provider profile")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self.manifest = manifest
        self._environment = {str(name): str(value) for name, value in environment.items()}
        self._live_transport = transport is None
        self._transport = transport or _urllib_json_transport
        self.timeout = float(timeout)
        self._budget_ledger = budget_ledger
        self._bounded_compatibility_probe = bool(bounded_compatibility_probe)

    def complete(self, request: dict[str, Any]) -> BackendCompletion:
        profile = self.manifest.provider_profile
        if profile is None:  # pragma: no cover - constructor invariant
            raise RuntimeError("provider profile unavailable")
        secret = self._environment.get(profile.credential_env_name)
        if not secret:
            raise RuntimeError(f"required provider credential is missing: {profile.credential_env_name}")
        payload = _openai_request_payload(request, model=self.manifest.request.requested_model)
        budget_reservation = None
        if self._budget_ledger is not None:
            budget_reservation = self._budget_ledger.reserve(
                manifest=self.manifest,
                maximum_tokens=_maximum_completion_tokens(payload),
            )
        elif self._live_transport and not self._bounded_compatibility_probe:
            raise RuntimeError("live provider transport requires an approval-bound budget ledger")
        response = self._transport(
            url=profile.base_url.rstrip("/") + "/chat/completions",
            headers={
                "Authorization": f"Bearer {secret}",
                "Content-Type": "application/json",
            },
            body=json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
            timeout=self.timeout,
        )
        if not isinstance(response, dict):
            raise RuntimeError("provider response must be a JSON object")
        sanitized = _redact_payload(response, secret_values=[secret])
        resolved_model = str(sanitized.get("model") or "missing-provider-model")
        runtime_request = self.manifest.request
        receipt = RuntimeReceipt(
            resolved_provider=profile.profile_id,
            resolved_model=resolved_model,
            resolved_agent_product=runtime_request.agent_product,
            resolved_low_level_runtime=runtime_request.low_level_runtime,
        )
        return BackendCompletion(
            response=sanitized,
            receipt=receipt,
            validation=validate_runtime_receipt(self.manifest, receipt),
            request_hash=stable_json_hash(payload),
            budget_reservation=budget_reservation,
        )


@dataclass(frozen=True)
class CommandSpec:
    agent_product: str
    argv: tuple[str, ...]
    cwd: str
    output_format: str
    environment_overrides: tuple[tuple[str, str], ...] = ()
    credential_env_names: tuple[str, ...] = ()
    runtime_resolution_source: str = "command_and_runtime_receipt"

    def __post_init__(self) -> None:
        for field_name in ("agent_product", "cwd", "output_format", "runtime_resolution_source"):
            value = str(getattr(self, field_name) or "").strip()
            if not value:
                raise ValueError(f"{field_name} must be nonempty")
            object.__setattr__(self, field_name, value)
        argv = tuple(str(value) for value in self.argv)
        if not argv or any(not value for value in argv):
            raise ValueError("argv must contain nonempty arguments")
        object.__setattr__(self, "argv", argv)
        environment_overrides = tuple(
            sorted((str(name).strip(), str(value)) for name, value in self.environment_overrides)
        )
        if any(not name for name, _value in environment_overrides):
            raise ValueError("environment override names must be nonempty")
        if len({name for name, _value in environment_overrides}) != len(environment_overrides):
            raise ValueError("environment override names must be unique")
        if any(name not in _SERIALIZABLE_ENVIRONMENT_METADATA for name, _value in environment_overrides):
            raise ValueError("credential values cannot be environment overrides")
        object.__setattr__(self, "environment_overrides", environment_overrides)
        credential_env_names = tuple(sorted({str(value).strip() for value in self.credential_env_names}))
        if any(not value for value in credential_env_names):
            raise ValueError("credential environment names must be nonempty")
        if {name for name, _value in environment_overrides}.intersection(credential_env_names):
            raise ValueError("credential values cannot be environment overrides")
        object.__setattr__(self, "credential_env_names", credential_env_names)

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_product": self.agent_product,
            "argv": list(self.argv),
            "cwd": self.cwd,
            "output_format": self.output_format,
            "environment_overrides": [
                {"name": name, "value": value} for name, value in self.environment_overrides
            ],
            "credential_env_names": list(self.credential_env_names),
            "runtime_resolution_source": self.runtime_resolution_source,
        }


def build_opencode_command(
    *,
    request: RuntimeRequest,
    prompt: str,
    cwd: Path,
    provider_profile: Optional[ProviderProfile] = None,
    config_path: Optional[Path] = None,
) -> CommandSpec:
    _require_agent_product(request, "opencode")
    working_directory = _absolute_path(cwd)
    model = _provider_model(request.requested_provider, request.requested_model)
    return CommandSpec(
        agent_product="opencode",
        argv=(
            "opencode",
            "run",
            "--pure",
            "--model",
            model,
            "--format",
            "json",
            "--dir",
            working_directory,
            _required_text(prompt, "prompt"),
        ),
        cwd=working_directory,
        output_format="json_events",
        environment_overrides=(
            (("OPENCODE_CONFIG", _absolute_path(config_path)),) if config_path is not None else ()
        ),
        credential_env_names=_credential_env_names(request, provider_profile),
    )


def build_opencode_provider_config(
    *,
    request: RuntimeRequest,
    provider_profile: ProviderProfile,
    local_gateway_base_url: Optional[str] = None,
) -> dict[str, Any]:
    _require_agent_product(request, "opencode")
    if provider_profile.profile_id != request.requested_provider:
        raise ValueError("provider profile does not match requested_provider")
    provider_id = provider_profile.profile_id
    model_id = request.requested_model
    base_url = provider_profile.base_url
    api_key = f"{{env:{provider_profile.credential_env_name}}}"
    if local_gateway_base_url is not None:
        gateway = str(local_gateway_base_url).rstrip("/")
        if not gateway.startswith(("http://127.0.0.1:", "http://localhost:")):
            raise ValueError("OpenCode local gateway must use a loopback HTTP endpoint")
        base_url = gateway
        api_key = "invart-local-loopback-non-secret"
    return {
        "$schema": "https://opencode.ai/config.json",
        "model": f"{provider_id}/{model_id}",
        "small_model": f"{provider_id}/{model_id}",
        "autoupdate": False,
        "enabled_providers": [provider_id],
        "plugin": [],
        "mcp": {},
        "instructions": [],
        "provider": {
            provider_id: {
                "npm": "@ai-sdk/openai-compatible",
                "name": "QwenCloud Token Plan",
                "options": {
                    "baseURL": base_url,
                    "apiKey": api_key,
                },
                "models": {model_id: {"name": model_id}},
            }
        },
    }


def write_opencode_isolated_config(
    *,
    path: Path,
    request: RuntimeRequest,
    provider_profile: ProviderProfile,
    local_gateway_base_url: Optional[str] = None,
) -> Path:
    resolved = path.expanduser().resolve()
    resolved.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    resolved.parent.chmod(0o700)
    payload = build_opencode_provider_config(
        request=request,
        provider_profile=provider_profile,
        local_gateway_base_url=local_gateway_base_url,
    )
    resolved.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    resolved.chmod(0o600)
    return resolved


def build_hermes_command(
    *,
    request: RuntimeRequest,
    prompt: str,
    cwd: Path,
    isolated_home: Path,
    provider_profile: Optional[ProviderProfile] = None,
) -> CommandSpec:
    _require_agent_product(request, "hermes")
    working_directory = _absolute_path(cwd)
    home = _absolute_path(isolated_home)
    return CommandSpec(
        agent_product="hermes",
        argv=(
            "hermes",
            "chat",
            "--query",
            _required_text(prompt, "prompt"),
            "--quiet",
            "--model",
            request.requested_model,
        ),
        cwd=working_directory,
        output_format="final_text",
        environment_overrides=(("HOME", home),),
        credential_env_names=_credential_env_names(request, provider_profile),
        runtime_resolution_source="isolated_config_and_runtime_receipt",
    )


def build_openclaw_command(
    *,
    request: RuntimeRequest,
    prompt: str,
    cwd: Path,
    agent_id: str,
    session_id: str,
    provider_profile: Optional[ProviderProfile] = None,
) -> CommandSpec:
    _require_agent_product(request, "openclaw")
    return CommandSpec(
        agent_product="openclaw",
        argv=(
            "openclaw",
            "agent",
            "--local",
            "--json",
            "--agent",
            _required_text(agent_id, "agent_id"),
            "--session-id",
            _required_text(session_id, "session_id"),
            "--message",
            _required_text(prompt, "prompt"),
        ),
        cwd=_absolute_path(cwd),
        output_format="json",
        credential_env_names=_credential_env_names(request, provider_profile),
        runtime_resolution_source="manifest_and_runtime_receipt",
    )


def build_codex_command(*, prompt: str, cwd: Path) -> CommandSpec:
    working_directory = _absolute_path(cwd)
    return CommandSpec(
        agent_product="codex",
        argv=(
            "codex",
            "--ask-for-approval",
            "never",
            "exec",
            "--cd",
            working_directory,
            "--sandbox",
            "workspace-write",
            _required_text(prompt, "prompt"),
        ),
        cwd=working_directory,
        output_format="text",
        runtime_resolution_source="agent_native_control",
    )


def build_claude_code_command(*, prompt: str, cwd: Path) -> CommandSpec:
    return CommandSpec(
        agent_product="claude-code",
        argv=(
            "claude",
            "--print",
            "--permission-mode",
            "bypassPermissions",
            "--output-format",
            "text",
            "--max-budget-usd",
            "2",
            _required_text(prompt, "prompt"),
        ),
        cwd=_absolute_path(cwd),
        output_format="text",
        runtime_resolution_source="agent_native_control",
    )


def _require_agent_product(request: RuntimeRequest, expected: str) -> None:
    if request.agent_product != expected:
        raise ValueError(f"{expected} command requires agent_product={expected}")


def _provider_model(provider: str, model: str) -> str:
    prefix = f"{provider}/"
    return model if model.startswith(prefix) else prefix + model


def _credential_env_names(
    request: RuntimeRequest,
    provider_profile: Optional[ProviderProfile],
) -> tuple[str, ...]:
    profile = provider_profile or provider_profile_for_id(request.requested_provider)
    if profile is None:
        return ()
    if profile.profile_id != request.requested_provider:
        raise ValueError("provider profile does not match requested_provider")
    return (profile.credential_env_name,)


def _absolute_path(path: Path) -> str:
    return str(Path(path).expanduser().resolve())


def _required_text(value: str, name: str) -> str:
    rendered = str(value or "")
    if not rendered.strip():
        raise ValueError(f"{name} must be nonempty")
    return rendered


def _openai_request_payload(request: dict[str, Any], *, model: str) -> dict[str, Any]:
    messages = request.get("messages")
    if not isinstance(messages, list):
        raise ValueError("OpenAI-compatible completion requires a messages list")
    payload: dict[str, Any] = {"model": model, "messages": messages}
    for field_name in _OPENAI_FORWARD_FIELDS[1:]:
        if field_name in request:
            payload[field_name] = request[field_name]
    if request.get("stream") is True:
        raise ValueError("streaming provider responses are not supported by this evidence path")
    return payload


def _urllib_json_transport(
    *,
    url: str,
    headers: dict[str, str],
    body: str,
    timeout: float,
) -> dict[str, Any]:
    http_request = urllib_request.Request(
        url,
        data=body.encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urllib_request.urlopen(http_request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib_error.HTTPError as exc:
        provider_code = "unknown"
        try:
            error_payload = json.loads(exc.read().decode("utf-8"))
            if isinstance(error_payload, dict):
                nested_error = error_payload.get("error")
                nested_code = nested_error.get("code") if isinstance(nested_error, dict) else None
                provider_code = str(error_payload.get("code") or nested_code or "unknown")
        except Exception:
            provider_code = "unparseable"
        raise RuntimeError(f"provider transport failed: HTTP {exc.code} code={provider_code}") from exc
    except Exception as exc:
        raise RuntimeError(f"provider transport failed: {type(exc).__name__}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("provider response must be a JSON object")
    return payload


def _redact_payload(value: Any, *, secret_values: Iterable[str]) -> Any:
    secrets = tuple(str(item) for item in secret_values if str(item))
    if isinstance(value, dict):
        return {str(key): _redact_payload(item, secret_values=secrets) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_payload(item, secret_values=secrets) for item in value]
    if isinstance(value, str):
        return redact_provider_secrets(value, secret_values=secrets)
    return value


__all__ = [
    "BackendCompletion",
    "CommandSpec",
    "OpenAICompatibleCompletionBackend",
    "build_claude_code_command",
    "build_codex_command",
    "build_hermes_command",
    "build_openclaw_command",
    "build_opencode_command",
    "build_opencode_provider_config",
    "write_opencode_isolated_config",
]
