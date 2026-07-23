from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Mapping, Sequence


_ENV_PASSTHROUGH = {
    "COMSPEC",
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "PATH",
    "PATHEXT",
    "PYTHONPATH",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "TMPDIR",
    "VIRTUAL_ENV",
}
_SECRET_NAME_MARKERS = ("KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "AUTH")
_SECRET_ARG_FLAGS = {"--api-key", "--token", "--secret", "--password", "--authorization"}
_AUTHORIZATION_RE = re.compile(r"(?i)(Authorization\s*:\s*Bearer\s+)([^\s\"']+)")
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)((?:DASHSCOPE_TP_API_KEY|DASHSCOPE_API_KEY|OPENAI_API_KEY|ANTHROPIC_API_KEY)\s*=\s*)([^\s\"']+)"
)
_LOOPBACK_NO_PROXY = ("localhost", "127.0.0.1", "::1")


def provider_api_keys(agent: str, *, provider: str | None = None) -> list[str]:
    normalized_provider = _normalize_agent(provider or "")
    if normalized_provider in {"qwencloud", "qwencloud-token-plan", "dashscope-token-plan", "token-plan"}:
        return ["DASHSCOPE_TP_API_KEY"]
    if normalized_provider in {"dashscope", "qwencloud-payg", "qwen-payg"}:
        return ["DASHSCOPE_API_KEY"]
    normalized = _normalize_agent(agent)
    if normalized in {"codex", "openai-codex"}:
        return ["OPENAI_API_KEY"]
    if normalized in {"claude", "claude-code"}:
        return ["ANTHROPIC_API_KEY"]
    if normalized in {"gemini", "gemini-cli"}:
        return ["GEMINI_API_KEY"]
    return []


def provider_credential_options(agent: str, *, provider: str | None = None) -> list[dict[str, Any]]:
    options: list[dict[str, Any]] = []
    for key in provider_api_keys(agent, provider=provider):
        options.append({
            "name": key,
            "kind": "provider_api_key",
            "present": bool(os.environ.get(key)),
            "secret_material": True,
        })
    config = None if provider else _provider_cli_config(agent)
    if config:
        present = any(Path(path).expanduser().exists() for path in config["paths"])
        options.append({
            "name": config["name"],
            "kind": "provider_cli_config",
            "present": present,
            "secret_material": True,
            "candidates": config["labels"],
        })
    return options


def provider_credential_present(agent: str, *, provider: str | None = None) -> bool:
    return any(bool(item.get("present")) for item in provider_credential_options(agent, provider=provider))


def provider_credential_missing_label(agent: str) -> str:
    normalized = _normalize_agent(agent) or "unknown-agent"
    return f"provider_credential:{normalized}"


def provider_credential_shell_missing_condition(agent: str, *, provider: str | None = None) -> str:
    checks = [f'[[ -z "${{{key}:-}}" ]]' for key in provider_api_keys(agent, provider=provider)]
    config = None if provider else _provider_cli_config(agent)
    if config:
        for label in config["labels"]:
            checks.append(f'[[ ! -e "$HOME/{label}" ]]')
    return " && ".join(checks) or "false"


def provider_credential_label(agent: str, *, provider: str | None = None) -> str:
    names = [item["name"] for item in provider_credential_options(agent, provider=provider)]
    return " or ".join(names) if names else "provider credential"


def build_scoped_provider_environment(
    *,
    provider: str | None,
    agent: str = "",
    base_env: Mapping[str, str] | None = None,
    additional: Mapping[str, str] | None = None,
    include_provider_credentials: bool = True,
    include_passthrough: bool = True,
) -> dict[str, str]:
    """Build a least-privilege child environment without serializing secret values.

    Provider credentials are selected by provider identity, not inferred from the
    agent product. Additional values are accepted only when their names are not
    secret-like; provider keys must come from ``base_env`` so callers cannot
    accidentally place literal credentials in manifests or command builders.
    """

    source = dict(base_env or os.environ)
    scoped = (
        {name: value for name, value in source.items() if name in _ENV_PASSTHROUGH}
        if include_passthrough
        else {}
    )
    scoped.update(loopback_no_proxy_environment(source))
    if include_provider_credentials:
        for name in provider_api_keys(agent, provider=provider):
            value = source.get(name)
            if value:
                scoped[name] = value
    for name, value in (additional or {}).items():
        if _is_secret_name(name):
            raise ValueError(f"secret-like additional environment variable is not allowed: {name}")
        scoped[str(name)] = str(value)
    return scoped


def loopback_no_proxy_environment(
    source: Mapping[str, str] | None = None,
) -> dict[str, str]:
    values: list[str] = []
    for name in ("NO_PROXY", "no_proxy"):
        for value in str((source or {}).get(name) or "").split(","):
            normalized = value.strip()
            if normalized and normalized not in values:
                values.append(normalized)
    for value in _LOOPBACK_NO_PROXY:
        if value not in values:
            values.append(value)
    merged = ",".join(values)
    return {"NO_PROXY": merged, "no_proxy": merged}


def provider_secret_values(
    *,
    provider: str | None,
    agent: str = "",
    base_env: Mapping[str, str] | None = None,
) -> list[str]:
    source = base_env or os.environ
    return [
        str(source[name])
        for name in provider_api_keys(agent, provider=provider)
        if source.get(name)
    ]


def assert_no_secret_argv(command: Sequence[str], *, secret_values: Sequence[str] = ()) -> None:
    secrets = [str(value) for value in secret_values if str(value)]
    for index, part in enumerate(command):
        text = str(part)
        if text.lower() in _SECRET_ARG_FLAGS:
            raise ValueError("provider secret material must not be supplied through command arguments")
        if any(secret in text for secret in secrets):
            raise ValueError(f"secret material detected in command argument {index}")


def redact_provider_secrets(text: str, *, secret_values: Sequence[str] = ()) -> str:
    redacted = str(text)
    for secret in sorted({str(value) for value in secret_values if str(value)}, key=len, reverse=True):
        redacted = redacted.replace(secret, "<redacted>")
    redacted = _AUTHORIZATION_RE.sub(r"\1<redacted>", redacted)
    redacted = _SECRET_ASSIGNMENT_RE.sub(r"\1<redacted>", redacted)
    return redacted


def _provider_cli_config(agent: str) -> dict[str, Any] | None:
    normalized = _normalize_agent(agent)
    if normalized in {"codex", "openai-codex"}:
        return {
            "name": "CODEX_CLI_CONFIG",
            "paths": ["~/.codex/auth.json", "~/.codex"],
            "labels": [".codex/auth.json", ".codex"],
        }
    if normalized in {"claude", "claude-code"}:
        return {
            "name": "CLAUDE_CLI_CONFIG",
            "paths": ["~/.claude.json", "~/.claude/settings.json", "~/.claude"],
            "labels": [".claude.json", ".claude/settings.json", ".claude"],
        }
    if normalized in {"gemini", "gemini-cli"}:
        return {
            "name": "GEMINI_CLI_CONFIG",
            "paths": ["~/.gemini"],
            "labels": [".gemini"],
        }
    return None


def _normalize_agent(agent: str) -> str:
    return str(agent or "").strip().replace("_", "-").lower()


def _is_secret_name(name: str) -> bool:
    normalized = str(name).upper()
    return any(marker in normalized for marker in _SECRET_NAME_MARKERS)
