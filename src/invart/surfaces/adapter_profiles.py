from __future__ import annotations

import os
from typing import Any

SECRET_KEY_MARKERS = ("KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "AUTH", "SSH")


def build_adapter_profile(kind: str, env: dict[str, str] | None = None) -> dict[str, Any]:
    env = dict(os.environ if env is None else env)
    return {
        "schema_version": "invart.adapter_profile.v0.10",
        "adapter": kind,
        "environment": summarize_environment(env),
        "process_supervision": {
            "target": "strong_consistency",
            "mode": "best_effort_until_native_supervision",
            "degraded_mode_allowed": True,
            "degraded_mode_must_be_recorded": True,
        },
        "claude_code": {
            "first_hardened_target": kind == "claude-code",
            "expected_hooks": ["wrapper_command", "session_env", "tool_event_bridge"],
        } if kind == "claude-code" else {},
    }


def summarize_environment(env: dict[str, str], *, max_value_length: int = 96) -> dict[str, Any]:
    items = []
    for key in sorted(env):
        value = str(env[key])
        secret_like = any(marker in key.upper() for marker in SECRET_KEY_MARKERS)
        display = "[REDACTED]" if secret_like else _fold(value, max_value_length)
        items.append({
            "key": key,
            "value": display,
            "value_present": value != "",
            "secret_like_key": secret_like,
            "folded_by_default": True,
            "original_length": len(value),
            "content_note": "secret-like environment key" if secret_like else "environment value folded/truncated for audit display",
        })
    return {"count": len(items), "items": items}


def _fold(value: str, max_value_length: int) -> str:
    if len(value) <= max_value_length:
        return value
    return value[: max_value_length - 3] + "..."
