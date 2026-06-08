from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any


LEGACY_KAPPASKI_ENV_FLAG = "INVART_ENABLE_LEGACY_KAPPASKI_ENV"


def legacy_kappaski_env_enabled(environ: Mapping[str, str] | None = None) -> bool:
    env = environ or os.environ
    return (
        env.get(LEGACY_KAPPASKI_ENV_FLAG) == "1"
        or "KAPPASKI_SESSION_ID" in env
        or "KAPPASKI_LEDGER" in env
    )


def invart_session_env(
    *,
    session_id: str,
    ledger: str,
    target: str | None = None,
    adapter: str | None = None,
    adapter_kind: str | None = None,
    include_legacy: bool | None = None,
    environ: Mapping[str, str] | None = None,
) -> dict[str, str]:
    payload = {
        "INVART_SESSION_ID": session_id,
        "INVART_LEDGER": ledger,
    }
    if target is not None:
        payload["INVART_TARGET"] = target
    if adapter is not None:
        payload["INVART_ADAPTER"] = adapter
    if adapter_kind is not None:
        payload["INVART_ADAPTER_KIND"] = adapter_kind

    legacy_enabled = legacy_kappaski_env_enabled(environ) if include_legacy is None else include_legacy
    if legacy_enabled:
        payload["KAPPASKI_SESSION_ID"] = session_id
        payload["KAPPASKI_LEDGER"] = ledger
        if target is not None:
            payload["KAPPASKI_TARGET"] = target
        if adapter is not None:
            payload["KAPPASKI_ADAPTER"] = adapter
        if adapter_kind is not None:
            payload["KAPPASKI_ADAPTER_KIND"] = adapter_kind
    return payload


def child_env(base: Mapping[str, str] | None = None, **session_values: Any) -> dict[str, str]:
    env = dict(base or os.environ)
    env.update(invart_session_env(environ=env, **session_values))
    return env


__all__ = ["LEGACY_KAPPASKI_ENV_FLAG", "child_env", "invart_session_env", "legacy_kappaski_env_enabled"]
