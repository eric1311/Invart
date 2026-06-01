from __future__ import annotations

import json
import hashlib
try:
    import tomllib  # type: ignore
except ModuleNotFoundError:  # pragma: no cover - exercised on Python < 3.11
    tomllib = None
from pathlib import Path
from typing import Any
import uuid

from .ledger import append_ledger_entry
from .models import LedgerEntry, utc_now

DEFAULT_PROFILE: dict[str, Any] = {
    "schema_version": "kappaski.policy_profile.v0.11",
    "name": "balanced",
    "mode": "advisory",
    "taint": {"handoff_inheritance": "resource-reference"},
    "replay": {"raw_content": "folded", "max_raw_content_length": 1200},
    "enterprise": {"local_override": False, "break_glass": False},
}


def load_profile_file(path: Path) -> dict[str, Any]:
    suffix = path.suffix.lower()
    data = path.read_bytes()
    if suffix == ".toml":
        payload = tomllib.loads(data.decode("utf-8")) if tomllib else _parse_minimal_toml(data.decode("utf-8"))
    elif suffix == ".json":
        payload = json.loads(data.decode("utf-8"))
    else:
        raise ValueError("policy profile must be TOML or JSON")
    if not isinstance(payload, dict):
        raise ValueError("policy profile must be an object")
    return payload


def resolve_profile(*, team: Path | None = None, repo: Path | None = None, session: Path | None = None) -> dict[str, Any]:
    resolved = dict(DEFAULT_PROFILE)
    sources = []
    for scope, path in (("team", team), ("repo", repo), ("session", session)):
        if not path:
            continue
        profile = load_profile_file(path)
        resolved = _deep_merge(resolved, profile)
        sources.append({"scope": scope, "path": str(path)})
    resolved["resolution"] = {"precedence": "session > repo > team", "sources": sources}
    return resolved


def _deep_merge(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    merged = dict(left)
    for key, value in right.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _parse_minimal_toml(text: str) -> dict[str, Any]:
    root: dict[str, Any] = {}
    current = root
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            name = line[1:-1].strip()
            current = root.setdefault(name, {})
            if not isinstance(current, dict):
                raise ValueError(f"invalid TOML section: {name}")
            continue
        if "=" not in line:
            raise ValueError(f"unsupported TOML line: {raw_line}")
        key, value = [part.strip() for part in line.split("=", 1)]
        current[key] = _parse_toml_scalar(value)
    return root


def _parse_toml_scalar(value: str) -> Any:
    if value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    if value in {"true", "false"}:
        return value == "true"
    try:
        return int(value)
    except ValueError:
        return value


def resolve_profile_from_paths(team: str | None = None, repo: str | None = None, session: str | None = None) -> dict[str, Any] | None:
    if not team and not repo and not session:
        return None
    return resolve_profile(
        team=Path(team) if team else None,
        repo=Path(repo) if repo else None,
        session=Path(session) if session else None,
    )


def policy_mode_from_profile(profile: dict[str, Any] | None, fallback: str) -> str:
    if not profile:
        return fallback
    mode = profile.get("mode")
    return str(mode) if mode else fallback


def include_raw_replay(profile: dict[str, Any] | None, fallback: bool = True) -> bool:
    if not profile:
        return fallback
    replay = profile.get("replay") if isinstance(profile.get("replay"), dict) else {}
    raw_policy = str(replay.get("raw_content", "folded"))
    if raw_policy in {"hidden", "redacted", "none"}:
        return False
    return fallback


def record_break_glass_override(ledger_path: Path, *, session_id: str, actor: str, reason: str, scope: str, expires_at: str | None = None) -> dict[str, Any]:
    if not actor:
        raise ValueError("break-glass requires actor")
    if not reason:
        raise ValueError("break-glass requires reason")
    now = utc_now()
    result = {
        "override_type": "break_glass",
        "override_id": "pov_" + uuid.uuid4().hex[:16],
        "session_id": session_id,
        "actor": actor,
        "reason": reason,
        "scope": scope,
        "expires_at": expires_at,
        "recorded_at": now,
    }
    entry = LedgerEntry(
        sequence=0,
        entry_id=f"led_{uuid.uuid4().hex[:16]}",
        session_id=session_id,
        timestamp=now,
        entry_type="profile_override",
        event={"type": "profile_override", **result},
        result=result,
    )
    appended = append_ledger_entry(entry, ledger_path)
    return {"override": result, "entry": appended.to_dict()}


def create_profile_distribution_bundle(profile: dict[str, Any], *, scope: str, distributed_by: str) -> dict[str, Any]:
    if scope not in {"team", "repo", "session"}:
        raise ValueError("profile distribution scope must be team, repo, or session")
    canonical = json.dumps(profile, ensure_ascii=False, sort_keys=True)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return {
        "schema_version": "kappaski.profile_distribution.v0.11",
        "bundle_id": "pdb_" + uuid.uuid4().hex[:16],
        "scope": scope,
        "distributed_by": distributed_by,
        "distributed_at": utc_now(),
        "hash": f"sha256:{digest}",
        "profile": json.loads(canonical),
        "precedence": "session > repo > team",
        "local_override_allowed": bool(profile.get("enterprise", {}).get("local_override")) if isinstance(profile.get("enterprise"), dict) else False,
    }


def create_profile_registry(*, owner: str, profiles: list[tuple[str, dict[str, Any]]]) -> dict[str, Any]:
    if not owner:
        raise ValueError("profile registry requires owner")
    records = []
    for scope, profile in profiles:
        if scope not in {"team", "repo", "session"}:
            raise ValueError("profile registry scope must be team, repo, or session")
        canonical = json.dumps(profile, ensure_ascii=False, sort_keys=True)
        records.append(
            {
                "scope": scope,
                "name": str(profile.get("name", scope)),
                "version": str(profile.get("version", profile.get("schema_version", "unversioned"))),
                "hash": "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
                "profile": json.loads(canonical),
                "pinned": False,
            }
        )
    return {
        "schema_version": "kappaski.profile_registry.v0.23",
        "registry_id": "preg_" + uuid.uuid4().hex[:16],
        "owner": owner,
        "created_at": utc_now(),
        "precedence": "session > repo > team",
        "profiles": records,
    }


def pin_profile_bundle(registry: dict[str, Any], *, scope: str, profile_name: str, distributed_by: str) -> dict[str, Any]:
    profile = _find_registry_profile(registry, scope, profile_name)
    if profile is None:
        raise ValueError("profile not found in registry")
    return {
        "schema_version": "kappaski.profile_pin.v0.23",
        "pin_id": "pin_" + uuid.uuid4().hex[:16],
        "registry_id": registry.get("registry_id"),
        "scope": scope,
        "profile_name": profile_name,
        "profile_hash": profile["hash"],
        "profile": profile["profile"],
        "distributed_by": distributed_by,
        "pinned_at": utc_now(),
        "precedence": registry.get("precedence", "session > repo > team"),
    }


def verify_profile_bundle(bundle: dict[str, Any], registry: dict[str, Any]) -> dict[str, Any]:
    profile = _find_registry_profile(registry, str(bundle.get("scope")), str(bundle.get("profile_name")))
    matches = bool(profile and profile.get("hash") == bundle.get("profile_hash"))
    return {
        "schema_version": "kappaski.profile_pin_verify.v0.23",
        "status": "pass" if matches else "fail",
        "bundle_id": bundle.get("pin_id"),
        "registry_id": registry.get("registry_id"),
        "profile": dict(bundle.get("profile") or {}),
        "hash_matches": matches,
        "precedence": "session > repo > team",
    }


def apply_raw_content_policy(raw_content: str, profile: dict[str, Any] | None) -> dict[str, Any]:
    replay = profile.get("replay") if isinstance(profile, dict) and isinstance(profile.get("replay"), dict) else {}
    mode = str(replay.get("raw_content", "folded"))
    max_len = int(replay.get("max_raw_content_length", 1200))
    if mode in {"hidden", "none"}:
        return {"display": "hidden", "content": "", "original_length": len(raw_content), "truncated": False}
    if mode == "redacted":
        return {"display": "redacted", "content": "[REDACTED]", "original_length": len(raw_content), "truncated": False}
    if mode == "truncated" or len(raw_content) > max_len:
        return {"display": "truncated", "content": raw_content[:max_len], "original_length": len(raw_content), "truncated": len(raw_content) > max_len}
    if mode == "visible":
        return {"display": "visible", "content": raw_content, "original_length": len(raw_content), "truncated": False}
    return {"display": "folded", "content": raw_content[:max_len], "original_length": len(raw_content), "truncated": len(raw_content) > max_len}


def _find_registry_profile(registry: dict[str, Any], scope: str, profile_name: str) -> dict[str, Any] | None:
    for item in registry.get("profiles", []):
        if not isinstance(item, dict):
            continue
        if item.get("scope") == scope and item.get("name") == profile_name:
            return item
    return None


def review_break_glass_override(
    ledger_path: Path,
    *,
    override_id: str,
    reviewer: str,
    status: str,
    reason: str,
) -> dict[str, Any]:
    if status not in {"approved", "rejected"}:
        raise ValueError("break-glass review status must be approved or rejected")
    if not reviewer:
        raise ValueError("break-glass review requires reviewer")
    if not reason:
        raise ValueError("break-glass review requires reason")
    review = {
        "schema_version": "kappaski.profile_review.v0.11",
        "review_id": "prv_" + uuid.uuid4().hex[:16],
        "override_id": override_id,
        "reviewer": reviewer,
        "status": status,
        "reason": reason,
        "reviewed_at": utc_now(),
    }
    entry = LedgerEntry(
        sequence=0,
        entry_id="led_" + uuid.uuid4().hex[:16],
        session_id=_session_id_from_ledger(ledger_path),
        timestamp=utc_now(),
        entry_type="profile_review",
        event={"type": "profile_review", **review},
        result=review,
    )
    appended = append_ledger_entry(entry, ledger_path)
    return {"review": review, "entry": appended.to_dict()}


def _session_id_from_ledger(ledger_path: Path) -> str:
    from .ledger import load_ledger_entries

    entries, _warnings = load_ledger_entries(ledger_path)
    for entry in entries:
        if entry.session_id:
            return entry.session_id
    return "profile_review"


def gate_requires_closed_session(profile: dict[str, Any] | None) -> bool:
    if not profile:
        return False
    gate = profile.get("gate") if isinstance(profile.get("gate"), dict) else {}
    return bool(gate.get("require_closed_session", False))


def gate_coverage_requirements(profile: dict[str, Any] | None) -> dict[str, str]:
    if not profile:
        return {}
    gate = profile.get("gate") if isinstance(profile.get("gate"), dict) else {}
    requirements = gate.get("coverage_requirements") if isinstance(gate.get("coverage_requirements"), dict) else {}
    return {str(key): str(value) for key, value in requirements.items()}
