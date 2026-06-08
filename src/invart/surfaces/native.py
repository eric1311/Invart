from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "invart.native_integration.v0.15"

AGENT_SURFACE_PATHS: dict[str, dict[str, list[str]]] = {
    "claude-code": {
        "hooks": [".claude/settings.json"],
        "mcp": [".claude/settings.json"],
        "skills": [".claude/skills", "CLAUDE.md"],
    },
    "codex": {
        "hooks": [".codex/config.toml"],
        "plugins": [".codex/plugins"],
        "mcp": [".codex/config.toml"],
    },
    "gemini-cli": {
        "extensions": [".gemini/extensions"],
        "mcp": [".gemini/settings.json"],
        "sandbox": [".gemini/settings.json"],
    },
    "cursor": {
        "rules": [".cursor/rules", ".cursorrules"],
        "mcp": [".cursor/mcp.json"],
        "hooks": [".cursor/hooks"],
    },
    "opencode": {
        "plugins": ["opencode.json", ".opencode/plugin"],
        "mcp": ["opencode.json", ".opencode/mcp.json"],
    },
    "openclaw": {
        "config": [".openclaw", "openclaw.json"],
        "mcp": [".openclaw/mcp.json"],
    },
    "hermes": {
        "config": [".hermes", "hermes.json"],
        "mcp": [".hermes/mcp.json"],
    },
}


def inventory_native_integrations(target: Path, *, include_global_config: bool = False) -> dict[str, Any]:
    target = target.expanduser().resolve()
    profiles = []
    for agent, surfaces in AGENT_SURFACE_PATHS.items():
        profile = {
            "agent": agent,
            "schema_version": SCHEMA_VERSION,
            "discovery_mode": "discovery_only" if agent in {"openclaw", "hermes"} else "full",
            "surfaces": {},
        }
        for surface, relative_paths in surfaces.items():
            matches = _find_matches(target, relative_paths, scope="repo")
            if include_global_config:
                matches.extend(_find_matches(Path(os.environ.get("HOME", "~")).expanduser(), relative_paths, scope="global"))
            profile["surfaces"][surface] = _surface_record(surface, matches)
        profiles.append(profile)
    return {
        "schema_version": SCHEMA_VERSION,
        "target": str(target),
        "global_config_included": include_global_config,
        "profiles": profiles,
    }


def install_native_integration(target: Path, *, agent: str, mode: str = "preview") -> dict[str, Any]:
    if mode not in {"preview", "confirm"}:
        raise ValueError("mode must be preview or confirm")
    target = target.expanduser().resolve()
    path, payload = _install_payload(target, agent)
    result: dict[str, Any] = {
        "agent": agent,
        "mode": mode,
        "target_path": str(path),
        "would_write": True,
        "written": False,
        "backup_path": None,
    }
    if mode == "preview":
        result["content_preview"] = payload
        return result

    path.parent.mkdir(parents=True, exist_ok=True)
    existing_payload: dict[str, Any] = {}
    if path.exists():
        backup = path.with_suffix(path.suffix + ".invart.bak")
        backup.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
        result["backup_path"] = str(backup)
        if path.suffix == ".json":
            try:
                existing_payload = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                existing_payload = {}

    if isinstance(payload, str):
        path.write_text(payload, encoding="utf-8")
    else:
        existing_payload.update(payload)
        path.write_text(json.dumps(existing_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    result["written"] = True
    return result


def _install_payload(target: Path, agent: str) -> tuple[Path, dict[str, Any] | str]:
    if agent == "claude-code":
        return target / ".claude" / "settings.json", {
            "hooks": {
                "PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "invart bridge native --agent claude-code"}]}],
                "PostToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "invart bridge native --agent claude-code --phase post"}]}],
            },
            "invart": {"managed": True, "installed_by": "invart.native.v0.15"},
        }
    if agent == "codex":
        return target / ".codex" / "config.toml", (
            '[hooks]\n'
            'pre_tool_use = "invart bridge native --agent codex"\n'
            'post_tool_use = "invart bridge native --agent codex --phase post"\n'
        )
    if agent == "opencode":
        return target / "opencode.json", {"plugin": ["invart-native-plugin"], "invart": {"managed": True}}
    raise ValueError(f"unsupported install target: {agent}")


def native_conformance_report(target: Path, *, include_global_config: bool = False) -> dict[str, Any]:
    inventory = inventory_native_integrations(target, include_global_config=include_global_config)
    profiles = []
    checks: list[bool] = []
    for profile in inventory["profiles"]:
        enriched = dict(profile)
        enriched_surfaces: dict[str, Any] = {}
        for surface_name, surface in profile.get("surfaces", {}).items():
            enriched_surface = dict(surface)
            hashes = []
            parse_statuses = []
            for match in surface.get("matches", []):
                path = Path(match["path"])
                item = dict(match)
                item["hash"] = _path_hash(path)
                item["parse_status"] = _parse_status(path)
                hashes.append(item["hash"])
                parse_statuses.append(item["parse_status"])
            enriched_surface["matches"] = [
                {
                    **dict(match),
                    "hash": _path_hash(Path(match["path"])),
                    "parse_status": _parse_status(Path(match["path"])),
                }
                for match in surface.get("matches", [])
            ]
            enriched_surface["hash"] = hashes[0] if hashes else None
            enriched_surface["parse_status"] = "pass" if parse_statuses and all(status == "pass" for status in parse_statuses) else "not_applicable" if not parse_statuses else "warn"
            checks.append(enriched_surface["parse_status"] in {"pass", "not_applicable"})
            enriched_surfaces[surface_name] = enriched_surface
        enriched["surfaces"] = enriched_surfaces
        profiles.append(enriched)
    return {
        "schema_version": "invart.native_conformance.v0.15",
        "status": "pass" if all(checks or [True]) else "warn",
        "target": inventory["target"],
        "global_config_included": include_global_config,
        "profiles": profiles,
        "summary": {
            "profiles": len(profiles),
            "surfaces": sum(len(profile.get("surfaces", {})) for profile in profiles),
            "hashed_matches": sum(
                len(surface.get("matches", []))
                for profile in profiles
                for surface in profile.get("surfaces", {}).values()
            ),
        },
    }


def native_capability_matrix(target: Path, *, include_global_config: bool = False) -> dict[str, Any]:
    inventory = inventory_native_integrations(target, include_global_config=include_global_config)
    agents = []
    for profile in inventory["profiles"]:
        surfaces: dict[str, Any] = {}
        for surface_name, surface in profile.get("surfaces", {}).items():
            matches = list(surface.get("matches", []))
            coverage_state = _surface_coverage_state(str(profile["agent"]), surface_name, matches)
            source_evidence = [
                {
                    "path": match["path"],
                    "scope": match["scope"],
                    "kind": match["kind"],
                    "hash": _path_hash(Path(match["path"])),
                    "parse_status": _parse_status(Path(match["path"])),
                }
                for match in matches
            ]
            surfaces[surface_name] = {
                "surface": surface_name,
                "coverage_state": coverage_state,
                "vendor_owned": coverage_state == "vendor_owned",
                "observed_by": _surface_observers(surface_name, coverage_state),
                "possible_mediation": coverage_state in {"mediated", "vendor_owned"},
                "enforcement_claim": "enforced" if coverage_state == "enforced" else "not_enforced",
                "degraded_reason": None if coverage_state in {"mediated", "enforced"} else "surface discovered without Invart-owned pre-side-effect boundary" if matches else "surface not discovered",
                "source_evidence": source_evidence,
            }
        agents.append(
            {
                "agent": profile["agent"],
                "discovery_mode": profile["discovery_mode"],
                "surfaces": surfaces,
                "summary": {
                    "surfaces": len(surfaces),
                    "discovered": sum(1 for surface in surfaces.values() if surface["coverage_state"] != "not_covered"),
                    "mediated": sum(1 for surface in surfaces.values() if surface["coverage_state"] == "mediated"),
                    "vendor_owned": sum(1 for surface in surfaces.values() if surface["coverage_state"] == "vendor_owned"),
                },
            }
        )
    return {
        "schema_version": "invart.native_capability_matrix.v0.41",
        "target": inventory["target"],
        "global_config_included": include_global_config,
        "agents": agents,
        "summary": {
            "agents": len(agents),
            "discovered_agents": sum(1 for agent in agents if agent["summary"]["discovered"] > 0),
            "vendor_owned_surfaces": sum(agent["summary"]["vendor_owned"] for agent in agents),
            "mediated_surfaces": sum(agent["summary"]["mediated"] for agent in agents),
        },
    }


def unmanaged_agent_inventory(target: Path, *, include_global_config: bool = False) -> dict[str, Any]:
    target = target.expanduser().resolve()
    matrix = native_capability_matrix(target, include_global_config=include_global_config)
    findings: list[dict[str, Any]] = []
    for agent in matrix["agents"]:
        managed = _managed_launcher_exists(target, str(agent["agent"]))
        for surface_name, surface in agent["surfaces"].items():
            if not surface["source_evidence"]:
                continue
            if managed:
                continue
            findings.append(
                {
                    "finding_id": f"unmanaged:{agent['agent']}:{surface_name}",
                    "agent": agent["agent"],
                    "surface": surface_name,
                    "severity": "medium" if surface["coverage_state"] != "vendor_owned" else "high",
                    "source_evidence": surface["source_evidence"],
                    "coverage_fact": {
                        "state": "unmanaged_detected",
                        "runtime_enforcement": surface["coverage_state"],
                        "managed_launcher": False,
                    },
                    "recommendation": f"install or verify a Invart managed launcher for {agent['agent']}",
                }
            )
    return {
        "schema_version": "invart.unmanaged_agent_inventory.v0.41",
        "target": str(target),
        "global_config_included": include_global_config,
        "findings": findings,
        "summary": {
            "findings": len(findings),
            "unmanaged_detected": len({item["agent"] for item in findings}),
            "surfaces": len(findings),
        },
        "claim_boundary": "Unmanaged inventory is discovery evidence; it does not claim runtime enforcement until a Invart-managed launcher, wrapper, proxy, or shim is active.",
    }


def _surface_coverage_state(agent: str, surface_name: str, matches: list[dict[str, Any]]) -> str:
    if not matches:
        return "not_covered"
    if agent in {"hermes", "openclaw"}:
        return "vendor_owned"
    if surface_name in {"hooks", "plugins", "extensions", "mcp"}:
        return "mediated"
    if surface_name in {"sandbox"}:
        return "vendor_owned"
    return "discovered"


def _surface_observers(surface_name: str, coverage_state: str) -> list[str]:
    if coverage_state == "not_covered":
        return []
    if coverage_state == "vendor_owned":
        return [f"vendor_{surface_name}"]
    if coverage_state == "mediated":
        return [f"native_{surface_name}", "invart_adapter"]
    return ["invart_inventory"]


def _managed_launcher_exists(target: Path, agent: str) -> bool:
    return (target / ".invart" / "launchers" / f"{agent}.sh").exists()


def _find_matches(root: Path, relative_paths: list[str], *, scope: str) -> list[dict[str, Any]]:
    matches = []
    for relative in relative_paths:
        path = root / relative
        if path.exists():
            matches.append({
                "path": str(path),
                "scope": scope,
                "kind": "directory" if path.is_dir() else "file",
                "summary": _summarize_path(path),
            })
    return matches


def _surface_record(surface: str, matches: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "surface": surface,
        "grade": "declared" if matches else "none",
        "scope": matches[0]["scope"] if matches else None,
        "matches": matches,
    }


def _summarize_path(path: Path) -> dict[str, Any]:
    if path.is_dir():
        return {"entries": sorted(child.name for child in path.iterdir())[:20]}
    text = path.read_text(encoding="utf-8", errors="replace")[:4000]
    parsed_json = None
    if path.suffix == ".json":
        try:
            parsed_json = json.loads(text)
        except json.JSONDecodeError:
            parsed_json = None
    return {
        "size": path.stat().st_size,
        "json_keys": sorted(parsed_json) if isinstance(parsed_json, dict) else [],
    }


def _path_hash(path: Path) -> str:
    if path.is_dir():
        parts = []
        for child in sorted(item for item in path.rglob("*") if item.is_file()):
            parts.append(f"{child.relative_to(path)}:{hashlib.sha256(child.read_bytes()).hexdigest()}")
        digest = hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()
    else:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return f"sha256:{digest}"


def _parse_status(path: Path) -> str:
    if path.is_dir():
        return "pass"
    if path.suffix == ".json":
        try:
            json.loads(path.read_text(encoding="utf-8"))
            return "pass"
        except json.JSONDecodeError:
            return "warn"
    return "pass"
