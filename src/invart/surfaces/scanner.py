from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from invart.core.models import Asset, Finding, ScanReport, display_path, utc_now
from invart.control.rules import analyze_path, analyze_text, is_ignored, iter_interesting_files, load_ignore_patterns


AGENT_MARKERS: tuple[tuple[str, str, str], ...] = (
    ("codex", ".codex/config.toml", "OpenAI Codex CLI project config"),
    ("claude-code", ".claude/settings.json", "Claude Code project settings"),
    ("cursor", ".cursor", "Cursor project settings"),
    ("cline", ".clinerules", "Cline project rules"),
    ("windsurf", ".windsurfrules", "Windsurf project rules"),
    ("generic-agent", "AGENTS.md", "Generic agent instructions"),
    ("claude-code", "CLAUDE.md", "Claude Code instructions"),
)

HOME_AGENT_MARKERS: tuple[tuple[str, str, str], ...] = (
    ("codex", ".codex/config.toml", "OpenAI Codex CLI user config"),
    ("claude-code", ".claude/settings.json", "Claude Code user settings"),
    ("claude-code", ".claude.json", "Claude Code user config"),
)


def scan_pre_runtime(target: Path, include_home: bool = True) -> ScanReport:
    target = target.expanduser().resolve()
    ignore_patterns = load_ignore_patterns(target)
    report = ScanReport(generated_at=utc_now(), target=str(target))
    report.checks = collect_environment_checks(target)
    report.assets.extend(detect_agent_assets(target, include_home=include_home))
    report.assets.extend(detect_mcp_assets(target))
    report.assets.extend(detect_skill_assets(target))
    report.findings.extend(scan_sensitive_paths(target, ignore_patterns))
    report.findings.extend(scan_static_content(target, ignore_patterns))
    report.findings.extend(review_runtime_target(target))
    return report


def collect_environment_checks(target: Path) -> dict[str, Any]:
    checks: dict[str, Any] = {
        "target_exists": target.exists(),
        "target_is_git_repo": (target / ".git").exists(),
        "tools": {},
        "git": {},
    }
    for tool in ("codex", "claude", "cursor", "node", "python", "git"):
        checks["tools"][tool] = shutil.which(tool) is not None
    if (target / ".git").exists() and shutil.which("git"):
        checks["git"] = _git_checks(target)
    return checks


def detect_agent_assets(target: Path, include_home: bool = True) -> list[Asset]:
    assets: list[Asset] = []
    for kind, relative, description in AGENT_MARKERS:
        path = target / relative
        if path.exists():
            assets.append(
                Asset(
                    kind="agent_config",
                    name=kind,
                    path=display_path(path),
                    metadata={"description": description, "scope": "project"},
                )
            )
    if include_home:
        home = Path.home()
        for kind, relative, description in HOME_AGENT_MARKERS:
            path = home / relative
            if path.exists():
                assets.append(
                    Asset(
                        kind="agent_config",
                        name=kind,
                        path=display_path(path),
                        metadata={"description": description, "scope": "user"},
                    )
                )
    return assets


def detect_mcp_assets(target: Path) -> list[Asset]:
    assets: list[Asset] = []
    candidates = [
        target / ".mcp.json",
        target / "mcp.json",
        target / ".cursor" / "mcp.json",
        target / ".claude" / "mcp.json",
        Path.home() / ".cursor" / "mcp.json",
        Path.home() / ".claude" / "mcp.json",
    ]
    for path in candidates:
        if path.exists() and path.is_file():
            assets.append(Asset(kind="mcp_config", name=path.name, path=display_path(path), metadata=_read_json_metadata(path)))
    return assets


def detect_skill_assets(target: Path) -> list[Asset]:
    assets: list[Asset] = []
    for skill_file in target.rglob("SKILL.md"):
        if ".git" in skill_file.parts:
            continue
        assets.append(
            Asset(
                kind="skill",
                name=skill_file.parent.name,
                path=display_path(skill_file),
                metadata={"directory": display_path(skill_file.parent)},
            )
        )
    return assets


def scan_sensitive_paths(target: Path, ignore_patterns: set[str] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for path in target.rglob("*"):
        if ".git" in path.parts:
            continue
        if ignore_patterns and is_ignored(path, target, ignore_patterns):
            continue
        if path.is_file():
            findings.extend(analyze_path(display_path(path), phase="pre-runtime", action="present"))
    return findings


def scan_static_content(target: Path, ignore_patterns: set[str] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for path in iter_interesting_files(target, ignore_patterns=ignore_patterns):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        findings.extend(analyze_text(text, phase="pre-runtime", path=display_path(path)))
        findings.extend(_scan_mcp_config(path, text))
    return findings


def review_runtime_target(target: Path) -> list[Finding]:
    findings: list[Finding] = []
    if not target.exists():
        findings.append(
            Finding(
                rule_id="target.missing",
                title="Runtime target does not exist",
                severity="critical",
                phase="pre-runtime",
                category="target",
                path=str(target),
                recommendation="Create or checkout the target before launching an agent.",
            )
        )
        return findings
    if os.access(target, os.W_OK):
        findings.append(
            Finding(
                rule_id="target.writeable",
                title="Runtime target is writable",
                severity="info",
                phase="pre-runtime",
                category="target",
                path=display_path(target),
                recommendation="Use audit mode for normal work, and require approval for sensitive writes.",
            )
        )
    if (target / ".github" / "workflows").exists():
        findings.append(
            Finding(
                rule_id="target.ci_cd_present",
                title="Target contains CI/CD workflow configuration",
                severity="medium",
                phase="pre-runtime",
                category="ci-cd",
                path=display_path(target / ".github" / "workflows"),
                recommendation="Require approval before an agent modifies CI/CD workflows.",
            )
        )
    return findings


def _scan_mcp_config(path: Path, text: str) -> list[Finding]:
    if "mcp" not in path.name.lower() and "mcpServers" not in text:
        return []
    findings: list[Finding] = []
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return findings
    servers = payload.get("mcpServers", payload if isinstance(payload, dict) else {})
    if isinstance(servers, dict):
        for name, config in servers.items():
            if not isinstance(config, dict):
                continue
            command = str(config.get("command", ""))
            args = " ".join(str(arg) for arg in config.get("args", []))
            combined = f"{command} {args}".strip()
            if command in {"npx", "uvx", "docker"} and "@" not in combined and ":" not in combined:
                findings.append(
                    Finding(
                        rule_id="mcp.unpinned_server",
                        title="MCP server command appears unpinned",
                        severity="medium",
                        phase="pre-runtime",
                        category="mcp",
                        path=display_path(path),
                        evidence=f"{name}: {combined}",
                        recommendation="Pin MCP server package or image versions before allowing agent runtime use.",
                    )
                )
    return findings


def _read_json_metadata(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    return {"top_level_keys": sorted(str(key) for key in payload.keys())[:20]}


def _git_checks(target: Path) -> dict[str, Any]:
    def run_git(args: list[str]) -> str:
        try:
            result = subprocess.run(["git", *args], cwd=target, check=False, capture_output=True, text=True, timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            return ""
        return result.stdout.strip()

    return {
        "branch": run_git(["branch", "--show-current"]),
        "dirty": bool(run_git(["status", "--porcelain"])),
        "remote": run_git(["remote", "get-url", "origin"]),
    }
