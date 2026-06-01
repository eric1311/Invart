# Native Integration And Coverage Plane Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build v0.15-v0.18 so Kappaski can inventory native agent integrations, ingest native hook/plugin events, transparently broker MCP tool calls, and make proof/replay/gate coverage-aware.

**Architecture:** Add a native integration layer at the edge while keeping the daemon and ledger as the product core. Native hooks/plugins/extensions provide early intent and UX; wrapper/proxy/shim layers provide stronger evidence and enforcement. Coverage grade is dimensional and profile-driven, not a single risk score.

**Tech Stack:** Python 3 standard library, existing Kappaski JSONL ledger/proof/gate modules, argparse CLI, pytest, Rust shim remains in `rust/kappaski-shim`.

---

## Locked Product Decisions

- v0.15 covers Claude Code, Codex, Gemini CLI, Cursor, and OpenCode as first-class inventory targets.
- OpenClaw and Hermes are discovery-only until stable hook/extension guarantees are confirmed.
- Coverage grade dimensions are `preflight_visibility`, `runtime_observation`, `runtime_enforcement`, and `postruntime_audit`.
- Coverage grade values are `none`, `declared`, `observed`, `mediated`, and `enforced`.
- Global user config scanning is opt-in through `--include-global-config`; enterprise profiles may require it.
- v0.16 bridge priority is Claude Code first, Codex second, OpenCode third.
- Native hooks may block when the vendor surface supports blocking.
- Hook/plugin installer is required, but must use preview/confirm/backup semantics.
- v0.17 MCP broker is transparent-first.
- Raw MCP/tool content remains folded, truncated, summarized, and profile-governed.
- v0.18 gate behavior for insufficient coverage is profile-driven.
- Enterprise signoff is out of scope for v0.18.

## File Structure

- Create `src/kappaski/coverage.py`: coverage grade constants, coverage records, merge helpers, and policy comparison.
- Create `src/kappaski/native.py`: native integration inventory scanner and installer preview/confirm logic.
- Create `src/kappaski/native_bridge.py`: vendor hook/plugin event normalization and response rendering.
- Create `src/kappaski/mcp_broker.py`: transparent MCP JSON-RPC line broker and transcript summarizer.
- Modify `src/kappaski/cli.py`: add `native`, `bridge`, and `mcp broker` commands.
- Modify `src/kappaski/postruntime.py`: include coverage summary in proof export.
- Modify `src/kappaski/replay.py`: label events by observed/enforced layer and coverage grade.
- Modify `src/kappaski/gate.py`: apply profile-driven minimum coverage requirements.
- Modify `src/kappaski/profiles.py`: parse optional coverage requirements.
- Modify `src/kappaski/evals.py`: add v0.15-v0.18 benchmark suites.
- Modify `src/kappaski/roadmap.py`: register v0.15-v0.18 capabilities.
- Modify `tests/test_core.py`: add deterministic tests for all new behavior, following the existing single-file test style.
- Modify docs: `README.md`, `docs/roadmap.md`, `docs/roadmap.html`, `docs/product-decisions.md`, `docs/architecture.html`, and new version docs `docs/v0.15-native-integration-inventory.html` through `docs/v0.18-coverage-aware-runtime.html`.

## Task 1: Coverage Grade Core

**Files:**
- Create: `src/kappaski/coverage.py`
- Modify: `tests/test_core.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_core.py`:

```python
from kappaski.coverage import (
    COVERAGE_GRADES,
    CoverageRecord,
    coverage_meets_requirement,
    default_coverage_for_layer,
    merge_coverage_records,
)


def test_v18_coverage_grade_order_and_layer_defaults() -> None:
    assert COVERAGE_GRADES == ("none", "declared", "observed", "mediated", "enforced")
    hook = default_coverage_for_layer("native_hook")
    assert hook.runtime_observation == "mediated"
    assert hook.runtime_enforcement == "mediated"
    shim = default_coverage_for_layer("rust_shim")
    assert shim.runtime_enforcement == "enforced"


def test_v18_coverage_merge_keeps_strongest_dimension() -> None:
    observed = CoverageRecord(runtime_observation="observed", runtime_enforcement="none", observed_by=["agent_log"])
    enforced = CoverageRecord(runtime_observation="mediated", runtime_enforcement="enforced", enforced_by=["rust_shim"])
    merged = merge_coverage_records([observed, enforced])
    assert merged.runtime_observation == "mediated"
    assert merged.runtime_enforcement == "enforced"
    assert merged.observed_by == ["agent_log"]
    assert merged.enforced_by == ["rust_shim"]


def test_v18_coverage_requirement_comparison() -> None:
    record = CoverageRecord(runtime_observation="mediated", runtime_enforcement="observed")
    assert coverage_meets_requirement(record, {"runtime_observation": "observed"}) is True
    assert coverage_meets_requirement(record, {"runtime_enforcement": "enforced"}) is False
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
PYTHONPYCACHEPREFIX=/tmp/kappaski_pycache PYTHONPATH=src /usr/bin/python3 -m pytest tests/test_core.py::test_v18_coverage_grade_order_and_layer_defaults -q
```

Expected: fail with `ModuleNotFoundError: No module named 'kappaski.coverage'`.

- [ ] **Step 3: Implement `src/kappaski/coverage.py`**

Create:

```python
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

COVERAGE_GRADES = ("none", "declared", "observed", "mediated", "enforced")


def _rank(grade: str) -> int:
    if grade not in COVERAGE_GRADES:
        raise ValueError(f"unknown coverage grade: {grade}")
    return COVERAGE_GRADES.index(grade)


def _stronger(left: str, right: str) -> str:
    return left if _rank(left) >= _rank(right) else right


@dataclass
class CoverageRecord:
    preflight_visibility: str = "none"
    runtime_observation: str = "none"
    runtime_enforcement: str = "none"
    postruntime_audit: str = "none"
    observed_by: list[str] = field(default_factory=list)
    enforced_by: list[str] = field(default_factory=list)
    degraded_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "preflight_visibility": self.preflight_visibility,
            "runtime_observation": self.runtime_observation,
            "runtime_enforcement": self.runtime_enforcement,
            "postruntime_audit": self.postruntime_audit,
            "observed_by": list(self.observed_by),
            "enforced_by": list(self.enforced_by),
            "coverage_grade": {
                "preflight_visibility": self.preflight_visibility,
                "runtime_observation": self.runtime_observation,
                "runtime_enforcement": self.runtime_enforcement,
                "postruntime_audit": self.postruntime_audit,
            },
            "degraded_reason": self.degraded_reason,
        }


def default_coverage_for_layer(layer: str) -> CoverageRecord:
    if layer in {"native_hook", "native_plugin", "mcp_broker"}:
        return CoverageRecord(
            preflight_visibility="declared",
            runtime_observation="mediated",
            runtime_enforcement="mediated",
            postruntime_audit="observed",
            observed_by=[layer],
        )
    if layer in {"shell_wrapper", "rust_shim", "sandbox"}:
        return CoverageRecord(
            preflight_visibility="observed",
            runtime_observation="mediated",
            runtime_enforcement="enforced",
            postruntime_audit="observed",
            enforced_by=[layer],
        )
    if layer in {"agent_log", "audit_import"}:
        return CoverageRecord(runtime_observation="observed", postruntime_audit="observed", observed_by=[layer])
    return CoverageRecord(degraded_reason=f"unknown coverage layer: {layer}")


def merge_coverage_records(records: list[CoverageRecord]) -> CoverageRecord:
    merged = CoverageRecord()
    for record in records:
        merged.preflight_visibility = _stronger(merged.preflight_visibility, record.preflight_visibility)
        merged.runtime_observation = _stronger(merged.runtime_observation, record.runtime_observation)
        merged.runtime_enforcement = _stronger(merged.runtime_enforcement, record.runtime_enforcement)
        merged.postruntime_audit = _stronger(merged.postruntime_audit, record.postruntime_audit)
        for source in record.observed_by:
            if source not in merged.observed_by:
                merged.observed_by.append(source)
        for source in record.enforced_by:
            if source not in merged.enforced_by:
                merged.enforced_by.append(source)
        if record.degraded_reason and not merged.degraded_reason:
            merged.degraded_reason = record.degraded_reason
    return merged


def coverage_meets_requirement(record: CoverageRecord, requirements: dict[str, str]) -> bool:
    for dimension, minimum in requirements.items():
        actual = getattr(record, dimension)
        if _rank(actual) < _rank(minimum):
            return False
    return True
```

- [ ] **Step 4: Run tests**

Run:

```bash
PYTHONPYCACHEPREFIX=/tmp/kappaski_pycache PYTHONPATH=src /usr/bin/python3 -m pytest tests/test_core.py::test_v18_coverage_grade_order_and_layer_defaults tests/test_core.py::test_v18_coverage_merge_keeps_strongest_dimension tests/test_core.py::test_v18_coverage_requirement_comparison -q
```

Expected: all three tests pass.

## Task 2: v0.15 Native Integration Inventory

**Files:**
- Create: `src/kappaski/native.py`
- Modify: `src/kappaski/cli.py`
- Modify: `tests/test_core.py`

- [ ] **Step 1: Write failing tests**

Append:

```python
from kappaski.native import inventory_native_integrations


def test_v15_native_inventory_detects_repo_local_agent_surfaces(tmp_path: Path) -> None:
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(json.dumps({"hooks": {"PreToolUse": []}}), encoding="utf-8")
    (tmp_path / ".codex").mkdir()
    (tmp_path / ".codex" / "config.toml").write_text('[hooks]\npre_tool_use = "kappaski bridge"\n', encoding="utf-8")
    (tmp_path / ".cursor").mkdir()
    (tmp_path / ".cursor" / "rules").mkdir()
    (tmp_path / ".cursor" / "rules" / "security.mdc").write_text("Never expose secrets", encoding="utf-8")
    (tmp_path / ".gemini").mkdir()
    (tmp_path / ".gemini" / "settings.json").write_text(json.dumps({"mcpServers": {"fs": {"command": "node"}}}), encoding="utf-8")
    (tmp_path / "opencode.json").write_text(json.dumps({"plugin": ["./plugin.js"], "mcp": {"fs": {}}}), encoding="utf-8")

    report = inventory_native_integrations(tmp_path, include_global_config=False)
    by_agent = {profile["agent"]: profile for profile in report["profiles"]}
    assert by_agent["claude-code"]["surfaces"]["hooks"]["grade"] == "declared"
    assert by_agent["codex"]["surfaces"]["hooks"]["grade"] == "declared"
    assert by_agent["cursor"]["surfaces"]["rules"]["grade"] == "declared"
    assert by_agent["gemini-cli"]["surfaces"]["mcp"]["grade"] == "declared"
    assert by_agent["opencode"]["surfaces"]["plugins"]["grade"] == "declared"


def test_v15_native_inventory_global_config_is_opt_in(tmp_path: Path, monkeypatch) -> None:
    fake_home = tmp_path / "home"
    (fake_home / ".claude").mkdir(parents=True)
    (fake_home / ".claude" / "settings.json").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("HOME", str(fake_home))
    repo = tmp_path / "repo"
    repo.mkdir()
    without_global = inventory_native_integrations(repo, include_global_config=False)
    with_global = inventory_native_integrations(repo, include_global_config=True)
    assert without_global["global_config_included"] is False
    assert with_global["global_config_included"] is True
    assert any(surface["scope"] == "global" for profile in with_global["profiles"] for surface in profile["surfaces"].values())
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
PYTHONPYCACHEPREFIX=/tmp/kappaski_pycache PYTHONPATH=src /usr/bin/python3 -m pytest tests/test_core.py::test_v15_native_inventory_detects_repo_local_agent_surfaces -q
```

Expected: fail because `kappaski.native` does not exist.

- [ ] **Step 3: Implement inventory scanner**

Create `src/kappaski/native.py` with:

```python
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "kappaski.native_integration.v0.15"

AGENT_SURFACE_PATHS = {
    "claude-code": {"hooks": [".claude/settings.json"], "mcp": [".claude/settings.json"], "skills": [".claude/skills", "CLAUDE.md"]},
    "codex": {"hooks": [".codex/config.toml"], "plugins": [".codex/plugins"], "mcp": [".codex/config.toml"]},
    "gemini-cli": {"extensions": [".gemini/extensions"], "mcp": [".gemini/settings.json"], "sandbox": [".gemini/settings.json"]},
    "cursor": {"rules": [".cursor/rules", ".cursorrules"], "mcp": [".cursor/mcp.json"], "hooks": [".cursor/hooks"]},
    "opencode": {"plugins": ["opencode.json", ".opencode/plugin"], "mcp": ["opencode.json", ".opencode/mcp.json"]},
    "openclaw": {"config": [".openclaw", "openclaw.json"], "mcp": [".openclaw/mcp.json"]},
    "hermes": {"config": [".hermes", "hermes.json"], "mcp": [".hermes/mcp.json"]},
}


def inventory_native_integrations(target: Path, *, include_global_config: bool = False) -> dict[str, Any]:
    target = target.expanduser().resolve()
    profiles = []
    for agent, surfaces in AGENT_SURFACE_PATHS.items():
        profile = {"agent": agent, "schema_version": SCHEMA_VERSION, "discovery_mode": "full" if agent not in {"openclaw", "hermes"} else "discovery_only", "surfaces": {}}
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


def _find_matches(root: Path, relative_paths: list[str], *, scope: str) -> list[dict[str, Any]]:
    matches = []
    for rel in relative_paths:
        path = root / rel
        if path.exists():
            matches.append({"path": str(path), "scope": scope, "kind": "directory" if path.is_dir() else "file", "summary": _summarize_path(path)})
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
    return {"size": path.stat().st_size, "json_keys": sorted(parsed_json) if isinstance(parsed_json, dict) else []}
```

- [ ] **Step 4: Add CLI command**

Modify `src/kappaski/cli.py` imports:

```python
from .native import inventory_native_integrations
```

Add parser near other top-level commands:

```python
    native = subparsers.add_parser("native", help="Inspect and manage native agent integration surfaces.")
    native_sub = native.add_subparsers(dest="native_command", required=True)
    native_inventory = native_sub.add_parser("inventory", help="Inventory hooks, plugins, extensions, rules, MCP, sandbox, and config surfaces.")
    native_inventory.add_argument("--target", default=".")
    native_inventory.add_argument("--include-global-config", action="store_true")
```

Add dispatch:

```python
    if args.command == "native" and args.native_command == "inventory":
        print(json.dumps(inventory_native_integrations(Path(args.target), include_global_config=args.include_global_config), indent=2, sort_keys=True))
        return 0
```

- [ ] **Step 5: Run tests**

Run:

```bash
PYTHONPYCACHEPREFIX=/tmp/kappaski_pycache PYTHONPATH=src /usr/bin/python3 -m pytest tests/test_core.py::test_v15_native_inventory_detects_repo_local_agent_surfaces tests/test_core.py::test_v15_native_inventory_global_config_is_opt_in -q
```

Expected: both tests pass.

## Task 3: v0.15 Hook/Plugin Installer Preview

**Files:**
- Modify: `src/kappaski/native.py`
- Modify: `src/kappaski/cli.py`
- Modify: `tests/test_core.py`

- [ ] **Step 1: Write failing tests**

Append:

```python
from kappaski.native import install_native_integration


def test_v15_native_install_preview_does_not_write(tmp_path: Path) -> None:
    result = install_native_integration(tmp_path, agent="claude-code", mode="preview")
    assert result["mode"] == "preview"
    assert result["would_write"]
    assert not (tmp_path / ".claude" / "settings.json").exists()


def test_v15_native_install_confirm_writes_backup_on_existing_file(tmp_path: Path) -> None:
    settings = tmp_path / ".claude" / "settings.json"
    settings.parent.mkdir()
    settings.write_text(json.dumps({"hooks": {}}), encoding="utf-8")
    result = install_native_integration(tmp_path, agent="claude-code", mode="confirm")
    assert result["mode"] == "confirm"
    assert result["written"]
    assert result["backup_path"]
    payload = json.loads(settings.read_text(encoding="utf-8"))
    assert "kappaski" in json.dumps(payload)
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
PYTHONPYCACHEPREFIX=/tmp/kappaski_pycache PYTHONPATH=src /usr/bin/python3 -m pytest tests/test_core.py::test_v15_native_install_preview_does_not_write -q
```

Expected: fail because `install_native_integration` is missing.

- [ ] **Step 3: Implement installer preview/confirm**

Add to `src/kappaski/native.py`:

```python
def install_native_integration(target: Path, *, agent: str, mode: str = "preview") -> dict[str, Any]:
    if mode not in {"preview", "confirm"}:
        raise ValueError("mode must be preview or confirm")
    target = target.expanduser().resolve()
    if agent == "claude-code":
        path = target / ".claude" / "settings.json"
        payload = {
            "hooks": {
                "PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "kappaski bridge native --agent claude-code"}]}],
                "PostToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "kappaski bridge native --agent claude-code --phase post"}]}],
            },
            "kappaski": {"managed": True, "installed_by": "kappaski.native.v0.15"},
        }
    elif agent == "codex":
        path = target / ".codex" / "config.toml"
        payload = '[hooks]\npre_tool_use = "kappaski bridge native --agent codex"\npost_tool_use = "kappaski bridge native --agent codex --phase post"\n'
    elif agent == "opencode":
        path = target / "opencode.json"
        payload = {"plugin": ["kappaski-native-plugin"], "kappaski": {"managed": True}}
    else:
        raise ValueError(f"unsupported install target: {agent}")
    result = {"agent": agent, "mode": mode, "target_path": str(path), "would_write": True, "written": False, "backup_path": None}
    if mode == "preview":
        result["content_preview"] = payload if isinstance(payload, str) else payload
        return result
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        backup = path.with_suffix(path.suffix + ".kappaski.bak")
        backup.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
        result["backup_path"] = str(backup)
    if isinstance(payload, str):
        path.write_text(payload, encoding="utf-8")
    else:
        existing = {}
        if path.exists() and path.stat().st_size:
            try:
                existing = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                existing = {}
        existing.update(payload)
        path.write_text(json.dumps(existing, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    result["written"] = True
    return result
```

- [ ] **Step 4: Add CLI command**

Add parser:

```python
    native_install = native_sub.add_parser("install", help="Preview or install native Kappaski hook/plugin config.")
    native_install.add_argument("--target", default=".")
    native_install.add_argument("--agent", choices=("claude-code", "codex", "opencode"), required=True)
    native_install.add_argument("--confirm", action="store_true")
```

Add dispatch:

```python
    if args.command == "native" and args.native_command == "install":
        from .native import install_native_integration
        mode = "confirm" if args.confirm else "preview"
        print(json.dumps(install_native_integration(Path(args.target), agent=args.agent, mode=mode), indent=2, sort_keys=True))
        return 0
```

- [ ] **Step 5: Run tests**

Run:

```bash
PYTHONPYCACHEPREFIX=/tmp/kappaski_pycache PYTHONPATH=src /usr/bin/python3 -m pytest tests/test_core.py::test_v15_native_install_preview_does_not_write tests/test_core.py::test_v15_native_install_confirm_writes_backup_on_existing_file -q
```

Expected: both tests pass.

## Task 4: v0.16 Native Hook/Plugin Event Bridge

**Files:**
- Create: `src/kappaski/native_bridge.py`
- Modify: `src/kappaski/cli.py`
- Modify: `tests/test_core.py`

- [ ] **Step 1: Write failing tests**

Append:

```python
from kappaski.native_bridge import normalize_native_event, render_native_response


def test_v16_claude_pretool_event_normalizes_to_invocation() -> None:
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "rm -rf ."},
        "session_id": "claude-session",
    }
    action = normalize_native_event("claude-code", payload)
    assert action.type == "shell"
    assert action.command == "rm -rf ."
    assert action.adapter == "native_hook:claude-code"
    assert "native_hook" in action.metadata["observed_by"]


def test_v16_codex_event_response_can_block() -> None:
    response = render_native_response("codex", {"effect": "deny", "reason": "dangerous deletion"})
    assert response["allow"] is False
    assert "dangerous deletion" in response["message"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
PYTHONPYCACHEPREFIX=/tmp/kappaski_pycache PYTHONPATH=src /usr/bin/python3 -m pytest tests/test_core.py::test_v16_claude_pretool_event_normalizes_to_invocation -q
```

Expected: fail because `kappaski.native_bridge` does not exist.

- [ ] **Step 3: Implement normalizer and response renderer**

Create `src/kappaski/native_bridge.py`:

```python
from __future__ import annotations

from typing import Any

from .models import ActionEvent


def normalize_native_event(agent: str, payload: dict[str, Any]) -> ActionEvent:
    if agent == "claude-code":
        tool = str(payload.get("tool_name") or payload.get("tool") or "")
        tool_input = dict(payload.get("tool_input") or {})
        event_type = "shell" if tool.lower() in {"bash", "shell"} else "tool"
        command = tool_input.get("command") if event_type == "shell" else None
    elif agent == "codex":
        tool = str(payload.get("tool") or payload.get("tool_name") or "")
        args = dict(payload.get("arguments") or payload.get("tool_input") or {})
        event_type = "shell" if tool.lower() in {"shell", "exec", "bash"} else "tool"
        command = args.get("command") if event_type == "shell" else None
        tool_input = args
    elif agent == "opencode":
        tool = str(payload.get("tool") or "")
        tool_input = dict(payload.get("input") or {})
        event_type = "shell" if tool.lower() in {"bash", "shell"} else "tool"
        command = tool_input.get("command") if event_type == "shell" else None
    else:
        tool = str(payload.get("tool") or payload.get("tool_name") or "unknown")
        tool_input = dict(payload.get("tool_input") or payload.get("arguments") or {})
        event_type = "tool"
        command = None
    return ActionEvent(
        type=event_type,
        adapter=f"native_hook:{agent}",
        actor=agent,
        session_id=payload.get("session_id"),
        command=command,
        tool=tool,
        parameters=tool_input,
        source="agent_native_event",
        trust_level="internal",
        metadata={"native_payload": payload, "observed_by": ["native_hook"], "coverage_layer": "native_hook"},
    )


def render_native_response(agent: str, decision: dict[str, Any]) -> dict[str, Any]:
    effect = str(decision.get("effect") or "")
    reason = str(decision.get("reason") or decision.get("summary") or effect)
    allowed = effect not in {"deny", "block"}
    if agent == "claude-code":
        return {"decision": "block" if not allowed else "allow", "reason": reason, "kappaski": decision}
    if agent == "codex":
        return {"allow": allowed, "message": reason, "kappaski": decision}
    if agent == "opencode":
        return {"status": "denied" if not allowed else "allowed", "message": reason, "kappaski": decision}
    return {"allow": allowed, "message": reason, "kappaski": decision}
```

- [ ] **Step 4: Add CLI command**

Add imports:

```python
from .native_bridge import normalize_native_event, render_native_response
```

Add parser:

```python
    bridge = subparsers.add_parser("bridge", help="Native hook/plugin bridge commands.")
    bridge_sub = bridge.add_subparsers(dest="bridge_command", required=True)
    bridge_native = bridge_sub.add_parser("native", help="Normalize a native hook payload and return a native response.")
    bridge_native.add_argument("--agent", choices=("claude-code", "codex", "opencode", "generic"), required=True)
    bridge_native.add_argument("--event", required=True)
```

Add dispatch:

```python
    if args.command == "bridge" and args.bridge_command == "native":
        action = normalize_native_event(args.agent, json.loads(args.event))
        findings = analyze_event_payload(action.to_dict())
        effect = "deny" if any(f.get("severity") == "critical" for f in findings.get("findings", [])) else "allow"
        print(json.dumps(render_native_response(args.agent, {"effect": effect, "reason": "kappaski native bridge decision", "action": action.to_dict()}), indent=2, sort_keys=True))
        return 0
```

- [ ] **Step 5: Run tests**

Run:

```bash
PYTHONPYCACHEPREFIX=/tmp/kappaski_pycache PYTHONPATH=src /usr/bin/python3 -m pytest tests/test_core.py::test_v16_claude_pretool_event_normalizes_to_invocation tests/test_core.py::test_v16_codex_event_response_can_block -q
```

Expected: both tests pass.

## Task 5: v0.17 Transparent MCP Broker

**Files:**
- Create: `src/kappaski/mcp_broker.py`
- Modify: `src/kappaski/cli.py`
- Modify: `tests/test_core.py`

- [ ] **Step 1: Write failing tests**

Append:

```python
from kappaski.mcp_broker import summarize_mcp_message, transparent_broker_step


def test_v17_mcp_broker_summarizes_tool_call_without_raw_content_loss() -> None:
    message = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "write_file", "arguments": {"path": ".env", "content": "SECRET=abc"}}}
    summary = summarize_mcp_message(message, max_raw_length=12)
    assert summary["kind"] == "tool_call"
    assert summary["tool_name"] == "write_file"
    assert summary["raw_content_folded"] is True
    assert summary["raw_content_length"] > len(summary["raw_content_preview"])


def test_v17_transparent_mcp_broker_step_preserves_message() -> None:
    message = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
    forwarded, evidence = transparent_broker_step(message)
    assert forwarded == message
    assert evidence["mode"] == "transparent"
    assert evidence["summary"]["kind"] == "tools_list"
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
PYTHONPYCACHEPREFIX=/tmp/kappaski_pycache PYTHONPATH=src /usr/bin/python3 -m pytest tests/test_core.py::test_v17_mcp_broker_summarizes_tool_call_without_raw_content_loss -q
```

Expected: fail because `kappaski.mcp_broker` does not exist.

- [ ] **Step 3: Implement transparent broker helpers**

Create `src/kappaski/mcp_broker.py`:

```python
from __future__ import annotations

import json
from typing import Any


def summarize_mcp_message(message: dict[str, Any], *, max_raw_length: int = 256) -> dict[str, Any]:
    method = str(message.get("method") or "")
    params = dict(message.get("params") or {})
    raw = json.dumps(message, sort_keys=True)
    if method == "tools/call":
        kind = "tool_call"
        tool_name = str(params.get("name") or "")
    elif method == "tools/list":
        kind = "tools_list"
        tool_name = None
    else:
        kind = "jsonrpc"
        tool_name = None
    preview = raw[:max_raw_length]
    return {
        "kind": kind,
        "method": method,
        "tool_name": tool_name,
        "id": message.get("id"),
        "raw_content_preview": preview,
        "raw_content_length": len(raw),
        "raw_content_folded": len(raw) > len(preview),
        "content_note": "MCP JSON-RPC message folded/truncated for audit display",
    }


def transparent_broker_step(message: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    return message, {"mode": "transparent", "summary": summarize_mcp_message(message)}
```

- [ ] **Step 4: Add CLI parser**

Add import:

```python
from .mcp_broker import transparent_broker_step
```

Add parser:

```python
    mcp = subparsers.add_parser("mcp", help="MCP broker and inspection commands.")
    mcp_sub = mcp.add_subparsers(dest="mcp_command", required=True)
    mcp_broker = mcp_sub.add_parser("broker-step", help="Run one transparent MCP broker step for a JSON message.")
    mcp_broker.add_argument("--message", required=True)
```

Add dispatch:

```python
    if args.command == "mcp" and args.mcp_command == "broker-step":
        forwarded, evidence = transparent_broker_step(json.loads(args.message))
        print(json.dumps({"forwarded": forwarded, "evidence": evidence}, indent=2, sort_keys=True))
        return 0
```

- [ ] **Step 5: Run tests**

Run:

```bash
PYTHONPYCACHEPREFIX=/tmp/kappaski_pycache PYTHONPATH=src /usr/bin/python3 -m pytest tests/test_core.py::test_v17_mcp_broker_summarizes_tool_call_without_raw_content_loss tests/test_core.py::test_v17_transparent_mcp_broker_step_preserves_message -q
```

Expected: both tests pass.

## Task 6: v0.18 Coverage-Aware Proof, Replay, And Gate

**Files:**
- Modify: `src/kappaski/runtime.py`
- Modify: `src/kappaski/postruntime.py`
- Modify: `src/kappaski/replay.py`
- Modify: `src/kappaski/gate.py`
- Modify: `src/kappaski/profiles.py`
- Modify: `tests/test_core.py`

- [ ] **Step 1: Write failing tests**

Append:

```python
def test_v18_runtime_event_coverage_is_exported_to_proof(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    session = start_session(tmp_path, ledger, agent="claude-code", goal="coverage")
    record_action(
        RuntimeEvent(type="shell", session_id=session.session_id, command="echo ok", metadata={"coverage_layer": "native_hook"}),
        ledger,
    )
    close_session(ledger)
    proof = export_proof_report(ledger, tmp_path / "proof.json")
    assert proof["coverage"]["summary"]["runtime_observation"]["mediated"] >= 1


def test_v18_gate_profile_fails_when_required_coverage_is_missing(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    session = start_session(tmp_path, ledger, agent="generic", goal="coverage gate")
    record_action(RuntimeEvent(type="shell", session_id=session.session_id, command="echo ok", metadata={"coverage_layer": "agent_log"}), ledger)
    close_session(ledger)
    proof_path = tmp_path / "proof.json"
    export_proof_report(ledger, proof_path)
    report = verify_gate(proof_path=proof_path, ledger_path=ledger, mode="ci", coverage_requirements={"runtime_enforcement": "mediated"})
    assert report["status"] == "fail"
    assert any("coverage" in finding["category"] for finding in report["findings"])
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
PYTHONPYCACHEPREFIX=/tmp/kappaski_pycache PYTHONPATH=src /usr/bin/python3 -m pytest tests/test_core.py::test_v18_runtime_event_coverage_is_exported_to_proof -q
```

Expected: fail because proof has no `coverage` field.

- [ ] **Step 3: Attach coverage during `record_action`**

In `src/kappaski/runtime.py`, import:

```python
from .coverage import default_coverage_for_layer
```

Before constructing the ledger entry in `record_action`, add:

```python
    coverage_layer = action.metadata.get("coverage_layer") if isinstance(action.metadata, dict) else None
    coverage = default_coverage_for_layer(str(coverage_layer or action.metadata.get("adapter_layer") or "agent_log"))
    action.metadata["coverage"] = coverage.to_dict()
```

- [ ] **Step 4: Summarize coverage in proof**

In `src/kappaski/postruntime.py`, add helper:

```python
def _coverage_summary(entries: list[Any]) -> dict[str, Any]:
    dimensions = ("preflight_visibility", "runtime_observation", "runtime_enforcement", "postruntime_audit")
    summary = {dimension: {} for dimension in dimensions}
    events = []
    for entry in entries:
        event = entry.event or {}
        metadata = event.get("metadata") if isinstance(event, dict) else {}
        coverage = metadata.get("coverage") if isinstance(metadata, dict) else None
        if not isinstance(coverage, dict):
            continue
        grade = coverage.get("coverage_grade") or {}
        for dimension in dimensions:
            value = str(grade.get(dimension) or coverage.get(dimension) or "none")
            summary[dimension][value] = summary[dimension].get(value, 0) + 1
        events.append({"event_id": event.get("event_id"), "coverage": coverage})
    return {"summary": summary, "events": events}
```

In `export_proof_report`, add:

```python
        "coverage": _coverage_summary(entries),
```

- [ ] **Step 5: Add gate coverage requirement**

In `src/kappaski/gate.py`, extend `verify_gate` signature:

```python
coverage_requirements: dict[str, str] | None = None,
```

After proof loading, add:

```python
    if coverage_requirements:
        coverage_events = proof.get("coverage", {}).get("events", [])
        for item in coverage_events:
            grade = item.get("coverage", {}).get("coverage_grade", {})
            for dimension, minimum in coverage_requirements.items():
                if COVERAGE_GRADES.index(str(grade.get(dimension, "none"))) < COVERAGE_GRADES.index(minimum):
                    findings.append({
                        "category": "coverage.gap",
                        "severity": "high",
                        "message": f"coverage requirement not met: {dimension} requires {minimum}",
                    })
                    status = "fail" if mode == "ci" else "warn"
```

Import:

```python
from .coverage import COVERAGE_GRADES
```

- [ ] **Step 6: Run tests**

Run:

```bash
PYTHONPYCACHEPREFIX=/tmp/kappaski_pycache PYTHONPATH=src /usr/bin/python3 -m pytest tests/test_core.py::test_v18_runtime_event_coverage_is_exported_to_proof tests/test_core.py::test_v18_gate_profile_fails_when_required_coverage_is_missing -q
```

Expected: both tests pass.

## Task 7: Benchmarks And Roadmap Coverage

**Files:**
- Modify: `src/kappaski/evals.py`
- Modify: `src/kappaski/roadmap.py`
- Modify: `tests/test_core.py`

- [ ] **Step 1: Write failing tests**

Append:

```python
def test_v15_to_v18_benchmarks_are_registered() -> None:
    for suite in (
        "v0.15-native-integration-inventory",
        "v0.16-hook-plugin-bridge",
        "v0.17-mcp-broker",
        "v0.18-coverage-aware-runtime",
    ):
        result = run_benchmark(suite)
        assert result["passed"] is True


def test_v15_to_v18_roadmap_entries_are_planned_or_complete() -> None:
    capabilities = roadmap_capabilities()
    versions = {cap["version"] for cap in capabilities}
    assert {"v0.15", "v0.16", "v0.17", "v0.18"}.issubset(versions)
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
PYTHONPYCACHEPREFIX=/tmp/kappaski_pycache PYTHONPATH=src /usr/bin/python3 -m pytest tests/test_core.py::test_v15_to_v18_benchmarks_are_registered -q
```

Expected: fail because benchmark suite names are missing.

- [ ] **Step 3: Add deterministic benchmark suites**

In `src/kappaski/evals.py`, add suites that call the public functions from Tasks 1-6 with temporary directories and assert deterministic pass/fail behavior. The returned shape must match existing benchmark report style:

```python
{
    "suite": "v0.15-native-integration-inventory",
    "passed": True,
    "checks": [{"name": "inventory_detects_surfaces", "passed": True}],
}
```

- [ ] **Step 4: Add roadmap capabilities**

In `src/kappaski/roadmap.py`, add four capabilities:

```python
{
    "version": "v0.15",
    "capability_id": "native_integration_inventory",
    "title": "Native integration inventory",
    "status": "milestone_complete",
    "docs": ["docs/v0.15-native-integration-inventory.html"],
    "tests": ["v0.15-native-integration-inventory"],
}
```

Repeat for v0.16-v0.18 with matching docs and benchmark names.

- [ ] **Step 5: Run tests**

Run:

```bash
PYTHONPYCACHEPREFIX=/tmp/kappaski_pycache PYTHONPATH=src /usr/bin/python3 -m pytest tests/test_core.py::test_v15_to_v18_benchmarks_are_registered tests/test_core.py::test_v15_to_v18_roadmap_entries_are_planned_or_complete -q
```

Expected: both tests pass.

## Task 8: Version Docs And HTML Index

**Files:**
- Create: `docs/v0.15-native-integration-inventory.html`
- Create: `docs/v0.16-hook-plugin-bridge.html`
- Create: `docs/v0.17-mcp-broker.html`
- Create: `docs/v0.18-coverage-aware-runtime.html`
- Modify: `docs/index.html`
- Modify: `docs/README.md`
- Modify: `README.md`

- [ ] **Step 1: Write docs**

Each version doc must include:

- goal;
- scope;
- CLI usage;
- data model;
- tests;
- limitations;
- link back to `plugin-extension-architecture-review-2026-05.html`.

- [ ] **Step 2: Add index links**

Add four cards to `docs/index.html`:

```html
<div class="card"><h3><a href="v0.15-native-integration-inventory.html">v0.15 Native Integration Inventory</a></h3><p>Agent hook/plugin/extension/MCP/rules/sandbox inventory and coverage baseline.</p></div>
<div class="card"><h3><a href="v0.16-hook-plugin-bridge.html">v0.16 Hook/Plugin Bridge</a></h3><p>Native hook/plugin event normalization and blocking response rendering.</p></div>
<div class="card"><h3><a href="v0.17-mcp-broker.html">v0.17 MCP Broker</a></h3><p>Transparent-first MCP tool-call audit, redaction, and compatibility path.</p></div>
<div class="card"><h3><a href="v0.18-coverage-aware-runtime.html">v0.18 Coverage-Aware Runtime</a></h3><p>Coverage-aware proof, replay, audit, and gate behavior.</p></div>
```

- [ ] **Step 3: Update README**

Add a section:

```markdown
## v0.15-v0.18 Native Integration And Coverage Snapshot

Kappaski now inventories native agent integrations, normalizes hook/plugin events,
brokers MCP messages in transparent mode, and exports coverage-aware proof/gate
artifacts. The coverage model separates visibility, observation, enforcement,
and audit instead of hiding them behind one score.
```

- [ ] **Step 4: Run documentation checks**

Run:

```bash
rg -n "v0.15|v0.16|v0.17|v0.18|coverage_grade|NativeIntegrationProfile|MCP Broker" docs README.md
```

Expected: the new docs, index links, roadmap, and README all contain the new version references.

## Task 9: Full Verification

**Files:**
- No code edits.

- [ ] **Step 1: Run full test suite**

Run:

```bash
PYTHONPYCACHEPREFIX=/tmp/kappaski_pycache PYTHONPATH=src /usr/bin/python3 -m pytest -q
```

Expected: all tests pass.

- [ ] **Step 2: Run roadmap status**

Run:

```bash
PYTHONPYCACHEPREFIX=/tmp/kappaski_pycache PYTHONPATH=src /usr/bin/python3 -m kappaski.cli roadmap status
```

Expected: pass with no missing docs or tests.

- [ ] **Step 3: Run strict roadmap status**

Run:

```bash
PYTHONPYCACHEPREFIX=/tmp/kappaski_pycache PYTHONPATH=src /usr/bin/python3 -m kappaski.cli roadmap status --require-full
```

Expected: fail until full enterprise hardening is complete. The failure must list remaining full-product gaps, not missing local slice docs/tests.

## Self-Review Checklist

- Spec coverage: v0.15 inventory, v0.16 bridge, v0.17 broker, and v0.18 coverage proof/gate all have tasks, tests, docs, and CLI scope.
- Decision coverage: the plan encodes all accepted decisions from the v0.15-v0.18 discussion.
- Placeholder scan: the plan avoids `TBD`, `TODO`, and unspecified implementation steps.
- Type consistency: `CoverageRecord`, `NativeIntegrationProfile` report shape, bridge response shape, and benchmark suite names are consistent across tasks.

