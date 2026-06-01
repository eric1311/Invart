# Runtime Adapter Direction

Kappaski should expose agent-specific integrations as thin adapters over the
same audit primitives instead of building separate products per agent.

## Recommended Shape

- Claude Code: native hook/plugin adapter first where the user has enabled it,
  plus wrapper command support and scanner support for `.claude/`, `CLAUDE.md`,
  permissions, hooks, Skills, and MCP config. Native hooks should report into
  the same daemon policy path and should not own the ledger.
- Codex CLI: native hook/plugin adapter plus wrapper command. Codex now exposes
  official hooks and plugin-bundled hooks, so Kappaski should no longer model it
  as wrapper-only. Wrapper and sandbox-aware enforcement remain required because
  hook coverage is not a complete security boundary.
- OpenCode: native plugin adapter candidate plus MCP scanning. Use OpenCode to
  validate that Kappaski can be plugin-native without becoming vendor-specific.
- Cursor: rules, MCP, and config scanning first, with marketplace/native hook
  integration where available. Do not assume complete runtime interception across
  all IDE actions.
- Gemini CLI: extension/config/MCP scanning plus sandbox and tool-exclusion
  policy checks.
- OpenClaw and Hermes: adapter discovery first; only add native behavior once
  stable public extension or hook guarantees are confirmed.
- MCP: proxy/broker mode for tool-call logging, tool description scanning,
  approval decisions, redaction, and cross-agent compatibility.
- Skill: static scan before install or execution, then runtime event logging
  whenever a skill is loaded.

## Plugin-Assisted, Not Plugin-Only

The 2026-05 public interface review changes the emphasis. Native plugins and
hooks are now strong enough in Claude Code, Codex, OpenCode, and parts of Cursor
and Gemini CLI that they should be treated as first-class adapter surfaces, not
future niceties.

The key rule remains that hooks and plugins are adapter inputs, not the root of
trust. They may create runtime invocations, add semantic context, and request
policy decisions, but they should not own policy, storage, replay, or the final
enforcement claim.

Wrappers, proxies, native shims, and sandbox integrations are still necessary
because they can audit launch context, target directory, sensitive paths, MCP
traffic, subprocess effects, and file/network behavior independently of one
vendor's hook coverage.

## Prototype Integration Model

The prototype uses one canonical runtime path:

```text
native hook or plugin or extension or launch wrapper or MCP proxy
    -> adapter
    -> local daemon
    -> policy decision
    -> append-only event store
    -> replay
```

This makes backend differences explicit:

- Agents with reliable hooks can get better UX and earlier prompts.
- Agents without hooks still work through launch wrappers, config scanning, and
  MCP proxying.
- Closed-source IDEs can start with wrapper/config scanning and later add deeper
  integrations if APIs become available.
- CI agents can use the same daemon and policy envelope without an IDE plugin.
- Every session should record which action classes were observed by plugin,
  hook, wrapper, MCP proxy, shim, sandbox, or not covered.

The adapter contract should normalize all sources into:

- `Session`
- `Actor`
- `Adapter`
- `CapabilityGrant`
- `Invocation`
- `ResourceRef`
- `PolicyDecision`
- `Evidence`
- `ReplayFrame`

The first production adapter should therefore be:

```bash
kappaski runtime shell --agent codex --target /repo -- codex
kappaski runtime shell --agent claude-code --target /repo -- claude
kappaski runtime shell --agent cursor --target /repo -- cursor-agent
```

The next adapter wave should add:

- `NativeIntegrationProfile` discovery for Claude Code, Codex, Gemini CLI,
  Cursor, OpenCode, OpenClaw, and generic agents.
- Hook/plugin event bridges for Claude Code, Codex, and OpenCode.
- MCP broker/proxy support as a cross-agent control substrate.
- Coverage-aware proof fields: `observed_by`, `enforced_by`,
  `coverage_grade`, and `degraded_reason`.
