# Plugin And Extension Architecture Review

Date: 2026-05-28
Status: accepted architecture correction

## Executive Conclusion

The product direction is still valid, but the wording and priority should be
corrected.

The earlier design assumption should not be read as "plugins and extensions are
not useful." That is now too weak and misleading. Current mainstream agent
products expose more native integration surface than the original v0.1 wording
assumed.

The corrected architecture is:

> Kappaski should be plugin-assisted, hook-aware, daemon-owned, and enforcement-backed.

Native plugins, hooks, rules, and MCP config should become the first integration
layer whenever a target agent supports them. They provide the best user
experience, the earliest tool-call context, and the cleanest pre-runtime
visibility. They still should not be the only trusted enforcement boundary or
the only fact source.

## Public Interface Signals Checked

The review used public product documentation and official or vendor-adjacent
sources where available.

| Agent surface | Public capability signal | Architecture implication |
| --- | --- | --- |
| Claude Code | Official docs expose hooks at lifecycle and tool-call events, including `PreToolUse` and `PostToolUse`; plugins can bundle slash commands, subagents, hooks, and MCP servers. Sources: [Claude Code hooks](https://docs.anthropic.com/en/docs/claude-code/hooks), [Claude Code plugins](https://code.claude.com/docs/en/plugins). | Claude Code should be a tier-1 native hook adapter. Kappaski should use hooks for early observation and approval prompts, while still writing decisions through the daemon and guarding shell/file/network through wrappers or shims. |
| OpenAI Codex | Official docs expose hooks and plugins; Codex plugins can bundle commands, agents, hooks, and MCP servers. Official docs also document sandbox/safety posture and note that some hook coverage, especially around shell/WebSearch, has limitations. Sources: [Codex hooks](https://developers.openai.com/codex/hooks), [Codex plugins](https://developers.openai.com/codex/plugins), [Codex security](https://developers.openai.com/codex/security). | Codex should no longer be treated as wrapper-only. Kappaski should support a Codex native plugin/hook path, but keep wrapper and sandbox-aware enforcement because hook coverage is not a complete control layer. |
| Gemini CLI | Gemini CLI documents extensions that can bundle context files, MCP servers, custom commands, and tool exclusions. Gemini also documents configuration, MCP server settings, and sandboxing. Sources: [Gemini CLI extensions](https://google-gemini.github.io/gemini-cli/docs/extensions/), [Gemini CLI configuration](https://google-gemini.github.io/gemini-cli/docs/cli/configuration/), [Gemini CLI sandboxing](https://google-gemini.github.io/gemini-cli/docs/cli/sandbox/). | Gemini should be integrated through extension/config scanning plus MCP mediation. Native extension packaging is useful for deployment and configuration, while daemon/proxy/shim layers remain necessary for durable audit and stronger enforcement. |
| Cursor | Cursor documents MCP integration and project/user rules. Cursor also has a hooks marketplace surface, but the agent runtime interception guarantees are not yet a cross-agent standard equivalent to an external control plane. Sources: [Cursor MCP](https://docs.cursor.com/en/context/mcp), [Cursor Rules](https://docs.cursor.com/en/context/rules), [Cursor Hooks marketplace](https://cursor.com/marketplace/hooks/pretooluse). | Cursor should be treated as config/rules/MCP-native first, with marketplace hook integration when available. Kappaski should not assume Cursor exposes a complete third-party runtime control boundary across all IDE actions. |
| OpenCode | OpenCode documents a plugin system with hooks for tool execution and permission-related behavior, plus MCP support. Sources: [OpenCode plugins](https://opencode.ai/docs/plugins/), [OpenCode MCP servers](https://opencode.ai/docs/mcp-servers/). | OpenCode is a strong candidate for a Kappaski native plugin adapter. It should be used to validate the plugin-assisted architecture beside Claude Code and Codex. |
| OpenClaw | Public documentation emphasizes CLI control, MCP/server extensibility, terminal integration, and sandboxed execution. Source: [OpenClaw documentation](https://docs.openclaw.ai/). | Treat OpenClaw as a launch/config/MCP adapter target until its stable hook/extension guarantees are confirmed. |
| Hermes | Public documentation is less authoritative and more fragmented than Claude/Codex/Gemini/Cursor/OpenCode sources. Source signal: [Hermes docs mirror](https://hermes-agent.app/en/docs). | Do not hard-code Hermes assumptions yet. Add it to adapter discovery, then decide once the actual supported extension and runtime interception APIs are verified. |

## Does This Break Kappaski's Original Thesis?

No. It changes the integration priority, not the core product thesis.

The original thesis was:

- pre-runtime checks must understand environment, agent config, Skills,
  tools, APIs, MCP servers, and supply-chain inputs;
- runtime governance must observe and decide on commands, files, network, MCP,
  Skills, external content, target deviation, sensitive reads, and risky writes;
- post-runtime audit must produce a durable replay, proof, and risk report;
- the control plane must work across multiple agents and users.

Plugins and extensions help with all three stages, but they do not by themselves
provide the full control plane.

## Where Native Plugins Are Strong

Native plugins and hooks should be used aggressively for:

- discovering agent-specific configuration;
- installing the Kappaski adapter in the user's native workflow;
- observing tool-call intent before execution;
- presenting approval prompts in the agent's own UX;
- capturing high-level semantic context that is difficult to infer from a shell
  wrapper;
- mapping vendor-specific tool names to Kappaski's canonical `Invocation`;
- collecting agent identity, model/session identifiers, and tool-call metadata;
- making adoption feel natural instead of forcing every user through a wrapper.

This is especially true for Claude Code, Codex, and OpenCode, where public
documentation now shows meaningful hook/plugin surfaces.

## Where Native Plugins Are Still Not Enough

Plugins and hooks are not enough as the sole boundary because:

- vendor APIs are fragmented and change independently;
- coverage differs by agent, tool type, policy mode, and execution path;
- some hooks are advisory or approval-oriented rather than OS enforcement;
- project-local settings can be modified, disabled, or misconfigured;
- hook execution is often inside the same user trust domain as the agent;
- a shell command can spawn subprocesses after the original hook decision;
- file-system and network effects can occur below the agent tool layer;
- local plugin logs are not automatically a single-writer tamper-evident ledger;
- enterprise audit needs a common fact model across many agents, not one vendor's
  event vocabulary.

The correct question is not "plugin or wrapper." The correct split is:

| Layer | Best at | Not enough for |
| --- | --- | --- |
| Native plugin/hook | Intent, context, UX, early decision points | Cross-agent consistency, tamper-evident fact source, OS-level effects |
| Wrapper/proxy | Portable launch control, command/MCP mediation, common evidence | Rich in-agent context and IDE UX |
| Daemon | Session registry, single-writer ledger, policy API, approval state | Direct OS interception by itself |
| Native shim/sandbox | File/network/process enforcement | Product UX, semantic reasoning, post-runtime report |

## Revised Architecture

```text
Agent UI / CLI / IDE / CI
        |
        v
Native Plugin / Hook / Extension
  - Claude hooks
  - Codex hooks/plugins
  - Gemini extensions
  - Cursor rules/hooks/MCP
  - OpenCode plugins
        |
        v
Kappaski Adapter Layer
  - normalize vendor events
  - map tools to Invocation
  - attach source/trust/taint/context
        |
        v
Kappaski Runtime Daemon
  - session registry
  - policy API
  - approval state
  - single-writer ledger
  - replay/proof source
        |
        +--> Shell wrapper
        +--> MCP proxy / broker
        +--> Rust/native file guard
        +--> Env/secret guard
        +--> Network guard
        |
        v
OS sandbox / enterprise controls
```

The daemon remains the product core. Native plugins and hooks are not demoted;
they are promoted to the first observation and UX layer. They just do not own
policy, storage, or the final enforcement claim.

## Impact On The Three Runtime Stages

### 1. Before Runtime

Native integrations should improve pre-runtime coverage:

- read agent-specific config from `.claude/`, Codex plugin directories,
  `.gemini/`, `.cursor/`, OpenCode config, MCP definitions, rules, commands, and
  installed extensions;
- compute a capability surface before launch;
- identify risky Skills, MCP servers, hooks, custom commands, and tool
  exclusions;
- register capability grants in the ledger before the agent starts;
- flag policy drift, dangerous local rules, and unknown extension packages.

This stage can lean heavily on plugins/extensions because the job is discovery
and configuration validation.

### 2. During Runtime

Runtime should be mixed-mode:

- use native pre-tool hooks where available to make early `allow`,
  `require_approval`, or `deny` decisions;
- pass all native hook events through the same `Invocation` envelope;
- enforce deterministic critical decisions through wrapper, proxy, or native
  shim when possible;
- record degraded coverage explicitly when a vendor hook cannot intercept a
  particular action class;
- keep LLM review as a risk classifier and explainer, not a deterministic
  critical-rule downgrader.

This is the most important architecture correction: native hooks are no longer a
future optional nicety. They are part of the primary runtime path for supported
agents.

### 3. After Runtime

Post-runtime still requires Kappaski-owned proof and ledger:

- plugin logs can be evidence, but not the canonical ledger;
- every vendor event should be normalized into Kappaski event types;
- proof remains a portable summary derived from the hash-chain ledger;
- replay should explain which layer observed each action and which enforcement
  layer, if any, could act on it;
- audit reports should include coverage gaps, degraded modes, bypass surfaces,
  and residual risk.

## Product And Roadmap Adjustments

1. Reword the thesis from "plugin route cannot achieve the goal" to "plugin
   route cannot achieve the goal alone."
2. Add `NativeIntegration` as a first-class adapter class, beside wrapper,
   proxy, and shim.
3. Promote Claude Code, Codex, and OpenCode native hook/plugin adapters into the
   next implementation wave.
4. Re-elevate MCP from low priority to medium-high priority because it is a
   cross-agent integration substrate across Claude Code, Codex, Gemini, Cursor,
   OpenCode, and other tools. It is still not the product core.
5. Add coverage-grade reporting: every session should say which action classes
   were observed by plugin/hook, wrapper, MCP proxy, shim, sandbox, or not
   covered.
6. Add tamper and bypass checks for plugin-local config: disabled hooks,
   project-local override, unregistered extension packages, changed MCP servers,
   and agent-writable settings.
7. Keep Rust/native enforcement after the current v0.13 line, but wire it to
   native hook decisions so a hook `deny` can be backed by a stronger file or
   network guard where available.

## Recommended Next Versions

### v0.15 Native Integration Inventory

Goal: turn public adapter assumptions into a machine-readable inventory.

Deliverables:

- scanner support for Claude, Codex, Gemini, Cursor, OpenCode, OpenClaw, and
  generic agents;
- `NativeIntegrationProfile` records for hooks, plugins, extensions, rules, MCP,
  sandbox, and command surfaces;
- CLI report that grades pre-runtime, runtime, and post-runtime coverage per
  agent;
- docs that explain "coverage grade" and "trusted boundary grade."

### v0.16 Hook And Plugin Event Bridge

Goal: make native hook/plugin paths real, not just scanned.

Deliverables:

- Claude Code hook bridge hardening;
- Codex hook/plugin bridge prototype;
- OpenCode plugin bridge prototype;
- canonical event schema for native `PreToolUse`, `PostToolUse`,
  permission/approval, and tool-result events;
- tests using real fixture payloads from public docs and locally installed
  binaries where available.

### v0.17 MCP Broker Reprioritization

Goal: use MCP as a cross-agent tool-call control and audit layer.

Deliverables:

- MCP server scanner and allowlist profile;
- stdio proxy/broker skeleton;
- tool-call approval and redaction path;
- evidence capture for tool arguments and results;
- compatibility tests for representative public MCP server fixtures.

### v0.18 Coverage-Aware Runtime Report

Goal: make Kappaski honest about what it did and did not control.

Deliverables:

- proof fields for `observed_by`, `enforced_by`, `coverage_grade`, and
  `degraded_reason`;
- replay timeline labels for plugin/hook/wrapper/proxy/shim/sandbox;
- enterprise audit section for bypass and residual risk;
- gates that can fail when required coverage is missing for a policy profile.

Accepted details:

- Coverage grade is dimensional, not a single score:
  `preflight_visibility`, `runtime_observation`, `runtime_enforcement`, and
  `postruntime_audit`.
- Grade values are `none`, `declared`, `observed`, `mediated`, and `enforced`.
- Coverage gate failures are profile-driven: warn in `audit`, require approval
  or policy resolution in `managed`, and fail in `ci` when the profile requires
  stronger coverage.
- Enterprise signoff is not part of v0.18. It belongs after coverage-aware proof
  and audit are stable.

## Decision

The implementation logic does not need to be abandoned. It needs to become more
plugin-native at the edge while remaining daemon-owned at the core.

The new product sentence should be:

> Kappaski is a full-lifecycle agent runtime control plane that uses native
> plugins and hooks for first-class integration, but relies on a daemon-owned
> ledger, policy API, wrappers, proxies, and native shims for durable governance,
> cross-agent consistency, and stronger enforcement.
