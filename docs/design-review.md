# Kappaski MVP Review and Design Direction

Date: 2026-05-22
Issue: KAP-3
Scope: Review KAP-1 and the first Kappaski MVP implementation.

## Current Baseline

Kappaski currently provides a local-first Python CLI with three phases:

- `pre-runtime`: scans the target directory, home-level agent configs, MCP config, Skills, sensitive paths, and suspicious instruction content.
- `runtime`: evaluates and records structured events for shell, file, network, MCP, Skill, and external content activity.
- `post-runtime`: aggregates a JSONL event log into an audit report.

The prototype is intentionally dependency-free. It has useful security primitives, but it is not yet a complete runtime security product. The biggest missing pieces are adapter contracts, MCP proxying, approval workflow, richer session replay, external content classification, and a policy model that connects the three phases.

## Meeting Flow

The review was structured as a product and implementation meeting with four perspectives:

- Hewitt perspective: product abstraction, multi-agent ecosystem, MCP and Skill design.
- Hopper perspective: runtime architecture, wrappers, proxies, sandboxing, event model.
- Redding perspective: red-team risk model across pre-runtime, runtime, and post-runtime.
- Gogo perspective: chairing, scope control, and final synthesis.

The live Multica discussion was initiated on KAP-3 with the three specialist agents. The final discussion converged on a narrower and stronger direction: Kappaski should become an AI coding agent capability firewall with a taint-aware replay ledger, not a broader scanner or generic audit log.

## Round 1: Initial Positions

### Hewitt Perspective

Agree:

- The product should not be framed as a generic security platform. It should define a small set of agent runtime objects and govern their interactions.
- The core abstraction should be the agent session, not a single command or a static scan report.
- Skills and MCP tools must be treated as supply-chain and runtime capabilities, not just text files.

Main objection:

- The current implementation has rules and events, but no explicit object model for capability, policy, approval, session, actor, or evidence. Without that, the product will become a bag of scanners.

Required changes:

- Define canonical objects: `AgentRuntime`, `RuntimeTarget`, `Capability`, `Policy`, `Session`, `Event`, `Finding`, `Decision`, and `Evidence`.
- Treat MCP tools and Skills as capabilities with declared intent, source, trust level, input/output schema, side effects, and approval requirements.
- Make the minimum product loop: discover capabilities, evaluate launch risk, mediate runtime actions, then replay the session with decisions and evidence.

### Hopper Perspective

Agree:

- Wrapper-first is the right MVP path for Codex, Claude Code, and Cursor CLI. Native plugin APIs are too fragmented for the first implementation phase.
- The current `runtime shell` command is a valid seed, but it only covers one narrow action path.
- Event JSONL is acceptable for MVP as long as the schema becomes stable and versioned.

Main objection:

- The current runtime path blocks high-risk shell commands, but it does not actually sit between the agent and the important surfaces: file reads, MCP calls, network requests, tool outputs, and approval state.

Required changes:

- Add an adapter layer with a stable interface: `prepare`, `launch`, `observe`, `decide`, `record`, `finalize`.
- Add an MCP proxy before trying to build deep IDE integrations. MCP gives the cleanest tool-call boundary.
- Add policy decisions as first-class runtime records: `allow`, `warn`, `require_approval`, `block`, `redact`, `quarantine`.

### Redding Perspective

Agree:

- Pre-runtime static scanning is necessary, but it should be treated as only the first gate.
- Runtime content review is important because prompt injection usually enters through external text, tool descriptions, command output, files, docs, web pages, and issue content.
- Post-runtime value depends on whether the replay can show causality, not just a list of findings.

Main objection:

- The current rule set catches obvious payloads such as `curl | bash` and "ignore previous instructions", but real attacks will be indirect, contextual, encoded, or disguised as legitimate tool instructions.

Required changes:

- Track data provenance: user instruction, system/developer instruction, repo file, external web content, command output, MCP response, Skill file, and agent-generated text.
- Add runtime checks for goal hijacking, tool-use escalation, secret exfiltration path, suspicious outbound destinations, risky tool result content, and sensitive-to-external data flow.
- Post-runtime reports must include attack chain reconstruction: source, trigger, action attempted, decision, result, and residual risk.

### Gogo Perspective

Agree:

- The MVP should stay narrow: AI Coding Agent Runtime Audit and Control for local developer environments and PR workflows.
- The product should be sold as enabling enterprises to safely allow coding agents, not as a reason to ban them.
- The implementation should stay local-first and dependency-light until the event model and adapter boundary are stable.

Main objection:

- The current README describes primitives, but not the product contract. A user cannot yet tell what Kappaski promises to mediate and what it only reports.

Required changes:

- Update docs to state the product contract explicitly.
- Convert the PRD into engineering slices with clear order: schema, policy, adapters, MCP proxy, replay, PR bot.
- Keep scanner, runtime, and post-runtime connected through the same policy and event schema.

## Round 2: Debate and Revisions

### Debate 1: Product Objects vs Engineering Objects

Initial tension:

- Hewitt emphasized product-level objects: `Goal`, `Capability`, `Policy`, `Action`, `Decision`, `Evidence`, and `Replay`.
- Hopper emphasized serializable engineering objects: `Session`, `Actor`, `Adapter`, `Invocation`, `ResourceRef`, `PolicyDecision`, and `ArtifactRef`.
- Redding challenged both positions for not making source/taint tracking first-class enough to explain prompt-injection and tool-hijack chains.

Decision:

- Use both layers deliberately.
- Product and design language should use `Goal`, `Capability`, `Action`, `Decision`, `Evidence`, and `Replay`.
- Runtime schema and code should use `Session`, `Actor`, `Adapter`, `Invocation`, `ResourceRef`, `PolicyDecision`, and `ArtifactRef`.
- Every `Invocation` must carry source and taint context so the system can answer what triggered an action, not only what action occurred.

Implementation implication:

- Add a versioned schema before expanding integrations.
- Treat `RuntimeEvent` as a compatibility observation layer until it can be replaced by `Invocation + PolicyDecision + Evidence`.
- Avoid building a large abstract framework first; implement a vertical slice from session creation through invocation decision, append-only storage, and replay.

### Debate 2: Plugin vs Wrapper

Initial tension:

- A plugin sounds more native and product-like for Codex, Claude Code, and Cursor.
- A wrapper is less elegant but gives immediate control over launch context and shell execution.

Decision:

- Use wrapper adapters for the MVP.
- Keep the adapter interface plugin-compatible so future native integrations can use the same event and policy pipeline.
- Do not promise deep IDE telemetry until a vendor-specific integration exists.

Implementation implication:

- Add `kappaski run --agent codex --target /repo -- codex ...`.
- Add adapter metadata for each supported agent.
- Record launch environment, working directory, target repo, detected config, and declared capabilities.

### Debate 3: Scanner vs Runtime Control

Initial tension:

- Scanner is easiest to ship and easiest to demo.
- Runtime control is the actual differentiation.

Decision:

- Scanner remains the entry point, but the next engineering investment should be runtime mediation.
- The scanner should output a launch risk profile that the runtime consumes.

Implementation implication:

- Persist `pre-runtime` output as `.kappaski/preflight.json`.
- Runtime should load preflight context and policy before allowing agent launch.
- Post-runtime should reference the preflight baseline and show what changed during execution.

### Debate 4: MCP Proxy Ordering

Initial tension:

- MCP proxy is the cleanest runtime control boundary because tool calls have explicit names, schemas, arguments, and results.
- Starting with MCP proxy before a stable schema risks creating MCP-specific logs that do not generalize to shell, file, network, and adapter events.

Decision:

- Do not put MCP proxy first.
- Build `schema + policy + store` first, then adapt the shell wrapper, then add MCP proxy on the same envelope.
- Replay v0 can start alongside store, but polished reporting should not precede stable evidence records.

Implementation implication:

- First code slice: `Session -> Invocation -> PolicyDecision -> Evidence/Artifact -> JSONL store`.
- MCP proxy MVP should reuse this same envelope for tool list, tool call, tool result, and write-like operation approval.

### Debate 5: Content Review and Taint Awareness

Initial tension:

- Simple regex checks are fast and explainable.
- Prompt injection and tool hijacking often require contextual classification.

Decision:

- Keep deterministic local rules as the baseline.
- Add a pluggable content-review interface later, with local-only default behavior.
- Classify content by provenance before severity. The same instruction is less risky in a test fixture than in an MCP tool description or external issue comment.
- Make taint/source fields mandatory in the MVP envelope, even if propagation starts simple.

Implementation implication:

- Extend runtime records with `source`, `trust_level`, `input_refs`, `output_refs`, `taint_tags`, `correlation_id`, and `policy_version`.
- Add rule categories for `external-instruction`, `tool-hijack`, `data-flow`, and `goal-drift`.
- Implement two hard MVP policies:
  - Untrusted source triggering write, execution, outbound network, MCP write, Git push, issue update, or PR creation requires approval or is blocked by policy.
  - Sensitive reads followed by outbound, remote write, Git push, or external publication require approval or are blocked by policy.

### Debate 6: Audit Replay

Initial tension:

- A flat JSONL summary is enough for early testing.
- Security users need a causal chain.

Decision:

- Keep JSONL storage, but make session replay causal and decision-oriented.
- Every finding should be tied to the event that caused it and the decision made by policy.

Implementation implication:

- Add event IDs and parent/correlation IDs.
- Record decisions separately from findings.
- Generate a report with timeline, risk events, touched assets, approvals, blocked actions, and residual risk.

## Consensus

The group should converge on this product definition:

Kappaski is a local-first capability firewall and taint-aware replay ledger for AI coding agents. It discovers the agent's capabilities before launch, mediates high-risk behavior during execution, and reconstructs the session afterward as an evidence-backed replay that preserves source, trust, and causality.

The MVP should not try to become a full SIEM, EDR, IDE plugin suite, or generic LLM guardrail. Its defensible wedge is the cross-agent runtime behavior layer for coding agents, MCP tools, Skills, shell commands, file access, and external content.

## Prototype Architecture Decision

The prototype should use a layered runtime architecture rather than choosing a single integration style. Native hooks and plugins are useful when an agent exposes them, but they are inconsistent across vendors and cannot be treated as the hard enforcement boundary. The prototype architecture is therefore:

```text
Agent UI / CLI / IDE / CI
        |
        v
Native Hook or Plugin Adapter, when available
        |
        v
Kappaski Adapter Layer
        |
        v
Local Runtime Daemon
  - session registry
  - policy engine
  - capability grants
  - approval state
  - append-only event store
  - replay builder
        |
        +--> Shell Wrapper
        +--> MCP Proxy
        +--> File / Network Monitor, later
        |
        v
OS Sandbox, later
```

Key decision:

- Plugin-first is the user entry path, not the security boundary.
- Hook-first is an optimization for agents that support reliable pre-tool events.
- Wrapper/proxy-first is the enforcement baseline because it works across more backends and can record execution evidence independently of vendor plugin maturity.
- The daemon is the product core. Wrappers, proxies, native hooks, and future IDE plugins are enforcement or observation shims that all write the same runtime envelope.

This gives Kappaski a cross-backend shape: Codex, Claude Code, Cursor, Cline, Windsurf, Gemini CLI, CI agents, and future in-house agents can all be normalized into the same `Session -> Invocation -> PolicyDecision -> Evidence -> ReplayFrame` flow.

## Hook and Plugin Boundary

The 2026-05 public interface review changes the wording and adapter priority,
but not the daemon-owned architecture. The correct conclusion is not "plugins
are useless"; it is "plugins and hooks are first-class adapter surfaces, but
insufficient as the only control layer." See
`docs/plugin-extension-architecture-review-2026-05.md`.

Prototype assumptions:

- Claude Code, Codex, and OpenCode hooks/plugins can provide useful early
  interception where available.
- Gemini CLI extensions and Cursor rules/hooks/MCP can improve pre-runtime and
  runtime coverage, but should still be normalized into Kappaski's adapter path.
- No single vendor's hook/plugin surface is complete enough to be the only
  trusted boundary.
- Hooks can be bypassed by vendor-specific modes, misconfiguration, or agent-writable project settings.
- Hooks do not provide OS-level control over subprocesses, network egress, or file-system boundaries.

Therefore the prototype should model native hooks as an adapter source, not as a trusted enforcement root. A hook may create an `Invocation` and ask the policy engine for a decision, but the daemon, shell wrapper, MCP proxy, and later sandbox remain the consistent control layer.

## Prototype Object Model

The product model should stay small enough to implement in the next iteration:

- `Session`: one agent run or team run with a target repo, policy version, launch context, and runtime state.
- `Actor`: the agent, user, subprocess, MCP server, or plugin component that initiated or mediated an action.
- `Adapter`: the source of observation or enforcement, such as codex wrapper, claude hook, cursor launch adapter, MCP proxy, or CI adapter.
- `Goal`: the declared task or team objective for the session.
- `CapabilityGrant`: a scoped permission granted to an actor, with resource scope, expiration, and approval source.
- `Invocation`: a normalized attempted action: shell command, file read/write, MCP tool call, network outbound, Git operation, issue update, skill load, or external content ingest.
- `ResourceRef`: a local file, repo, URL, MCP server/tool, process, secret class, issue, PR, artifact, or network destination touched by an invocation.
- `PolicyDecision`: `allow`, `deny`, `require_approval`, `redact`, `quarantine`, or `audit_only`, with reasons and policy version.
- `Evidence`: local digests, redacted payload summaries, stdout/stderr summaries, diffs, tool arguments, tool result summaries, and approval records.
- `ReplayFrame`: a causally linked report frame that connects source, trust, taint, action, decision, result, and residual risk.

The MVP does not need a full data-flow engine. It does need mandatory provenance fields on every invocation: `source`, `trust_level`, `input_refs`, `output_refs`, `taint_tags`, `correlation_id`, and `policy_version`.

## Revised Product Contract

Kappaski should promise six things:

- Before launch, it can identify risky agent configuration, MCP servers, Skills, sensitive paths, and target repository conditions.
- At launch, it can create an auditable session with known agent, target, policy, and capability context.
- During execution, it can analyze and decide on shell commands, file events, MCP tool calls, Skill loads, network events, and external content.
- After execution, it can reconstruct what happened, what was risky, what was blocked or approved, and what residual risk remains.
- For security-relevant actions, it can explain the triggering source and taint context: user prompt, local repo, external web, MCP result, Skill instruction, issue comment, attachment, or unknown.
- Across all phases, it keeps source code and audit data local by default.

## Mandatory Runtime Envelope

The next schema should make source and taint context first-class fields, not optional metadata. Unknown values should be explicit rather than omitted.

Minimum fields:

- `session_id`: stable ID for the agent run.
- `seq`: monotonically increasing event sequence within the session.
- `actor`: agent or process identity.
- `adapter`: integration that observed or mediated the action.
- `operation` or `capability`: normalized action class such as shell execution, file read, file write, network outbound, MCP read, MCP write, Git operation, or issue update.
- `resource_refs`: target resources touched by the action.
- `source`: triggering input source, such as `user_prompt`, `local_repo`, `external_web`, `mcp_result`, `skill_instruction`, `issue_comment`, `attachment`, or `unknown`.
- `trust_level`: `trusted`, `internal`, `untrusted`, or `unknown`.
- `input_refs`: upstream event, content, or resource IDs that influenced this action.
- `output_refs`: downstream artifacts, files, network destinations, or tool results created by this action.
- `taint_tags`: tags such as `external_instruction`, `sensitive_read`, `user_pii`, `credential`, or `repo_secret`.
- `correlation_id`: ID that links related actions across adapters and event types.
- `policy_version`: policy version used to evaluate the action.
- `decision`: `allow`, `deny`, `require_approval`, `redact`, `quarantine`, or `audit_only`.
- `evidence_refs`: local artifacts, digests, or summaries supporting the decision.

This is intentionally a declaration model, not a full data-flow engine. The MVP only needs each action to declare its context and taint state. Cross-event propagation and deeper inference can be added in replay/report layers once the envelope is stable.

## Revised Architecture

### 1. Pre-runtime Layer

Responsibilities:

- Detect agent configs and installed tools.
- Detect MCP servers and Skills.
- Scan supply-chain risk in `AGENTS.md`, `CLAUDE.md`, `SKILL.md`, MCP config, scripts, and CI.
- Check target state, sensitive paths, Git state, and CI/CD files.
- Produce a preflight report used by runtime.

Near-term modules:

- `scanner.py`: keep current detection and expand MCP/Skill metadata.
- `policy.py`: new module for loading policy templates.
- `preflight.py`: new module for saving and loading launch profiles.

### 2. Adapter Layer

Responsibilities:

- Normalize launch for Codex, Claude Code, Cursor CLI, Cline, and future tools.
- Record agent identity, command, target, config paths, and capabilities.
- Provide wrapper-first integration while preserving a path to native plugins.

Near-term modules:

- `adapters/base.py`
- `adapters/codex.py`
- `adapters/claude_code.py`
- `adapters/cursor.py`

Minimum interface:

```python
class RuntimeAdapter:
    name: str

    def detect(self, target: Path) -> AdapterDetection: ...
    def prepare(self, target: Path, policy: Policy) -> LaunchContext: ...
    def launch(self, context: LaunchContext, command: list[str]) -> int: ...
```

### 3. Runtime Mediation Layer

Responsibilities:

- Record event stream.
- Analyze event risk.
- Apply policy decisions.
- Support approval and blocking.
- Redact sensitive evidence where needed.

Near-term modules:

- `runtime.py`: keep append/analyze/shell, but split decision logic out.
- `policy.py`: decision engine.
- `events.py`: versioned event schema.
- `approvals.py`: local approval stub for MVP.

Priority event types:

- `agent_launch`
- `shell_command`
- `shell_exit`
- `file_read`
- `file_write`
- `network_request`
- `mcp_tool_call`
- `mcp_tool_result`
- `skill_load`
- `external_content_ingest`
- `policy_decision`
- `approval_request`
- `approval_result`

### 4. MCP Proxy Layer

Responsibilities:

- Mediate MCP tool descriptions, calls, and responses.
- Detect hidden instructions or tool poisoning in descriptions.
- Require approval for high-risk tool calls.
- Record inputs and outputs with redaction.

MVP behavior:

- Start with stdio MCP proxy for configured servers.
- Support allow/block/require approval decisions.
- Keep raw payload local and record summarized evidence.

### 5. Post-runtime Replay Layer

Responsibilities:

- Load preflight and runtime logs.
- Reconstruct event timeline.
- Group findings into attack chains and policy outcomes.
- Produce local JSON and text/HTML reports.

Near-term modules:

- `postruntime.py`: extend from summary to replay.
- `report.py`: render human-readable report.
- `chains.py`: correlate source, trigger, action, decision, result.

## Next Implementation Plan

### Slice 1: Stable Schema, Policy, and Store

- Add `Session`, `Invocation`, `ResourceRef`, `PolicyDecision`, and `ArtifactRef` models.
- Add event ID, session ID, sequence, timestamp, actor, adapter, source, trust level, input refs, output refs, taint tags, correlation ID, and policy version fields.
- Add `Decision` model with `allow`, `deny`, `require_approval`, `redact`, `quarantine`, and `audit_only`.
- Add policy templates: `audit-only`, `balanced`, `strict`, `ci`.
- Add an append-only JSONL store with sequence numbers and previous-record hashes.
- Make runtime append invocations, findings, policy decisions, and evidence refs.

### Slice 2: Shell Wrapper and Launch Adapter

- Add `kappaski run --agent <agent> --target <path> -- <command>`.
- Detect Codex, Claude Code, and Cursor CLI config.
- Save preflight before launch.
- Record `agent_launch` and `agent_exit`.
- Convert the current shell wrapper to create an `Invocation` draft before execution, ask policy for a decision, then execute, block, or request approval.

### Slice 3: Replay v0

- Generate a session timeline from the append-only JSONL store.
- Generate blocked/approved action summaries.
- Generate source/taint summaries showing untrusted inputs, sensitive reads, and subsequent high-risk actions.
- Reference preflight baseline and runtime deltas.

### Slice 4: MCP Proxy Prototype

- Parse MCP server configs.
- Wrap stdio command launch.
- Record tool descriptions, calls, results.
- Apply high-risk tool policy decisions.
- Use the same `Invocation + PolicyDecision + Evidence` envelope as shell/file/network events.

### Slice 5: Runtime Content Review

- Add `external_content_ingest` event.
- Classify source/provenance.
- Expand rules for instruction hijack, data exfiltration, goal drift, suspicious URLs, and secret-to-network flow.

### Slice 6: Replay Report

- Generate timeline.
- Generate risk table.
- Generate blocked/approved actions.
- Generate attack-chain summaries.
- Reference preflight baseline and runtime deltas.

## Open Questions

- How much file-read visibility can be captured without OS-level hooks or a cooperating agent/plugin?
- Should local approval be terminal-based first, or should the MVP write approval requests to a file/socket for external UI integration?
- Should secret detection remain pattern-based in MVP, or should entropy-based token detection be added immediately?
- What is the first MCP server to use for an end-to-end proxy demo?
- Should PR Bot be added before MCP proxy, or after there is enough runtime evidence to make PR comments meaningful?

## Chair Decision

The next version should not add more isolated regex rules first. It should add the connective tissue: stable invocation schema, policy decisions, append-only evidence store, launch adapter, and preflight-to-runtime-to-replay continuity.

The final meeting decision is to hold the line on taint awareness in the core schema. Without `source`, `trust_level`, `input_refs`, `output_refs`, `taint_tags`, `correlation_id`, and `policy_version`, Kappaski would only be a better audit log. With those fields present from the MVP, it can become a runtime control plane that explains not only what an agent did, but what caused it and why the action was allowed, blocked, or escalated.
