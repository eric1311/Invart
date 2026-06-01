# Kappaski Product Decisions

Date: 2026-05-26
Status: accepted working decisions

## Product Direction

Kappaski is an Agent Runtime Control Plane.

Coding agents are the first high-risk, high-frequency wedge, but the final
product is not limited to coding. Kappaski should sit outside agent applications
such as Codex, Claude Code, Cursor, OpenClaw, or future domain agents, providing
unified observation, governance, audit, and risk analysis across them.

The proof report is an artifact produced by the control plane. It is not the
whole product. The durable product value is the ability to manage, decide,
record, and verify agent behavior across local developer workflows and future
team workflows.

## Version Boundaries

### v0.1 Frozen

v0.1 is now frozen as a local closed-loop proof foundation:

- persisted preflight baseline;
- managed local session;
- canonical `Invocation` envelope;
- deterministic rule findings;
- policy decisions;
- session-level taint;
- approval evidence;
- hash-chain JSONL ledger;
- proof export;
- proof-only, ledger-only, and proof+ledger verification;
- CLI-first workflow.

New semantic review, daemon, MCP proxy, TeamRun, Blackboard, Handoff, and UI work
belongs to v0.2+.

### v0.2 Direction

v0.2 focuses on the semantic decision engine:

- reviewer schema;
- LLM/semantic reviewer interface;
- heuristic reviewer for deterministic local testing;
- policy merger;
- automatic approval grading;
- decision trace;
- proof/report upgrade.

The v0.2 goal is to reduce unnecessary human approval by grading actions more
intelligently while preserving auditability.

## Policy Modes

Kappaski will support four policy modes:

- `audit`: record and evaluate, but do not block;
- `advisory`: produce decisions and allow user/agent override, recording the override;
- `managed`: wrapper/proxy pauses or blocks high-risk actions until resolution;
- `ci`: proof verification acts as a policy gate and returns non-zero on failure.

## LLM Reviewer Boundary

The LLM reviewer is a semantic reviewer, not the root of trust.

Its core value is automatic approval grading:

- low-risk actions can be automatically allowed or approved;
- medium-risk actions can be audited or require approval;
- high-risk semantic concerns should require human approval;
- deterministic critical rules can never be downgraded by LLM output.

The LLM reviewer should be able to upgrade risk. It should not silently downgrade
hard deterministic findings.

## Proof And Ledger

The ledger is the fact source.

The proof is a portable summary derived from the ledger.

Verification modes:

- ledger-only verification recomputes the raw evidence hash chain;
- proof-only verification is convenient but weaker;
- proof+ledger verification is the trusted v0.1+ path.

Future proof-only verification may be strengthened with signatures or a registry,
but that is not required now.

## Daemon Direction

A future daemon should be a runtime authority, not just a background process. It should own:

- session registry;
- single-writer ledger;
- policy API;
- approval state;
- wrapper/proxy coordination;
- MCP stdio proxy, when it becomes a priority;
- process supervision.

The daemon should not own rich report rendering, LLM provider experimentation, or
complex scanner logic by default. Those can remain in Python while the daemon is
introduced in Rust or Go later.

## Plugin And Extension Boundary

The 2026-05 public interface review changed the adapter emphasis.

Native plugins, hooks, extensions, rules, and MCP config are now first-class
integration surfaces. Claude Code, Codex, OpenCode, Gemini CLI, and Cursor all
expose meaningful public surfaces for native integration, even though their
guarantees and coverage differ.

Accepted wording:

- Kappaski is plugin-assisted and hook-aware, not plugin-only.
- Native plugins and hooks should be used for user experience, early intent,
  agent-specific context, tool-call metadata, and pre-runtime config discovery.
- Native plugins and hooks are not the root of trust. They should not own policy,
  storage, replay, or the final enforcement claim.
- The daemon remains the product core and the single-writer fact source.
- Wrappers, proxies, native shims, and sandbox integrations remain the stronger
  enforcement and evidence layers when vendor hook coverage is incomplete.
- Every proof and audit report should eventually record coverage: which actions
  were observed by plugin/hook, wrapper, MCP proxy, shim, sandbox, or not
  covered.

Reference design: `docs/plugin-extension-architecture-review-2026-05.md`.

## MCP Proxy Priority

MCP proxy priority is revised from low to medium-high.

Skills remain important, but current mainstream agents increasingly expose MCP
as a common integration substrate for tools, servers, and extension bundles.
MCP is still not the product core. The product core is daemon-owned session
registry, policy, approval state, and ledger. But MCP proxy/broker support should
be treated as an important cross-agent control path for v0.17+ because it can
normalize tool-call audit, approval, redaction, and compatibility across several
agent products.

## Coverage Grade Decision

Coverage grade is not a risk score. It describes Kappaski's actual control
position for an action class or concrete runtime event.

Accepted grades:

- `none`: Kappaski cannot see the behavior.
- `declared`: Kappaski sees the capability in config or preflight inventory, but
  not during runtime.
- `observed`: Kappaski sees the event or log, but not before side effects occur.
- `mediated`: Kappaski is on the execution path and can pause, approve, modify,
  or reject before the action proceeds.
- `enforced`: Kappaski has a stronger boundary, such as a wrapper, proxy, shim,
  or sandbox, that can block the real side effect.

Coverage should be recorded by dimension rather than as a single score:

- `preflight_visibility`;
- `runtime_observation`;
- `runtime_enforcement`;
- `postruntime_audit`.

Gate behavior for insufficient coverage is profile-driven:

- `audit` mode warns;
- `managed` mode may require human approval;
- `ci` mode may fail when policy requires a higher coverage grade.

Enterprise signoff is intentionally deferred beyond v0.18. v0.18 should make
proof, replay, audit, and gate coverage-aware. Signoff introduces identity,
authority, review, immutability, and compliance workflow concerns and should be
handled as a later product layer.

## UI Timing

v0.2 and v0.3 should not prioritize UI. Focus on daemon and CLI first. TeamRun,
Blackboard, and Handoff should begin as ledger-backed data models before any UI
investment.

## Evaluation Direction

Public benchmarks are useful, but none of them directly evaluate Kappaski's full
control-plane loop. The accepted direction is to use external suites as scenario
corpora, then score Kappaski-specific outcomes: decision quality, approval grade,
outcome recording, proof completeness, and ledger verification.

Near-term external benchmark priority:

- AgentDyn for indirect prompt injection and over-defense;
- ShadowBench for agent crash-test failure modes;
- ARA Eval for enterprise risk-gate precision and recall.

Kappaski's own built-in benchmark remains the regression harness for the complete
closed loop.


## Accepted Roadmap Decisions For v0.8-v0.14

- v0.8 uses an OpenAI-compatible LLM reviewer provider first. LLM review may produce `deny`, but must include structured explanation suitable for proof and audit. Raw content may be reviewed, but display must be folded, truncated, summarized, and profile-governed.
- v0.9 uses SWE-Bench Lite for the first full harness compatibility target. Managed mode may pause the harness for human approval. Success means matching exit code, expected artifacts, and grading result, with minor metadata differences allowed.
- v0.10 hardens the Claude Code adapter first. Environment keys are recorded by default, while values are redacted, folded, summarized, or truncated by profile. Child process supervision aims for strong consistency but must expose degraded modes explicitly.
- v0.11 introduces policy profiles with precedence `session > repo > team`. Enterprise mode disallows local override by default. Future break-glass override requires explicit reason, elevated identity, time-bound scope, immutable ledger record, and administrator/auditor review.
- v0.12 introduces multi-user TeamRun and user-declared agent identity validated against adapter/session facts. Handoff taint inheritance defaults to resource-reference inheritance, with a session-wide inheritance switch available through policy profiles for stricter enterprise use.
- v0.13 selects Rust as the native enforcement-shim direction. The implemented local slice includes Python control-plane guard decision checks plus a source-level Rust file-write shim contract and build-check command. Enforcement order is file-write guard, then env/secrets guard, then network egress guard, with enterprise profile customization for stricter behavior. Enforcement failure defaults to fail-open with critical alert unless a strict enterprise profile later chooses fail-closed.
- v0.14 packages an enterprise-security-team demo around secret leak and unsafe deletion workflows. The implemented slice is deterministic and ledger-derived, exporting proof, replay, audit JSON, and audit HTML. Replay raw content remains folded by default and profile-controlled; live real-agent execution and enterprise report signoff remain later hardening.

## Open Questions To Revisit

- When, if ever, may LLM output alone produce `deny` instead of `require_approval`?
- What is the first enterprise demo loop that best communicates value?
- When should daemon implementation begin, and should it be Rust or Go?
- How should Skills be modeled relative to MCP tools in capability grants?
- Should approval reasons be reviewed by LLM before being accepted?
