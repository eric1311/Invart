# Invart Project Instructions

Invart is an agent runtime control plane for safety, observability, policy, proof, and audit across coding agents and related tool ecosystems.

## Product Boundary

Invart is not a plugin-only wrapper. Agent-specific plugins, hooks, and MCP integrations can improve coverage, but the durable product boundary is the control plane around runtime execution:

- before runtime: inventory environment, tools, skills, MCP, supply chain, policy profile, and risk posture;
- during runtime: observe and mediate commands, files, network, process tree, tool calls, policy decisions, approval state, and potential target deviation;
- after runtime: produce proof, replay, audit summary, evidence bundles, and actionable risk findings.

## Architecture Boundary

- Ledger is the fact source; proof is the portable summary.
- Deterministic critical rules cannot be downgraded by LLM judgment.
- LLM reviewers may classify, explain, or upgrade risk, but policy enforcement and hard safety boundaries remain rule-governed.
- Profiles may bind to session, repo, and team, with priority `session > repo > team`.
- Enterprise mode should prefer explicit policy and auditable override paths over local silent override.

## Validation Boundary

Use real harnesses and data whenever feasible. For coding-agent compatibility, prefer SWE-Bench Lite, ClawBench-like cases, or real plugin/skill/tool corpora over mock-only tests.

Compatibility claims should state evidence: same exit code, same artifact, same grading result, or documented acceptable metadata differences. Do not claim security coverage from plugin/extension integration alone when lower-level runtime behavior remains unobserved.

## Implementation Defaults

- Keep public CLI behavior, docs, tests, and benchmarks synchronized.
- Prefer `invart` in new code and docs.
- Keep `kappaski` compatibility aliases unless there is a deliberate migration plan.
- Do not commit `.invart/`, `.kappaski/`, `.venv/`, `build/`, `dist/`, `logs/`, Rust `target/`, or `internal/`.
