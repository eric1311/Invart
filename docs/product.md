# The local-first control plane for AI agent runtime risk.

[HTML version](html/product.html)


Invart wraps agent execution with identity, policy, mediation, ledger-backed evidence, and post-run audit. It is built for teams that want agent autonomy without blind trust.

[Start](quickstart.md) · [Architecture](architecture.md) · [Evaluate](evaluation.md) · [GitHub README](../README.md)

## Why Invart Exists

Modern agents can run shell commands, edit files, call MCP tools, load skills, read secrets, and interact with external services. Plugin hooks help, but they are not enough as the only safety boundary. Invart treats the agent run itself as a governed runtime.

### Quick Demo

```bash
invart demo real-world-risk-cases \
  --out-dir .invart/real-world-risk-demo
```

Outputs a safe risk demo with ledger, proof, replay, audit, and evidence artifacts.

## Three Stages

| Stage | Question | Invart Output |
| --- | --- | --- |
| Before runtime | What can this agent touch? | Preflight inventory, capability surface, credential boundary, policy profile. |
| During runtime | Should this action continue? | Mediation decision, approval state, taint record, coverage level, ledger event. |
| After runtime | What happened, why, and under whose authority? | Proof, replay, path graph, evidence bundle, audit report, gate result. |

## Five Control Layers

### L1 Execution Surface

Commands, files, network, MCP, skills, plugins, launchers, wrappers, and native hooks.

### L2 Runtime Facts

Normalized invocations, identity, resources, taint, coverage, outcomes, and hash-chained ledger entries.

### L3 Decision Plane

Deterministic policy, path-aware rules, reviewer explanations, and non-downgradable critical findings.

### L4 Mediation Plane

Allow, audit, require approval, deny, enforced block, and fail-open alert with consistent semantics.

### L5 Evidence Plane

Proof, replay, audit, path graph, evidence bundle, benchmark metrics, and release gates.

## What You Can Show A Team

### Security

Which agent read sensitive material, which policy applied, whether the action was blocked or approved, and what evidence proves it.

### Platform

Whether managed launchers, wrappers, hooks, and benchmark harnesses can run without breaking normal developer workflow.

### Developers

Low-risk commands continue automatically, while high-risk steps receive precise context instead of vague warnings.
