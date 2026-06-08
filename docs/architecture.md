# Three lifecycle stages, five control layers.

[HTML version](html/architecture.html)


Invart is not a plugin-only wrapper. Plugin and hook integration can improve coverage, but the durable product boundary is the runtime control plane.

## Lifecycle

## Layer Model

| Layer | Responsibility | Example modules |
| --- | --- | --- |
| L1 Execution Surface | Adapters, wrappers, launchers, native hooks, MCP broker, Rust shim. | surfaces/adapter.py, surfaces/launcher.py, surfaces/native.py, surfaces/mcp_broker.py, surfaces/enforcement.py |
| L2 Runtime Fact Model | Sessions, invocations, ledger entries, identity, resources, taint, outcomes. | core/models.py, control/runtime.py, core/ledger.py, governance/identity.py |
| L3 Decision Plane | Rules, policy-as-code, semantic review, path policy. | control/rules.py, control/policy_as_code.py, control/path_policy.py, control/review.py |
| L4 Mediation Plane | Unified decision and outcome contract across surfaces. | control/mediation.py, control/approval.py, control/gate.py |
| L5 Evidence Plane | Proof, replay, graph, audit, coverage, evidence bundle, release gate. | assurance/postruntime.py, assurance/replay.py, assurance/path_graph.py, assurance/evidence_bundle.py |

## Demo Verification

The [runtime effect demo](runtime-effect-demo.md) is the concrete verification surface for this model. It renders a stage × layer matrix in the final demo entrypoint and an action timeline in each container risk case audit page. The timeline connects agent intent/action, Invart observation, policy or mediation decision, outcome, and the artifact that proves the step.

Coverage terms remain strict: observed, mediated, and enforced are not interchangeable. Unmanaged direct execution is shown as a coverage gap unless it enters a managed launcher, wrapper, hook, broker, or shim.

## Source Layout

```bash
src/invart/core/       fact model, ledger, stable artifact helpers
src/invart/control/    runtime, policy, mediation, gate, review
src/invart/governance/ identity, profile, TeamRun, grants
src/invart/surfaces/   adapters, native hooks, MCP, scanner, enforcement
src/invart/assurance/  proof, replay, audit, coverage, evidence bundle
src/invart/evaluation/ benchmarks, demos, external evidence, RC gate
src/invart/commands/   CLI parser and command handlers
src/kappaski/          compatibility import path
tests/                 product-slice tests
benchmarks/            pinned fixtures and experiment cases
rust/invart-shim/      source-level Rust enforcement shim prototype
```
