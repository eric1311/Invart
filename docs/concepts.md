# Core concepts reference

[HTML version](html/concepts.html)

This page is a glossary-style compatibility reference. If you are learning Invart for the first time, start with [Product Overview](product.md), then use the [five-layer operator guide](five-layer-operator-guide.md) for command-level usage.

| Concept | Meaning | Where to use it |
| --- | --- | --- |
| Session | A bounded agent run with target, goal, agent identity, principal, and ledger. | [Quickstart](quickstart.md) |
| Invocation | A normalized runtime action such as shell, file, network, MCP, skill, or content activity. | [Five-layer operator guide](five-layer-operator-guide.md) |
| Ledger | The append-only fact source. Proof, replay, graph, audit, and gates derive from it. | [Product Overview](product.md) |
| Proof | A portable summary of the run. It should answer who, what, why, policy, approval, outcome, and coverage. | [API & SDK](api-sdk.md) |
| Mediation | The decision contract for allow, audit, require approval, deny, enforced block, and fail-open alert. | [Five-layer operator guide](five-layer-operator-guide.md) |
| Coverage | The strength of observation or control: declared, observed, mediated, enforced, or fail-open. | [Evaluation](evaluation.md) |
| Path graph | A ledger-derived graph connecting identity, grant, invocation, resource, taint, decision, approval, outcome, and artifact. | [Runtime effect demo](runtime-effect-demo.md) |
| Evidence bundle | A verifiable package containing manifest hashes, proof, replay, graph, coverage, audit JSON/HTML, and policy summary. | [API & SDK](api-sdk.md) |

For internal module boundaries, use [Architecture](architecture.md).
