# 0.9 pre-release boundary.

[HTML version](html/release-history.html)


Invart has a long local implementation history. The public docs summarize capability areas instead of publishing every internal version-design page.

| Track | Capability Area |
| --- | --- |
| Foundation | Managed sessions, runtime event normalization, deterministic rules, ledger, proof, proof verification. |
| Runtime authority | Session registry, daemon-compatible state, approval and outcome records. |
| Integrations | Adapter runtime, Claude-style profile, native inventory, hook/plugin bridge, MCP broker, launcher migration. |
| Policy and governance | Identity binding, profile precedence, policy-as-code, path-aware policy, raw-content display control, break-glass facts. |
| Evidence | Replay, path graph, coverage report, evidence bundle, audit HTML/JSON, release-candidate gate. |
| Evaluation | Full-product readiness, real-world-risk demo, containerized demo, experiment cases, optional external benchmark evidence contracts. |
| Research readiness | Paper evidence tables, coverage mediation pilot, audit reconstruction study, reviewer ablation/cost, product-control matrix, research-ready gate. |

## Pre-1.0 Research-Ready Track

| Version | Status | Focus |
| --- | --- | --- |
| v0.46 | Implemented | Paper evidence table export from LLM/agent workflow artifacts. |
| v0.47 | Implemented | Coverage mediation pilot that prevents observed/mediated/enforced label inflation. |
| v0.48 | Implemented | Audit reconstruction study with tamper and mismatch scenarios. |
| v0.49 | Implemented | LLM reviewer ablation, estimated cost, redaction, and deterministic non-downgrade checks. |
| v0.50 | Implemented | Product control matrix showing why plugin-only coverage is not full runtime mediation. |
| v0.51 | Implemented | Separate research-ready gate layered on top of product RC readiness. |

## 0.9 Patch Track

| Version | Status | Focus |
| --- | --- | --- |
| v0.9.3 | Implemented | Agent adapter contract registry and fixture-backed real-agent conformance foundation. The live mode can be strict, but missing local agent binaries are not reported as successful live validation. |
| v0.9.4 | Implemented | Claude Code reference full adapter: hook events and child command mediation, managed risk pause/block before launch, full L5 evidence package, and truthful degraded process-tree coverage when only portable subprocess supervision is active. |

## Internal History

Detailed historical roadmap and design pages live in internal/history/docs/. They are local-only planning material and are ignored by git for the open-source boundary.
