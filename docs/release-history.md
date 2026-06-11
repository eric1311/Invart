# 0.9 pre-release boundary.

[HTML version](html/release-history.html)


Invart has a long local implementation history. The public docs summarize capability areas instead of publishing every internal version-design page.

This page is a reference, not the first-run learning path. Start with [Product Overview](product.md), [Quickstart](quickstart.md), or the [five-layer operator guide](five-layer-operator-guide.md).

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
| v0.9.5 | Implemented | Priority agent tracks for Claude Code, Codex, Gemini CLI, Cursor, OpenCode, OpenClaw, Hermes, cloud agents, and frameworks, with profile-derived product matrix rows and explicit vendor/import versus Invart-mediated control positions. |
| v0.9.6 | Implemented | Ledger-derived L1-L5 runtime operation workflow via `runtime layers`, exporting a stage x layer matrix, layer timeline, operator command guide, and linked proof/replay/path graph/coverage/audit/evidence artifacts. |
| v0.9.7 | Implemented | L5 evidence workspace and gate hardening via `evidence inspect`, verifying bundle hashes, required artifacts, layer workflow/adapter package links, and whether proof/audit evidence answers who, what, why, policy, approval, outcome, and coverage. |
| v0.9.8 | Implemented | Claude Code strict-live adapter: binary probing, missing-binary failure, pre-side-effect managed risk block, full adapter package, layer-runtime workflow, evidence workspace, and explicit degraded process-tree coverage when only portable subprocess supervision is active. |
| v0.9.9 | Implemented | Live adapter conformance contract v2: each real-agent row now records evidence level, control position, side-effect timing, required artifacts, claimable coverage, and a claim gate that rejects vendor/import/discovery evidence inflated into Invart-mediated or enforced coverage. |
| v0.9.10 | Implemented | OpenCode real adapter track: binary-backed managed wrapper run, plugin/MCP config inventory, L5 artifact export, benign autonomy preservation, and managed risk blocking before side effects without treating plugin-only inventory as mediation. |
| v0.9.11 | Implemented | Terminal-agent managed wrappers for Gemini CLI and Aider: binary-backed wrapper runs, Gemini MCP/config inventory, Aider config/repo-context inventory, artifact parity, and low approval-noise checks for benign workflows. |
| v0.9.12 | Implemented | Codex deep adapter boundary: Codex managed-wrapper runs remain Invart-mediated, while Codex-native sandbox, approval, network, and credential-boundary facts are imported as vendor-owned evidence and rejected if inflated into Invart enforcement. |
| v0.9.13 | Implemented | IDE extension bridge and inventory track for Cursor, Cline, and Roo: config/MCP/extension discovery is reported as a coverage gap, while explicit native bridge events preserve source metadata and can receive normalized decisions. |

## Internal History

Detailed historical roadmap and design pages live in internal/history/docs/. They are local-only planning material and are ignored by git for the open-source boundary.
