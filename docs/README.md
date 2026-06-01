# Kappaski Documentation Index

HTML-first entry: [`index.html`](index.html)

Date: 2026-05-26
Status: canonical docs index

## Current Product Spine

Read these first. They represent the current agreed direction.

1. [`kappaski-new-user-briefing.html`](kappaski-new-user-briefing.html)
   - The single best document for a first-time user.
   - Explains Kappaski's goal, identity, value, usage, trajectory evidence,
     validation state, expected benefits, and honest boundaries.

2. [`concepts-glossary.html`](concepts-glossary.html)
   - Chinese concept and terminology guide.
   - Explains product vocabulary, architecture terms, roadmap language, and common confusions.
   - Cross-links architecture, roadmap, product decisions, evaluation, and version docs.

3. [`product-decisions.html`](product-decisions.html)
   - Product identity: Kappaski is an AI Coding Agent runtime control plane.
   - Version boundaries and accepted decisions.
   - Policy modes, LLM reviewer boundary, proof/ledger relationship, daemon direction.

4. [`roadmap.html`](roadmap.html)
   - Version roadmap from frozen v0.1 through implemented v0.40.
   - v0.30-v0.39 experiment code route is implemented as local experiment substrate.
   - v0.40 adds the full SWE-Bench external-validation contract.
   - Current local implementation status and external-validation boundaries.
   - Product boundaries by version.

5. [`full-product-readiness.html`](full-product-readiness.html)
   - Per-version local implementation readiness for v0.8-v0.40.
   - Commands, tests, benchmark coverage, and honest boundaries.

6. [`implementation-audit-v0.1-v0.39.html`](implementation-audit-v0.1-v0.39.html)
   - Truthfulness audit separating local product capability, local experiment substrate, and optional external/live benchmark validation.

7. [`code-design-and-development-standards.html`](code-design-and-development-standards.html)
   - Code design, maintainability rules, module boundaries, TDD completion definition, and refactor route.
   - Current engineering structure: `cli.py` and `evals.py` are compatibility façades; command handlers and argparse registration live in `src/kappaski/commands/`, benchmark runners live in version/product slices under `src/kappaski/benchmarks/`, portable artifact writing lives in `src/kappaski/artifacts.py`, and product tests are split by runtime/governance/integration/policy/demo boundaries.

8. [`enterprise-unregistered-agent-coverage-roadmap.html`](enterprise-unregistered-agent-coverage-roadmap.html)
   - Enterprise discovery and coverage model for agents that bypass daemon registration.

9. [`concepts-and-closed-loop-v0.1.md`](concepts-and-closed-loop-v0.1.md)
   - Core vocabulary: Invocation, taint, decision, approval, outcome, proof, ledger.
   - Explains why Kappaski is a closed loop rather than a session proof generator.

10. [`evaluation-and-benchmarks.html`](evaluation-and-benchmarks.html)
   - How to validate correctness and product effectiveness.
   - Built-in benchmark suite.
   - External benchmark candidates and how they map to Kappaski.

11. [`benchmark-research-and-experiment-mapping.html`](benchmark-research-and-experiment-mapping.html)
   - Detailed benchmark landscape.
   - Problem-by-problem mapping from external benchmark scope to Kappaski
     experiments, metrics, and paper framing.
   - v0.30-v0.39 code route from external corpora to experiment runner,
     corpus adapters, metrics, and paper-ready reports.
   - Full Markdown research note:
     [`benchmark-research-and-experiment-mapping.md`](benchmark-research-and-experiment-mapping.md).

12. [`v0.40-swe-bench-full-validation-contract.html`](v0.40-swe-bench-full-validation-contract.html)
   - Full SWE-Bench validation contract.
   - Separates development contract tests from the real upstream full benchmark run.
   - Documents `external-validation swe-bench-full`.

13. [`plugin-extension-architecture-review-2026-05.html`](plugin-extension-architecture-review-2026-05.html)
   - 2026-05 recheck of Claude Code, Codex, Gemini CLI, Cursor, OpenCode,
     OpenClaw, and Hermes plugin/hook/extension/MCP surfaces.
   - Corrects the architecture wording to plugin-assisted, hook-aware,
     daemon-owned, and enforcement-backed.

14. [`agent-control-plane-model-and-paper-direction.md`](agent-control-plane-model-and-paper-direction.md)
   - Five-layer Agent Control Plane model.
   - Pre-runtime / runtime / post-runtime lifecycle.
   - Coverage, trust-boundary, cost/friction, and paper direction.

15. [`industry-research-and-comparison.md`](industry-research-and-comparison.md)
   - Academic and industry research map.
   - Comparison with observability, guardrails, workflow runtimes, enterprise
     governance toolkits, benchmarks, and protocol surfaces.

## Version Design Docs

Use these when working on a specific release scope.

- [`v0.2-semantic-decision-engine.md`](v0.2-semantic-decision-engine.md)
  - v0.2 semantic reviewer, policy merger, approval grading, LLM reviewer contract.

- [`v0.3-runtime-authority-daemon.md`](v0.3-runtime-authority-daemon.md)
  - v0.3 runtime authority, session registry, state transitions, and daemon-compatible CLI.

- [`v0.4-adapter-capability-surface.html`](v0.4-adapter-capability-surface.html)
  - v0.4 real-corpus Skill/tool/MCP capability surface scanning and validation.

- [`proof-workflow-v0.1.md`](proof-workflow-v0.1.md)
  - v0.1 proof export and verification workflow.

- [`security-v0.1.md`](security-v0.1.md)
  - v0.1 security boundary and threat model.

- [`adapters.md`](adapters.md)
  - Runtime adapter direction.

## Product Exploration And Future Work

These are important, but less canonical than the product spine.

- [`enterprise-value-loops.md`](enterprise-value-loops.md)
  - Candidate enterprise demos and value loops.

- [`design-review.md`](design-review.md)
  - Earlier MVP/design review.

- [`dev-plan-v0.1.md`](dev-plan-v0.1.md)
  - Earlier v0.1 implementation plan.

## Historical / Generated Artifacts

- [`kappaski-v0.1-prototype-design.html`](kappaski-v0.1-prototype-design.html)
  - Historical prototype design artifact.

## Current Position

- v0.1 is frozen as the local closed-loop proof foundation.
- v0.2-v0.7 are part of the current local closed-loop product baseline.
- v0.8-v0.29 are `implemented` for the local control-plane product scope.
- v0.30-v0.39 are `implemented` for the local experiment-substrate scope; upstream/live benchmark validation is separate and currently optional.
- v0.40 is `implemented` for the full SWE-Bench validation contract; it does not claim the full upstream run has already completed.
- `kappaski roadmap status --require-full` is expected to pass.
- `kappaski roadmap status --require-external-validation` is expected to fail until optional external benchmark runs are executed and recorded.
- The current codebase has completed the P1/P2/P3 refactor tracked in `code-design-and-development-standards.html`: CLI split, parser-family split, benchmark façade and runner split, `test_core.py` product-slice split, and unified JSON/HTML artifact writer helper.

- [`v0.6-real-workflow-demo.html`](v0.6-real-workflow-demo.html): reference adapter wrapper and CI artifact flow.

8. [`v0.8-llm-reviewer.html`](v0.8-llm-reviewer.html) through [`v0.14-enterprise-audit-demo.html`](v0.14-enterprise-audit-demo.html)
   - Implemented full-product local surfaces for LLM review, harness compatibility, Claude adapter profile, policy profiles, TeamRun/Handoff, enforcement guards, and enterprise audit.

9. [`roadmap-coverage.html`](roadmap-coverage.html)
   - Strict coverage matrix for implemented, partial, and planned roadmap capabilities.

10. [`v0.15-native-integration-inventory.html`](v0.15-native-integration-inventory.html) through [`v0.18-coverage-aware-runtime.html`](v0.18-coverage-aware-runtime.html)
   - Implemented native integration inventory/conformance, hook/plugin bridge conformance,
     transparent MCP broker/stdin transcript capture, and coverage-aware proof/replay/gate/report behavior.

11. [`v0.19-identity-principal-binding.html`](v0.19-identity-principal-binding.html) through [`v0.24-pre-v1-control-plane.html`](v0.24-pre-v1-control-plane.html)
   - Implemented identity binding, ledger-derived execution graph, path-aware policy, unified mediation, enterprise profile governance, and pre-v1 demo/evaluation package.

12. [`v0.25-adapter-runtime-integration.html`](v0.25-adapter-runtime-integration.html) through [`v0.29-release-candidate-gate.html`](v0.29-release-candidate-gate.html)
   - Implemented adapter runtime package closure, policy-as-code, enterprise evidence export, benchmark harness expansion, and local 1.0 release-candidate gate.

13. [`v0.30-experiment-case-runner.html`](v0.30-experiment-case-runner.html) through [`v0.39-paper-ready-experiment-suite.html`](v0.39-paper-ready-experiment-suite.html)
   - Implemented local benchmark-derived LLM agent experiment infrastructure: ExperimentCase runner, AgentDojo/AgentDyn-shaped IPI cases, AgentSecBench-shaped authority/data-flow cases, SWE-bench-like friction, SKILL-INJECT-shaped supply-chain, secure-code gate, coverage truthfulness, LLM reviewer selectivity, audit tamper assurance, and paper-ready E0-E6 bundle. These are not claims that official upstream benchmark suites have been run.

14. [`v0.40-swe-bench-full-validation-contract.html`](v0.40-swe-bench-full-validation-contract.html)
   - Implemented full SWE-Bench validation contract: all-data report checks, official artifact-shape compatibility, and subset-evidence rejection.
