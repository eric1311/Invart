# Kappaski

Kappaski is a local-first Agent Runtime Control Plane.

Current architecture note: Kappaski is plugin-assisted and hook-aware, not
plugin-only. Native integrations for Claude Code, Codex, Gemini CLI, Cursor,
OpenCode, and similar agents should be used for early intent, UX, and
agent-specific context, while the daemon, ledger, wrappers, proxies, and native
shims remain the durable governance and enforcement layers. See
`docs/plugin-extension-architecture-review-2026-05.md`.

v0.1 is focused on an effective local closed loop: preflight, managed session,
invocation normalization, policy decision, taint tracking, approval evidence,
hash-chain ledger, proof export, and proof verification.

It is not yet a daemon-enforced enterprise control plane. The current release
builds the core evidence and verification path that later adapters, MCP proxying,
TeamRun, Blackboard, Handoff, and UI workflows can use.

## v0.1 Capability Scope

Kappaski v0.1 can:

- scan a target repo before launch and persist a preflight baseline;
- start and close a managed local session with a stable session id;
- run a command through a managed wrapper with `kappaski run`;
- normalize runtime events into `Invocation` records;
- attach source, trust, taint, correlation, capability grant, policy, resource, and evidence fields to invocations;
- evaluate shell, file, network, MCP, Skill, and content events with deterministic rules;
- track session-level taint after sensitive reads, suspicious content, high-risk commands, or suspicious outbound activity;
- record explicit policy decisions and approval evidence;
- write an append-only JSONL ledger with sequence numbers, previous hashes, and entry hashes;
- export a compact proof JSON report;
- verify a ledger, a proof summary, or a proof and ledger together.


## v0.2 Development Snapshot

The current tree also includes the first v0.2 implementation slice on top of the
frozen v0.1 foundation:

- semantic review records with `ReviewFinding` and `SemanticReview`;
- a local `HeuristicReviewer` used as a deterministic stand-in for a future LLM reviewer;
- merged `PolicyEvaluation` records with approval grades: `auto_approve`, `audit`, `require_human`, and `blocked`;
- review and policy modes via `--review off|auto|always|required` and `--policy-mode audit|advisory|managed|ci`;
- decision explanation with `kappaski policy explain`;
- semantic review inspection with `kappaski review invocation`;
- execution outcome records with `kappaski runtime outcome`;
- proof export and proof+ledger verification coverage for reviews, evaluations, and outcomes.

This is still local CLI/control-plane work. v0.2 does not yet include the daemon,
external LLM provider integration, or UI.

## v0.3 Development Snapshot

The current tree includes the first v0.3 local authority slice:

- file-backed runtime authority state under `.kappaski/daemon/state.json`;
- lock-protected session registry updates;
- session lifecycle commands for create, list, show, pause, resume, interrupt, stop, and delete;
- authority-mediated `record-event`, `approve`, `reject`, `outcome`, and `heartbeat`;
- registry metadata for latest invocation, decision, risk, effect, approval grade, pending approvals, heartbeat, and activity timestamps.

This is daemon-compatible infrastructure, not yet a resident network service. It
establishes the authority contract before introducing a long-running process.

## v0.4 Development Snapshot

The current tree now includes the v0.4 adapter and capability surface loop:

- pinned real public Skill/MCP/tool corpus snapshots under `benchmarks/corpora`;
- corpus scanning with source URL, upstream sha, content hash, license, and fetched date metadata;
- capability extraction for shell, file, network, git, MCP, messaging, payment, database, cloud, browser, and calendar surfaces;
- risk extraction for credential references, external writes, destructive actions, shell execution, external dependencies, unbounded filesystem access, and target deviation;
- deterministic capability grant ids derived from adapter, source id, kind, and content hash;
- authority-mediated `daemon register-capabilities`, which records scanned surfaces into a session ledger before runtime use;
- policy decisions and pending approvals for high-risk adapter/skill surfaces;
- proof export coverage for capability grants;
- a real-corpus benchmark that verifies scan, policy, approval, and proof behavior end to end.

This does not execute third-party code. v0.4 treats public Skill/MCP/tool assets as pinned documents for static analysis and grant decisions.

## v0.5 Development Snapshot

The current tree includes the first proof-consumption gate slice:

- `kappaski gate verify` consumes proof and ledger artifacts as pass/warn/fail decisions;
- gate modes: `audit`, `managed`, and `ci`;
- CI mode requires both proof and ledger so the hash chain can be recomputed;
- unresolved required approvals and high-risk capability grants fail managed/CI gates;
- gate reports are machine-readable JSON and can be written with `--out`;
- `kappaski eval benchmark --suite v0.5-proof-gate` validates clean, missing-approval, approved-capability, and tampered-proof cases.

## v0.6 Development Snapshot

The current tree includes a reference real-workflow adapter and CI demo slice:

- `kappaski adapter run` creates an authority session, optionally registers pinned capability corpus, runs a child command, closes the session, exports proof, and optionally runs a gate;
- wrapper artifacts are `ledger.jsonl`, `proof.json`, and `gate-report.json`;
- capability registration supports `off`, `audit`, and `managed` modes;
- `.github/workflows/kappaski-proof-gate.yml` shows how CI can verify proof plus ledger and upload artifacts;
- `kappaski eval benchmark --suite v0.6-adapter-workflow` validates pass and fail wrapper paths.


## v0.8-v0.14 Full Product Snapshot

Kappaski now treats v0.8-v0.14 as implemented local control-plane product capabilities: each version has runnable APIs/CLI, tests, benchmark coverage, documentation, and explicit product boundaries.

- v0.8: OpenAI-compatible LLM reviewer provider, deny explanations, folded raw-content evidence, deterministic reviewer-quality corpus, and optional live provider smoke.
- v0.9: SWE-Bench Lite-style compatibility runner, managed pause/approval/resume harness check, baseline/wrapped command-pair comparison, and optional official `swebench.harness.run_evaluation` wrapper.
- v0.10: Claude Code adapter profile, local wrapper/hook JSONL bridge, env key recording/redaction, real-binary environment check, and process-group supervision metadata.
- v0.11: TOML/JSON policy profile resolution, profile distribution bundle, runtime/gate/replay/enforce/daemon profile injection, approval restrictions, ledger-backed break-glass records, and administrator/auditor review.
- v0.12: ledger-backed multi-user TeamRun, agent identity, BlackboardEntry, Handoff, restrict-only grant delegation, TeamRun proof, multi-ledger aggregate proof, and HTML TeamRun timeline.
- v0.13: enforcement guard decisions for file-write, env/secrets, and network egress, Rust file-write shim, wrapper-level file-write interception, and generic `enforce run --domain ...` execution control. Kernel/OS-level interception is still an explicit boundary.
- v0.14: enterprise audit demo package for secret leak and unsafe deletion workflows, exporting ledger, proof, replay, audit JSON/HTML, plus ledger-backed security signoff.

Verification commands:

```bash
kappaski eval benchmark --suite v0.8-llm-reviewer
kappaski eval benchmark --suite v0.9-harness-compatibility
kappaski eval benchmark --suite v0.10-claude-adapter-profile
kappaski eval benchmark --suite v0.11-policy-profiles
kappaski eval benchmark --suite v0.12-teamrun-handoff
kappaski enforce shim-spec --domain file-write
kappaski enforce rust-build-check --skip-if-unavailable
kappaski enforce shim-decision --event '{"type":"shell","command":"rm -rf ."}'
kappaski enforce run-file-write --ledger ledger.jsonl --session ks_demo -- sh -c "touch safe.txt"
kappaski eval benchmark --suite v0.13-enforcement-guards
kappaski demo enterprise-audit --out-dir /tmp/kappaski-demo
kappaski demo signoff --ledger /tmp/kappaski-demo/ledger.jsonl --actor security-lead --status approved --reason reviewed
kappaski eval benchmark --suite v0.14-enterprise-audit-demo
kappaski eval benchmark --suite full-product-readiness
kappaski roadmap status
kappaski roadmap status --require-full
```

## v0.15-v0.18 Full Product Snapshot

Kappaski now includes the native integration and coverage plane as implemented local product capability:

- v0.15: native integration inventory plus conformance hashing and parse validation for discovered hook/plugin/config surfaces.
- v0.16: native hook/plugin event bridge plus response-shape conformance matrix for Claude Code, Codex, OpenCode, and generic adapters.
- v0.17: transparent-first MCP broker step plus line-oriented JSONL stdio broker transcript capture.
- v0.18: coverage-aware runtime records, proof summaries, replay labels, profile-driven gate failures, and coverage matrix HTML export.

Verification commands:

```bash
kappaski native inventory --target .
kappaski native conformance --target .
kappaski native install --target . --agent claude-code
kappaski bridge native --agent codex --event '{"tool":"shell","arguments":{"command":"rm -rf ."},"session_id":"demo"}'
kappaski bridge conformance
kappaski mcp broker-step --message '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
kappaski mcp broker-stdio --input in.jsonl --output out.jsonl --transcript transcript.jsonl
kappaski coverage html --proof proof.json --out coverage.html
kappaski eval benchmark --suite v0.15-native-integration-inventory
kappaski eval benchmark --suite v0.16-hook-plugin-bridge
kappaski eval benchmark --suite v0.17-mcp-broker
kappaski eval benchmark --suite v0.18-coverage-aware-runtime
```

## v0.19-v0.24 Pre-v1 Control Plane Snapshot

Kappaski now includes the pre-1.0 model-closure layer as implemented local product capability:

- v0.19: principal, agent identity, credential boundary, session accountability, and capability grants are ledger-backed and exported in proof.
- v0.20: ledger-derived execution path graph with JSON/HTML export and upstream/downstream queries.
- v0.21: path-aware deterministic policy for secret egress, CI/deploy mutation, and external-instruction-to-destructive-shell chains.
- v0.22: unified mediation request/decision/outcome contract with pause/resume, fail-open alert, and coverage-aware proof behavior.
- v0.23: enterprise profile registry, pinning, verification, raw-content display policy, and break-glass review readiness.
- v0.24: repeatable pre-v1 benchmark and enterprise demo package producing ledger, proof, replay, path graph, coverage report, and audit report.

Verification commands:

```bash
kappaski identity declare --principal alice@example.com --out identity.json
kappaski graph export --ledger ledger.jsonl --out path-graph.json
kappaski graph html --ledger ledger.jsonl --out path-graph.html
kappaski policy check-path --ledger ledger.jsonl --out path-policy.json
kappaski mediation inspect --ledger ledger.jsonl
kappaski profile registry --owner security --profile '{"scope":"repo","name":"repo","mode":"managed"}'
kappaski demo pre-v1-control-plane --out-dir /tmp/kappaski-pre-v1
kappaski eval benchmark --suite v0.19-identity-principal-binding
kappaski eval benchmark --suite v0.20-path-graph
kappaski eval benchmark --suite v0.21-path-aware-policy
kappaski eval benchmark --suite v0.22-unified-mediation
kappaski eval benchmark --suite v0.23-enterprise-policy-governance
kappaski eval benchmark --suite pre-v1-control-plane
kappaski roadmap status --require-full
```

## v0.7 Development Snapshot

The current tree includes approval resolution and runtime replay:

- `kappaski approval list` shows missing, approved, rejected, blocked, and not-required approval items from a ledger;
- `kappaski approval approve --all` resolves all missing approvals, requires a reason, and writes one approval evidence event per decision;
- `kappaski replay export` writes a static HTML runtime replay with timeline, approvals, gate findings, folded raw proof JSON, and optional real case context;
- pinned SWE-Bench Lite metadata lives under `benchmarks/cases/swe-bench-lite`;
- `kappaski eval benchmark --suite v0.7-approval-replay` validates fail -> approve -> proof -> gate pass -> replay.


## Current Product Decisions

- Gate does not require a closed session by default. Enterprise workflows should be able to evaluate staged proof while a run is active to avoid partial blind periods. A future `--require-closed-session` option can exist as an explicit strict control, but it is not the CI default.
- v0.7 allows `approval approve --all` as the most open operating mode, with a required reason and one approval evidence record per decision.
- Replay should include command/path/url details and may include raw content in collapsed sections; stricter redaction modes can be added later.
- Real-case validation uses pinned SWE-Bench Lite / Verified metadata first. v0.9 adds the local harness compatibility report model; optional full Docker/harness execution remains a heavier future validation path.

## What Current Local Releases Are Not

v0.1 does not yet provide:

- a resident local daemon as the only ledger writer;
- OS-level sandboxing, process tracing, file-system hooks, or network egress control;
- a full MCP proxy implementation;
- multi-agent TeamRun, Blackboard, or Handoff UI;
- a central policy server or enterprise dashboard;
- content-level DLP or complete secret detection.

The security claim is therefore audit-and-attest for managed flows, not complete
prevention of bypass. If an agent runs outside Kappaski, v0.1 cannot observe that
behavior.

## Install

```bash
python3 -m pip install -e .
```

For local development, tests use the `src` package layout configured in
`pyproject.toml`.

## Usage Manual

For a first-time product briefing, start here:

- [docs/kappaski-new-user-briefing.html](docs/kappaski-new-user-briefing.html)
- [docs/code-design-and-development-standards.html](docs/code-design-and-development-standards.html)
- [docs/enterprise-unregistered-agent-coverage-roadmap.html](docs/enterprise-unregistered-agent-coverage-roadmap.html)

For a command-by-command guide, tutorial, and recipes, see:

- [docs/user-guide.html](docs/user-guide.html)
- [docs/user-guide.md](docs/user-guide.md)

## Quick Start

Create and save a preflight baseline:

```bash
kappaski pre-runtime --target . --save --preflight .kappaski/preflight.json
```

Start a managed session:

```bash
kappaski session start \
  --target . \
  --agent codex \
  --goal "Demonstrate local proof generation" \
  --preflight .kappaski/preflight.json
```

Record runtime events into the session ledger:

```bash
kappaski runtime record-event \
  --session "$KAPPASKI_SESSION_ID" \
  --ledger "$KAPPASKI_LEDGER" \
  --event '{"type":"file_read","path":"/repo/.env","agent":"codex"}'

kappaski runtime record-event \
  --session "$KAPPASKI_SESSION_ID" \
  --ledger "$KAPPASKI_LEDGER" \
  --event '{"type":"network","url":"https://webhook.site/example","agent":"codex"}'
```

Close the session and export proof:

```bash
kappaski session close --ledger "$KAPPASKI_LEDGER"

kappaski proof export \
  --ledger "$KAPPASKI_LEDGER" \
  --out .kappaski/proof.json
```

Verify both proof and ledger:

```bash
kappaski proof verify \
  --proof .kappaski/proof.json \
  --ledger "$KAPPASKI_LEDGER"
```

## Managed Run Shortcut

For simple command wrapping:

```bash
kappaski run \
  --target . \
  --agent codex \
  --goal "Run under Kappaski" \
  -- codex
```

This is an alias for `kappaski session run`: it starts a session, sets
`KAPPASKI_SESSION_ID` and `KAPPASKI_LEDGER` in the child environment, runs the
child command, and records a session end event when the child exits.

## Core Commands

```text
kappaski daemon init --target .
kappaski daemon session create --target . --agent codex --goal "..."
kappaski daemon record-event --target . --session <id> --event '<json>'
kappaski daemon register-capabilities --target . --session <id> --corpus-root benchmarks/corpora --adapter codex-wrapper
kappaski daemon session pause|resume|interrupt|stop --target . --session <id>

kappaski pre-runtime --target . [--save --preflight .kappaski/preflight.json]

kappaski session start --target . --agent codex --goal "..."
kappaski session run --target . --agent codex --goal "..." -- <command>
kappaski session close --ledger <ledger.jsonl>
kappaski run --target . --agent codex --goal "..." -- <command>

kappaski runtime analyze-event --session <id> --event '<json>'
kappaski runtime record-event --session <id> --ledger <ledger.jsonl> --event '<json>'
kappaski runtime shell --session <id> --ledger <ledger.jsonl> -- <command>
kappaski runtime approve --ledger <ledger.jsonl> --decision <id> --approver <name> --reason "..."
kappaski runtime reject --ledger <ledger.jsonl> --decision <id> --approver <name> --reason "..."
kappaski runtime outcome --ledger <ledger.jsonl> --decision <id> --status executed|blocked|skipped|overridden|failed

kappaski policy explain --ledger <ledger.jsonl> --decision <id>
kappaski review invocation --ledger <ledger.jsonl> --invocation <id>
kappaski eval benchmark --suite v0.2-semantic
kappaski corpus scan --root benchmarks/corpora
kappaski eval benchmark --suite v0.4-real-skill-surface
kappaski gate verify --proof proof.json --ledger ledger.jsonl --mode ci
kappaski eval benchmark --suite v0.5-proof-gate
kappaski adapter run --target . --agent codex --goal "..." --out-dir .kappaski/demo --capabilities audit --gate ci -- <command>
kappaski eval benchmark --suite v0.6-adapter-workflow
kappaski approval list --ledger ledger.jsonl --status missing
kappaski approval approve --ledger ledger.jsonl --all --approver <name> --reason "..."
kappaski replay export --ledger ledger.jsonl --out replay.html
kappaski eval benchmark --suite v0.7-approval-replay

kappaski proof export --ledger <ledger.jsonl> --out proof.json
kappaski proof verify --ledger <ledger.jsonl>
kappaski proof verify --proof proof.json
kappaski proof verify --proof proof.json --ledger <ledger.jsonl>
```

## Invocation And Taint Model

`Invocation` is the canonical runtime object. `RuntimeEvent` remains as a loose
CLI input format, but managed runtime records are normalized before policy and
ledger writing.

Each invocation can carry:

- session and sequence identity;
- actor and adapter;
- operation and resource references;
- source and trust level;
- input and output references;
- taint tags;
- correlation id;
- capability grant id;
- policy version;
- evidence references.

Taint does not automatically mean "stop everything." It records that sensitive
or untrusted context has entered the session. Policy uses taint to elevate later
write-like, outbound, MCP, Git, or shell actions. The ledger keeps findings,
taint, policy decisions, approval evidence, and execution outcomes separate.

## Proof Verification Modes

Kappaski supports three verification modes:

- `--ledger`: recomputes the JSONL hash chain from the raw evidence ledger.
- `--proof`: checks proof structure and embedded summary fields only. This is convenient but weaker because the ledger root cannot be recomputed.
- `--proof --ledger`: recommended trusted path. It verifies the ledger and checks that proof summary fields match ledger-derived facts.

## Project Documentation

Start with the documentation index and concept document:

- [`docs/index.html`](docs/index.html): HTML documentation index and reading order.
- [`docs/README.md`](docs/README.md): Markdown compatibility index.
- [`docs/concepts-glossary.html`](docs/concepts-glossary.html): Chinese glossary for product terms, architecture vocabulary, roadmap language, and common confusions.
- [`docs/concepts-and-closed-loop-v0.1.md`](docs/concepts-and-closed-loop-v0.1.md)

Supporting design notes:

- [`docs/architecture.html`](docs/architecture.html): code architecture, runtime dataflow, data models, and trust boundaries.
- [`docs/code-design-and-development-standards.html`](docs/code-design-and-development-standards.html): code design, maintainability rules, module boundaries, TDD completion definition, and refactor route.
- [`docs/enterprise-unregistered-agent-coverage-roadmap.html`](docs/enterprise-unregistered-agent-coverage-roadmap.html): enterprise discovery and coverage roadmap for agents that bypass daemon registration.
- [`docs/agent-control-plane-model-and-paper-direction.md`](docs/agent-control-plane-model-and-paper-direction.md): five-layer Agent Control Plane model, pre/runtime/post lifecycle, and paper direction.
- [`docs/industry-research-and-comparison.md`](docs/industry-research-and-comparison.md): academic and industry research comparison for agent governance, observability, guardrails, and assurance.
- [`docs/product-decisions.html`](docs/product-decisions.html): accepted product decisions and version boundaries.
- [`docs/roadmap.html`](docs/roadmap.html): roadmap from v0.1 through v0.40, distinguishing local product capability, local experiment substrate, and external-validation contracts.
- [`docs/full-product-readiness.html`](docs/full-product-readiness.html): per-version local-product commands, tests, and boundaries.
- [`docs/implementation-audit-v0.1-v0.39.html`](docs/implementation-audit-v0.1-v0.39.html): truthfulness audit separating local product capability, experiment substrate, external-validation contracts, and optional external validation gaps.
- [`docs/roadmap-coverage.html`](docs/roadmap-coverage.html): strict implementation coverage matrix and explicit product boundaries.
- [`docs/v0.2-semantic-decision-engine.html`](docs/v0.2-semantic-decision-engine.html): v0.2 reviewer and policy merger design.
- [`docs/v0.3-runtime-authority-daemon.html`](docs/v0.3-runtime-authority-daemon.html): v0.3 runtime authority and session registry design.
- [`docs/v0.4-adapter-capability-surface.html`](docs/v0.4-adapter-capability-surface.html): v0.4 real-corpus capability surface design.
- [`docs/v0.5-proof-gate.html`](docs/v0.5-proof-gate.html): v0.5 proof consumption and CI gate design.
- [`docs/v0.6-real-workflow-demo.html`](docs/v0.6-real-workflow-demo.html): v0.6 reference adapter wrapper and CI workflow demo.
- [`docs/v0.7-approval-replay.html`](docs/v0.7-approval-replay.html): v0.7 approval inbox, replay export, and real case fixture design.
- [`docs/v0.8-llm-reviewer.html`](docs/v0.8-llm-reviewer.html): v0.8 OpenAI-compatible LLM reviewer.
- [`docs/v0.9-harness-compatibility.html`](docs/v0.9-harness-compatibility.html): v0.9 SWE-Bench Lite harness compatibility target.
- [`docs/v0.10-claude-adapter-profile.html`](docs/v0.10-claude-adapter-profile.html): v0.10 Claude Code adapter hardening.
- [`docs/v0.11-policy-profiles.html`](docs/v0.11-policy-profiles.html): v0.11 TOML/JSON policy profiles.
- [`docs/v0.12-teamrun-handoff.html`](docs/v0.12-teamrun-handoff.html): v0.12 TeamRun and Handoff records.
- [`docs/v0.13-enforcement-guards.html`](docs/v0.13-enforcement-guards.html): v0.13 enforcement guard plan and local checks.
- [`docs/v0.14-enterprise-audit-demo.html`](docs/v0.14-enterprise-audit-demo.html): v0.14 enterprise audit demo package.
- [`docs/v0.15-native-integration-inventory.html`](docs/v0.15-native-integration-inventory.html): v0.15 native integration inventory.
- [`docs/v0.16-hook-plugin-bridge.html`](docs/v0.16-hook-plugin-bridge.html): v0.16 hook/plugin bridge.
- [`docs/v0.17-mcp-broker.html`](docs/v0.17-mcp-broker.html): v0.17 transparent MCP broker.
- [`docs/v0.18-coverage-aware-runtime.html`](docs/v0.18-coverage-aware-runtime.html): v0.18 coverage-aware runtime.
- [`docs/v0.19-identity-principal-binding.html`](docs/v0.19-identity-principal-binding.html): v0.19 identity and principal binding.
- [`docs/v0.20-ledger-execution-graph.html`](docs/v0.20-ledger-execution-graph.html): v0.20 ledger-derived execution path graph.
- [`docs/v0.21-path-aware-policy.html`](docs/v0.21-path-aware-policy.html): v0.21 path-aware policy.
- [`docs/v0.22-unified-mediation.html`](docs/v0.22-unified-mediation.html): v0.22 unified mediation contract.
- [`docs/v0.23-enterprise-policy-governance.html`](docs/v0.23-enterprise-policy-governance.html): v0.23 enterprise policy governance.
- [`docs/v0.24-pre-v1-control-plane.html`](docs/v0.24-pre-v1-control-plane.html): v0.24 pre-v1 evaluation and demo package.
- [`docs/v0.25-adapter-runtime-integration.html`](docs/v0.25-adapter-runtime-integration.html): v0.25 adapter runtime integration.
- [`docs/v0.26-policy-as-code.html`](docs/v0.26-policy-as-code.html): v0.26 policy-as-code.
- [`docs/v0.27-enterprise-evidence-export.html`](docs/v0.27-enterprise-evidence-export.html): v0.27 enterprise evidence export.
- [`docs/v0.28-benchmark-harness-expansion.html`](docs/v0.28-benchmark-harness-expansion.html): v0.28 benchmark harness expansion.
- [`docs/v0.29-release-candidate-gate.html`](docs/v0.29-release-candidate-gate.html): v0.29 release-candidate gate.
- [`docs/v0.30-experiment-case-runner.html`](docs/v0.30-experiment-case-runner.html): v0.30 ExperimentCase runner.
- [`docs/v0.31-external-ipi-control-plane.html`](docs/v0.31-external-ipi-control-plane.html): v0.31 AgentDojo/AgentDyn-shaped local IPI experiments.
- [`docs/v0.32-authority-dataflow-boundary.html`](docs/v0.32-authority-dataflow-boundary.html): v0.32 AgentSecBench-shaped authority/data-flow boundary experiments.
- [`docs/v0.33-swebench-friction-track.html`](docs/v0.33-swebench-friction-track.html): v0.33 SWE-bench-like friction track; official heavy validation is separate.
- [`docs/v0.34-skill-supply-chain-track.html`](docs/v0.34-skill-supply-chain-track.html): v0.34 SKILL-INJECT-shaped supply-chain track.
- [`docs/v0.35-secure-coding-gate.html`](docs/v0.35-secure-coding-gate.html): v0.35 secure coding gate.
- [`docs/v0.36-coverage-truthfulness-matrix.html`](docs/v0.36-coverage-truthfulness-matrix.html): v0.36 coverage truthfulness matrix.
- [`docs/v0.37-llm-reviewer-selectivity.html`](docs/v0.37-llm-reviewer-selectivity.html): v0.37 LLM reviewer selectivity.
- [`docs/v0.38-audit-tamper-assurance.html`](docs/v0.38-audit-tamper-assurance.html): v0.38 audit tamper assurance.
- [`docs/v0.39-paper-ready-experiment-suite.html`](docs/v0.39-paper-ready-experiment-suite.html): v0.39 paper-ready experiment suite.
- [`docs/v0.40-swe-bench-full-validation-contract.html`](docs/v0.40-swe-bench-full-validation-contract.html): v0.40 full SWE-Bench validation contract.
- [`docs/paper-experiment-protocol.html`](docs/paper-experiment-protocol.html): reproducible experiment protocol.
- [`docs/enterprise-value-loops.md`](docs/enterprise-value-loops.md): candidate enterprise demo and value loops.
- [`docs/evaluation-and-benchmarks.html`](docs/evaluation-and-benchmarks.html): benchmark and product-effectiveness validation plan.
- [`docs/benchmark-research-and-experiment-mapping.html`](docs/benchmark-research-and-experiment-mapping.html): public benchmark research map and v0.30-v0.39 local experiment route, with external validation called out separately.
- [`docs/benchmark-research-and-experiment-mapping.md`](docs/benchmark-research-and-experiment-mapping.md): full Markdown research note behind the HTML route.
- [`docs/design-review.md`](docs/design-review.md): MVP review and architecture direction.
- [`docs/dev-plan-v0.1.md`](docs/dev-plan-v0.1.md): minimal v0.1 proof-generator implementation plan.
- [`docs/proof-workflow-v0.1.md`](docs/proof-workflow-v0.1.md): proof workflow and CLI shape.
- [`docs/security-v0.1.md`](docs/security-v0.1.md): threat model and security boundary.
- [`docs/adapters.md`](docs/adapters.md): runtime adapter direction.

## Development

Run tests:

```bash
python3 -m pytest -q
PYTHONPATH=src python3 -m kappaski.cli release-candidate verify --out-dir .kappaski/rc
```

Run the local product suite in a container:

```bash
scripts/container-test.sh local
```

This builds `Dockerfile.test`, mounts the current checkout, and runs pytest,
the v0.40 contract benchmark, full-product readiness, roadmap full status, and
the RC gate. If Docker Hub cannot be reached, the script can fall back to an
already-pulled SWE-Bench image when it is available locally.

Run the optional heavy full SWE-Bench path in the same containerized style:

```bash
scripts/container-test.sh swe-bench-full gold kappaski_full_20260601 .kappaski/swe-bench-full
```

That command is external validation evidence only after the upstream SWE-Bench
run completes and produces the full 2294-instance report bundle.
