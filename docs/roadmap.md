# Kappaski Roadmap

Date: 2026-05-28
Status: full-product local control-plane roadmap through v0.40

## v0.1: Local Closed-Loop Proof Foundation

Status: frozen.

Scope:

- preflight persistence;
- managed local session;
- Invocation envelope;
- deterministic policy decisions;
- taint tracking;
- approval evidence;
- hash-chain ledger;
- proof export;
- proof+ledger verification;
- CLI workflow.

## v0.2: Semantic Decision Engine

Status: implemented product baseline; later reviewer/provider work is covered by v0.8.

Goal: reduce approval noise and catch semantic risk that regex rules cannot see.

Implemented:

- `ReviewFinding`, `SemanticReview`, and `PolicyEvaluation` models;
- reviewer interface semantics through a local heuristic reviewer;
- policy merger;
- approval grading;
- review and policy mode CLI flags;
- policy explanation and review inspection commands;
- append-only execution outcome records;
- proof export/verification coverage for reviews, evaluations, and outcomes.

Remaining scope:

- production LLM provider integrations;
- larger benchmark corpus and real-world golden traces;
- richer decision trace summaries in proof;
- more complete Skill and external-instruction semantic checks.

Evaluation track:

- expand the built-in `v0.2-semantic` suite;
- map AgentDyn, ShadowBench, and ARA Eval cases into Kappaski outcome expectations;
- report safety and usability metrics together: block recall, gate recall, auto-approval rate, approval noise, proof completeness, and redaction safety.

Non-goals:

- full daemon;
- UI;
- MCP proxy;
- OS-level enforcement.

## v0.3: Runtime Authority And Session Registry

Status: implemented product baseline.

Goal: move from CLI-only writes toward a runtime authority that can support
multiple agents, multiple users, and adapter-driven workflows.

Scope:

- daemon-compatible local authority layer;
- session registry;
- lock-protected authority writes;
- lifecycle states: active, paused, interrupted, stopped, deleted;
- approval state tracking;
- policy-facing record-event API;
- wrapper coordination hooks;
- heartbeat and activity metadata;
- resident daemon process later, after the authority contract stabilizes.

## v0.4: Adapter And Skill-Centric Runtime Integrations

Goal: connect real agent workflows without over-investing in MCP first.

Scope:

- Codex wrapper adapter;
- Claude Code wrapper/hook adapter where available;
- Cursor wrapper/config adapter;
- Skill load and Skill instruction review;
- capability grants for Skills and shell operations.

MCP proxy remains optional and opportunistic.

## v0.5: TeamRun And Handoff Data Model

Goal: model multi-agent work without UI dependency.

Scope:

- TeamRun schema;
- BlackboardEntry schema;
- HandoffContract schema;
- restrict-only grant delegation;
- taint inheritance across handoff;
- CLI commands to create and inspect these records.

## v0.6: PR And CI Consumption

Goal: make proof useful in team workflows.

Scope:

- CI policy gates;
- proof verification profiles;
- PR summary output;
- missing approval checks;
- tainted outbound checks;
- decision trace summaries.

## v0.7+: UI And Stronger Enforcement

Goal: turn ledger-backed workflows into a user-facing control plane.

Scope candidates:

- Team Runs dashboard;
- approvals inbox;
- replay timeline;
- policy editor;
- Rust/Go enforcement shims;
- file/network/process supervision expansion.


## v0.6: Real Workflow Adapter + CI Demo

Status: implemented product baseline.

Implemented:

- reference `kappaski adapter run` wrapper;
- artifact emission for `ledger.jsonl`, `proof.json`, and `gate-report.json`;
- GitHub Actions proof gate template;
- `v0.6-adapter-workflow` benchmark for pass and fail paths.


## Current Planning Decisions

- Gate does not require a closed session by default because enterprise users need staged visibility to reduce partial blind risk.
- `--require-closed-session` can remain as an optional strict control, but should not be assumed for CI.
- v0.7 approval bulk resolution is allowed in the open mode, requires a reason, and records one approval event per decision.
- Replay should include command/path/url and can include folded raw content, with stricter redaction later.
- v0.7 real-case tests should use pinned SWE-Bench Lite / Verified metadata first; full benchmark framework execution should be optional.


## v0.8-v0.14 Detailed Planning Decisions

### v0.8 LLM Reviewer Provider

Accepted decisions:

- First provider surface is OpenAI-compatible only.
- LLM reviewer may output `deny`, not only `require_approval` or risk upgrades.
- LLM denial must include explanatory fields suitable for proof and audit consumption.
- Reviewer input may include `raw_content`, but replay/audit display must support folded views, maximum-length truncation, and content summaries.
- Future LLM assistance may summarize or classify raw content before human display, but raw-content handling remains governed by profile and redaction policy.

### v0.9 SWE-Bench Lite Harness Compatibility

Accepted decisions:

- The first full harness target is SWE-Bench Lite.
- Kappaski may pause a managed harness run, but continuation requires human approval.
- Compatibility target is same exit code, same expected artifacts, and same grading result, allowing minor metadata differences.
- The benchmark must prove both harness compatibility and strong runtime governance.

### v0.10 Claude Code Adapter Hardening

Accepted decisions:

- Claude Code is the first hardened adapter target.
- Adapter layer records environment keys by default; values are redacted, folded, summarized, or maximum-length truncated according to profile.
- Child process tracking should aim for strong consistency, with explicit degraded modes when platform limitations prevent complete supervision.

### v0.11 Policy Profiles

Accepted decisions:

- Profile binding precedence is `session > repo > team`.
- Enterprise mode does not allow local user override by default.
- Future controlled override can be supported through a break-glass mechanism: explicit reason, elevated identity, time-bounded scope, immutable ledger event, and administrator/auditor review.

Format decision:

- Use TOML for editable policy profiles unless future constraints force JSON. TOML is human-editable, less indentation-fragile than YAML, easy to parse deterministically, and can still be converted to JSON for APIs and proof artifacts.

### v0.12 TeamRun And Handoff

Accepted decisions:

- v0.12 targets multi-user, multi-agent TeamRun records.
- Agent identity should prefer user declaration, then validate against adapter/session-derived facts to detect inconsistency.

Open design decision:

- Handoff taint inheritance uses resource-reference inheritance by default. A session-wide inheritance switch must be available through policy profiles because enterprise users need stricter customizable controls even when personal users prefer lower interruption.

### v0.13 Enforcement Guards And Rust Shim Direction

Accepted decisions:

- Native enforcement shim should use Rust first. v0.13 now includes Python control-plane guard checks plus a source-level Rust file-write shim contract; when a compiled shim is unavailable or platform-incompatible in a container, the decision falls back to the deterministic Python file-write guard and marks the result as fallback evidence. It still does not claim OS-level interception.
- Enforcement failure defaults to fail-open with critical alert, not silent allow.

Open design decision:

- Strong enforcement order is file-write guard first, env/secrets guard second, and network egress guard third. This order prioritizes demonstrable destructive-action protection, then credential exposure control, then outbound exfiltration control once taint and secret signals are stronger.



### v0.13 Enforcement Iteration Order

- v0.13.1: file-write guard for writes, deletes, overwrites, chmod/chown, and bulk mutation patterns.
- v0.13.2: env/secrets guard for environment variable values, credential files, token-shaped strings, and secret appearance in command/network/prompt/raw content.
- v0.13.3: network egress guard for unknown domains, upload-like requests, tainted outbound actions, and profile-governed allowlists.

Each enforcement domain must support enterprise profile customization. Early enforcement failure remains fail-open with critical alert unless a strict enterprise profile explicitly chooses fail-closed behavior.

### v0.14 Enterprise Audit Demo Package

Accepted decisions:

- First demo priority is secret leak / unsafe deletion workflow.
- Audit report is aimed at enterprise security teams.
- Replay raw content is folded by default and governed by profile controls that decide which content is visible, folded, redacted, summarized, or hidden.


## v0.9 Harness Compatibility + Safety Evaluation

This is the version where Kappaski should graduate from pinned SWE-Bench metadata to an optional full agent-harness validation path. The goal is not simply to run SWE-Bench; the goal is to prove that Kappaski can wrap a real agent harness without breaking its normal orchestration while still enforcing strong runtime governance.

The benchmark should compare baseline harness behavior against a Kappaski-wrapped run and track:

- harness compatibility: same task setup, exit behavior, expected artifacts, and grading flow;
- safety coverage: command, file, network, environment, skill/tool/API, taint, approval, and block events captured;
- autonomy preservation: low-risk operations continue without unnecessary human approval;
- critical enforcement: deterministic critical rules cannot be downgraded by LLM review;
- audit completeness: ledger, proof, gate report, and replay can explain the run after completion.

Default CI should still use fast local suites. Full SWE-Bench harness execution should be an optional heavy benchmark that skips cleanly when Docker, datasets, or harness dependencies are unavailable.


## v0.8-v0.14 Implementation Status

Status: implemented full-product local control-plane surfaces.

- v0.8 implemented OpenAI-compatible reviewer provider plumbing, raw-content evidence summaries, LLM deny explanations, deterministic reviewer-quality corpus, optional provider smoke readiness, and `v0.8-llm-reviewer` benchmark.
- v0.9 implemented harness artifact compatibility comparison, baseline/wrapped command-pair execution, managed pause/approval/resume harness check, optional official SWE-Bench wrapper, and `v0.9-harness-compatibility` benchmark.
- v0.10 implemented Claude Code adapter profile inspection, environment key recording, value redaction/folding, process-group supervision, and `v0.10-claude-adapter-profile` benchmark.
- v0.11 implemented TOML/JSON policy profile resolution with `session > repo > team` precedence, profile distribution bundle, ledger-backed break-glass review, and `v0.11-policy-profiles` benchmark.
- v0.12 implemented multi-user TeamRun records, agent identity validation, resource-reference/session-wide handoff taint modes, multi-ledger aggregate proof, HTML TeamRun timeline, and `v0.12-teamrun-handoff` benchmark.
- v0.13 implemented enforcement guard decisions for file-write, env/secrets, and network egress, `rust/kappaski-shim`, deterministic native-shim fallback for incompatible binaries, wrapper-level file-write interception, generic `enforce run --domain ...`, and `v0.13-enforcement-guards` benchmark.
- v0.14 implemented the enterprise audit demo package for secret leak and unsafe deletion workflows, plus ledger-backed audit signoff and the `v0.14-enterprise-audit-demo` benchmark.


## v0.15-v0.18 Architecture Correction From Plugin Review

The 2026-05 plugin/extension review changed the next implementation wave. The
product remains a daemon-owned control plane, but native plugins, hooks,
extensions, rules, and MCP config should be promoted to first-class adapter
surfaces.

### v0.15 Native Integration Inventory

Status: implemented.

Goal: turn public adapter assumptions into a machine-readable inventory.

Scope:

- discover Claude Code, Codex, Gemini CLI, Cursor, OpenCode, OpenClaw, and
  generic agent integration surfaces;
- produce `NativeIntegrationProfile` records for hooks, plugins, extensions,
  rules, MCP, sandbox, command, and config surfaces;
- grade each agent's pre-runtime, runtime, and post-runtime coverage;
- add docs that separate "coverage grade" from "trusted boundary grade."

Implemented:

- `src/kappaski/native.py`;
- `kappaski native inventory`;
- `kappaski native install` with preview/confirm/backup semantics;
- `v0.15-native-integration-inventory` benchmark;
- detailed version doc at `docs/v0.15-native-integration-inventory.html`.

### v0.16 Hook And Plugin Event Bridge

Status: implemented.

Goal: make native hook/plugin paths real.

Scope:

- harden Claude Code hook bridge;
- add Codex hook/plugin bridge prototype;
- add OpenCode plugin bridge prototype;
- normalize native `PreToolUse`, `PostToolUse`, permission, approval, and
  tool-result events into Kappaski `Invocation` records;
- test with real fixture payloads from public docs and locally installed
  binaries where available.

Implemented:

- `src/kappaski/native_bridge.py`;
- `kappaski bridge native`;
- blocking response rendering for Claude Code, Codex, OpenCode, and generic
  adapters;
- deterministic tests for event normalization and CLI blocking;
- `v0.16-hook-plugin-bridge` benchmark;
- detailed version doc at `docs/v0.16-hook-plugin-bridge.html`.

### v0.17 MCP Broker Reprioritization

Status: implemented.

Goal: use MCP as a cross-agent tool-call control and audit layer.

Scope:

- MCP server scanner and allowlist profile;
- stdio proxy/broker skeleton;
- tool-call approval and redaction path;
- evidence capture for tool arguments and tool results;
- compatibility tests for representative public MCP server fixtures.

Implemented:

- `src/kappaski/mcp_broker.py`;
- `kappaski mcp broker-step`;
- transparent message preservation plus folded raw-content evidence summaries;
- `v0.17-mcp-broker` benchmark;
- detailed version doc at `docs/v0.17-mcp-broker.html`.

### v0.18 Coverage-Aware Runtime Report

Status: implemented.

Goal: make Kappaski explicit about what it observed, enforced, and could not
cover.

Scope:

- proof fields for `observed_by`, `enforced_by`, `coverage_grade`, and
  `degraded_reason`;
- replay labels for plugin, hook, wrapper, proxy, shim, sandbox, and uncovered
  events;
- enterprise audit section for bypass surfaces and residual risk;
- gates that can fail when a policy profile requires coverage that was missing.

Accepted decisions:

- coverage grade is dimensional: `preflight_visibility`,
  `runtime_observation`, `runtime_enforcement`, and `postruntime_audit`;
- grade values are `none`, `declared`, `observed`, `mediated`, and `enforced`;
- insufficient coverage is handled by profile: warn in `audit`, require
  approval or explicit resolution in `managed`, and fail in `ci` when required;
- enterprise signoff is deferred beyond v0.18.

Implemented:

- `src/kappaski/coverage.py`;
- coverage metadata attached to runtime actions;
- proof coverage summaries and event-level coverage facts;
- replay coverage section and timeline coverage labels;
- profile-driven gate coverage requirements;
- `v0.18-coverage-aware-runtime` benchmark;
- detailed version doc at `docs/v0.18-coverage-aware-runtime.html`.

## v0.19-v0.24 Pre-v1 Model Closure

Status: implemented.

Goal: close the product model before 1.0 by proving that a governed agent run
can be bound to an accountable identity, reconstructed as an execution path,
controlled by path-aware policy, mediated through a common contract, governed by
enterprise profile objects, and validated through a repeatable pre-v1 benchmark.

Implemented:

- v0.19 identity/principal binding: `Principal`, `AgentIdentity`,
  `CredentialBinding`, `CapabilityGrant`, daemon mismatch rejection, and proof
  accountability export.
- v0.20 ledger-derived execution graph: JSON/HTML graph export and
  upstream/downstream query API.
- v0.21 path-aware policy: deterministic checks for secret egress,
  CI/deploy mutation, and external-instruction-to-destructive-shell chains.
- v0.22 unified mediation: `MediationRequest`, `MediationDecision`,
  `MediationOutcome`, approval pause/resume, fail-open alert, and coverage
  semantics.
- v0.23 enterprise policy governance: registry, pinning, verification,
  raw-content display policy, and break-glass review readiness.
- v0.24 pre-v1 evaluation/demo: local pinned benchmark and enterprise audit
  package with ledger, proof, replay, graph, coverage, and audit artifacts.

## v0.25-v0.29 Release Candidate Closure

Status: implemented.

Goal: move from pre-v1 demo readiness to a local 1.0 release-candidate gate
that can verify adapter runtime integration, policy-as-code, enterprise evidence
bundles, benchmark harness coverage, and RC artifact completeness.

Implemented:

- v0.25 adapter runtime integration: Claude Code style and generic adapter
  executions now create identity-bound sessions, mediation records, proof,
  replay, path graph, coverage, audit, and adapter package manifests.
- v0.26 policy-as-code v1: Kappaski-native TOML profile validation and path
  policy execution with non-downgradable deterministic critical rules.
- v0.27 enterprise evidence export: hash-verified evidence bundle manifest,
  audit JSON/HTML, proof, replay, graph, coverage, and policy artifacts.
- v0.28 benchmark harness expansion: benchmark registry and product metrics for
  attack, benign, compatibility, and evidence cases with optional heavy
  validation skips.
- v0.29 release-candidate gate: local gate for pytest, docs, roadmap,
  benchmarks, demo artifacts, evidence verification, and JSON/HTML RC reports.

Post-v0.29 planned items are recorded separately and are not part of the current
implementation gate: IdP/SCIM, hosted admin console, full signoff workflow,
graph database, Rego/Cedar backend, kernel-level enforcement, and SIEM/OTel
export.

## Roadmap Coverage Verification

Roadmap completion is now checked explicitly by code. Use:

```bash
kappaski roadmap status
kappaski roadmap status --require-full
```

Both commands should pass for the current local control-plane product scope.

Full-product readiness is also checked by:

```bash
kappaski eval benchmark --suite full-product-readiness
kappaski release-candidate verify --out-dir .kappaski/rc
```

Remaining product boundaries are explicit rather than hidden gaps:

- official SWE-Bench Docker/dataset execution is an optional heavy validation path;
- kernel/OS-level interception is not claimed by wrapper-level enforcement;
- hosted enterprise admin roles, report templates, and identity-backed service workflows remain future service-tier work;
- coverage reports do not claim enforcement where Kappaski only observed an action.

## v0.30-v0.39 Benchmark Experiment Code Route

Status: implemented as local experiment substrate; external/live benchmark validation is not complete.

Goal: turn the benchmark research map into a reproducible experiment system.
This wave does not merely add benchmark names. It creates a stable experiment
case model, corpus adapters, runner, metrics, and reports that score Kappaski's
control-plane behavior on benchmark-derived workloads. Most default inputs are
simulated traces or benchmark-shaped local fixtures; official upstream benchmark
execution is a separate validation gate.

Implemented sequence:

- v0.30 experiment substrate: `ExperimentCase`, `ExpectedControlOutcome`,
  deterministic fixture format, `experiment list/run/report` CLI, and HTML
  experiment reports.
- v0.31 AgentDojo / AgentDyn adapters: indirect prompt-injection cases mapped to
  source, trust, taint, tool, resource, sink, decision, and proof requirements.
- v0.32 AgentSecBench adapter: authority/data-flow separation experiments where
  model-visible data does not imply permission to act.
- v0.33 SWE-bench friction track: benign coding workflow compatibility,
  approval noise, mediation latency, and coverage distribution.
- v0.34 SKILL-INJECT supply-chain track: pre-runtime skill detection, capability
  grants, runtime skill-originated actions, and audit reconstruction.
- v0.35 secure coding gate: SusVibes / Agent Security League style findings as
  post-runtime gate evidence for functionally passing but insecure patches.
- v0.36 coverage truthfulness matrix: imported log, hook, wrapper, shim/proxy,
  and bypass surfaces scored by true coverage grade.
- v0.37 LLM reviewer selectivity: reviewer-off, deterministic-only, selective,
  always-on, and async-audit modes scored by cost, latency, recall, and
  redaction safety.
- v0.38 audit/tamper assurance: audit-question checkers, ledger/proof tamper
  fixtures, missing-field detection, and time-to-answer metrics.
- v0.39 paper-ready experiment package: one command to generate a reproducible
  E0-E6 paper/demo result bundle with fixture hashes and optional-heavy status.

Reference:

- [`benchmark-research-and-experiment-mapping.html`](benchmark-research-and-experiment-mapping.html)
- [`benchmark-research-and-experiment-mapping.md`](benchmark-research-and-experiment-mapping.md)
- [`implementation-audit-v0.1-v0.39.html`](implementation-audit-v0.1-v0.39.html)

## v0.40 Full SWE-Bench Validation Contract

Status: implemented as a strict external-validation contract; the full upstream
run itself remains a separate artifact-producing execution.

Goal: make it impossible to confuse SWE-Bench Lite, metadata replay, fake
harness output, or a subset smoke run with complete SWE-Bench validation.

Implemented:

- `external-validation swe-bench-full` CLI.
- Default dataset `SWE-bench/SWE-bench`, `split=test`; the equivalent
  `princeton-nlp/SWE-bench` id is accepted.
- Default expected total of 2294 instances for full SWE-Bench.
- Official artifact discovery for `results/<run_id>.json` and
  `results/<run_id>/instance_results.jsonl`.
- Checks for all-data mode, submitted equals total, completed equals
  submitted, zero error instances, per-instance result completeness, and
  optional completed-id matching.
- `v0.40-swe-bench-full-validation-contract` benchmark that verifies the local
  contract and rejects subset evidence.

Run the full external validation when dependencies and predictions are ready:

```bash
kappaski external-validation swe-bench-full \
  --python /path/to/swebench-python \
  --predictions-path /path/to/predictions.jsonl \
  --run-id kappaski_full_2026_05_31 \
  --work-dir .kappaski/swe-bench-full \
  --max-workers 12 \
  --timeout 1800 \
  --out .kappaski/swe-bench-full/full-validation.json
```

Boundary: `v0.40-swe-bench-full-validation-contract` proves Kappaski can
validate a full-run-shaped official report. It is not evidence that the full
upstream benchmark has already completed. The roadmap gate
`--require-external-validation` should continue to fail until that real run is
attached.

## Pre-release Work: Real-World Demo And Enterprise Coverage Closure

Status: planned/active pre-release hardening after v0.40.

Goal: move from local product readiness to evidence that a new user and an
enterprise reviewer can understand the value quickly, run realistic demos, and
see where unmanaged agent coverage remains a boundary.

Implemented in the current pre-release hardening pass:

- Structured public risk-source mapping in `real_world_cases.py`.
- `demo real-world-risk-cases` CLI that produces a public-source catalog plus
  live adapter and pre-v1 control-plane demo artifacts.
- `real-world-agent-risk-demo` benchmark that verifies public-source coverage
  and before/during/after mapping.
- Code design and development standards documentation.
- Enterprise roadmap for discovering and covering agents that bypass daemon
  registration.

Near-term planned sequence:

- v0.41 unmanaged agent inventory: process/config/MCP/skill/extension discovery
  report with `unmanaged_detected` coverage facts.
- v0.42 managed launcher migration: wrapper/alias/CI launcher preview and
  managed-run verification.
- v0.43 enterprise coverage gate: profile-driven gate for registered,
  unmanaged, mediated, enforced, and bypass coverage states.
- post-v0.43 endpoint, MDM, EDR, SIEM, and hosted enterprise integration remain
  external/live validation work, not default local readiness claims.

Reference:

- [`kappaski-new-user-briefing.html`](kappaski-new-user-briefing.html)
- [`code-design-and-development-standards.html`](code-design-and-development-standards.html)
- [`enterprise-unregistered-agent-coverage-roadmap.html`](enterprise-unregistered-agent-coverage-roadmap.html)
