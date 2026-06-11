# Invart Roadmap

[HTML version](html/roadmap.html)

This roadmap describes the open-source Invart product path from the current
0.9 pre-release toward a credible 1.0 release candidate. It is intentionally
product-facing: it covers daemon, adapters, registration, policy, evidence,
validation, and benchmark work that belongs in the public project.

It does not include local-only planning artifacts. Those remain outside the
open-source boundary.

## Roadmap Principles

Invart is an agent runtime control plane. The roadmap therefore optimizes for
control-plane evidence rather than feature volume.

| Principle | Meaning for development |
| --- | --- |
| Ledger first | Runtime facts enter an append-only ledger. Proof, replay, graph, audit, and evidence are derived artifacts. |
| Coverage honesty | Observed, mediated, enforced, fail-open, degraded, imported, and discovered positions must stay distinct. |
| Real agent evidence | Adapter claims need live or fixture-backed runtime artifacts, not only product documentation. |
| Low-friction governance | Benign coding workflows should continue with low approval noise and measured overhead. |
| Test-driven delivery | Each stage starts with product-level tests and ends with benchmark, docs, and release-gate validation. |
| No false enterprise claim | Enterprise control-plane language requires registration, enrollment, policy, and unmanaged-gap evidence. |

## Current Baseline

The current public baseline is a local-first 0.9 pre-release:

- CLI-first managed sessions, ledger, proof, replay, path graph, coverage,
  audit, evidence bundles, and release-candidate checks.
- Generic adapter wrapper and Claude Code reference adapter.
- Adapter profile registry for major agent products with truthful coverage
  grades.
- L1-L5 runtime workflow and L5 evidence workspace.
- Local benchmark suites, product readiness checks, and progressive external
  evidence attachment.

The current baseline is not yet:

- a hosted enterprise admin console;
- an IdP/SCIM-backed organization service;
- an OS or kernel-level sandbox;
- a guarantee that unmanaged agents cannot bypass Invart;
- a full live adapter for every agent product.

## Coverage Grade Vocabulary

| Grade | What it means | What it cannot claim |
| --- | --- | --- |
| `full_live_adapter` | A real installed agent enters Invart through managed launch, daemon session registration, mediation, and L5 artifact export. | Universal OS-level containment or complete visibility into vendor-private internals. |
| `managed_wrapper` | Invart controls launch and visible command/file/network-shaped workflow boundaries. | Fine-grained native hook coverage unless actual hook events enter Invart. |
| `native_bridge` | Vendor hook, plugin, extension, MCP, or SDK events enter Invart and can receive normalized decisions. | Full runtime enforcement beyond the covered native event surface. |
| `vendor_evidence_import` | Invart imports vendor logs, sandbox facts, approval records, traces, PRs, or backend reports. | Invart mediation or enforcement of the original side effect. |
| `discovery_inventory` | Invart discovers binaries, configs, plugins, skills, MCP servers, or unmanaged surfaces. | Runtime control. This is a coverage gap unless paired with mediation evidence. |

## Stage Plan

### v0.9.8 Claude Code Full Live Adapter

Goal:

- Make Claude Code the first complete live adapter that proves Invart can wrap
  a real installed agent through the full control-plane loop.

Development:

- Promote the Claude adapter from reference fixture to full live adapter.
- Detect real binary path, version, and execution health.
- Start sessions through the daemon/runtime authority.
- Bind principal, agent identity, goal, policy profile, credential boundary,
  and active grant.
- Launch Claude Code through Invart-managed wrapper or launcher.
- Normalize hook, permission, tool, command, and child-process events into the
  mediation contract.
- Export adapter package, ledger, proof, replay, path graph, coverage, audit,
  evidence bundle, and layer-runtime report.

Tests:

- Strict live mode fails when Claude Code is missing or not invokable.
- Fixture mode uses binary-shaped subprocesses and does not masquerade as live.
- Risk-equivalent actions are denied or paused before side effect under a
  managed profile.
- Benign repo inspection runs with low approval noise.
- Missing hook or process-tree coverage is reported as degraded coverage.

Validation:

- `real-agent run --agent claude-code --require-live` produces complete
  artifacts when Claude Code is installed.
- `adapter inspect` verifies the generated adapter package.
- `evidence inspect` confirms L5 answers who, what, why, policy, approval,
  outcome, and coverage.

Experiments:

- Baseline direct run versus Invart-managed run for benign repo inspection.
- Managed risk-equivalent run for dummy secret egress or unsafe deletion.
- Hook-mediated event and wrapper-mediated command comparison.

### v0.9.9 Live Adapter Conformance Contract v2

Goal:

- Make live, fixture, imported, and discovered evidence comparable across
  products without inflating coverage.

Development:

- Extend adapter profiles with evidence level, control position, side-effect
  timing, required artifacts, source citation, and last-reviewed metadata.
- Add conformance report schema shared by CLI, benchmarks, product matrix, and
  release gate.
- Add gate rules that reject mediated/enforced claims when only plugin-only,
  trace-only, vendor-import, or discovery-only evidence exists.

Tests:

- Each grade requires the correct artifact set.
- Imported vendor evidence cannot satisfy Invart-mediated or enforced claims.
- Coverage labels fail closed when evidence is missing or inconsistent.

Validation:

- `real-agent check` emits per-product conformance rows.
- `roadmap status --require-full` and release-candidate checks reject claim
  inflation.

Experiments:

- Same action across raw, trace-only, managed wrapper, native bridge, shim, and
  vendor-import positions.
- Negative controls for plugin-only and discovery-only claims.

### v0.9.10 OpenCode Real Adapter Track

Goal:

- Add a second real product track using an open-source agent that is easier to
  inspect and reproduce.

Development:

- Add OpenCode live binary discovery, version probe, profile, plugin/config
  inventory, and managed wrapper support.
- Capture plugin, agent, and MCP configuration before runtime.
- Route visible command/file/network-shaped actions through mediation where the
  wrapper controls the boundary.
- Export the same adapter and L5 artifacts as the Claude track when possible.

Tests:

- OpenCode profile reports truthful control position and required artifacts.
- Fixture-backed OpenCode run emits ledger/proof/evidence package.
- Plugin/config inventory produces pre-runtime facts without claiming mediation.
- Risk-equivalent workflow is blocked or approval-gated under managed profile.

Validation:

- Live OpenCode run succeeds when binary is installed.
- Missing binary is blocked or pending, never reported as live pass.
- Product control matrix shows OpenCode as live, fixture, or wrapper-backed
  according to actual artifacts.

Experiments:

- OpenCode benign repo task: baseline versus Invart-managed.
- OpenCode plugin or skill supply-chain scan.
- Managed risk-equivalent command/file action.

### v0.9.11 Terminal Agent Managed Wrapper Track

Goal:

- Validate the generic terminal-agent path with Gemini CLI and Aider.

Development:

- Add Gemini CLI and Aider live profiles with binary detection, version probe,
  config inventory, MCP/context discovery, and managed wrapper execution.
- Preserve artifact parity checks for direct versus managed runs.
- Keep hook-level claims out of the grade unless real native events are
  available.

Tests:

- Gemini CLI and Aider profiles use `managed_wrapper` or lower unless hook
  evidence exists.
- Baseline and managed fixture runs preserve exit code and expected artifacts.
- Approval noise is measured for benign workflows.

Validation:

- `real-agent run` can execute installed Gemini CLI or Aider through Invart.
- Compatibility report records exit code, artifact parity, metadata drift, and
  approval count.

Experiments:

- Gemini CLI managed wrapper with MCP/config inventory.
- Aider small repo edit/test workflow.
- Paired benign coding friction runs for both products.

### v0.9.12 Codex Deep Adapter And Native-Control Boundary

Goal:

- Integrate Codex deeply while keeping Codex-native sandbox and approval facts
  separate from Invart-owned enforcement.

Development:

- Add Codex live binary/profile detection and managed wrapper support.
- Import or reference Codex sandbox, approval, network, and credential-boundary
  evidence as vendor-native facts.
- Add report language and gate checks that prevent Codex-native sandboxing from
  counting as Invart enforcement.
- Preserve compatibility with Codex-like generic wrapper flows.

Tests:

- Codex native control facts are imported as vendor evidence, not Invart
  enforcement.
- Managed wrapper actions can still produce Invart mediation decisions.
- Gate fails when a report upgrades vendor-owned sandboxing into Invart
  enforced coverage.

Validation:

- Direct Codex run versus Invart-managed run can be compared when Codex is
  installed.
- Missing live Codex is reported honestly in strict mode.

Experiments:

- Benign workflow compatibility comparison.
- Risk-equivalent managed run with Invart policy mediation.
- Vendor-native evidence import row for sandbox/approval facts.

### v0.9.13 IDE Extension Bridge And Inventory Track

Goal:

- Bring Cline, Roo, and Cursor into the control-plane vocabulary without
  overclaiming full local mediation.

Development:

- Add profiles for extension, rule, MCP, and settings surfaces.
- Add inventory commands for IDE agent configuration and workspace policy.
- Add native bridge or imported-event support where event exports are available.
- Mark default coverage as native bridge, vendor import, or discovery inventory
  based on actual evidence.

Tests:

- Discovery-only IDE config cannot satisfy mediated runtime claims.
- Imported extension events preserve source and limitation metadata.
- Coverage reports expose blind spots rather than hiding them.

Validation:

- IDE inventory report links discovered config to coverage gaps.
- Evidence bundle can include imported or bridged IDE event artifacts.

Experiments:

- Cline/Roo/Cursor config and MCP inventory.
- Imported or bridged extension event sample where available.
- Negative gate test for discovery-only evidence.

### v0.9.14 Gateway And Server-Agent Evidence Track

Goal:

- Treat OpenClaw and Hermes as gateway or server-agent runtimes, not only local
  CLI tools.

Development:

- Add profiles for gateway, security, skill, container, backend, and command
  evidence fields.
- Support managed launcher where a local launch boundary exists.
- Support evidence importer where the product owns the runtime boundary.
- Link container/backend/security logs to Invart evidence bundles without
  claiming Invart mediation.

Tests:

- Gateway/server profiles distinguish vendor-owned evidence from Invart-owned
  control.
- Evidence import preserves source hash, source timestamp, limitation, and
  coverage grade.
- Managed launcher mode, when available, emits normal ledger/proof/evidence.

Validation:

- OpenClaw and Hermes reports show whether each row is managed, imported, or
  discovery-only.
- Release gate fails if imported vendor logs are used as enforced coverage.

Experiments:

- Configuration and security posture inventory.
- Safe-equivalent secret leak or unsafe command case when a local boundary is
  available.
- Vendor evidence import case with audit-only coverage.

### v0.9.15 Enterprise Registration Authority

Goal:

- Turn the local daemon from a session registry into an enterprise-registration
  prototype for agent enrollment, launcher registry, adapter registry, and
  coverage-gap reporting.

Development:

- Add agent catalog backed by adapter profiles and conformance reports.
- Add launcher registry entries with owner, scope, hash, install state, and
  verification state.
- Add registration policy for managed sessions: declared agent identity,
  enrollment state, profile scope, and launcher evidence.
- Add unmanaged discovery report for detected but unregistered agents.
- Keep hosted IdP/SCIM/admin console out of scope.

Tests:

- Registered agent is accepted and launched.
- Declared-agent mismatch is rejected under managed or enterprise profile.
- Unregistered detected agent appears as a coverage gap.
- Full-control claim fails without registered launcher or adapter evidence.

Validation:

- `daemon status` and registration reports show active sessions, enrolled
  agents, launchers, profile scope, and unmanaged gaps.
- Release gate can require registration evidence for managed profiles.

Experiments:

- Registered versus unregistered agent comparison.
- Same agent run with correct identity, mismatched identity, and missing
  launcher evidence.
- Coverage-gap report over a workspace with mixed managed and unmanaged agent
  surfaces.

### v0.9.16 Public Benchmark Slice For Control-Plane Metrics

Goal:

- Validate Invart on a small public benchmark slice using control-plane
  metrics, not task-solve performance claims.

Development:

- Select a small reproducible slice from public benchmark families already
  compatible with Invart-style cases.
- Map cases to source localization, taint propagation, path policy,
  pre-side-effect mediation, coverage grade, audit completeness, and
  false-positive proxy.
- Keep full upstream benchmark runs attachable external evidence, not default
  local CI.

Tests:

- Each case emits ledger, proof, replay, path graph, coverage, audit, and
  evidence bundle.
- Metrics are stable over pinned local fixtures.
- Optional external dependencies skip cleanly unless strict mode is requested.

Validation:

- `eval benchmark` reports block rate, approval rate, benign false-positive
  proxy, proof completeness, coverage distribution, and reconstruction status.
- External evidence verifier distinguishes sample, slice, and full-run
  manifests.

Experiments:

- Indirect-instruction case.
- Risky code/tool action case.
- Skill or plugin poisoning case.
- Benign control case.

### v0.9.17 Benign Coding Friction And Compatibility Study

Goal:

- Measure whether Invart preserves ordinary coding-agent workflows while
  escalating high-risk paths.

Development:

- Add paired baseline versus Invart-managed workflow runner.
- Compare exit code, output artifact, task/grading result when available,
  approval count, approval noise, latency/overhead, and evidence completeness.
- Cover Claude Code, OpenCode, Gemini CLI, Aider, and Codex where installed or
  fixture-backed.

Tests:

- Paired-run report keeps baseline and managed artifacts separate.
- Approval noise is computed from ledger decisions.
- Managed run cannot be marked compatible if task artifact or grading result
  diverges without explanation.

Validation:

- Compatibility report shows same exit code, same artifact, same grading result
  when available, or names metadata-only differences.
- Release gate can require benign-friction evidence for full adapter claims.

Experiments:

- Low-risk repo inspection.
- Test command or small edit/test workflow.
- SWE-Bench-Lite-shaped sample when harness dependencies are available.

## Cross-Cutting Test Strategy

Each stage should use the same delivery pattern:

1. Write product-level failing tests first.
2. Implement the smallest feature-bearing path.
3. Add CLI coverage.
4. Add benchmark or experiment coverage.
5. Update Markdown and HTML docs.
6. Run targeted tests, full pytest, relevant benchmark, and release-candidate
   verification.

Required test families:

| Test family | Product question |
| --- | --- |
| Profile contract tests | What does Invart claim for this product, and what evidence is required? |
| Adapter workflow tests | Can a real or fixture agent enter Invart and produce ledger/proof/evidence? |
| Risk intervention tests | Does Invart block or pause risky side effects before they happen on covered surfaces? |
| Benign autonomy tests | Does Invart avoid excessive approval noise for ordinary work? |
| Coverage truthfulness tests | Are observed, mediated, enforced, imported, and discovered positions kept distinct? |
| Evidence integrity tests | Can a reviewer trust the bundle and detect missing or tampered artifacts? |
| Release gate tests | Do missing docs, tests, benchmarks, registration, or evidence fail the right gate? |

## Validation Commands

The exact command names may evolve with implementation, but every completed
stage should have equivalent validation:

```bash
PYTHONPATH=src uv run --with pytest pytest -q
PYTHONPATH=src python -m invart.cli roadmap status --require-full
PYTHONPATH=src python -m invart.cli eval benchmark --suite full-product-readiness
PYTHONPATH=src python -m invart.cli release-candidate verify --out-dir .invart/rc --skip-pytest
```

Live adapter stages should also support strict validation:

```bash
PYTHONPATH=src python -m invart.cli real-agent check --require-live --out-dir .invart/live-agent-check
PYTHONPATH=src python -m invart.cli real-agent run --agent claude-code --require-live --out-dir .invart/live-claude
```

Strict live validation must fail when required live evidence is absent. Missing
local binaries are never reported as a successful live run.

## Deferred Beyond This Roadmap

The following items remain outside this open-source roadmap slice:

- Hosted enterprise admin console.
- IdP, SCIM, SAML, or organization identity provider integration.
- Production SIEM or OTel export.
- Kernel-level enforcement or universal OS containment.
- Graph database backend.
- Full signoff workflow.
- Local-only planning artifacts.
