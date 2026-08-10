---
title: "feat: Real agent conformance validation before 1.0"
type: "feat"
status: "planned"
date: "2026-06-09"
origin: "User request: real validation for Claude, Codex, Hermes, and OpenClaw"
---

# feat: Real agent conformance validation before 1.0

## Summary

Invart 0.9.2 proves a local control-plane loop over deterministic experiments, paper tables, coverage matrices, and release gates. The next release line must prove something harder: real mainstream agent runtimes can be launched, observed, mediated, audited, and scored against upstream benchmark evidence without breaking the normal agent workflow.

For the paper-facing P0 path, the first locked agents are:

- Claude Code
- Codex

Hermes Agent and OpenClaw remain important compatibility targets, but they are optional extension/control rows for P0 and move to P1 unless their official or upstream-compatible benchmark integration is ready. The reason is methodological: P0 should optimize for true end-to-end evidence on real benchmark cases, not for a broad product matrix with weak scoring semantics.

The broader pre-1.0 product line still tracks:

- Hermes Agent
- OpenClaw

This does not mean every product has equal integration depth on day one. It means every product claim must name its evidence level. Claude Code and Codex are required for the first official benchmark bridge. Hermes and OpenClaw may be included through the same generic CLI contract when available, but missing optional rows must not block the P0 paper path or be counted as official benchmark evidence.

## System Frame

Objective function:

- Maximize truthful evidence that Invart can govern real agent execution on real benchmark cases, starting with Claude Code and Codex as locked P0 agents.
- Minimize false security claims, especially plugin-only or vendor-owned surfaces presented as Invart mediation.
- Preserve developer workflow compatibility: same task, comparable exit/artifact result, plus Invart ledger/proof/replay/coverage/audit.

System boundary:

- In scope: local CLI, daemon/session registry, adapter runtime, managed launcher, native inventory, mediation, evidence bundle, benchmark and release gate.
- Out of scope: hosted enterprise UI, IdP/SCIM, kernel-level enforcement, SIEM export, vendor-private APIs, claiming universal bypass prevention.
- Externally controlled: vendor CLI behavior, docs, hook payload shapes, installation channels, network availability, model/provider behavior.

Feedback loop:

- Unit tests prove harness correctness.
- Container/local smoke tests prove the validator can invoke binary-shaped agent runtimes.
- Live conformance runs prove actual installed products entered Invart and generated complete evidence.
- Official benchmark rows prove utility/security outcomes only through upstream runners or graders.
- Release gate fails if the plan claims live support or official benchmark evidence but the artifacts are missing.

## Current Evidence And Source References

Current Invart code already has partial coverage:

- Claude adapter and environment check: `src/invart/surfaces/claude_adapter.py`
- Generic adapter runtime: `src/invart/surfaces/adapter.py`
- Managed launcher install/verify: `src/invart/surfaces/launcher.py`
- Native surface inventory and conformance: `src/invart/surfaces/native.py`
- Product control matrix: `src/invart/evaluation/product_control_matrix.py`
- Paper/research gate: `src/invart/evaluation/research_readiness.py`

External surfaces to respect:

- Claude Code documents hooks, permissions, and security controls in official docs: <https://docs.anthropic.com/en/docs/claude-code/hooks> and <https://docs.anthropic.com/en/docs/claude-code/security>
- OpenAI Codex documents sandboxing, approvals, network policy, and credential guidance in its safety writeup: <https://openai.com/index/running-codex-safely/>
- Hermes Agent documents safety controls and container isolation in its user guide: <https://hermes-agent.nousresearch.com/docs/user-guide/security/>
- OpenClaw documents permission modes and approval policies: <https://docs.openclaw.ai/tools/permission-modes>

Implementation must pin source URLs and observation timestamps in the generated conformance report because these products are moving targets.

## Step 0 Scope Challenge

### What already exists

| Sub-problem | Existing flow | Reuse or rebuild |
|---|---|---|
| Run child command under Invart | `run_adapter_command`, `run_adapter_runtime` | Reuse. Do not build a parallel executor. |
| Claude-specific wrapper/hook bridge | `run_claude_code_adapter`, `check_claude_code_environment` | Reuse, but fix live binary check bug first. |
| Native product surface discovery | `inventory_native_integrations`, `native_capability_matrix` | Reuse and extend with live conformance facts. |
| Managed launchers | `preview_managed_launcher`, `install_managed_launcher`, `verify_managed_launcher` | Reuse. Add real-agent report integration. |
| Coverage truthfulness | `run_coverage_truthfulness_matrix` | Reuse labels and gate semantics. |
| Evidence artifacts | proof, replay, path graph, coverage, audit, bundle | Reuse. Real-agent validation must emit the same bundle. |
| Benchmark registry | `src/invart/benchmarks/registry.py` | Extend with one new suite. |
| Release gate | `verify_release_candidate` | Extend with opt-in `--real-agents` or `--require-live-agents`. |

### Minimum useful change

The smallest complete paper-facing slice is:

1. Fix Claude environment check regression.
2. Add a `real_agent` conformance module that validates Claude Code and Codex through one schema, with Hermes/OpenClaw as optional profiles.
3. Add CLI: `real-agent check`, `real-agent run`, `real-agent report`.
4. Add benchmark: `v0.9.3-real-agent-conformance`.
5. Add official benchmark bridge commands that keep provider CLIs separate from upstream runners/graders.
6. Add release-gate mode that fails when required live or official evidence is absent.
7. Add docs explaining what is truly validated vs discovered.

This touches more than eight files, but the scope is not accidental. The change crosses CLI, adapter, benchmark, docs, and gate because the product claim crosses those layers. The way to keep it sane is not to shrink the claim, it is to reuse existing surfaces and add one narrow conformance schema.

### Benchmark execution contract

The paper-facing benchmark path must optimize for official scoring semantics
before product breadth. If a benchmark provides an upstream runner, grader,
judge, or repository replication protocol, that mechanism is the score
authority. Invart may prepare the task workspace, launch the agent, supervise
runtime effects, convert provider artifacts into the upstream submission format,
and attach evidence, but it must not replace the benchmark score with a local
smoke test or vendor-native trace.

The generic bridge is:

```text
official benchmark row
  -> prepared workspace
  -> product CLI or registered benchmark adapter
  -> upstream submission artifact
  -> official runner / grader / judge
  -> Invart evidence bundle and claim matrix
```

Claude Code and Codex are the locked P0 provider CLIs because they are available
now and cover the first coding-agent paper path. Hermes and OpenClaw remain P1
or optional extension rows unless they can enter through the same bridge without
inventing product-specific scoring semantics.

Code work should therefore be ordered by four gates:

| Gate | Code responsibility | Invalid substitute |
| --- | --- | --- |
| Benchmark authority | emit/run official commands, validate official artifacts, reject override-only rows as paper scores | local smoke test, native trace, provider success log |
| Generic agent bridge | run provider CLI or official model adapter with bounded cwd, timeout, env, and artifact capture | benchmark-specific prompt rewrite or hidden agent shim |
| Independent side-effect truth | capture workspace diff, process tree, transcript, network/package events, canaries, and stability status | ledger-only self-attestation |
| Paper artifact synthesis | derive claim matrix, cost/stability summary, and paper table from row-level artifacts | hand-written readiness text |

P0 should close 8-12 real cases across AgentDojo, AgentSecBench, Skill-Inject,
and SWE-Bench Verified or full SWE-Bench samples. Each case should have
baseline, observe-only, and mediated rows when the benchmark task shape allows
it. P1 scales the same protocol to larger family subsets; it should not relax
the official scoring boundary.

### Complexity control

Do not create four new full adapters in v0.9.3. That is how this becomes a software museum.

Create one conformance harness with product profiles:

```text
RealAgentProfile
  ├─ product id
  ├─ binary candidates
  ├─ version probe command
  ├─ managed run command shape
  ├─ native surface expectations
  ├─ known vendor-owned limits
  └─ evidence requirements
```

Product-specific logic is data-first unless payload parsing truly differs.

## Version Plan

## v0.9.3 Real Agent Conformance Foundation

Goal:

- Prove Claude Code and Codex have real validation attempts and evidence records for the first official benchmark bridge, while Hermes/OpenClaw remain optional profile rows.
- Establish one conformance schema used by CLI, benchmark, docs, and RC gate.

Implementation:

- Fix `src/invart/surfaces/claude_adapter.py`: `returncode` in `check_claude_code_environment` must use `completed.returncode`.
- Create `src/invart/surfaces/real_agent.py`.
- Create `src/invart/evaluation/real_agent_conformance.py`.
- Add parser/handler under `src/invart/commands/parser_integrations.py` and `src/invart/commands/integrations.py`.
- Add benchmark runner in `src/invart/benchmarks/releases_v52_v57.py` or an equivalent pre-1.0 release module.
- Add benchmark registry entry `v0.9.3-real-agent-conformance`.
- Extend roadmap with `v0.52` or patch-level `v0.9.3` capability. Pick one naming convention and use it consistently in code and docs.

CLI:

```bash
PYTHONPATH=src python -m invart.cli real-agent check --target . --out-dir .invart/real-agent-check
PYTHONPATH=src python -m invart.cli real-agent run --agent claude-code --scenario benign-repo-inspection --out-dir .invart/real-agent-claude
PYTHONPATH=src python -m invart.cli real-agent report --run-dir .invart/real-agent-check --out .invart/real-agent-check/report.html
PYTHONPATH=src python -m invart.cli release-candidate verify --real-agents --require-live-agents --out-dir .invart/rc-real-agents
```

Required output schema:

```json
{
  "schema_version": "invart.real_agent_conformance.v0.9.3",
  "status": "pass|fail|blocked",
  "required_agents": ["claude-code", "codex"],
  "optional_agents": ["hermes", "openclaw"],
  "agents": [
    {
      "agent": "claude-code",
      "binary": {"status": "found|missing|error", "path": "...", "version": "..."},
      "native_inventory": {"status": "pass|warn|fail", "artifact": "..."},
      "managed_run": {"status": "pass|fail|blocked", "ledger": "...", "proof": "..."},
      "risk_run": {"status": "blocked|requires_approval|failed|not_run", "side_effect_prevented": true},
      "coverage": {"runtime_observation": "observed|mediated|enforced|none", "runtime_enforcement": "mediated|enforced|none"},
      "evidence": {"bundle": "...", "audit_html": "..."},
      "claim_boundary": "..."
    }
  ]
}
```

Acceptance:

- Default CI may use deterministic binary-shaped fixtures to test Invart's harness logic.
- Live paper mode must attempt real binaries for Claude Code and Codex.
- If `--require-live-agents` is set, missing Claude/Codex evidence is `fail`, not `skip`.
- Hermes/OpenClaw failures are recorded as optional blocked rows unless the caller explicitly adds them to the required agent list.
- Reports must say `blocked_missing_binary` or `blocked_vendor_unavailable` honestly.

## v0.9.4 Product-Specific Runtime Profile Hardening

Goal:

- Turn v0.9.3 from "one harness attempts all products" into product-aware validation.

Implementation:

- Add `RealAgentProfile` entries for:
  - Claude Code hooks and permission surfaces.
  - Codex sandbox/approval/network policy surfaces.
  - Hermes security/container surfaces.
  - OpenClaw permission-mode surfaces.
- Each profile must define:
  - version probe
  - safe benign task
  - safe risk-equivalent task
  - config files to inventory
  - native/vendor-owned coverage boundary
  - expected artifacts

Acceptance:

- Product reports are no longer generic rows with different names.
- Each product report explains the specific surface used and the specific blind spot left.

## v0.9.5 Containerized Real-Agent Validation

Goal:

- Make real-agent validation reproducible in local containers, not just on one developer laptop.

Implementation:

- Add `containers/real-agents/` or `scripts/real-agent-containers/` with one entrypoint per product.
- Each container runs one agent validation scenario and writes its `.invart/` artifacts to a mounted output directory.
- Keep secret-leak and unsafe-deletion demos safe-equivalent: use dummy secrets and throwaway files, never real credentials.
- Add command:

```bash
scripts/container-real-agent-validation.sh --sample small --agents all
```

Acceptance:

- Each container produces a conformance JSON, ledger, proof, replay, coverage, audit HTML, and evidence bundle.
- Container failures are preserved as evidence.
- The suite can run a small sample first, then expand.

## v0.9.6 Real Agent Benchmark Workflows

Goal:

- Validate that Invart can wrap real agent workflows, not only toy commands.

Implementation:

- Add three workflow classes:
  - benign repo inspection
  - SWE-Bench Lite selected issue run
  - risk-equivalent workflow: secret egress, unsafe deletion, external instruction hijack, and skill/plugin supply-chain scan
- For each product, compare:
  - baseline direct run
  - Invart managed run
  - difference in exit code, produced artifacts, and task result

Acceptance:

- At least one real workflow per product is captured end to end.
- SWE-Bench Verified and full SWE-Bench samples are preferred over SWE-Bench Lite for paper evidence. Any local or Lite slice must be labeled as benchmark-shaped evidence, not a full upstream benchmark score.
- The command must preserve official harness artifacts when run in full mode.
- Compatibility output reports same exit code / same artifact / same grading result when available, and names metadata-only differences.

## v0.9.7 Pre-Release Real-Agent Gate

Goal:

- Make real-agent validation a first-class pre-release gate.

Implementation:

- Extend `release-candidate verify`:
  - `--real-agents`
  - `--require-live-agents`
  - `--require-container-real-agents`
  - `--require-agent-workflows`
- Add HTML summary section:
  - product
  - binary status
  - managed run status
  - risk decision
  - coverage grade
  - compatibility delta
  - artifact links

Acceptance:

- Release report cannot say "ready" while real-agent validation is absent.
- If live validation is intentionally not run, status is `local_rc_ready_with_live_agent_pending`, not `ready`.

## Architecture

```text
User / release gate
      |
      v
real-agent CLI
      |
      v
RealAgentConformanceRunner
      |
      +--> Product profile registry
      |       ├── Claude Code
      |       ├── Codex
      |       ├── Hermes
      |       └── OpenClaw
      |
      +--> Binary discovery + version probe
      |
      +--> Native inventory / config hash
      |
      +--> Managed launcher / adapter runtime
      |       |
      |       v
      |   RuntimeAuthority + mediation
      |       |
      |       v
      |   ledger.jsonl
      |
      +--> Artifact exporters
              ├── proof.json
              ├── replay.html
              ├── path-graph.html
              ├── coverage.html
              ├── audit.html
              └── evidence bundle
```

State machine:

```text
not_started
  |
  v
binary_checked
  | missing and required
  v
blocked_missing_binary

binary_checked
  |
  v
inventory_checked
  |
  v
managed_run_started
  |
  +--> runtime_blocked_before_side_effect
  |
  +--> runtime_executed
  |
  +--> runtime_failed
  |
  v
artifacts_verified
  |
  v
pass | fail | blocked
```

Code comments should include this state machine in `src/invart/surfaces/real_agent.py` if the implementation becomes branchy.

## Test Plan

Use TDD. The tests must cover agent workflow behavior, not just function output.

### Unit and integration tests

Create or extend:

- `tests/test_integrations.py`
- `tests/test_policy_evidence_rc.py`
- possibly `tests/test_real_agents.py` if the file gets too large

Required tests:

1. Claude environment regression
   - Fake `claude` binary returns `--version`.
   - `check_claude_code_environment()` records `completed.returncode`.
   - This catches the current `returncode` undefined bug.

2. Real-agent profile registry
   - Registry includes Claude Code, Codex, Hermes, OpenClaw.
   - Each profile has binary candidates, version probe, benign scenario, risk scenario, source URLs, and claim boundary.

3. Binary-shaped conformance harness
   - Temporary fake binaries simulate each product CLI.
   - Harness must still launch a real subprocess, not call a mock function.
   - Each run emits conformance JSON and artifact bundle.

4. Missing required product fails live gate
   - With `require_live_agents=True`, missing Hermes or OpenClaw is a failure.
   - Without it, status is pending/blocked, never pass.

5. Managed run closes the evidence loop
   - For each agent profile:
     - session is created
     - principal/agent identity is bound
     - ledger exists and verifies
     - proof answers who/what/why/outcome/coverage
     - replay and coverage HTML exist

6. Risk scenario blocks or requires approval before side effect
   - Fake binary tries to write a forbidden file or execute a network-like command.
   - Invart decision occurs before child execution.
   - Artifact states `side_effect_prevented=true`.

7. Coverage truthfulness
   - Native/vendor-owned surface is not reported as Invart enforced.
   - Managed launcher can report mediated.
   - File-write shim can report enforced only if the command actually went through enforcement.

8. CLI tests
   - `real-agent check`
   - `real-agent run --agent claude-code`
   - `real-agent report`
   - `eval benchmark --suite v0.9.3-real-agent-conformance`
   - `release-candidate verify --real-agents --skip-pytest`

9. Live tests
   - Marked optional by default.
   - Enabled by explicit flag/environment only:

```bash
INVART_LIVE_AGENTS=1 \
PYTHONPATH=src python -m invart.cli real-agent check \
  --require-agents claude-code,codex,hermes,openclaw \
  --out-dir .invart/live-real-agent-check
```

10. Container tests
    - Small sample first.
    - Preserve raw output, exit code, and artifacts.
    - Missing container dependency is environment-blocked, not pass.

### Coverage diagram

```text
CODE PATH COVERAGE
==================
[+] src/invart/surfaces/real_agent.py
    |
    +-- profile registry
    |   +-- [GAP -> UNIT] all four products present
    |   +-- [GAP -> UNIT] source URL and claim boundary required
    |
    +-- binary discovery
    |   +-- [GAP -> UNIT] found binary
    |   +-- [GAP -> UNIT] missing optional binary
    |   +-- [GAP -> UNIT] missing required binary fails
    |   +-- [GAP -> UNIT] version probe timeout
    |
    +-- managed run
    |   +-- [GAP -> INTEGRATION] benign run completes
    |   +-- [GAP -> INTEGRATION] risk run blocks before side effect
    |   +-- [GAP -> INTEGRATION] child nonzero produces failed outcome
    |
    +-- artifact verification
        +-- [GAP -> INTEGRATION] ledger/proof/replay/coverage/audit exist
        +-- [GAP -> UNIT] missing artifact fails conformance

[+] src/invart/evaluation/real_agent_conformance.py
    |
    +-- [GAP -> INTEGRATION] suite aggregates all products
    +-- [GAP -> INTEGRATION] report preserves per-product blocked state
    +-- [GAP -> INTEGRATION] benchmark pass/fail follows evidence

USER FLOW COVERAGE
==================
[+] Developer checks installed agent coverage
    +-- [GAP -> CLI] real-agent check writes HTML/JSON report

[+] Developer runs one real agent through Invart
    +-- [GAP -> CLI] real-agent run --agent X produces full artifact bundle

[+] Security reviewer opens release report
    +-- [GAP -> CLI/EVAL] RC report shows missing live agents as pending/fail

[+] Release manager requires real validation
    +-- [GAP -> CLI/EVAL] --require-live-agents fails if any required product lacks evidence
```

Target for v0.9.3:

- 100% of new branches above have tests.
- Live product availability is not forced in normal `pytest`.
- Release conformance cannot pass with fake or missing live evidence when `--require-live-agents` is set.

## Product-Level Validation Matrix

| Product | v0.9.3 must do | v0.9.3 must not claim |
|---|---|---|
| Claude Code | Real binary check, native hook/config inventory, managed run, hook/wrapper evidence when configured. | Kernel-level coverage or all child process effects if not routed through Invart. |
| Codex | Real binary check when installed, managed wrapper run, sandbox/approval/network control boundary in report. | That Codex-native sandbox is Invart enforcement. |
| Hermes | Real binary/config validation when installed, container/security surface inventory, managed wrapper run if CLI supports it. | That Hermes vendor security layers are Invart-owned mediation. |
| OpenClaw | Real binary/config validation when installed, permission-mode surface inventory, managed wrapper run if CLI supports it. | That OpenClaw allowlists or approvals equal Invart ledger-backed proof unless imported. |

## Failure Modes

| Failure | Test | Handling | User-visible result |
|---|---|---|---|
| Vendor binary missing | yes | blocked/pending depending mode | report says missing product evidence |
| Version probe hangs | yes | timeout and fail product check | report names timeout |
| Product CLI changes output shape | yes for parser fallback | store raw stdout/stderr preview | report says unparsed version |
| Managed run child exits nonzero | yes | ledger outcome failed | audit shows failed run |
| Risk side effect executes before mediation | yes | test fails | release gate fails |
| Artifact missing | yes | conformance fail | report names artifact |
| Coverage label inflated | yes | coverage gate fail | report says observed/mediated/enforced mismatch |
| Live validation not run | yes | `live_pending`, fail if required | release report does not say ready |

Critical gap if not implemented:

- If v0.9.3 has product rows for all four agents but no per-agent runtime artifact, the plan fails. Documentation cannot substitute for runtime evidence.

## Performance Review

Expected costs:

- Binary discovery: negligible.
- Version probe: timeout bounded, default 10 seconds per product.
- Managed benign run: bounded by scenario timeout, default 60 seconds per product.
- Risk run: should usually block before execution, default 10 seconds.
- Container live validation: minutes, not part of default pytest.

Implementation must expose timeout flags for live runs. A release gate that can hang forever is not a gate, it is a trapdoor with a progress bar.

## Documentation Plan

Add or update:

- `docs/real-agent-conformance.md`
- `docs/html/real-agent-conformance.html`
- `docs/evaluation.md`
- `docs/html/evaluation.html`
- `docs/release-history.md`
- `docs/html/release-history.html`
- `README.md`

Docs must explain:

- How to run local deterministic harness validation.
- How to run live real-agent validation.
- Why missing live evidence is not a pass.
- What each product validates.
- What remains vendor-owned or uncovered.
- Difference between observed, mediated, enforced, fail-open, and bypassed.

## NOT In Scope

- Hosted admin console: this is still CLI/local artifact work.
- IdP/SAML/SCIM: identity remains local declaration for now.
- Kernel-level enforcement: managed launcher/wrapper/shim coverage only.
- Claiming plugin-only security is enough: product docs must keep this boundary explicit.
- Full official SWE-Bench run for all products in v0.9.3: v0.9.6 owns workflow-scale benchmark expansion.
- Building four deep vendor adapters in v0.9.3: first add one conformance harness, then harden product-specific profiles.

## Worktree Parallelization Strategy

| Step | Modules touched | Depends on |
|---|---|---|
| A. Real-agent conformance core | `src/invart/surfaces/`, `tests/` | Claude bug fix |
| B. CLI integration | `src/invart/commands/`, `tests/` | A |
| C. Benchmark and RC gate | `src/invart/benchmarks/`, `src/invart/evaluation/`, `tests/` | A |
| D. Docs | `docs/`, `README.md` | A, B, C behavior known |
| E. Container validation scripts | `scripts/` or `containers/`, `tests/` | A, B |

Parallel lanes:

- Lane 1: A -> B
- Lane 2: C after A
- Lane 3: E after A/B command shape is stable
- Lane 4: D last

Recommended execution:

1. Do A and B sequentially first. They define the public shape.
2. Do C and E in parallel after the schema stabilizes.
3. Do D last, after commands and artifact names are real.

## Implementation Checklist

v0.9.3:

- [ ] Add regression test for Claude environment check.
- [ ] Fix Claude environment check.
- [ ] Add `RealAgentProfile` and product registry.
- [ ] Add conformance runner with all four required products.
- [ ] Add CLI commands.
- [ ] Add benchmark.
- [ ] Extend release gate.
- [ ] Add docs and release-history entry.
- [ ] Run unit tests and local conformance benchmark.
- [ ] Run live conformance with all available real binaries.
- [ ] Record unavailable product evidence honestly.

v0.9.4:

- [ ] Harden product-specific profiles.
- [ ] Add product-specific native expectations and parsing.

v0.9.5:

- [ ] Add container validation scripts.
- [ ] Add progressive small-sample run before full expansion.

v0.9.6:

- [ ] Add real agent workflow benchmark cases.
- [ ] Attach SWE-Bench Lite selected workflow evidence.

v0.9.7:

- [ ] Make real-agent validation part of pre-release gate.
- [ ] Update release report with real-agent readiness section.

## Acceptance Commands

Narrow:

```bash
uv run --with pytest pytest -q tests/test_integrations.py
PYTHONPATH=src python -m invart.cli real-agent check --target . --out-dir .invart/real-agent-check
PYTHONPATH=src python -m invart.cli eval benchmark --suite v0.9.3-real-agent-conformance
```

Full local:

```bash
uv run --with pytest pytest -q
PYTHONPATH=src python -m invart.cli roadmap status --require-full
PYTHONPATH=src python -m invart.cli release-candidate verify --out-dir .invart/rc-real-agent-local --skip-pytest --real-agents
```

Live required:

```bash
INVART_LIVE_AGENTS=1 \
PYTHONPATH=src python -m invart.cli real-agent check \
  --target . \
  --require-agents claude-code,codex,hermes,openclaw \
  --out-dir .invart/live-real-agent-check

INVART_LIVE_AGENTS=1 \
PYTHONPATH=src python -m invart.cli release-candidate verify \
  --out-dir .invart/rc-live-real-agents \
  --skip-pytest \
  --real-agents \
  --require-live-agents
```

Container progressive:

```bash
scripts/container-real-agent-validation.sh --sample small --agents all
scripts/container-real-agent-validation.sh --sample expanded --agents all
```

## Open Decisions

1. Version naming:
   - Recommendation: keep public package version `0.9.3`, but roadmap internal capability can continue as `v0.52-real-agent-conformance`.
   - Reason: users understand package semver, while the roadmap has already used internal capability numbers through v0.51.

2. Live gate strictness:
   - Recommendation: P0 `--require-live-agents` should fail when required Claude Code or Codex rows are missing; Hermes/OpenClaw should fail strict mode only when explicitly promoted into the required agent set.
   - Reason: the paper-facing benchmark package should prioritize official runner/grader semantics over a broad product matrix. Optional agents must use the same generic bridge contract, but missing optional rows must not be counted as missing official benchmark evidence.

3. Container dependency:
   - Recommendation: implement containers as v0.9.5, but design v0.9.3 artifacts so container runs are just another conformance evidence source.
   - Reason: do not block v0.9.3 on packaging every vendor install path, but do not let v0.9.3 fake product support either.

## Completion Definition

v0.9.3 is done only when:

- All four product profiles exist.
- The conformance command can attempt all four products, but the P0 official benchmark path requires Claude Code and Codex first.
- Missing required products fail strict live mode.
- Optional Hermes/OpenClaw rows are recorded as blocked or skipped unless the caller explicitly marks them as required.
- At least one managed runtime artifact bundle exists for every available product.
- The report distinguishes real live evidence, deterministic fixture evidence, vendor-owned evidence, and missing evidence.
- Product docs show exactly how to reproduce the check.

That is the useful first release.
