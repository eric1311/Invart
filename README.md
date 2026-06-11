# Invart

Invart is a local-first **agent runtime control plane** for people and teams that run AI agents with real tools, repositories, credentials, shells, MCP servers, skills, plugins, and network access.

It does not try to replace Codex, Claude Code, Gemini CLI, Cursor, OpenCode, or other agent apps. Invart sits around agent execution and gives you a closed loop:

- **Before runtime:** inventory the repo, environment, agent config, skills, MCP servers, tool surfaces, credential boundaries, and policy profile.
- **During runtime:** mediate commands, file activity, network intent, MCP/tool calls, native hook events, identity, approvals, taint, and coverage.
- **After runtime:** produce a ledger, proof, replay, path graph, coverage report, benchmark result, and audit/evidence bundle.

The goal is simple: make agent behavior accountable, policy-aware, and reviewable without turning every low-risk action into a human approval chore.

<p align="center">
  <img src="assets/brand/png-from-original/invart-logo-horizontal-1600x800.png" alt="Invart logo" width="860">
</p>

## Who This Is For

Invart is useful if you are:

- a developer using coding agents on repositories with secrets, deploy scripts, CI config, or production-adjacent credentials;
- a security or platform team trying to understand what multiple agents did across sessions;
- an open-source maintainer who wants reproducible evidence for agent-assisted changes;
- a team evaluating whether agent workflows can be governed without killing autonomy.

Invart is currently a CLI-first **0.9 pre-release**. It is suitable for local evaluation, demos, experiments, adapter work, and pre-release feedback. It is not yet a hosted enterprise console or kernel-level sandbox.

## What Invart Can Do Now

- Create managed sessions with stable identity, goal, agent, ledger, and environment context.
- Scan pre-runtime surfaces such as repo files, skills, MCP/tool corpora, and native integration points.
- Analyze runtime events for shell, file, network, content, MCP, skills, and policy risk.
- Apply deterministic policy, path-aware checks, approval decisions, and LLM-reviewer-compatible risk explanations.
- Preserve facts in an append-only JSONL ledger and export portable proof.
- Generate replay HTML, path graphs, coverage reports, evidence bundles, audit reports, and release-candidate gates.
- Run built-in benchmarks and demos, including real-world-risk-shaped and containerized risk flows.
- Keep old `kappaski` imports and CLI as compatibility aliases while the public project name moves to `Invart`.

## Start Here

README is the landing page. The docs are organized as a user journey:

| If you want to... | Start with |
| --- | --- |
| Understand what Invart is and why it exists | [`docs/product.md`](docs/product.md) |
| Run one local managed session | [`docs/quickstart.md`](docs/quickstart.md) |
| Operate the five runtime layers on a ledger | [`docs/five-layer-operator-guide.md`](docs/five-layer-operator-guide.md) |
| See the before / during / after demo artifacts | [`docs/runtime-effect-demo.md`](docs/runtime-effect-demo.md) |
| Integrate with CLI, artifacts, or Python helpers | [`docs/cli-reference.md`](docs/cli-reference.md) and [`docs/api-sdk.md`](docs/api-sdk.md) |
| Evaluate claims and benchmarks | [`docs/evaluation.md`](docs/evaluation.md) |
| Browse the full documentation map | [`docs/index.md`](docs/index.md) or [`docs/html/index.html`](docs/html/index.html) |

The recommended first path is: **Quickstart -> Five-layer operator guide -> Runtime effect demo -> Evaluation**. That path shows the whole loop from a local ledger to proof, replay, path graph, coverage, audit, and evidence review.

## Install For Local Development

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
invart --help
```

The package exposes both commands during the migration:

```bash
invart --help
kappaski --help
```

Use `invart` for new docs, examples, and scripts.

## Five-Minute Quickstart

Create a managed session, record one command, close the session, and verify the proof:

```bash
mkdir -p .invart/quickstart

invart session start \
  --target . \
  --agent demo-agent \
  --goal "Inspect the repository without risky changes" \
  --session-id invart_quickstart \
  --ledger .invart/quickstart/ledger.jsonl

invart runtime shell \
  --session invart_quickstart \
  --ledger .invart/quickstart/ledger.jsonl \
  -- python -c "from pathlib import Path; print(len(list(Path('.').iterdir())))"

invart session close --ledger .invart/quickstart/ledger.jsonl

invart proof export \
  --ledger .invart/quickstart/ledger.jsonl \
  --out .invart/quickstart/proof.json

invart proof verify \
  --proof .invart/quickstart/proof.json \
  --ledger .invart/quickstart/ledger.jsonl
```

The resulting `.invart/quickstart/ledger.jsonl` is the fact source. The proof JSON is the portable summary.

## Try The Risk Demo

Generate a local real-world-risk-shaped demo:

```bash
PYTHONPATH=src python -m invart.cli demo real-world-risk-cases \
  --out-dir .invart/real-world-risk-demo
```

Run the containerized demo, one isolated container per risk case:

```bash
scripts/container-demo.sh all .invart/container-risk-demo
```

The demo emits ledgers, proofs, replay/audit pages, and a suite HTML entrypoint. These cases are safe equivalents of common agent-runtime risks such as unfriendly skills, secret egress, and unsafe deletion.

Key outputs to open after the demo:

- `.invart/real-world-risk-demo/real-world-risk-demo.html`
- `.invart/real-world-risk-demo/live-adapter-demo/audit-report.html`
- `.invart/real-world-risk-demo/live-adapter-demo/replay.html`
- `.invart/real-world-risk-demo/pre-v1-demo/audit-report.html`
- `.invart/real-world-risk-demo/pre-v1-demo/replay.html`
- `.invart/real-world-risk-demo/pre-v1-demo/path-graph.html`
- `.invart/real-world-risk-demo/pre-v1-demo/coverage.html`

## Benchmark And Readiness Checks

```bash
python -m pytest -q
PYTHONPATH=src python -m invart.cli eval benchmark --suite full-product-readiness
PYTHONPATH=src python -m invart.cli eval benchmark --suite real-world-agent-risk-demo
PYTHONPATH=src python -m invart.cli roadmap status --require-full
PYTHONPATH=src python -m invart.cli release-candidate verify --out-dir .invart/rc --skip-pytest
```

Heavy external validation such as full SWE-Bench runs is intentionally separate from the default test suite. Invart distinguishes local product capability from external benchmark evidence.

## Documentation

Open the docs home for the structured journey:

- [Markdown docs home](docs/index.md)
- [HTML docs home](docs/html/index.html)

Reference pages:

- [Docs README](docs/README.md)
- [Concepts](docs/concepts.md)
- [Architecture](docs/architecture.md)
- [Examples](docs/examples.md)
- [Open-source boundary](docs/open-source-boundary.md)
- [Brand assets](assets/brand/README.md)

## Repository Layout

```text
src/invart/core/       Fact model, ledger, and stable artifact helpers
src/invart/control/    Runtime, policy, mediation, gate, and review plane
src/invart/governance/ Identity, profiles, TeamRun, and grants
src/invart/surfaces/   Adapters, native hooks, MCP, scanner, and enforcement
src/invart/assurance/  Proof, replay, audit, coverage, and evidence bundle
src/invart/evaluation/ Benchmarks, demos, external evidence, and RC gate
src/invart/commands/   CLI parser and command handlers
src/kappaski/          Compatibility import path for older integrations
tests/                 Product-slice tests
benchmarks/            Pinned local fixtures and experiment cases
examples/              Small runnable examples
docs/                  Public Markdown docs plus docs/html HTML site
assets/brand/          Public Invart PNG brand assets generated from the selected original logo
rust/invart-shim/      Source-level Rust enforcement shim prototype
internal/              Local-only design notes and historical planning docs, ignored by git
```

## Security Boundary

Invart is a control plane, not magic containment. Current local capabilities include wrappers, mediation, evidence, policy gates, native/hook integration surfaces, and a source-level Rust shim prototype. It does not yet provide hosted administration, IdP integration, kernel-level enforcement, or guaranteed coverage for agents that intentionally bypass all managed launchers and wrappers.

Critical deterministic rules are not downgraded by LLM judgment. LLM reviewers can explain, classify, or upgrade risk, but they are not the root of trust.

## License

Apache-2.0. See [LICENSE](LICENSE).
