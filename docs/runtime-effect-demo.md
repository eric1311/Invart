# Runtime effect demo

[HTML version](html/runtime-effect-demo.html)

This page explains how to see Invart's three runtime stages and five control layers in the demo artifacts.

The short version: run a demo, open the HTML entrypoint, then read the matrix first and the timeline second.

## Run The Demo

```bash
PYTHONPATH=src python -m invart.cli demo pre-1.0-final \
  --out-dir .invart/pre-1-demo-check
```

For isolated per-risk-case runs:

```bash
scripts/container-demo.sh all .invart/container-risk-demo
```

For any existing Invart ledger:

```bash
PYTHONPATH=src python -m invart.cli runtime layers \
  --ledger .invart/session.jsonl \
  --out-dir .invart/layer-workflow
```

Open `.invart/layer-workflow/layer-runtime-workflow.html`. This report is derived from the ledger and links the proof, replay, path graph, coverage, audit, and evidence manifest produced for that run.

## What To Look For

| View | What it proves | Main artifact |
| --- | --- | --- |
| Runtime Effect Matrix | Before, during, and after runtime are mapped to L1-L5. | `pre-1.0-final-demo.html` |
| Action Timeline | One case shows agent action, Invart observation, policy decision, outcome, and artifact. | `container-risk-audit.html` |
| Path Graph | Risk chains such as secret read to external network sink can be traced. | `path-graph.html` |
| Coverage Report | Observed, mediated, and enforced are reported as different claims. | `coverage.html` |
| Audit Report | A reviewer can answer who, what, why, policy, approval, outcome, and coverage. | `audit-report.html` |
| Layer Runtime Workflow | A command-level way to operate L1-L5 for a single ledger. | `layer-runtime-workflow.html` |

## Three Runtime Stages

| Stage | Demo signal |
| --- | --- |
| Before runtime | Surface inventory, unmanaged agent findings, identity binding, credential boundary, and grant setup. |
| During runtime | File, network, shell, skill, content, and mediation events become ledger-backed facts. |
| After runtime | Proof, replay, path graph, coverage, audit, and evidence bundles reconstruct what happened. |

## Five Control Layers

| Layer | Demo effect |
| --- | --- |
| L1 Execution Surface | Shows where commands, files, network, skills, MCP, launchers, and hooks enter the control plane. |
| L2 Runtime Fact Model | Shows invocations, taint, identity, resources, coverage, outcomes, and ledger records. |
| L3 Decision Plane | Shows deterministic rules, path-aware policy, and non-downgradable critical findings. |
| L4 Mediation Plane | Shows allow, audit, require approval, deny, enforced block, and fail-open alert semantics. |
| L5 Evidence Plane | Shows proof, replay, graph, coverage, audit, evidence bundle, and release gate outputs. |

## Layer Operation Flow

| Layer | Practical command | What the user gets |
| --- | --- | --- |
| L1 Execution Surface | `invart pre-runtime --target . --save` | Surface inventory and unmanaged coverage gaps. |
| L2 Runtime Fact Model | `invart runtime record-event --ledger ledger.jsonl --event '{...}'` | Normalized invocation, resource, taint, identity, and outcome facts. |
| L3 Decision Plane | `invart policy check-path --ledger ledger.jsonl --out path-policy.json` | Deterministic and path-aware reasons for allow, approval, or deny. |
| L4 Mediation Plane | `invart mediation inspect --ledger ledger.jsonl` | Pause, block, fail-open, approval, and mediation outcome state. |
| L5 Evidence Plane | `invart runtime layers --ledger ledger.jsonl --out-dir .invart/layers` | A reviewable stage x layer matrix with proof/replay/graph/coverage/audit links. |

## Boundaries

The container demo uses safe equivalent trajectories. It does not install hostile packages or replay private incidents.

Coverage labels are intentionally strict. `observed`, `mediated`, and `enforced` are not interchangeable, and unmanaged direct agent execution is shown as a coverage gap unless it enters a managed Invart surface.
