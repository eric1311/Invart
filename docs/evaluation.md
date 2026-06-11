# Measure control-plane behavior, not just code paths.

[HTML version](html/evaluation.html)


Invart separates local product checks from optional heavy external benchmark evidence.

[Operate L1-L5](five-layer-operator-guide.md) · [Runtime Effect Demo](runtime-effect-demo.md) · [CLI](cli-reference.md)

## Default Local Checks

```bash
python -m pytest -q
PYTHONPATH=src python -m invart.cli eval benchmark --suite full-product-readiness
PYTHONPATH=src python -m invart.cli eval benchmark --suite real-world-agent-risk-demo
PYTHONPATH=src python -m invart.cli roadmap status --require-full
```

## Metrics

| Metric | Why it matters |
| --- | --- |
| Critical block/approval behavior | High-risk actions should not silently pass. |
| Benign false-positive proxy | Low-risk agent work should keep moving. |
| Proof completeness | The proof should answer who, what, why, policy, approval, outcome, and coverage. |
| Coverage truthfulness | Observed, mediated, enforced, and fail-open are not the same claim. |
| Audit reconstruction | A reviewer should reconstruct the run from durable evidence. |

## Product claim to benchmark

| Product claim | Local check | Evidence to inspect |
| --- | --- | --- |
| Invart can preserve a closed before / during / after runtime loop. | `invart eval benchmark --suite pre-v1-control-plane` | ledger, proof, replay, path graph, coverage, audit report |
| High-risk agent-like actions are blocked, paused, or escalated without silent pass-through. | `invart eval benchmark --suite real-world-agent-risk-demo` | risk demo HTML, case audit report, mediation decisions |
| Coverage labels remain truthful across observed, mediated, enforced, fail-open, and bypassed paths. | `invart eval benchmark --suite v0.47-coverage-mediation-pilot` | coverage matrix JSON/HTML |
| Auditors can reconstruct who, what, why, policy, approval, outcome, and coverage. | `invart eval benchmark --suite v0.48-audit-reconstruction-study` | audit reconstruction study and evidence bundle |
| Plugin-only or vendor-native visibility is not reported as full runtime mediation. | `invart eval benchmark --suite v0.50-product-control-matrix` | product control matrix |
| Pre-release evidence can be checked separately from external benchmark completion. | `invart eval benchmark --suite v0.51-pre-1.0-research-ready-gate` | research-ready gate report |

## Research-Ready Validation Loop

The pre-1.0 research track validates an LLM/agent workflow end to end:

```text
agent task / prompt / skill / case
  -> simulated or imported agent trace
  -> Invart ledger, policy, reviewer, mediation, and outcome
  -> proof, replay, path graph, evidence bundle
  -> paper table row, audit reconstruction, coverage matrix, release gate
```

Run the local loop:

```bash
PYTHONPATH=src python -m invart.cli experiment paper-suite --out-dir .invart/paper-suite
PYTHONPATH=src python -m invart.cli experiment paper-tables \
  --paper-suite .invart/paper-suite/paper-metrics.json \
  --out-dir .invart/paper-tables
PYTHONPATH=src python -m invart.cli experiment coverage-matrix --out-dir .invart/research-coverage
PYTHONPATH=src python -m invart.cli experiment reviewer-ablation --out-dir .invart/research-reviewer
PYTHONPATH=src python -m invart.cli experiment audit-reconstruction --out-dir .invart/research-audit
PYTHONPATH=src python -m invart.cli experiment product-control-matrix --out-dir .invart/research-matrix
PYTHONPATH=src python -m invart.cli eval benchmark --suite v0.47-coverage-mediation-pilot
PYTHONPATH=src python -m invart.cli eval benchmark --suite v0.48-audit-reconstruction-study
PYTHONPATH=src python -m invart.cli eval benchmark --suite v0.49-reviewer-ablation-cost
PYTHONPATH=src python -m invart.cli eval benchmark --suite v0.50-product-control-matrix
PYTHONPATH=src python -m invart.cli release-candidate verify \
  --out-dir .invart/research-rc \
  --skip-pytest \
  --paper \
  --paper-tables .invart/paper-tables/paper-tables.json \
  --coverage .invart/research-coverage/coverage-truthfulness-matrix.json \
  --reviewer .invart/research-reviewer/reviewer-selectivity.json \
  --audit .invart/research-audit/audit-reconstruction-study.json \
  --product-matrix .invart/research-matrix/product-control-matrix.json
```

For a single-command benchmark check:

```bash
PYTHONPATH=src python -m invart.cli eval benchmark --suite v0.51-pre-1.0-research-ready-gate
```

The research gate is separate from the product release-candidate gate. `local_rc_ready` means the product artifacts and local product checks pass. `research_ready` means the paper/evaluation artifacts are present and internally consistent. Full external benchmark validation still requires an attached external evidence manifest.

## v0.46-v0.51 Evidence Artifacts

| Version | Artifact | Product question answered |
| --- | --- | --- |
| v0.46 | Paper evidence tables | Can every claim row link back to ledger, proof, replay, path graph, and evidence? |
| v0.47 | Coverage mediation pilot | Are observed, mediated, enforced, fail-open, and bypass labels kept truthful for the same action? |
| v0.48 | Audit reconstruction study | Can an auditor answer who/what/why/policy/approval/outcome/coverage, and detect tamper? |
| v0.49 | Reviewer ablation and cost | Does selective LLM review reduce calls/cost without downgrading deterministic critical rules? |
| v0.50 | Product control matrix | Why is plugin-only visibility not equivalent to runtime mediation or enforcement? |
| v0.51 | Research-ready gate | Are the product RC and research/paper evidence gates reported separately? |

## External Validation Boundary

Full SWE-Bench and other upstream benchmark runs are optional heavy validation. Invart can verify complete external evidence artifacts, but local tests do not pretend that a partial sample is a full upstream benchmark result.
