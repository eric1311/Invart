# Kappaski Evaluation And Benchmarks

Date: 2026-05-26
Status: v0.2 baseline implemented

## Why This Exists

Kappaski needs to prove two things:

1. Functional correctness: every invocation should produce the expected ledger,
   decision, review, approval grade, outcome, proof, and verification behavior.
2. Product effectiveness: the control plane should reduce unnecessary human
   approvals while still escalating or blocking meaningful risk.

Unit tests prove the first claim. Benchmarks and evaluation suites are needed for
the second claim.

## Current Built-In Benchmark

The first benchmark suite is available through:

```bash
kappaski eval benchmark --suite v0.2-semantic
```

It runs complete runtime pipeline cases, not isolated rule checks:

```text
RuntimeEvent
  -> Invocation
  -> deterministic rules
  -> semantic reviewer
  -> policy merger
  -> approval grade
  -> ledger
```

The suite currently includes:

- benign file read should auto approve;
- sensitive file read should require human approval;
- outbound action after taint should require human approval;
- curl-pipe-shell should be blocked;
- external goal hijack should be blocked;
- Skill instruction override should require human approval.

The output reports per-case checks and aggregate rates:

- pass rate;
- effects by `allow`, `ask`, `deny`;
- approval grades by `auto_approve`, `require_human`, `blocked`;
- auto-approve rate;
- human-approval rate;
- blocked rate.

## Metrics We Should Track

For v0.2 and v0.3, the useful metrics are:

- Critical safety recall: percentage of critical cases correctly blocked.
- High-risk escalation recall: percentage of high-risk cases requiring human approval.
- Benign auto-approval rate: percentage of safe cases that do not interrupt users.
- Approval noise rate: percentage of benign cases incorrectly escalated.
- Deterministic override safety: critical deterministic rules are never downgraded.
- Review stability: repeated runs with the same evidence produce compatible grades.
- Redaction safety: reviewer inputs do not expose raw secret values.

## How To Grow The Benchmark

The benchmark should grow from three sources:

1. Synthetic adversarial cases: goal hijack, prompt injection, suspicious Skills,
   outbound after sensitive read, encoded archives, CI/CD mutation.
2. Golden real-world traces: anonymized ledger snippets from actual agent runs.
3. Regression cases: every bug or false positive becomes a permanent benchmark case.

Each case should define:

- input event or event sequence;
- expected final effect;
- expected approval grade;
- minimum expected risk;
- expected semantic category when applicable;
- tags such as `benign`, `skill`, `taint`, `outbound`, `critical`.

## LLM Reviewer Evaluation

The v0.2 code now has an LLM reviewer contract, but no network provider is enabled
by default. This is intentional: the default test path must stay deterministic.

A real LLM reviewer should be evaluated by running the same benchmark with:

```bash
kappaski eval benchmark --suite v0.2-semantic --reviewer llm
```

For local deterministic provider tests, set `KAPPASKI_LLM_REVIEW_JSON` to a strict
JSON review object. Production provider integration should add provider-specific
fixtures and compare:

- deterministic baseline vs LLM reviewer;
- pass/fail by risk class;
- approval-noise delta;
- reviewer invalid-output rate;
- redaction failures.


## External Benchmarks And Leaderboards

There is no single public benchmark that directly proves Kappaski's full value,
because most public suites evaluate model or agent behavior rather than a runtime
control plane with durable ledger/proof closure. We should use external suites as
input corpora and comparison baselines, then score Kappaski-specific closed-loop
metrics on top.

For the detailed benchmark landscape, problem-by-problem experiment mapping, and
v0.30-v0.39 code route, see
[`benchmark-research-and-experiment-mapping.html`](benchmark-research-and-experiment-mapping.html)
and the full Markdown note
[`benchmark-research-and-experiment-mapping.md`](benchmark-research-and-experiment-mapping.md).

Important boundary: v0.30-v0.39 currently provide local experiment substrate and
benchmark-shaped fixtures. Official upstream/live benchmark validation is
separate and is tracked by `roadmap status --require-external-validation`.

Recommended priority:

1. AgentDyn
   - Best fit for indirect prompt injection in dynamic real-world environments.
   - Useful for measuring both missed attacks and over-defense.
   - Maps to Kappaski metrics: high-risk escalation recall, approval noise rate,
     and benign auto-approval rate.
   - Reference: https://arxiv.org/abs/2602.03117

2. ShadowBench
   - Agent crash-test benchmark focused on prompt injection, secret leakage,
     unsafe actions, source confusion, and tool misuse.
   - Useful for showing why runtime evidence, approval grading, and proof are
     needed around agents.
   - Maps to Kappaski metrics: taint closure rate, unsafe-action blocking,
     trace/proof completeness.
   - Reference: https://shadowbench.dev/

3. ARA Eval
   - Risk-gate oriented evaluation for enterprise agent scenarios.
   - Useful because Kappaski's product value is close to gate precision/recall:
     when should an action continue, pause for approval, or block?
   - Maps to Kappaski metrics: A-Gate-style recall, precision, calibration,
     false positive rate, false negative rate.
   - Reference: https://ara-eval.org/

4. HarmActionsEval / Agent Action Safety Leaderboard
   - Measures whether agents execute harmful actions with powerful tools.
   - Useful as a model/agent safety baseline, but less specific to Kappaski's
     ledger/proof control-plane claim.
   - Reference: https://agent-leaderboard.github.io/

5. AgentHarm
   - Harmful agent task benchmark covering clearly malicious tasks.
   - Useful for validating obvious malicious-task blocking.
   - Less representative of normal enterprise coding workflows where approval
     noise and contextual taint matter.
   - Reference: https://arxiv.org/abs/2410.09024

6. OASIS
   - Offensive cybersecurity agent benchmark with vulnerable applications.
   - Useful later for security-agent workflows, high-risk command approval, and
     proof of controlled cyber activity.
   - Reference: https://oasis.kryptsec.com/

7. ClawBench
   - Browser-agent benchmark with live websites, traces, and a leaderboard.
   - Useful later when Kappaski has browser/tool adapters and richer trace
     capture. Lower priority for v0.2/v0.3 because UI/browser agent work is not
     the current focus.
   - Reference: https://www.harness-eval.com/

## Benchmark Strategy Decision

Kappaski should not claim success by topping a generic model leaderboard. The
right validation approach is:

1. Run external benchmark cases through Kappaski as runtime traces.
2. Convert each case into expected control-plane outcomes:
   - `allow` / `audit_only` / `require_approval` / `deny`;
   - approval grade;
   - minimum risk;
   - expected taint and semantic categories;
   - required proof fields.
3. Score both safety and usability:
   - critical block recall;
   - high-risk gate recall;
   - benign auto-approve rate;
   - approval noise rate;
   - proof completeness;
   - redaction safety.
4. Keep Kappaski's built-in benchmark as the regression harness and use external
   suites to expand the corpus.

The initial integration priority should be AgentDyn, ShadowBench, and ARA Eval.
Together they cover indirect prompt injection, unsafe agent actions, and
enterprise-style risk gating, which are the closest public approximations of
Kappaski's value proposition.

## Product Validation Framing

The key product question is not whether Kappaski can flag suspicious strings. The
key question is whether it can reliably close the loop:

```text
risky context observed
  -> action proposed
  -> policy decision made
  -> approval grade assigned
  -> execution allowed, blocked, or deferred
  -> outcome recorded
  -> proof verifies the complete chain
```

A useful benchmark should therefore score end-to-end control-plane behavior, not
only classifier accuracy.

## v0.24 Pre-v1 Control-Plane Benchmark

The implemented `pre-v1-control-plane` suite is the local 1.0 readiness gate.
It is intentionally fixture-backed so CI remains deterministic, while optional
external benchmark execution can be layered on later.

Run:

```bash
kappaski eval benchmark --suite pre-v1-control-plane
```

The suite validates:

- attack coverage: secret egress, unsafe deletion, external instruction, and
  coverage-gated failure;
- benign autonomy: low-risk work remains allowed without unnecessary approval;
- compatibility: artifacts are produced in the same local proof/replay/gate
  shape used by earlier wrappers;
- evidence completeness: ledger, proof, replay, path graph, coverage report,
  and audit report are all generated.

Metrics include `block_rate`, `approval_rate`,
`benign_false_positive_proxy`, `latency_overhead_ms`, `llm_cost_usd`,
`proof_completeness`, `coverage_distribution`, and
`audit_reconstruction_success`.

## v0.30+ Experiment Code Route

The research mapping now translates public benchmark families into an
implemented code route. The key implementation shift is an experiment substrate
between external corpora and Kappaski's existing runtime:

```text
external benchmark seed
  -> corpus adapter
  -> ExperimentCase
  -> Kappaski event sequence
  -> ledger / proof / replay / path graph / evidence bundle
  -> experiment metrics and HTML report
```

The implemented code path is:

- v0.30: `experiment_cases.py`, fixture schema, deterministic experiment runner,
  and `experiment list/run/report` CLI.
- v0.31: AgentDojo / AgentDyn corpus adapters for indirect prompt injection.
- v0.32: AgentSecBench adapter for authority/data-flow separation.
- v0.33: SWE-bench Lite/Verified friction track for benign coding workflows.
- v0.34: SKILL-INJECT supply-chain track.
- v0.35: secure coding gate track using SusVibes / Agent Security League style
  fixtures.
- v0.36: coverage and enforcement truthfulness matrix.
- v0.37: LLM reviewer selectivity and cost experiments.
- v0.38: audit reconstruction and tamper-evidence experiments.
- v0.39: paper-ready experiment suite and reproducible report bundle.
- v0.40: full SWE-Bench validation contract. This is not another fixture
  experiment; it is the strict CLI/report contract for running the complete
  `SWE-bench/SWE-bench` test split and rejecting subset evidence. The
  equivalent `princeton-nlp/SWE-bench` id is accepted.

Full SWE-Bench external validation command:

```bash
kappaski external-validation swe-bench-full \
  --python /path/to/swebench-python \
  --predictions-path /path/to/predictions.jsonl \
  --run-id kappaski_full_2026_05_31 \
  --work-dir .kappaski/swe-bench-full \
  --out .kappaski/swe-bench-full/full-validation.json
```

The detailed implementation route is maintained in
[`benchmark-research-and-experiment-mapping.html`](benchmark-research-and-experiment-mapping.html)
and the full Markdown note
[`benchmark-research-and-experiment-mapping.md`](benchmark-research-and-experiment-mapping.md).
