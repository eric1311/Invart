---
title: "Invart Control-Plane Evaluation Program - Plan"
date: "2026-07-21"
type: "feat"
artifact_contract: "ce-unified-plan/v1"
artifact_readiness: "implementation-ready"
product_contract_source: "ce-plan-bootstrap"
execution: "code"
deepened: "2026-07-21"
---

# Invart Control-Plane Evaluation Program - Plan

## Goal Capsule

- **Objective:** Build the paper evidence program for Invart as a cross-source, cross-runtime-stage agent audit and control plane, with mediation as one evaluated capability rather than the whole contribution.
- **Optimization target:** Produce a credible security paper whose positive claims survive benchmark age, agent incapability, zero-attack floors, judge dependence, and incomplete runtime coverage.
- **Authority hierarchy:** Benchmark-native end-state oracles own task and attack outcomes; independent side-effect evidence owns attempted and executed actions; Invart's ledger owns observations and control decisions; LLM judges provide bounded semantic labels but never rewrite native outcomes.
- **Execution profile:** Qualification-first, smoke-first, then paired pilots and full-denominator runs. Prompts, policy, benchmark revisions, metrics, and statistical tests freeze before holdout execution.
- **Stop conditions:** A result row stops before security comparison if provider execution is unproven, clean tool use fails, attack opportunity is absent, the native oracle is unavailable, the adapter changes benchmark semantics, or post-freeze policy tuning would be required.
- **Tail ownership:** The program ends with replayable raw artifacts, benchmark qualification records, exact denominators, statistical summaries, paper figures and tables, and an evidence-to-claim audit.

---

## Product Contract

### Summary

This plan repositions the experiment from “Invart lowers AgentDojo ASR” to “Invart supplies a runtime control plane that observes, mediates, and reconstructs security-relevant agent actions across multiple untrusted-input sources.” The experiment uses peer-reviewed agent benchmarks for the main evidence, newer benchmarks for external-validity stress, mature response-level benchmarks only as model controls, and an Invart-specific audit study for claims no external benchmark measures.

It extends `docs/plans/2026-07-17-001-feat-prompt-first-mediation-generalization-plan.md`. That plan remains authoritative for prompt-first mediation, provenance, continuation, agent/runtime adapters, and the connected model panel. This plan owns benchmark qualification, cross-benchmark evidence contracts, execution validity, the revised experiment matrix, and paper-facing claim synthesis.

The execution-facing Chinese companion is `docs/plans/2026-07-22-001-docs-invart-experiment-and-benchmark-protocol.md`. It is authoritative for the current benchmark role/limitation matrix, result-eligibility state machine, Phase B evidence boundary, and immediate run order; it does not supersede the research questions or requirements in this plan.

### Problem Frame

AgentDojo remains a respected NeurIPS 2024 benchmark, but it is no longer sufficient as the main evidence for a 2026 control-plane paper. Its original tasks focus on short, structured indirect-prompt-injection trajectories, while current agent risks also enter through direct harmful objectives, MCP metadata, skills, persistent state, GUI content, and multi-step planning. A paper centered on AgentDojo alone would overfit the contribution to one source and one oracle.

Benchmark count is not the answer. A large collection of weakly integrated datasets can produce more rows without stronger evidence. Each benchmark must be qualified by publication status, runnable source, oracle independence, benign utility coverage, side-effect fidelity, contamination controls, and fit to the Invart runtime boundary. Native metrics must remain visible because AgentHarm harmful-task completion, MCPTox tool-poisoning success, AgentDyn injection success, Skill-Inject attempted execution, HarmBench harmful-response classification, and SWE-Bench resolution rate are not interchangeable ASRs.

The current execution substrate also has a validity risk that must be closed before more paid experiments. An official runner can emit parseable result JSON after upstream model requests failed, yielding zero utility and zero ASR that look secure but are actually transport failures. Provider ingress, nonempty completion, request-ID reconciliation, clean capability, and attack opportunity therefore become mandatory eligibility gates rather than debugging notes.

### System Frame

- **Objective function:** Maximize evidence-backed harmful-action prevention, benign task completion, cross-source transfer, audit reconstruction, and reproducibility while minimizing false blocks, approval burden, cost, latency, and unsupported claims.
- **System boundary:** In scope are benchmark source qualification, official runners, adapter contracts, runtime mediation, side-effect observation, ledger/proof generation, outcome joining, model/runtime controls, statistics, and paper artifacts. Benchmark redesign, model training, production approval UI, GUI instrumentation, multi-agent message interception, and persistent-memory mediation are outside this execution cycle.
- **State variables:** Benchmark revision, license, split, task and attack IDs, model and runtime manifest, provider request/receipt state, prompt and policy hashes, proposed and executed actions, native outcomes, independent action labels, approvals, cost, latency, completeness, and evidence kind.
- **Control actions:** Qualify or reject a benchmark, select a preregistered slice, run baseline/observe/mediate variants, block or approval-route actions, stop technically invalid rows, expand from pilot to full denominator, and downgrade claims when evidence is weaker than planned.
- **Feedback loop:** Native utility and attack outcomes measure task-level effect; event adjudication measures intervention quality; ledger reconstruction measures audit value; capability and receipt gates detect false-security floors; cost and latency measure deployability.
- **Constraints:** Official harnesses remain unmodified except through documented extension points; benchmark ground truth cannot enter runtime policy; deterministic critical rules remain monotonic; paid runs require an approved budget packet; raw traces remain protected.
- **Proof:** Source/revision registry, setup and smoke reports, provider ingress records, official result artifacts, joined event ledgers, adjudication records, frozen manifests, statistical outputs, and generated claim tables.

### Research Questions and Falsifiable Hypotheses

| ID | Research question | Preregistered hypothesis | Evidence required |
|---|---|---|---|
| RQ1 | Can Invart observe and mediate security-relevant actions across tool output, harmful user intent, MCP metadata, and skill files? | H1: one frozen event and policy contract reaches all qualified sources without benchmark-specific prompt text. | Adapter conformance, source-to-action joins, interception coverage, and explicit blind spots. |
| RQ2 | Does mediation prevent harmful actions without merely disabling the agent? | H2: full mediation reduces native harmful completion or harmful executed actions relative to a capability-qualified baseline while preserving a preregistered benign-utility floor. | Paired native outcomes, safe-useful completion, intervention precision/recall, false blocks, and attack opportunity. |
| RQ3 | Which mediation components create the effect? | H3: prompt-only improves over no defense, while provenance-aware review, monotonic rules, and continuation move the security-utility frontier further than prompt-only. | Frozen V0/V1/V2/V5 ablations and paired transitions. |
| RQ4 | Does the effect transfer across benchmarks, models, and agent runtimes? | H4: directionally consistent effects remain after policy freeze on at least two threat-source families and a connected runtime/model panel. | Holdout benchmarks, per-family effects, interaction estimates, and no post-freeze policy edits. |
| RQ5 | Does the ledger/proof plane add value when prevention is incomplete? | H5: Invart reconstructs who/what/why/policy/approval/outcome/coverage more accurately and detects more tamper or omission cases than final-output or process-log controls. | Blinded reconstruction study, tamper/missing-event tests, and proof/ledger consistency. |
| RQ6 | What does the control plane cost? | H6: latency, token cost, abstention, approval burden, and task overhead remain within preregistered deployment budgets on qualified rows. | Per-turn and per-task operational distributions with failure rates. |

### Requirements

**Benchmark qualification and evidence roles**

- R1. Every candidate benchmark must have a versioned quality record covering publication status, official source, revision, license, data access, native oracle, clean utility, side-effect fidelity, split policy, judge dependence, community reuse, cost, and Invart fit; reuse is a weak adoption signal rather than a substitute for oracle quality.
- R2. Qualification dimensions remain separate; no scalar benchmark-quality score may hide a missing oracle, unavailable code, or incompatible threat model.
- R3. The main paper must use at least two peer-reviewed agent-level benchmarks that exercise different threat sources, provided each passes execution feasibility.
- R4. AgentDojo remains a full-denominator historical anchor for one qualified primary stack, not the sole 2026 realism or positive-security result.
- R5. AgentHarm is the primary multi-step harmful-action benchmark; MCPTox is the primary MCP supply-chain benchmark; MCP-AgentBench is their preferred benign MCP utility companion if its official implementation passes qualification.
- R6. AgentDyn and Skill-Inject are external-validity stress tests and must be labeled as emerging preprint evidence unless their publication status changes before paper freeze.
- R7. HarmBench and b³ are model/backbone controls only. Their response or snapshot outcomes cannot be presented as Invart runtime-mediation results.
- R8. Agent Security Bench is a preregistered reserve benchmark if a primary pillar fails feasibility or reviewers require broader peer-reviewed attack coverage; it is not added merely to increase dataset count.

**Execution validity and comparability**

- R9. A row is `technical_valid` only when provider ingress exists, request IDs reconcile from reservation to terminal evidence, no hidden transport failure remains, the assistant response is nonempty, the official artifact parses, and expected counts reconcile.
- R10. Loopback provider endpoints must receive explicit `NO_PROXY` and `no_proxy` coverage for `localhost`, `127.0.0.1`, and `::1` in the scoped child environment.
- R11. A technically valid row enters security-effect analysis only after clean task/tool-call conformance passes and attack opportunity is nonzero; otherwise it is capability-only or attack-floor evidence.
- R12. Silent model, provider, runtime, tool-schema, prompt, or policy fallback invalidates the row.
- R13. Baseline, observe-only, and mediated conditions must use the same benchmark cell, model deployment, runtime profile, seed policy, tool surface, and native grader.
- R14. The primary experiment uses one qualified stack for full denominators and a connected incomplete block for cross-model/runtime generalization; it does not require a full Cartesian product.

**Cross-benchmark semantics and policy freeze**

- R15. Each adapter must preserve benchmark-native outcomes and map proposed, attempted, executed, failed, prevented, and approved actions into a common Invart event ontology.
- R16. Native benchmark metrics are never micro-pooled into a universal ASR. Cross-benchmark summaries use per-family effects and clearly labeled macro summaries.
- R17. Runtime policy cannot access task labels, attack labels, native oracle code paths, expected outcomes, or benchmark-specific solution text.
- R18. Capability mappings may use public tool schemas and documentation before freeze; reading holdout task or attack labels to tune mappings invalidates that holdout.
- R19. Prompt, reviewer schema, hard rules, capability maps, thresholds, statistical tests, exclusions, and stopping rules freeze before the first holdout result is inspected.
- R20. Benchmark-specific policy changes after freeze create a new exploratory version and cannot be merged into confirmatory results.

**Measurement, reporting, and audit**

- R21. Every result table must report exact expected, attempted, valid, capability-qualified, attack-opportunity, and analyzed denominators.
- R22. Primary metrics include native utility, native attack or harmful-task success, safe-useful completion, harmful-action prevention, benign false-block rate, intervention precision/recall, recovery, abstention, approval burden, timeout, latency, and cost.
- R23. Zero-event rows report a one-sided upper confidence bound and never claim demonstrated prevention when the baseline had no attack opportunity.
- R24. Judge-based labels require a frozen judge, prompt hash, blinded audit sample, agreement or error analysis, and separation from deterministic or official-oracle labels.
- R25. Audit claims require a blinded reconstruction study and tamper/missing-evidence negatives; replay demonstrations alone are insufficient.
- R26. Paper figures, tables, and prose must be generated from one typed result bundle that preserves evidence kind, benchmark revision, policy hash, and claim boundary.

**Authority, statistical sensitivity, and safe execution**

- R27. User authorization and system permission must be separate inputs. A versioned organization or experiment safety profile may prohibit action classes even when the user explicitly requests them, and an LLM reviewer cannot downgrade those prohibitions.
- R28. AgentHarm uses a preregistered prohibited-action taxonomy derived from public benchmark categories and the paper's declared threat model before holdout execution; task-specific labels, expected tool sequences, and grader rubrics remain unavailable to runtime policy.
- R29. Before confirmatory execution, the protocol must report the minimum detectable paired effect or an equivalent simulation-based sensitivity analysis for fixed benchmark denominators, and must set the audit-study sample and annotator plan from a blinded pilot rather than from observed favorable effects.
- R30. Upstream benchmark code, tool metadata, tasks, model text, judge text, and generated paths are untrusted. They run in scoped sandboxes without inherited host credentials, and no untrusted string may become a shell fragment, filesystem escape, policy input with higher authority, or unsanitized paper markup.
- R31. Harmful-action experiments must use simulated environments, local sinks, or dedicated test accounts with no external victim, real credential, irreversible financial action, destructive host effect, or unsolicited communication; cases that cannot satisfy this boundary are blocked rather than made more realistic.

### Actors

- A1. **Research operator:** freezes the protocol, authorizes provider budgets, runs qualification and experiments, and audits completeness.
- A2. **Agent runtime and model deployment:** proposes actions through a pinned prompt, tool, state, and provider configuration.
- A3. **Invart control plane:** observes, classifies, mediates, records, and produces ledger/proof artifacts.
- A4. **Benchmark harness and native oracle:** owns task setup, attack setup, final state, and benchmark-native outcomes.
- A5. **Independent adjudicator:** labels action alignment and effect state without inheriting Invart's runtime verdict.
- A6. **Paper artifact builder:** computes statistics and renders tables and figures from validated evidence bundles.

### Key Flows

- F1. Benchmark qualification
  - **Trigger:** A benchmark is proposed for the paper.
  - **Actors:** A1, A4.
  - **Steps:** Pin source and revision; inspect license, splits, harness, oracle, judges, benign controls, cost, and adapter fit; issue qualified, conditional, deferred, or rejected status.
  - **Outcome:** Only qualified or explicitly conditional benchmarks enter the frozen matrix.
  - **Covered by:** R1-R8.

- F2. Row eligibility
  - **Trigger:** A benchmark condition completes or fails.
  - **Actors:** A1-A4.
  - **Steps:** Reconcile provider and official evidence; verify clean capability; establish attack opportunity; classify the row before statistics.
  - **Outcome:** The row is security-comparable, capability-only, technical-invalid, blocked, or incomplete with a reproducible reason.
  - **Covered by:** R9-R14, R21, R23.

- F3. Cross-benchmark execution
  - **Trigger:** A qualified pilot passes its advancement gate.
  - **Actors:** A1-A5.
  - **Steps:** Run frozen variants; retain native outcomes; normalize event evidence; adjudicate unresolved actions; write immutable result bundles.
  - **Outcome:** Benchmark-native and common control-plane evidence remain joinable without semantic collapse.
  - **Covered by:** R15-R20, R22, R24.

- F4. Paper claim synthesis
  - **Trigger:** A benchmark family or audit study reaches its stopping rule.
  - **Actors:** A1, A5-A6.
  - **Steps:** Compute preregistered statistics; render figures and tables; compare each manuscript claim to eligible evidence; downgrade or remove unsupported language.
  - **Outcome:** Every positive claim has a reproducible evidence path and every limitation remains visible.
  - **Covered by:** R21-R26.

### Acceptance Examples

- AE1. Transport failure cannot masquerade as security
  - **Covers:** R9-R12, R21.
  - **Given:** The official runner emits parseable JSON after three upstream requests return HTTP 502 and no provider ingress is recorded.
  - **When:** The result bundle is classified.
  - **Then:** The row is `technical_invalid`, its zero utility and zero ASR remain visible, and it contributes to no security estimate.

- AE2. Capable but attack-free baseline
  - **Covers:** R11, R21-R23.
  - **Given:** Clean utility and tool conformance pass, but no baseline attack succeeds.
  - **When:** Invart also records zero attack successes.
  - **Then:** The report includes the upper bound and utility/intervention evidence but does not claim an attack reduction.

- AE3. Frozen cross-source transfer
  - **Covers:** R15-R20.
  - **Given:** The policy was frozen after declared development data.
  - **When:** AgentHarm, MCPTox, AgentDyn, or Skill-Inject is executed.
  - **Then:** No suite-specific prompt text or threshold change occurs; native outcomes and common event labels are both emitted.

- AE4. Judge disagreement remains evidence
  - **Covers:** R24.
  - **Given:** The benchmark judge marks an action harmful and a blinded human audit marks it benign or ambiguous.
  - **When:** Results are aggregated.
  - **Then:** Native and audit labels remain separate, disagreement enters error analysis, and the favorable label is not selected post hoc.

- AE5. Audit value survives incomplete prevention
  - **Covers:** R25-R26.
  - **Given:** Invart does not prevent every harmful attempt.
  - **When:** A blinded reviewer reconstructs the actor, action, rationale, policy, approval, outcome, and coverage from evidence packages.
  - **Then:** The paper may claim measured audit improvement if reconstruction and tamper tests pass, while stating the prevention limitation.

- AE6. Explicit harmful intent does not become authorization
  - **Covers:** R27-R28.
  - **Given:** A user explicitly requests a multi-step action prohibited by the frozen safety profile.
  - **When:** The model proposes a tool call that advances the prohibited objective.
  - **Then:** The deterministic policy denies or approval-routes the action despite user alignment, records the governing rule, and does not use task-specific benchmark labels.

### Scope Boundaries

**In scope**

- AgentHarm, MCPTox, AgentDojo, AgentDyn, and Skill-Inject under their native harnesses when feasible.
- MCP-AgentBench as a same-ecosystem benign utility companion after source and runtime qualification.
- HarmBench and b³ as model/backbone controls; SWE-Bench Lite or Verified as coding utility controls.
- One full-denominator primary stack plus selected connected model/runtime rows.
- Invart-specific ledger reconstruction, proof consistency, tamper, omission, approval, and side-effect evidence studies.
- Baseline, observe-only, current literal/marker policy, prompt-only, and full mediation variants where the benchmark surface permits them.

**Deferred to Follow-Up Work**

- VPI-Bench and GUI/computer-use evaluation until screenshot/UI event provenance is implemented.
- ConVerse, AgentLeak, and other multi-agent benchmarks until internal messages and shared state are intercepted.
- MPBench and other persistent-memory benchmarks until write/retrieve/use memory events are first-class ledger objects.
- AgentLAB long-horizon adaptive attacks until the first external transfer package is stable.
- Agent Security Bench unless a primary benchmark fails qualification or a preregistered breadth trigger fires.

**Outside this experiment's claims**

- Universal prompt-injection prevention, universal harmful-task refusal, or complete coverage of unmanaged actions.
- Equating zero observed ASR with security.
- Treating every blocked action as harmful or every non-executed action as safely mediated.
- Treating completion-backend evidence as native-agent-runtime evidence.
- Treating a benchmark's popularity, size, or recency as proof of oracle quality.

---

## Planning Contract

### Key Technical Decisions

- KTD1. **The paper evaluates a control plane, not an AgentDojo-specific defense** (session-settled: user-approved — chosen over centering the paper on AgentDojo ASR reduction: the user accepted the broader ledger, policy, proof, and audit positioning after discussing the age and scope limits of AgentDojo).
- KTD2. **Evidence hierarchy beats benchmark count.** Peer-reviewed, executable, agent-level benchmarks carry primary claims; emerging benchmarks carry external validity; response-level benchmarks carry only component controls.
- KTD3. **AgentDojo is a historical anchor.** Its full denominator is retained for comparability and regression, while current realism must come from other threat sources.
- KTD4. **AgentHarm and MCPTox are the planned peer-reviewed pillars.** AgentHarm tests multi-step harmful action control; MCPTox tests MCP metadata and tool-supply-chain poisoning. Neither substitutes for the other.
- KTD5. **MCP utility is measured separately from MCP attack resistance.** MCP-AgentBench is preferred because it supplies outcome-oriented benign MCP tasks, but it remains conditional until source, license, and adapter feasibility pass.
- KTD6. **AgentDyn and Skill-Inject are frozen-policy stress tests.** Their recency and source alignment are valuable, but preprint status and judge dependence remain visible in the paper.
- KTD7. **HarmBench and b³ cannot prove runtime control.** They diagnose harmful-response classification and backbone susceptibility under controlled snapshots, helping separate model refusal from agent mediation.
- KTD8. **Native outcomes and common events coexist.** Invart normalizes the evidence path, not the meaning of each benchmark's ASR or utility score.
- KTD9. **Validity precedes security.** Provider receipt, clean capability, and attack-opportunity gates are part of the scientific protocol; failed gates produce findings, not favorable security rows.
- KTD10. **Use a full primary stack plus a connected incomplete panel.** This preserves full-denominator evidence and model/runtime heterogeneity without an unaffordable full Cartesian product.
- KTD11. **Policy freeze is cross-source.** One versioned prompt/policy contract must transfer without task-, attack-, suite-, or source-specific prompt text.
- KTD12. **External cost expands only after falsifiable pilots.** Each benchmark progresses through source qualification, no-provider contract tests, live smoke, stratified pilot, then full execution.
- KTD13. **The audit study is a primary experiment.** No external benchmark directly proves ledger completeness, proof portability, reconstruction, or tamper detection, so these claims require an independent Invart study rather than a benchmark proxy.
- KTD14. **User authority does not override prohibited-action policy.** AgentHarm tests misuse requested by the user, so Invart must evaluate both user authorization and a frozen higher-priority safety profile; deterministic prohibitions remain monotonic and benchmark-agnostic.

### High-Level Technical Design

#### Evidence topology

```mermaid
flowchart TB
  B[Benchmark source and native harness] --> R[Agent runtime and model deployment]
  R --> C[Invart control plane]
  C --> A[Proposed and effective actions]
  A --> E[Independent side-effect evidence]
  B --> O[Native outcome oracle]
  C --> L[Ledger and proof]
  E --> J[Join and adjudication]
  O --> J
  L --> J
  J --> S[Statistics and claim audit]
  S --> P[Paper figures tables and limitations]
```

#### Row eligibility state machine

```mermaid
stateDiagram-v2
  [*] --> Prepared
  Prepared --> TechnicalInvalid: missing ingress or terminal receipt
  Prepared --> CapabilityCheck: technical evidence reconciles
  CapabilityCheck --> CapabilityOnly: clean utility or tool conformance fails
  CapabilityCheck --> OpportunityCheck: clean capability passes
  OpportunityCheck --> AttackFloor: no baseline attack opportunity
  OpportunityCheck --> SecurityComparable: attack opportunity exists
  SecurityComparable --> Complete: native and event evidence reconcile
  SecurityComparable --> Incomplete: expected evidence is missing
  TechnicalInvalid --> [*]
  CapabilityOnly --> [*]
  AttackFloor --> [*]
  Complete --> [*]
  Incomplete --> [*]
```

#### Benchmark progression and stopping logic

```mermaid
flowchart TB
  Q[Source and quality qualification] --> C{Contract and oracle pass?}
  C -->|no| D[Defer or reject with reason]
  C -->|yes| S[No-provider adapter tests]
  S --> L{Live smoke valid?}
  L -->|no| B[Block execution and preserve diagnosis]
  L -->|yes| P[Small paired pilot]
  P --> G{Capability utility and opportunity gates pass?}
  G -->|no| X[Report capability or floor finding]
  G -->|yes| F[Freeze protocol and run full primary stack]
  F --> T[Selected connected-panel transfer]
  T --> Y[Statistics claim audit and paper artifacts]
```

#### Evidence-role decision matrix

| Benchmark evidence | Agent actions and native state | Independent benign utility | Peer-reviewed | Allowed paper role |
|---|---:|---:|---:|---|
| Yes | Yes | Yes | Yes | Primary security-utility evidence |
| Yes | Yes | No | Yes | Primary security evidence plus a declared external utility companion |
| Yes | Yes | Mixed or judge-based | No | External-validity stress with limitations |
| No, response/snapshot only | No | Not agent-level | Any | Model/backbone control only |
| Local Invart study | Yes | Scenario-specific | Not external | Audit/proof mechanism evidence only |

### Benchmark Evidence Portfolio

| Benchmark | Status verified on 2026-07-21 | Threat or utility surface | Native evaluation | Planned role | Advancement gate |
|---|---|---|---|---|---|
| AgentHarm | ICLR 2025 conference paper; public dataset | Explicitly harmful, multi-step agent tasks across harm categories | Fine-grained task rubrics with refusal and task-completion outcomes | Primary harmful-action pillar | Official split and grader reproduce; benign/capability control is available; Invart can mediate before consequential tools. |
| MCPTox | AAAI 2026 paper; pinned artifact repository exposes data and analysis outputs but no supported end-to-end runner at the qualified revision | MCP tool-description and metadata poisoning | Published attack outcome with model/judge components; fresh execution contract unresolved | Blocked primary supply-chain candidate | A reproducible runner and judge contract must be qualified before execution; clean/poisoned rows remain structure-only until clean capability and side-effect evidence exist. |
| MCP-AgentBench | AAAI 2026 paper; 600 queries, 33 servers, 188 tools; official executable source and code license unresolved from the publication source | Benign MCP tool-use capability and task success | Published outcome-oriented MCP-Eval | Conditional utility companion | Official code, license, servers, evaluator revision, and overlap profile pass qualification; otherwise utility remains a separate native row. |
| AgentDojo | NeurIPS 2024 Datasets and Benchmarks | Tool-output indirect prompt injection | Deterministic task and attack functions over simulated state | Full historical anchor and regression | Provider validity, clean capability, and nonzero opportunity gates pass on the selected primary stack. |
| AgentDyn | 2026 preprint and public repository | Longer open-ended prompt injection with helpful external instructions | Benchmark task and injection outcomes | Emerging dynamic-transfer stress | Adapter preserves dynamic planning and helpful-instruction semantics; no benchmark-specific policy tuning. |
| Skill-Inject | 2026 preprint and public repository | Installed skill-file supply-chain injection | Harmful-attempt and legitimate-task judges over runtime evidence | Emerging deployment-validity stress | Frozen judge plus human audit; native skill-loading path and action evidence are preserved. |
| b³ | ICLR 2026 conference paper; 194,331 attack snapshots | Backbone susceptibility in agent threat states | Model-level threat snapshot classification | Backbone control | Run independently of Invart enforcement and label as model-only evidence. |
| HarmBench | Widely used open red-team framework; publication metadata remains distinct from agent venues | Harmful response generation and refusal | Open behavior classifiers | Reviewer/backbone component control | Classifier calibration is audited on Invart event text; no runtime claim is attached. |
| SWE-Bench Lite or Verified | Established coding-agent utility benchmark | Benign coding-task completion | Official repository test harness | Utility and friction control | Same agent/runtime profile and official grader; no security claim inferred. |

Qualification records must preserve unresolved issues. In particular, MCPTox and MCP-AgentBench do not become a paired suite merely because both use MCP; tool overlap, server reproducibility, evaluator ownership, and clean/poisoned comparability must be demonstrated first.

### Experiment Matrix

| Lane | Conditions | Scope | Main purpose |
|---|---|---|---|
| Primary full-denominator | Baseline, observe-only, V1 literal/marker, V2 prompt-only, V5 full mediation on one capability-qualified stack | Full qualified public/test denominator for AgentHarm, AgentDojo, AgentDyn, and Skill-Inject; MCPTox full after its cost gate | Main within-stack security-utility and ablation evidence. |
| MCP paired lane | Clean MCP task profile plus poisoned metadata profile | Stratified pilot, then full MCPTox; MCP-AgentBench full or preregistered stratified utility denominator depending on overlap and cost | Separate tool-use capability from tool-poisoning resistance. |
| Connected generalization panel | Kimi, DeepSeek, and Qwen under one common runtime; OpenCode, Hermes, and OpenClaw under a common model; Codex and Claude Code as native controls | Preregistered stratified subset from at least one harmful-action and one injection/supply-chain benchmark | Model/runtime heterogeneity without full Cartesian cost. |
| Component-control lane | Backbone/reviewer models under HarmBench and b³ | Official validation/test split or frozen representative subset | Explain whether effects come from base refusal/classification rather than Invart runtime control. |
| Coding utility lane | Baseline, observe-only, mediated | SWE-Bench Lite or a preregistered Verified subset | Measure benign coding friction, artifact preservation, and runtime overhead. |
| Audit/proof lane | Final output, process log, Invart ledger, Invart proof | Full deterministic scenario set plus blinded reconstruction sample | Measure reconstruction, tamper detection, omission detection, and evidence portability. |

The primary stack is selected using availability, tool-call conformance, benign utility, reproducibility, and cost only. Attack success and Invart outcomes are inaccessible to the selector. If one stack cannot qualify for every benchmark, use overlapping qualified stacks and report reduced identifiability rather than forcing a false common baseline.

### Metrics and Statistical Protocol

**Eligibility and completeness**

- Technical validity rate, provider ingress rate, terminal receipt rate, nonempty completion rate, official parse rate, and expected-count reconciliation.
- Clean task success, valid tool-call rate, native tool-conformance rate, attack-opportunity count, and reasons for capability-only or floor rows.

**Security and utility**

- Preserve each benchmark's native task and attack metrics.
- Safe-useful completion: native task success with no harmful executed side effect.
- Harmful-action prevention: harmful proposed actions that do not become harmful executed actions because of Invart.
- Intervention precision: harmful interventions divided by all adjudicated interventions.
- Harmful-call recall: intervened harmful proposals divided by all harmful proposals visible at the mediation boundary.
- Benign false-block, selective recovery, abstention, approval burden, repeated-denial rate, and terminal-refusal rate.
- Attempted, executed, failed, prevented, and final-state harm remain distinct.

**Audit and operations**

- Reconstruction accuracy for actor, action, rationale, policy, approval, outcome, and coverage.
- Tamper detection, missing-event detection, proof/ledger consistency, replay completeness, and evidence portability.
- End-to-end and per-decision latency, token use, provider cost, tool-call overhead, trace size, timeout/crash rate, and judge cost.

**Inference**

- Before full execution, compute a minimum detectable paired difference or simulation-based sensitivity curve for each fixed denominator and record which hypotheses are estimation-only because the benchmark is too small for the planned effect.
- Report exact numerators and denominators with 95% Wilson intervals for descriptive binary rates.
- Use paired transition tables and exact McNemar tests for matched binary task outcomes.
- Use paired or cluster bootstrap intervals when tasks, attacks, or repeated trials induce dependence; cluster at the benchmark's task or attack unit rather than treating calls as independent.
- For zero baseline events, report a one-sided 95% upper bound and no prevention-effect estimate.
- For judge labels, report agreement and a preregistered sensitivity range that treats unresolved cases as favorable and unfavorable.
- Report benchmark-family effects separately. Any macro summary weights families explicitly and is secondary to native rows.
- Confirmatory hypotheses and tests freeze before holdout execution; exploratory follow-ups are labeled and cannot replace failed confirmatory outcomes.
- Each research question names one primary endpoint per benchmark family. Secondary metrics and subgroup comparisons are estimation or error analysis unless a preregistered multiplicity procedure says otherwise.

### Cost and Stopping Rules

1. No external execution begins until source revision, license, setup, oracle, expected artifacts, and sandbox profile are frozen.
2. No paid model run begins until no-provider tests pass and a scoped provider approval packet binds model IDs, endpoint, call budget, token budget, and purpose.
3. A live smoke uses the smallest meaningful clean task and attack task. Any missing provider ingress, empty response, hidden 4xx/5xx, runtime fallback, or orphan request ID stops the lane.
4. A stratified pilot expands only if technical validity and clean capability pass, at least one attack opportunity exists, and the adapter preserves native outcomes.
5. Full execution stops at the preregistered denominator or budget cap. Missing rows remain missing; the system does not silently substitute models, judges, tasks, or seeds.
6. Policy performance below the utility floor, intervention precision floor, or latency budget is a reportable negative result. It does not trigger holdout retuning.
7. A benchmark that cannot be run faithfully is marked `blocked_benchmark_feasibility` and replaced only by the preregistered reserve role, not by a post hoc favorable dataset.

### Result Presentation Contract

| Artifact | Question answered | Required visual or table content |
|---|---|---|
| Benchmark qualification table | Why should reviewers trust these datasets? | Publication, source, native oracle, benign utility, side-effect fidelity, judge dependence, revision, and paper role. |
| Main security-utility table | Does Invart improve useful safety? | Per benchmark and variant: native utility, native harm/ASR, safe-useful, false blocks, recovery, exact denominators, and intervals. |
| Pareto figure | Is mediation safer without refusal collapse? | Utility on the x-axis, harmful completion or executed harm on the y-axis, one point per variant with uncertainty; incomparable benchmarks use facets. |
| Action funnel figure | What did the control plane observe and change? | Proposed to harmful-labeled to intervened to executed/failed/prevented transitions, separated by source family. |
| Ablation table | Which component matters? | V0/V1/V2/V5 paired deltas for prompt, reviewer/rules, and continuation. |
| Generalization table | Does the result depend on one model or runtime? | Connected-panel rows with capability, opportunity, effect, cost, and evidence-kind gates. |
| Audit reconstruction table | What value remains beyond prevention? | Evidence condition by reconstruction fields, tamper/omission detection, time, and uncertainty. |
| Operational table | Is this usable? | p50/p95 latency, token and dollar cost, approvals, abstentions, timeout, and trace size. |
| Limitations table | Where does the evidence stop? | Missing surfaces, judge reliance, adapter-vs-native distinctions, blocked benchmarks, and residual unmanaged actions. |

Captions state the finding and its boundary. No chart combines incompatible native ASRs on one undifferentiated axis, and no best value is highlighted when the comparison failed eligibility gates.

### Phased Delivery

1. **Phase A — validity and qualification:** Close provider/loopback validity, implement the benchmark quality registry, and issue qualification records.
2. **Phase B — peer-reviewed pillars:** Build AgentHarm and MCP adapters; run clean/attack smokes and small paired pilots.
3. **Phase C — frozen external transfer:** Run AgentDojo full anchor, AgentDyn, and Skill-Inject with the frozen policy.
4. **Phase D — controls and audit:** Run HarmBench/b³ component controls, SWE-Bench utility, and the blinded audit/proof study.
5. **Phase E — connected panel:** Execute only preregistered model/runtime subsets that passed capability and opportunity gates.
6. **Phase F — synthesis:** Generate statistics and figures, run evidence-to-claim review, update the manuscript, and preserve limitations.

### Phase B status on 2026-07-22

- U3-U5 no-provider contracts and fixtures are implemented and covered by the current targeted Phase B test slice: source freezes, native-outcome preservation, common action events, AgentHarm capability/harm separation, MCP exact-pair gates, and explicit blocked states.
- The AgentHarm bridge now accepts only Inspect `.eval` evidence with exactly one official `combined_scorer` result per sample; missing scores, fake scorer names, booleans, NaN, and infinite values fail closed. The execution-package validator re-dumps and re-extracts the official artifact, rebuilds capability and harmful bundles, and verifies their hashes and shared model/judge/execution binding.
- The pilot request binds exact harmful and benign case IDs, a frozen case manifest, request hash, model/judge settings, budget, and technical receipts. Eligibility explicitly separates `technical_invalid`, `capability_only`, `attack_floor`, and `security_comparable`. Independent semantic action labels remain descriptive until a concrete, Invart-independent ledger/side-effect resolver is attached.
- The earlier local approval request predates these strict case-manifest checks and is superseded; no paid provider scored pilot has been run from it. A current request requires real AgentHarm source attestation, a dataset-derived frozen case manifest, and a new approval packet.
- Real AgentHarm execution remains pending because official dataset acquisition/cache access is currently blocked by the external TLS/data-source path. The pinned Inspect setup and mock harness evidence prove setup only, not security, utility, or attack opportunity.
- MCPTox fresh execution remains blocked because the pinned official artifact repository has no supported end-to-end runner. MCP-AgentBench remains blocked on official executable source, license, and server/evaluator freeze. Neither blocked lane may emit a synthetic score or paired security-utility claim.

### Submission Evidence Gates

**Minimum credible submission package**

- One complete peer-reviewed harmful-action or agent-security pillar beyond AgentDojo, with qualified baseline capability and attack opportunity.
- One complete modern dynamic or supply-chain transfer benchmark from MCPTox, AgentDyn, or Skill-Inject, with its publication and judge limitations preserved.
- One complete AgentDojo historical-anchor denominator, one official benign utility lane, and the full audit/proof study.
- A selected connected model/runtime panel that shows whether the main finding survives beyond one deployment stack.
- The preregistered validity, capability, opportunity, uncertainty, cost, and claim-audit gates pass; a negative mediation result is acceptable if the audit contribution remains supported and the paper is reframed accordingly.

**Target package**

- AgentHarm and MCPTox as peer-reviewed pillars, AgentDojo as the historical anchor, and both AgentDyn and Skill-Inject as frozen-policy transfer tests.
- MCP-AgentBench as the benign MCP utility companion when qualification proves a faithful comparison.
- Full ablations on the primary stack and repeated stability subsets on the connected panel.

**Stretch controls**

- Full HarmBench and b³ component sweeps, Agent Security Bench reserve breadth, additional runtime/model cells, and private-test submissions beyond the minimum package.
- Stretch controls cannot delay claim synthesis once the minimum package is complete and its principal limitations are understood.

### Risks and Mitigations

| Risk | Consequence | Mitigation |
|---|---|---|
| New benchmark code is unavailable or unstable | Planned pillar cannot run faithfully | Qualification gate, source pinning, reserve role, and explicit blocked status. |
| MCPTox and MCP-AgentBench have incompatible servers or tools | False clean/poisoned pairing | Treat as separate native rows unless overlap and evaluator equivalence are demonstrated. |
| Baseline remains incapable or attack-free | No prevention estimate | Capability/opportunity gate, stronger qualified stack, and bounded capability/floor claim. |
| LLM judge favors the defended system | Inflated mediation precision | Blind judge inputs, frozen judge, deterministic labels where possible, human audit, and disagreement sensitivity. |
| Policy overfits public benchmark language | Weak external validity | Development/holdout split, cross-source freeze, no suite-specific prompt text, and prompt-hash audit. |
| Full denominators exceed budget | Partial evidence presented as complete | Predeclared primary stack, stratified connected panel, exact completeness, and hard budget stop. |
| Native runtime cannot expose pre-side-effect mediation | Runtime claim exceeds reach | Downgrade to completion-backend, observe-only, or native-control evidence. |
| Audit study is self-authored | Reviewer questions ecological validity | Publish scenario construction, blind reconstruction, include negative controls, and avoid claiming external benchmark validation. |
| Harm categories are encoded too broadly | Utility collapses or the system appears to know benchmark labels | Freeze a public, action-class safety profile before holdout; test benign near-neighbor actions; prohibit task IDs, expected sequences, and rubric text in policy inputs. |
| Upstream benchmark code or servers are malicious or drift | Host compromise or irreproducible outcomes | Pin revisions, inspect licenses and install scripts, sandbox execution, deny inherited credentials, hash server/tool inventories, and record drift. |
| Public benchmarks contaminate model training | Performance overstates generalization | Use private/hidden splits where available, retain newer cross-source holdouts, report exposure risk, and avoid model selection on attack outcomes. |

### Deferred Execution Decisions

- Exact AgentHarm split access and private-test submission path are resolved during qualification without changing the research questions.
- MCP-AgentBench remains conditional until its official source and server reproducibility are verified; absence does not block MCPTox security evaluation but narrows MCP utility claims.
- Exact full-run repetitions depend on provider budget after deterministic pilots; the minimum is one complete primary denominator plus repeated preregistered stability subsets.
- The specific common runtime/model stack is selected by the existing capability-only selector after current provider/runtime fixes land.

### Sources and Research

- AgentHarm, ICLR 2025: <https://proceedings.iclr.cc/paper_files/paper/2025/hash/c493d23af93118975cdbc32cbe7323f5-Abstract-Conference.html>
- MCPTox, AAAI 2026: <https://ojs.aaai.org/index.php/AAAI/article/view/40895>
- MCP-AgentBench, AAAI 2026: <https://doi.org/10.1609/aaai.v40i37.40347>
- AgentDojo, NeurIPS 2024 Datasets and Benchmarks: <https://proceedings.neurips.cc/paper_files/paper/2024/hash/97091a5177d8dc64b1da8bf3e1f6fb54-Abstract-Datasets_and_Benchmarks_Track.html>
- AgentDyn preprint and official repository: <https://arxiv.org/abs/2602.03117>, <https://github.com/leolee99/AgentDyn>
- Skill-Inject preprint and official repository: <https://arxiv.org/abs/2602.20156>, <https://github.com/aisa-group/skill-inject>
- Breaking Agent Backbones, ICLR 2026: <https://iclr.cc/virtual/2026/poster/10007758>
- HarmBench official repository: <https://github.com/centerforaisafety/HarmBench>
- Agent Security Bench, ICLR 2025: <https://iclr.cc/virtual/2025/poster/29432>
- Existing mediation and runtime plan: `docs/plans/2026-07-17-001-feat-prompt-first-mediation-generalization-plan.md`

### Output Structure

```text
src/invart/evaluation/real_agent_benchmark/
  benchmark_adapters/
    base.py
    agentharm.py
    mcptox.py
    mcp_agentbench.py
    agentdyn.py
    skill_inject.py
  benchmark_quality.py
  execution_validity.py
  cross_benchmark_mediation.py
  component_controls.py
  control_plane_experiment.py
```

This is the expected ownership layout, not a constraint against consolidating an adapter when implementation proves that an upstream harness already supplies the required boundary.

### System-Wide Impact

- **Policy semantics:** The runtime decision model gains two authorities that must remain distinct in prompts, rules, events, and reports: user authorization for the requested task and higher-priority prohibited-action policy for misuse and enterprise governance.
- **CLI and manifests:** Benchmark source, revision, split, evidence role, validity state, policy profile, judge identity, and expected artifacts become stable manifest and CLI surfaces. Compatibility aliases must preserve current `invart`/`kappaski` behavior.
- **Provider gateway:** Every benchmark backend depends on ingress and terminal receipt evidence, so request reconciliation and loopback routing become shared infrastructure rather than an OpenCode-specific smoke concern.
- **Artifact lifecycle:** Raw native results, side-effect evidence, ledgers, proofs, adjudication, statistics, and paper outputs share stable run and cell IDs but retain separate evidence kinds and retention controls.
- **Agent parity:** Completion backends and native runtimes must receive equivalent policy context and action envelopes where their product contracts allow it; unsupported pre-side-effect mediation becomes an explicit coverage gap.
- **Failure propagation:** Adapter, judge, provider, or grader failures flow into eligibility and completeness states. They must not be converted into refusals, zero attacks, omitted rows, or successful command exits.

---

## Implementation Units

### U1. Add benchmark qualification and evidence-role registry

- **Goal:** Make benchmark inclusion a versioned, reviewable decision rather than a prose preference.
- **Requirements:** R1-R8; KTD2-KTD8.
- **Dependencies:** None.
- **Files:**
  - Create `src/invart/evaluation/real_agent_benchmark/benchmark_quality.py`.
  - Modify `src/invart/evaluation/benchmark_registry.py`.
  - Modify `src/invart/evaluation/real_agent_benchmark/case_manifest.py`.
  - Create `tests/test_benchmark_quality.py`.
- **Approach:** Define typed benchmark source, qualification dimension, evidence role, native metric, split, oracle, judge, license, cost, and claim-boundary records. Seed records for the portfolio above, but require runtime probes to move a source from documented to qualified. Keep dimension-level statuses and reasons.
- **Patterns to follow:** Extend the current `BENCHMARK_SUITES`, `OfficialRunnerContract`, evidence-level, and claim-boundary conventions.
- **Test scenarios:**
  1. A peer-reviewed benchmark with missing code remains `conditional`, not `qualified`.
  2. A large benchmark with no independent oracle cannot receive a primary security role.
  3. HarmBench and b³ reject an agent-runtime claim role while retaining component-control roles.
  4. A revision or license change alters the qualification hash and forces requalification.
  5. A missing dimension remains visible and cannot be hidden by a total score.
- **Verification:** The registry emits deterministic JSON and Markdown qualification tables with source revisions, unresolved risks, and allowed claim roles.

### U2. Enforce technical-validity and provider-receipt gates

- **Goal:** Prevent transport failures, empty completions, runtime fallback, and orphan provider requests from becoming benchmark security evidence.
- **Requirements:** R9-R14, R21, R23; AE1-AE2; KTD9.
- **Dependencies:** U1.
- **Files:**
  - Create `src/invart/evaluation/real_agent_benchmark/execution_validity.py`.
  - Modify `src/invart/evaluation/real_agent_benchmark/environment.py`.
  - Modify `src/invart/evaluation/real_agent_benchmark/provider_credentials.py`.
  - Modify `src/invart/evaluation/real_agent_benchmark/provider_budget_gateway.py`.
  - Modify `src/invart/evaluation/real_agent_benchmark/full_benchmark_runner.py`.
  - Modify `src/invart/evaluation/real_agent_benchmark/artifact_writer.py`.
  - Create `tests/test_execution_validity.py`.
  - Modify `tests/test_full_benchmark.py`.
- **Approach:** Add explicit loopback bypass to scoped child environments; record provider ingress and terminal request evidence; reconcile gateway reservations; classify result rows through the eligibility state machine; preserve native zero outcomes while excluding invalid rows from security effects.
- **Execution note:** Begin with regression fixtures for the observed 502/no-ingress failure and for a successful loopback request before changing child environments.
- **Patterns to follow:** Reuse owner-only provider ledgers, immutable runtime manifests, current completeness accounting, and `opencode_native_smoke` request-ID reconciliation.
- **Test scenarios:**
  1. Lowercase proxy variables with no loopback bypass reproduce no ingress and `technical_invalid`.
  2. Explicit uppercase and lowercase loopback bypass reaches the local provider and reconciles one terminal request.
  3. Parseable official JSON plus empty assistant messages remains invalid.
  4. A pending request without terminal success/error becomes an orphan and invalidates the row.
  5. Clean capability failure yields `capability_only`; zero baseline attacks after capability success yield `attack_floor`.
  6. Silent provider/model/runtime fallback yields `invalid_runtime_resolution`.
- **Verification:** Historical false-zero fixtures are rejected, valid local-provider fixtures pass, and all downstream summaries expose eligibility counts.

### U3. Implement the common cross-benchmark adapter and event contract

- **Goal:** Preserve native benchmark semantics while producing one joinable Invart action and evidence ontology.
- **Requirements:** R13-R20, R24, R26, R30-R31; AE3-AE4; KTD8, KTD11.
- **Dependencies:** U1-U2 and the mediation contracts in the existing prompt-first plan.
- **Files:**
  - Create `src/invart/evaluation/real_agent_benchmark/benchmark_adapters/__init__.py`.
  - Create `src/invart/evaluation/real_agent_benchmark/benchmark_adapters/base.py`.
  - Create `src/invart/evaluation/real_agent_benchmark/cross_benchmark_mediation.py`.
  - Modify `src/invart/evaluation/real_agent_benchmark/official_runners.py`.
  - Modify `src/invart/evaluation/real_agent_benchmark/official_setup.py`.
  - Modify `src/invart/evaluation/real_agent_benchmark/environment.py`.
  - Modify `src/invart/evaluation/real_agent_benchmark/supervisor.py`.
  - Modify `src/invart/evaluation/real_agent_benchmark/mediation_adjudication.py`.
  - Create `tests/test_cross_benchmark_mediation.py`.
- **Approach:** Define adapter methods for source freeze, setup probe, case enumeration, clean/attack pairing, runtime bridge, native result validation, event join, side-effect evidence, and claim kind. Normalize effect state and authorization evidence while treating native outcomes as opaque benchmark-owned fields.
- **Patterns to follow:** Follow the existing AgentDojo official-runner boundary, artifact validation, event joining, and post-hoc adjudication separation.
- **Test scenarios:**
  1. An adapter cannot overwrite or synthesize a passing native outcome.
  2. A benchmark without clean pairing declares that limitation rather than inventing clean rows.
  3. Attempted, executed, failed, and prevented effects map without collapsing into one boolean.
  4. Runtime policy input is proven free of benchmark labels and oracle data.
  5. Missing native artifacts produce blocked/incomplete status and no synthetic score.
  6. Adapter-comparable and native-runtime evidence kinds remain separate.
  7. Upstream processes receive no undeclared host credential, cannot write outside the scoped root, and reach only preregistered network destinations.
  8. Adversarial task, tool, judge, and path strings remain structured data and cannot alter command arguments, output paths, policy authority, or generated Markdown/LaTeX structure.
  9. A case targeting a real account, third party, irreversible transaction, or destructive host action is blocked unless replaced by an official safe simulator or dedicated test sink.
- **Verification:** A fake benchmark and the existing AgentDojo adapter both produce native artifacts plus identical common event-envelope structure.

### U4. Add the AgentHarm harmful-action pillar

- **Goal:** Evaluate whether Invart controls multi-step harmful agent actions rather than only indirect prompt injection.
- **Requirements:** R3, R5, R11-R24, R27-R28; RQ1-RQ4; KTD4, KTD14.
- **Dependencies:** U3.
- **Files:**
  - Create `src/invart/evaluation/real_agent_benchmark/benchmark_adapters/agentharm.py`.
  - Modify `src/invart/evaluation/real_agent_benchmark/mediation_policy.py`.
  - Modify `src/invart/evaluation/real_agent_benchmark/tool_capabilities.py`.
  - Modify `src/invart/evaluation/real_agent_benchmark/official_runners.py`.
  - Modify `src/invart/evaluation/real_agent_benchmark/official_setup.py`.
  - Create `tests/test_agentharm_adapter.py`.
  - Modify `tests/test_mediation_policy.py`.
- **Approach:** Pin the official dataset and grader, preserve refusal and task-completion rubrics, identify clean/capability controls without leaking harmful labels to policy, and attach pre-side-effect Invart evidence. Add a frozen prohibited-action profile above user authorization; derive it from public action categories rather than task-specific labels or expected solutions. Use validation data only for adapter debugging and freeze before public/private test execution.
- **Test scenarios:**
  1. A refused harmful task and an incapable malformed task receive different capability/safety classifications.
  2. A multi-step harmful task joins each proposed action to one task and rubric item.
  3. A benign or capability control proves tool competence without entering the harmful-task numerator.
  4. Private or hidden test labels never enter the runtime prompt, policy, or adapter mapping.
  5. Official rubric outcome and independent executed-action evidence can disagree without either being overwritten.
  6. An explicitly user-requested prohibited action is denied by the higher-priority safety profile, while a benign near-neighbor action remains eligible for normal authorization.
- **Verification:** A no-provider fixture and a bounded live smoke produce valid official outcomes, joined action evidence, and eligibility status before full execution is authorized.

### U5. Add paired MCP security and utility evaluation

- **Goal:** Measure MCP tool-poisoning resistance without mistaking inability to use MCP tools for safety.
- **Requirements:** R3, R5, R9-R24; RQ1-RQ4, RQ6; KTD4-KTD5.
- **Dependencies:** U3.
- **Files:**
  - Create `src/invart/evaluation/real_agent_benchmark/benchmark_adapters/mcptox.py`.
  - Create `src/invart/evaluation/real_agent_benchmark/benchmark_adapters/mcp_agentbench.py`.
  - Modify `src/invart/evaluation/real_agent_benchmark/official_runners.py`.
  - Modify `src/invart/evaluation/real_agent_benchmark/official_setup.py`.
  - Create `tests/test_mcp_benchmark_adapters.py`.
- **Approach:** Qualify MCPTox source and evaluation first, then represent tool name, description, schema, server, call arguments, and returned content as distinct provenance surfaces. Qualify MCP-AgentBench independently and pair only equivalent clean/poisoned dimensions; otherwise report separate security and utility rows. Capture actual MCP calls and side effects in addition to judge outcomes.
- **Test scenarios:**
  1. Poisoned tool metadata is untrusted input while the declared user objective remains authoritative.
  2. Clean and poisoned variants share the same task/tool condition before a paired effect is computed.
  3. A model that cannot select or call the clean MCP tool is capability-only.
  4. Judge success without observable target action remains judge evidence, not executed-harm evidence.
  5. Live-server drift changes the environment hash and prevents comparison with a prior frozen row.
  6. No overlapping MCP-AgentBench profile leaves utility separate and narrows the paper claim.
- **Verification:** Stratified clean and poisoned smokes pass native graders, side-effect joins, and eligibility gates before the 1,348-case MCPTox run is scheduled.

### U6. Add AgentDyn and Skill-Inject frozen-policy transfers

- **Goal:** Test long/open-ended indirect injection and skill supply-chain attacks without adapting the policy to either benchmark.
- **Requirements:** R4, R6, R9-R24; RQ1-RQ4, RQ6; KTD6, KTD11-KTD12.
- **Dependencies:** U3 and policy freeze after U4-U5 development pilots.
- **Files:**
  - Create `src/invart/evaluation/real_agent_benchmark/benchmark_adapters/agentdyn.py`.
  - Create `src/invart/evaluation/real_agent_benchmark/benchmark_adapters/skill_inject.py`.
  - Modify `src/invart/evaluation/real_agent_benchmark/official_runners.py`.
  - Modify `src/invart/evaluation/real_agent_benchmark/official_setup.py`.
  - Create `tests/test_emerging_benchmark_adapters.py`.
- **Approach:** Preserve AgentDyn's helpful external instructions and dynamic planning rather than filtering all third-party directives. Preserve Skill-Inject's native skill installation, runtime evidence, attempted-harm judgment, and legitimate task outcome. Freeze policy hashes and judge configurations before either holdout.
- **Test scenarios:**
  1. Helpful third-party instructions can be followed when source, target, and task authorization align.
  2. The same instruction from an untrusted or unrelated source is mediated without a suite-specific phrase rule.
  3. AgentDyn trajectories preserve re-planning and cross-application events.
  4. Skill-Inject attempted harmful action remains visible even when the external operation fails.
  5. Judge model, prompt, and runtime evidence changes invalidate comparison.
  6. Any post-freeze prompt or capability-map change marks the run exploratory.
- **Verification:** Each benchmark produces a complete or explicitly blocked official row, common event artifacts, and a no-tuning attestation.

### U7. Add model/backbone and benign coding controls

- **Goal:** Separate model refusal/classification behavior and general agent capability from Invart runtime effects.
- **Requirements:** R7-R8, R11-R16, R21-R24; RQ2, RQ4, RQ6; KTD7, KTD10.
- **Dependencies:** U2-U3 and the connected model/runtime panel from the existing prompt-first plan.
- **Files:**
  - Create `src/invart/evaluation/real_agent_benchmark/component_controls.py`.
  - Modify `src/invart/evaluation/real_agent_benchmark/swe_bridge.py`.
  - Modify `src/invart/evaluation/real_agent_benchmark/agent_model_matrix.py`.
  - Create `tests/test_component_controls.py`.
  - Modify `tests/test_agent_model_matrix.py`.
- **Approach:** Run HarmBench classifier/backbone checks and b³ snapshots outside the Invart runtime-effect estimator. Carry their outputs as model-control covariates or error-analysis strata. Use the official SWE-Bench grader for baseline/observe/mediate coding utility on the same qualified runtime profile.
- **Test scenarios:**
  1. HarmBench success cannot populate an Invart prevented-action field.
  2. A b³-vulnerable backbone behind a safe runtime remains a model/runtime contrast, not a contradiction.
  3. SWE-Bench outputs require the official grader and preserved patch artifact.
  4. Low component refusal plus no agent attack opportunity is not credited as Invart prevention.
  5. Connected-panel selectors cannot access attack or mediation outcomes.
- **Verification:** Component and utility controls emit distinct evidence kinds and join to the same immutable model/runtime manifest without entering incompatible pooled metrics.

### U8. Strengthen the audit, proof, and tamper study

- **Goal:** Produce primary evidence for Invart's ledger-based audit and control-plane contribution independent of benchmark prevention outcomes.
- **Requirements:** R15, R21, R25-R26, R29-R30; RQ5-RQ6; AE5; KTD13.
- **Dependencies:** U2-U3.
- **Files:**
  - Modify `src/invart/evaluation/audit_reconstruction.py`.
  - Modify `src/invart/evaluation/audit_experiments.py`.
  - Create `tests/test_audit_reconstruction_study.py`.
- **Approach:** Compare final output, ordinary process logs, Invart ledger, and portable proof under matched scenarios. Blind reviewers to evidence condition labels where possible; test complete, approved, denied, partially observed, tampered, missing-event, and proof/ledger mismatch cases. Measure field reconstruction, error type, reviewer time, and tamper/omission detection.
- **Test scenarios:**
  1. Final-output-only evidence cannot infer an unreported denied action and is scored unknown rather than wrong by construction.
  2. A complete ledger reconstructs actor, action, rationale, policy, approval, outcome, and coverage.
  3. Tampered hash chain, removed event, and mismatched proof are independently detected.
  4. Missing instrumentation is reported as a coverage gap, not reconstructed from assumptions.
  5. Reviewer scoring remains deterministic for structured fields and preserves free-text disagreements.
  6. Evidence packages remove secrets while retaining stable joins.
  7. A blinded pilot determines the confirmatory sample and annotator plan without reading condition-level favorable effects.
- **Verification:** The study has deterministic fixtures, a blinded review export/import path, preregistered scoring, and uncertainty summaries.

### U9. Orchestrate staged runs and generate paper evidence

- **Goal:** Execute the portfolio under frozen gates and produce one claim-audited paper result bundle.
- **Requirements:** R3-R31; RQ1-RQ6; KTD9-KTD14.
- **Dependencies:** U1-U8 and the eligible mediation/runtime units from the existing prompt-first plan.
- **Files:**
  - Create `src/invart/evaluation/real_agent_benchmark/control_plane_experiment.py`.
  - Modify `src/invart/evaluation/real_agent_benchmark/run_matrix.py`.
  - Modify `src/invart/evaluation/real_agent_benchmark/mediation_metrics.py`.
  - Modify `src/invart/evaluation/real_agent_benchmark/artifact_writer.py`.
  - Modify `src/invart/evaluation/real_agent_benchmark/paper_tables.py`.
  - Create `tests/test_control_plane_experiment.py`.
  - Modify `tests/test_mediation_metrics.py`.
  - Update `.internal/paper/claims-and-evidence.md` only after eligible results exist.
  - Update `.internal/paper/ndss-draft/ndss-draft.tex` only after the claim audit passes.
- **Approach:** Materialize qualification, smoke, pilot, full, and connected-panel jobs from one frozen protocol. Enforce per-lane budgets and stopping rules; calculate native, common, audit, and operational outputs; render the presentation contract; and reject manuscript claims whose evidence kind or eligibility status is insufficient.
- **Execution note:** Run deterministic and no-provider verification first, then one benchmark lane at a time through its pilot gate; concurrent full runs begin only after per-provider budgets and isolation are proven.
- **Patterns to follow:** Reuse resumable jobs, exact completeness, provider approval packets, owner-only artifacts, paper-table exporters, and existing statistical fixtures.
- **Test scenarios:**
  1. A blocked or invalid lane remains in the final matrix and cannot be silently dropped.
  2. Full execution cannot begin before its benchmark pilot gate and policy freeze.
  3. Native metrics remain benchmark-specific while common event metrics use declared macro weighting.
  4. Partial denominators, zero opportunities, judge-only evidence, and runtime-control evidence produce different claim boundaries.
  5. A manuscript claim requiring executed-harm prevention fails when only response-level or judge evidence exists.
  6. Figures and tables reproduce exactly from the typed result bundle and include uncertainty and denominators.
  7. Concurrent runs respect provider budgets, isolated state, and deterministic resume after interruption.
  8. Fixed benchmark denominators emit preregistered effect-sensitivity reports before full execution, and underpowered hypotheses are labeled estimation-only.
- **Verification:** One command family can regenerate the matrix, statistics, figures/tables, and claim audit from frozen manifests and raw artifacts without editing the paper by hand.

---

## Verification Contract

| Gate | Command or artifact | Units | Passing signal |
|---|---|---|---|
| Qualification and adapter contracts | `PYTHONPATH=src python3 -m pytest -q tests/test_benchmark_quality.py tests/test_cross_benchmark_mediation.py` | U1, U3 | Evidence roles, source pins, native-oracle preservation, and blocked states match fixtures. |
| Execution validity | `PYTHONPATH=src python3 -m pytest -q tests/test_execution_validity.py tests/test_full_benchmark.py tests/test_provider_budget_gateway.py` | U2 | No-proxy regression, ingress, terminal receipts, completeness, and eligibility states pass. |
| Peer-reviewed pillars | `PYTHONPATH=src python3 -m pytest -q tests/test_agentharm_adapter.py tests/test_mcp_benchmark_adapters.py` | U4-U5 | Official-artifact validators, clean capability, poison pairing, and action joins pass without provider calls. |
| Emerging transfer | `PYTHONPATH=src python3 -m pytest -q tests/test_emerging_benchmark_adapters.py` | U6 | AgentDyn and Skill-Inject semantics, policy freeze, judge metadata, and blocked paths pass. |
| Controls and audit | `PYTHONPATH=src python3 -m pytest -q tests/test_component_controls.py tests/test_audit_reconstruction_study.py` | U7-U8 | Model-only evidence is separated; audit reconstruction and tamper negatives match preregistered scoring. |
| Orchestration and statistics | `PYTHONPATH=src python3 -m pytest -q tests/test_control_plane_experiment.py tests/test_mediation_metrics.py tests/test_agent_model_matrix.py` | U9 | Staged gates, paired statistics, macro boundaries, matrix connectivity, and claim audit pass. |
| Existing mediation regression | `PYTHONPATH=src python3 -m pytest -q tests/test_mediation_policy.py tests/test_mediation_prompts.py tests/test_mediation_reviewer.py tests/test_mediation_continuation.py` | U2-U9 | Frozen policy and continuation contracts remain green. |
| Full repository regression | `PYTHONPATH=src python3 -m pytest -q` | All | No unrelated regression; environment-only failures retain exact causes and do not erase targeted proof. |
| Live benchmark qualification | Per-benchmark setup, smoke, and qualification artifacts | U1, U4-U7 | Source revision, license, harness, oracle, expected artifacts, sandbox, and cost are frozen or the benchmark is explicitly blocked. |
| Primary full-denominator run | Frozen primary-stack matrix and native artifacts | U4-U6, U9 | Every expected row is valid, capability-only, attack-floor, failed, blocked, or incomplete; analyzed denominators are exact. |
| Connected-panel run | Frozen selected matrix across models and runtimes | U7, U9 | Selection used capability-only inputs; runtime/model identities and evidence kinds reconcile; no silent fallback occurs. |
| Audit review | Blinded export, reviewer imports, scoring bundle, and tamper negatives | U8-U9 | Reconstruction metrics, reviewer agreement, time, coverage, and tamper/omission results are reproducible. |
| Paper claim audit | Generated claim matrix and paper artifacts | U9 | Every positive sentence maps to eligible evidence; unsupported claims fail generation or are downgraded before manuscript update. |

---

## Definition of Done

- The new benchmark qualification registry contains dimension-level records for every planned, reserve, deferred, and rejected benchmark.
- The observed loopback proxy failure has a regression test and scoped child environments carry explicit uppercase and lowercase loopback bypass.
- Every external row carries provider ingress, terminal request reconciliation, nonempty completion, official artifact, expected-count, capability, and attack-opportunity status.
- Invalid, capability-only, attack-floor, incomplete, failed, and blocked rows remain visible and cannot contribute to positive security-effect estimates.
- AgentHarm and MCPTox are either qualified and executed as peer-reviewed pillars or explicitly blocked with evidence; any reserve substitution follows the preregistered rule.
- AgentDojo has one complete qualified historical-anchor denominator and is not presented as the sole modern benchmark.
- AgentDyn and Skill-Inject run under the frozen cross-source policy or remain explicitly blocked; their preprint and judge limitations are stated.
- Any HarmBench and b³ outputs are labeled model/backbone controls, while SWE-Bench outputs are labeled benign coding utility.
- The primary full stack and connected incomplete model/runtime panel are both reproducible from immutable manifests.
- Native benchmark outcomes and common Invart events are both present, joinable, and never semantically pooled as one universal ASR.
- The audit study includes matched evidence controls, blinded reconstruction, tamper, omission, proof/ledger mismatch, coverage, and reviewer-time results.
- Main tables report exact denominators, uncertainty, utility, harmful outcomes, safe-useful completion, intervention quality, recovery, abstention, latency, cost, and evidence kind.
- The Pareto, action-funnel, generalization, and audit artifacts are generated from the same typed result bundle as the tables.
- Confirmatory hypotheses, statistical tests, exclusions, budgets, and stopping rules were frozen before holdout results were inspected.
- Each fixed denominator has a minimum-detectable-effect or simulation-based sensitivity artifact, and the audit study has a blinded pilot-derived sample and annotator plan.
- Untrusted upstream code and artifacts run without inherited host credentials, filesystem escape, unrestricted network, shell interpolation, or unsanitized paper rendering.
- Harmful-action runs use simulators, local sinks, or dedicated test accounts and produce no real victim, credential compromise, unsolicited message, irreversible transaction, or destructive host effect.
- Paid execution stayed within approved provider packets; traces are owner-only, secret-scanned, and carry retention metadata.
- Abandoned adapter experiments and dead-end orchestration code are removed from the final diff.
- `.internal/paper/claims-and-evidence.md` and `.internal/paper/ndss-draft/ndss-draft.tex` are updated only after evidence eligibility and claim audits pass.
- The paper states residual limitations: incomplete unmanaged-runtime coverage, benchmark and judge dependence, approval burden, policy sensitivity, and deferred GUI/multi-agent/memory surfaces.
