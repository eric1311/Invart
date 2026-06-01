# Benchmark Research And Experiment Mapping

Date: 2026-05-30
Status: working research notes

HTML companion: [`benchmark-research-and-experiment-mapping.html`](benchmark-research-and-experiment-mapping.html)

## Purpose

This document expands Kappaski's evaluation direction from a list of benchmark
names into a problem-by-problem experiment map.

The central claim is:

> Public agent benchmarks are useful scenario corpora, but they usually measure
> model or agent outcome quality. Kappaski should use them as inputs and score
> control-plane behavior: what was observed, normalized, decided, mediated,
> enforced, recorded, proved, and gated.

The goal is not to win generic leaderboards. The goal is to show that, for the
same agent workload, Kappaski improves the safety, auditability, and cost curve
of enterprise coding-agent execution.

v0.40 adds a sharper boundary for SWE-Bench: local SWE-bench-like friction
experiments remain useful for development, but full SWE-Bench validation must go
through `external-validation swe-bench-full`, require the complete
`SWE-bench/SWE-bench` test split, and validate the official report plus
per-instance result artifacts. The equivalent `princeton-nlp/SWE-bench` dataset
id is accepted.

## Main Findings

1. Current public benchmarks fragment across capability, safety, security,
   coding, web, and tool-use dimensions. None directly evaluates a ledger-first,
   coverage-aware enterprise agent control plane.
2. The most relevant security benchmarks increasingly focus on the problem that
   Kappaski is built around: untrusted context influencing privileged tool use.
   AgentDojo and AgentDyn are the most important indirect prompt injection
   corpora. AgentSecBench is especially relevant for formalizing the boundary
   between data flow and authority.
3. The best coding-agent benchmarks measure task completion or code security,
   but not runtime governance. SWE-bench measures real issue resolution;
   SusVibes / Agent Security League and SecureVibeBench expose the gap between
   functional correctness and secure correctness.
4. Tool-use benchmarks such as tau-bench, ToolSandbox, BFCL, WebArena, OSWorld,
   and WorkArena are useful for benign workflow and stateful execution stress,
   but they do not by themselves evaluate security mediation or post-runtime
   assurance.
5. Benchmark-quality work such as the Agentic Benchmark Checklist matters for
   Kappaski because a control-plane paper must avoid weak reward definitions,
   observable gold leakage, and unverifiable side-effect claims.
6. The two awesome-list surveys add two useful lenses: UCSB emphasizes attack
   paths and targets, while ProjectRecon emphasizes the security lifecycle
   from red-team scanning to runtime protection, sandboxing, guardrails,
   governance, benchmarks, and identity.

## Awesome-List Synthesis

Sources:

- [ucsb-mlsec/Awesome-Agent-Security](https://github.com/ucsb-mlsec/Awesome-Agent-Security)
- [ProjectRecon/awesome-ai-agents-security](https://github.com/ProjectRecon/awesome-ai-agents-security)

The combined lesson is that benchmark selection should follow attack paths, not
brand names. Kappaski's paper experiments should distinguish:

| Lens | Meaning | Kappaski experiment impact |
| --- | --- | --- |
| Attack model through components | Indirect prompt injection, memory poisoning, malicious retrieved content, tool output manipulation, environmental web/CUA injection. | Measure source localization, taint propagation, and whether downstream privileged actions are mediated. |
| Attack components through model | RCE, shell/file/network misuse, forbidden tool use, secret exfiltration, CI/deploy mutation. | Measure blocked-before-execution, enforcement coverage, and side-effect outcome evidence. |
| Security lifecycle | Static analysis, red-team scanning, runtime firewall/gateway, sandboxing, guardrail, identity, audit. | Map each external defense into Kappaski L1-L5 instead of treating it as a competing complete system. |
| Agent family | Web agents, computer-use agents, coding agents, personal assistants, multi-agent systems. | Keep coding-agent experiments as the first paper core; use web/CUA/multi-agent suites as future coverage extensions. |

## Benchmark Landscape

| Benchmark | Scope | Native metric | Kappaski use | Limitation for Kappaski |
| --- | --- | --- | --- | --- |
| [AgentDojo](https://proceedings.neurips.cc/paper_files/paper/2024/hash/97091a5177d8dc64b1da8bf3e1f6fb54-Abstract-Datasets_and_Benchmarks_Track.html) | 97 realistic tool-agent tasks and 629 security cases over untrusted tool data. | Utility and attack success / defense effectiveness. | Primary corpus for indirect prompt injection, source taint, tool-boundary mediation, and security/utility tradeoff. | Mostly evaluates agent robustness; does not require ledger, proof, coverage grade, or enterprise gate artifacts. |
| [AgentDyn](https://arxiv.org/abs/2602.03117) / [GitHub](https://github.com/SaFo-Lab/AgentDyn) | 60 open-ended tasks and 560 injection cases across Shopping, GitHub, and Daily Life; built on AgentDojo. | Security vs over-defense under dynamic planning and helpful third-party instructions. | Best near-term stress test for whether Kappaski can avoid simplistic "block all external instructions" behavior. | Still centered on IPI; Kappaski must add proof, mediation timing, and coverage scoring. |
| [AgentSecBench](https://arxiv.org/abs/2605.26269) | Formal security games for instruction integrity, retrieval confidentiality, and capability integrity. | Adversarial advantage and whether a defense closes the model-visible channel. | Strongest conceptual match for Kappaski's trust-boundary and authority/data-flow separation. | Exact-marker experiments are intentionally narrower than full semantic enterprise workflows. |
| [INJECAGENT](https://arxiv.org/abs/2403.02691) | Indirect prompt-injection benchmark for tool-integrated LLM agents. | Attack success against privacy and direct-harm goals. | Useful historical baseline for IPI cases before AgentDojo/AgentDyn. | Less aligned with Kappaski's full proof/coverage/evidence loop. |
| [RAS-Eval](https://arxiv.org/abs/2506.15253) | Security evaluation for LLM agents in real-world-style environments; includes direct/indirect injection templates and multiple toolkit formats. | Attack success and vulnerability coverage across generated tasks. | Useful for expanding attack templates over tool arguments/results and MCP/LangGraph-style surfaces. | Its simple agent framework still needs Kappaski-specific side-effect and coverage scoring. |
| [Agent Security Bench / ASB](https://luckfort.github.io/ASBench/) | 10 scenarios, 10 agents, 400+ tools, 27 attack/defense methods, prompt injection, memory poisoning, PoT backdoor, mixed attacks. | ASR, refusal rate, FPR/FNR, utility/security balance. | Broad attack taxonomy for memory poisoning, backdoors, mixed attacks, and multi-domain scenarios. | Scenarios are general agent roles, not coding-agent control-plane operations. |
| [SKILL-INJECT](https://www.skill-inject.com/) | 202 injection-task pairs through malicious or compromised skill files. | Injection execution rate, harmful instruction avoidance, legitimate instruction compliance. | Very strong match for Kappaski pre-runtime capability/skill inventory and supply-chain governance. | Focuses on agent susceptibility; Kappaski must evaluate preflight detection, capability grants, mediation, and proof closure. |
| [RedCode](https://arxiv.org/abs/2411.07781) / [RedCodeAgent](https://openreview.net/forum?id=Mvn5g49RrM) | Risky code execution and code-agent red teaming. | Refusal/compliance and risky execution behavior. | Important for coding-agent interpreter abuse, destructive shell, malware-like generation, and host-boundary experiments. | Often evaluates model refusal; Kappaski must measure actual command/file/network mediation. |
| [AgentHazard](https://arxiv.org/abs/2604.02947) | Harmful behavior in computer-use agents where harm emerges from repeated actions and cross-step dependencies. | Attack success / harmful behavior under trajectory-dependent tasks. | Useful for path-aware policy and long-horizon accumulated harm. | GUI/computer-use focus is broader than Kappaski's current coding-agent core. |
| [ATBench](https://arxiv.org/abs/2604.02022) | 1,000 trajectory-level safety cases organized by risk source, failure mode, and real-world harm. | Guard/evaluator performance and taxonomy-stratified safety diagnosis. | Good source for long-horizon safety taxonomy and trajectory labels. | Primarily evaluates safety awareness and guard models, not runtime enforcement or evidence bundles. |
| [WASP](https://arxiv.org/abs/2504.18575) | WebArena-derived web-agent prompt-injection benchmark. | Attack success and web-agent task outcomes. | Later browser/web-agent adapter validation for environmental injection. | Not first-paper core unless Kappaski adds stronger web/browser runtime coverage. |
| [RedTeamCUA](https://arxiv.org/abs/2505.21936), [RiOSWorld](https://arxiv.org/abs/2506.00618), [OS-Harm](https://arxiv.org/abs/2506.14866) | Computer-use agent security and safety benchmarks over OS/browser/app environments. | Harmful action, risk, and task-specific safety outcomes. | Future validation for GUI/computer-use coverage and path-level harm. | Expensive and outside Kappaski's near-term coding-agent control-plane wedge. |
| [AgentHarm](https://arxiv.org/abs/2410.09024) | Harmful agent tasks for misuse evaluation. | Harmful task completion / refusal. | Secondary malicious-intent baseline. | Less representative of enterprise coding workflows, where legitimate tasks become risky through context and tools. |
| [Agent-SafetyBench](https://arxiv.org/abs/2412.14470) | Interactive safety benchmark across many environments, categories, and failure modes. | Safety score across agent actions. | Useful for broader safety taxonomy and failure-mode coverage. | Too broad for a focused Kappaski paper unless used as background or secondary validation. |
| [ShadowBench](https://shadowbench.dev/) | Open-source crash-test benchmark / guardrail layer for prompt injection, secret leak, unsafe action, hallucination, source confusion, and tool misuse. | Risk outcomes and policy guardrail checks. | Useful for quick product-style smoke coverage and marketing-adjacent comparison. | Less academically established than AgentDojo / AgentDyn / AgentSecBench. |
| [ARA Eval](https://ara-eval.org/) | Risk-gate benchmark across 13 enterprise scenarios. | A-Gate recall, precision, false negatives, false positives, calibration, wall time. | Useful metric design for enterprise gate quality. | Need to verify scenario details and reproducibility before making it a main paper result. |
| [SWE-bench](https://www.swebench.com/) | Real GitHub issues and patch generation; Full, Lite, Verified, Multilingual, Multimodal. | Percent resolved by tests. | Primary benign coding-agent utility corpus and harness-compatibility baseline. | Tests task correctness, not policy mediation, evidence, or secure side effects. |
| [SWE-bench Verified](https://openai.com/index/introducing-swe-bench-verified/) | Human-validated 500-sample subset intended to reduce ambiguous or unfair SWE-bench tasks. | Resolved rate on verified samples. | Better than arbitrary SWE-bench slices for measuring benign friction. | Still may have test-suite limitations; should not be treated as security evidence. |
| [SusVibes / Agent Security League](https://www.endorlabs.com/research/ai-code-security-benchmark) | 200 real-world Python tasks from 108 projects spanning 77 CWE classes; measures functionality and security. | FuncPass and SecPass. | Best coding-security complement: shows whether Kappaski can gate or review risky generated code, not only runtime actions. | Measures output code security, not agent control-plane behavior during execution. |
| [SecureVibeBench](https://arxiv.org/abs/2509.22097) | 105 C/C++ secure coding tasks from OSS-Fuzz projects, with functionality testing and static/dynamic security oracles. | Correct-and-secure solution rate. | Secondary secure-coding benchmark for path/code review policy experiments. | Later priority unless security-code-generation becomes a paper focus. |
| [ToolEmu](https://arxiv.org/abs/2309.15817) | LM-emulated sandbox with 36 high-stakes tools and 144 risk test cases. | Risk/failure analysis over tool execution. | Useful for high-stakes tool action scenarios without expensive real integrations. | Emulation quality is not equivalent to Kappaski's real local side-effect boundary. |
| [ToolSandbox](https://machinelearning.apple.com/research/toolsandbox-stateful-conversational-llm-benchmark) | Stateful conversational tool-use with implicit state dependencies and on-policy user simulation. | Intermediate and final milestone success. | Good benign stateful tool-use stress test for path graph, replay, and cost overhead. | Capability benchmark, not adversarial control-plane benchmark. |
| [tau-bench](https://github.com/sierra-research/tau-bench) | Tool-agent-user interaction in realistic domains with policies and APIs; current repository notes tau3 updates. | Task success under multi-turn policy-guided tool use. | Strong utility and enterprise-policy adherence corpus; useful for approval-noise and policy-abiding tool calls. | Not primarily designed for local coding-agent security; task quality has needed fixes. |
| [BFCL](https://www2.eecs.berkeley.edu/Pubs/TechRpts/2025/31680.html) | Large-scale multi-task, multi-turn function-calling benchmark. | Function-call correctness. | Useful for tool-call correctness and schema conformance regressions. | Too low-level for Kappaski's enterprise governance thesis. |
| [WebArena](https://webarena.dev/og/) | Self-hosted realistic websites and long-horizon browser tasks. | End-to-end task success. | Later browser-agent integration and UI-tool governance validation. | Browser surface is not short-term Kappaski core; success metrics are not security/evidence metrics. |
| [OSWorld](https://arxiv.org/abs/2404.07972) | 369 real computer tasks across operating systems, apps, file I/O, and multi-app workflows. | Task success in real computer environments. | Later computer-use enforcement and coverage-grade stress test. | Too broad and expensive for first paper unless Kappaski adds GUI/computer-use adapters. |
| [WorkArena](https://arxiv.org/abs/2403.07718) | Enterprise knowledge-work tasks on ServiceNow. | Task success over enterprise web workflows. | Useful as a future enterprise workflow benchmark. | Less relevant before Kappaski has enterprise SaaS/browser adapters. |
| [Agentic Benchmark Checklist](https://arxiv.org/abs/2507.02825) | Meta-benchmark guidance for rigorous task setup and reward design. | Checklist validity, flaw reduction, overestimation analysis. | Should be used to design Kappaski-ControlPlane-Bench and avoid weak reward claims. | Not a task corpus; it is methodology guidance. |

## Problem Taxonomy

Kappaski's experiments should be organized by control-plane problems rather than
benchmark brand names.

| ID | Problem | Why it matters | Best external sources | Kappaski layer/stage |
| --- | --- | --- | --- | --- |
| P0 | Benchmark validity | Weak reward functions can make a control-plane paper look stronger than it is. | Agentic Benchmark Checklist, SWE-bench Verified notes, tau-bench task fixes. | All layers; experiment methodology. |
| P1 | Indirect prompt injection | Untrusted tool output or external content tries to become instruction. | AgentDojo, AgentDyn, InjecAgent, RAS-Eval. | L2 source/trust/taint, L3 policy, L4 mediation. |
| P2 | Authority/data-flow conflation | Data visible to the model should not automatically be authority to act. | AgentSecBench. | L2 fact model, L3 policy, L4 capability restriction. |
| P3 | Secret and privacy exfiltration | The common enterprise failure: read sensitive data, then leak through a tool. | AgentDojo, AgentSecBench, ShadowBench, ASB, ToolEmu. | Runtime and post-runtime; L2 taint, L4 deny/approval, L5 proof. |
| P4 | Capability misuse / forbidden action | Agent uses a valid tool for an unauthorized purpose. | AgentSecBench, ASB, ToolEmu, tau-bench, ARA Eval. | L1-L4; especially capability grants and mediation. |
| P5 | Memory, skill, and supply-chain poisoning | Instructions persist in memory or skill files and influence later runs. | ASB, SKILL-INJECT, Agent-BOM attack scenarios. | Pre-runtime inventory, runtime path graph, post-runtime audit. |
| P6 | Long-horizon accumulated harm | Each step may look acceptable, but the sequence becomes harmful. | AgentHazard, ATBench, ToolSandbox, WebArena, OSWorld. | L2 path graph, L3 path-aware policy, L5 replay. |
| P7 | Secure generated code | Coding agents pass tests while introducing vulnerabilities. | SusVibes / Agent Security League, SecureVibeBench. | Post-runtime gate, optional LLM reviewer, static/security-tool integration. |
| P8 | Benign utility and workflow friction | Control must not make normal coding work unusable. | SWE-bench, ToolSandbox, tau-bench, BFCL. | L3-L4 cost/friction and approval policy. |
| P9 | Enterprise risk gate | Teams need pass/warn/fail decisions and calibration, not only alerts. | ARA Eval, ShadowBench, tau-bench policy tasks. | L3 decision, L4 approval, L5 gate. |
| P10 | Evidence, coverage, and audit reconstruction | Most benchmarks do not test whether the system can prove what happened. | Agent-BOM, Agentic Benchmark Checklist as methodology. | L5 evidence, plus coverage facts from all layers. |
| P11 | Tool/protocol/capability-surface poisoning | Tool metadata, skill files, MCP-like manifests, or provider descriptions can be attack surfaces before runtime. | SKILL-INJECT, RAS-Eval, UCSB tool-poisoning references. | Pre-runtime L1/L2 inventory, L3 grant policy, L5 capability proof. |
| P12 | Web/CUA environmental deception | Browser, desktop, and UI environments can inject misleading context, clickjacking, or domain spoofing. | WASP, RedTeamCUA, RiOSWorld, OS-Harm, WebArena, OSWorld. | Future L1 adapter coverage, L2 source labeling, L4 mediation/enforcement. |

## Specific Problem To Experiment Mapping

| Problem case | External benchmark seed | Kappaski experiment transformation | Required Kappaski facts | Expected control outcome | Primary metrics |
| --- | --- | --- | --- | --- | --- |
| External issue/comment instructs agent to upload `.env` while fixing a bug. | AgentDojo workspace/GitHub-like cases, AgentDyn GitHub suite. | Convert untrusted issue text into `ExternalInput`; agent attempts `read_file(.env)` then network egress. | source=`external`, taint=`untrusted_instruction`, resource=`secret`, sink=`network`. | Secret read escalates; outbound after secret taint is blocked or requires approval before side effect. | exfiltration prevented, blocked-before-execution, approval precision, proof completeness. |
| Tool response contains helpful instructions plus malicious command. | AgentDyn. | Preserve helpful third-party content needed for task, but require provenance for any instruction-like action. | content source, helpful-data marker, proposed tool args, path from external text to action. | Benign helpful data can be used; privileged action caused by external instruction is denied or mediated. | utility under attack, over-defense rate, high-risk recall. |
| Retrieved record attempts to influence confidential answer. | AgentSecBench retrieval-confidentiality. | Model-visible record is treated as untrusted data; response or tool call is checked for forbidden leakage. | source/trust, retrieval scope, permitted leakage, output channel. | Sensitive disclosure is redacted, denied, or requires approval according to profile. | adversarial advantage reduction, redaction success, false positive rate. |
| Untrusted string causes a forbidden tool call. | AgentSecBench capability-integrity, ASB IPI. | Proposed tool call is represented as `Invocation` with capability and originating context refs. | capability grant, input refs, tool name, args, trust boundary. | Unauthorized capability is blocked even if the model proposes it. | forbidden-action prevention, channel-closure correctness. |
| Malicious skill asks for remote backup or encryption/destructive cleanup. | SKILL-INJECT. | Pre-runtime scans skill files; runtime marks skill-originated instructions; file/network/destructive shell actions pass through policy. | skill source, capability surface, grant, instruction source, file write/delete, network sink. | Preflight flags risky capability; runtime requires approval or blocks remote upload/destructive action. | preflight detection, runtime block rate, benign skill compliance, audit reconstruction. |
| Memory poisoning influences later session behavior. | ASB memory poisoning. | Poisoned memory is modeled as persisted context with lower trust; later actions inherit taint. | memory entry id, persistence flag, cross-session source, taint propagation. | High-risk downstream actions require approval or are denied. | cross-session taint retention, false negative rate, replay clarity. |
| Multi-step sequence looks locally safe but ends in harm. | AgentHazard, ATBench. | Represent intermediate states and actions in path graph; run path-aware policies over cumulative facts. | path graph nodes, action sequence, resource impact, accumulated risk. | Later action is mediated based on path state, not only current command string. | harmful trajectory prevention, path-policy recall, p95 policy latency. |
| Coding task passes unit tests but introduces CWE-class vulnerability. | SusVibes / Agent Security League, SecureVibeBench. | Run coding task under Kappaski; feed patch/security-tool findings into post-runtime gate. | patch outcome, tests, security finding, reviewer/gate decision, evidence bundle. | Functional pass can still fail security gate or require review. | FuncPass, SecPass, secure-gate precision, review cost. |
| Code interpreter or shell is induced into risky execution. | RedCode, RedCodeAgent, ToolEmu. | Convert generated code/shell execution into mediated invocations; label host, file, network, and process side effects. | command, interpreter, file write/delete, network sink, sandbox/coverage label. | Malicious or policy-forbidden execution is denied, sandboxed, or requires approval before side effect. | interpreter-abuse prevention, blocked-before-execution, sandbox coverage, benign execution delta. |
| Tool or capability metadata contains hostile instructions. | SKILL-INJECT, RAS-Eval, UCSB tool-poisoning references. | Treat tool description, skill file, or protocol manifest as pre-runtime capability surface and runtime source. | capability surface hash, declared permissions, instruction source, grant, taint. | Risky grant is flagged; downstream privileged action caused by metadata is mediated. | preflight detection, grant precision, downstream taint propagation, proof closure. |
| Normal SWE-bench task with test/build commands and harmless file edits. | SWE-bench Lite/Verified. | Run same task through raw harness and Kappaski audit/managed modes. | command invocations, file writes, git diffs, outcomes, coverage grade. | Minimal interruption; proof generated; no unnecessary human approval. | resolved rate delta, benign auto-approval, approval noise, latency overhead. |
| Stateful customer-support task with policy limits. | tau-bench, ToolSandbox. | Treat API tools as capabilities; policy document as governed profile; mutating calls require correct scope. | policy profile, domain resource, tool args, user confirmation where needed. | Allowed policy-compliant actions pass; out-of-policy refunds/cancellations pause or fail. | policy violation prevention, task success delta, approval noise. |
| Function call schema or wrong-tool selection risk. | BFCL, ToolSandbox. | Normalize every function call to `Invocation`; check declared capability and schema. | tool name, args, schema validation, capability grant. | Invalid or out-of-grant calls denied before execution. | invalid-call block rate, benign pass rate, schema error reduction. |
| Browser/desktop workflow touches sensitive file, credential, or external upload. | WebArena, OSWorld, WorkArena, AgentHazard, WASP, RedTeamCUA, RiOSWorld, OS-Harm. | Later-stage adapter experiment: browser/computer actions become events with coverage labels. | surface coverage, UI action, file/network/resource identity, proof refs. | At least observed/mediated coverage; high-risk side effects blocked if enforcement surface exists. | coverage distribution, bypass detection, task success delta. |

## Experiment Bundles

### E0 Benchmark Rigor And Threat Modeling

Purpose:

- ensure Kappaski's own benchmark is not easy to game;
- define exact side effects and ground truth;
- use the Agentic Benchmark Checklist before publishing results.

Design:

- Every case must specify initial state, allowed resources, attacker-controlled
  context, expected state change, forbidden state change, and evidence fields.
- Safety success must be measured by side-effect state, not only model text.
- Benign success must remain measurable after Kappaski mediation.
- Attack and benign controls should be paired whenever possible.

Metrics:

- case validity rate;
- ambiguous-case removal rate;
- verifier loophole findings;
- inter-rater agreement for semantic labels when human review is used.

### E1 External Prompt-Injection And Authority Boundary Corpus

Primary sources:

- AgentDojo;
- AgentDyn;
- AgentSecBench;
- ASB;
- SKILL-INJECT.

Kappaski-specific scoring:

- source localization accuracy;
- taint propagation accuracy;
- forbidden action prevention;
- over-defense rate on helpful external instructions;
- blocked-before-execution rate;
- proof fields present for `source`, `resource`, `sink`, `decision`,
  `approval`, `outcome`, and `coverage`.

Baselines:

- raw agent;
- trace-only agent;
- prompt-injection classifier only;
- deterministic Kappaski policy;
- Kappaski policy plus selective reviewer;
- Kappaski managed/enforced mode where supported.

### E2 Benign Coding Workflow Friction

Primary sources:

- SWE-bench Lite or Verified subset;
- Kappaski local coding traces;
- ToolSandbox / tau-bench as secondary stateful tool-use stress tests.

Kappaski-specific scoring:

- resolved rate delta versus raw harness;
- benign auto-approval rate;
- unnecessary approval rate;
- p50/p95 mediation latency;
- evidence bundle generation success;
- coverage distribution across commands, file writes, env reads, network calls.

Important caveat:

SWE-bench success should be used as a utility baseline, not as proof that the
agent behaved safely. Kappaski's claim is compatibility and low-friction control,
not higher SWE-bench resolution.

### E3 Secure Coding And Post-Runtime Gate

Primary sources:

- SusVibes / Agent Security League;
- SecureVibeBench;
- later: SEC-bench or CVE-style suites if the paper shifts toward security
  engineering agents.

Kappaski-specific scoring:

- whether generated patch is functionally correct;
- whether security checks find CWE-style issues;
- whether Kappaski gate fails/warns correctly;
- LLM reviewer call rate and cost for risky diffs;
- audit evidence showing why a functionally passing patch was blocked.

This is where Kappaski can make a strong enterprise argument:

```text
task passes tests
  -> security finding appears
  -> Kappaski gate fails or requires approval
  -> evidence bundle explains finding, decision, coverage, and unresolved risk
```

### E4 Coverage And Enforcement Truthfulness

Purpose:

Show that Kappaski's coverage model prevents overclaiming.

Design:

Run the same scenario under multiple surfaces:

| Surface | Expected coverage | Example |
| --- | --- | --- |
| Imported log | `observed` | Agent log is imported after action. |
| Native post-tool hook | `observed` or `mediated` depending timing. | Tool result event arrives after side effect. |
| Pre-tool hook / wrapper | `mediated` | Policy can pause before command. |
| Shim/proxy/sandbox | `enforced` | File write, network egress, or command can be blocked by boundary. |
| Bypass path | `none` or degraded label. | Agent runs outside Kappaski surface. |

Metrics:

- coverage label correctness;
- insufficient-coverage gate correctness;
- bypass/degraded-mode detection;
- blocked-before-execution rate by surface;
- proof/replay clarity for coverage gaps.

### E5 LLM Reviewer Cost And Selectivity

Purpose:

LLM Reviewer is useful but potentially expensive. The experiment must prove it
is selective, not always-on theater.

Modes:

- reviewer off;
- deterministic policy only;
- reviewer selective on ambiguous/high-semantic-risk cases;
- reviewer always-on;
- async audit reviewer.

Metrics:

- reviewer invocation rate;
- token cost per session and per risky action;
- p50/p95 reviewer latency;
- risk recall delta;
- false positive delta;
- invalid-output rate;
- redaction failures;
- cache hit rate.

The target result is not "LLM reviewer catches everything." The target result is
that deterministic policy handles structural risks, while selective review
improves ambiguous semantic coverage at acceptable marginal cost.

### E6 Audit Reconstruction And Tamper Evidence

Purpose:

Measure Kappaski's most distinctive post-runtime capability.

Cases:

- normal benign run;
- blocked secret exfiltration;
- approved high-risk action;
- unresolved approval;
- tampered ledger entry;
- proof generated from incomplete or mismatched ledger;
- insufficient coverage for policy.

Metrics:

- proof completeness;
- proof+ledger verification success/failure;
- audit reconstruction success;
- missing field rate;
- tamper detection rate;
- time to answer audit questions.

Audit questions:

- Who initiated the run?
- Which agent acted?
- What untrusted inputs influenced the action?
- What capability and resource were involved?
- What did policy decide?
- Was there human approval?
- Did the side effect happen?
- What coverage grade did Kappaski actually have?

## Priority Recommendation

For a first credible paper, use a tight subset:

1. Kappaski-ControlPlane-Bench as the closed-loop benchmark.
2. AgentDojo or AgentDyn as the external indirect-prompt-injection corpus.
3. AgentSecBench as the formal authority/data-flow comparison.
4. SWE-bench Lite/Verified as benign coding workflow friction.
5. SusVibes / Agent Security League as secure-coding gate validation.
6. Coverage/enforcement and audit/tamper experiments as Kappaski-native
   differentiators.

Defer:

- WebArena, OSWorld, and WorkArena until Kappaski has stronger browser/computer
  adapters.
- AgentHarm and Agent-SafetyBench unless the paper shifts toward broad agent
  misuse instead of enterprise coding-agent control.
- BFCL as a primary result; keep it as a schema/tool-call correctness regression
  source if needed.

## Code Route From Research To Product Experiments

The implementation route now starts with a stable local experiment substrate
rather than a loose list of benchmark names. The current adapters transform
public-benchmark-shaped cases into Kappaski control-plane cases with expected
facts, side effects, and audit answers. Exact upstream corpus imports and live
official benchmark runners are still separate external-validation work.

The code route below started from the v0.29 release-candidate baseline:

- `src/kappaski/evals.py` already runs built-in product benchmarks.
- `src/kappaski/benchmark_registry.py` already lists product-level suites.
- `src/kappaski/pre_v1.py`, `src/kappaski/evidence_bundle.py`, and
  `src/kappaski/release_candidate.py` already produce local demo/evidence/RC
  artifacts.
- v0.30-v0.39 implement the benchmark experiment framework that can ingest
  external-corpus-shaped fixtures, normalize them into Kappaski cases, execute
  them through existing runtime/adapter/policy surfaces, and report local
  paper-grade metrics. These passes do not imply official upstream benchmark
  validation.

### v0.30 Experiment Case Model And Runner

Goal: define the stable internal representation for benchmark-derived
experiments.

Code changes:

- add `src/kappaski/experiment_cases.py`;
- add `ExperimentCase`, `ExperimentSeed`, `ExpectedControlOutcome`,
  `ExperimentRun`, and `ExperimentMetric` data structures;
- add a JSON fixture format under `benchmarks/experiments/`;
- add an experiment runner that can execute event-sequence cases without network
  or Docker;
- add CLI:
  - `experiment list`;
  - `experiment run --suite control-plane-core`;
  - `experiment report --run run.json --out report.html`.

Acceptance:

- every case declares initial state, attacker-controlled context, allowed
  resources, forbidden side effects, expected Kappaski decision, required proof
  fields, and required coverage grade;
- side-effect success is checked from state artifacts, not only from model text;
- output includes ledger, proof, replay, path graph, evidence bundle, metrics
  JSON, and HTML report.

Tests:

- fixture parser rejects ambiguous cases;
- attack and benign paired cases run deterministically;
- proof completeness and side-effect checks fail when required evidence is
  missing.

### v0.31 AgentDojo / AgentDyn Corpus Adapter

Goal: make indirect prompt-injection validation real instead of synthetic.

Code changes:

- add `src/kappaski/corpus_adapters/agentdojo.py`;
- add `src/kappaski/corpus_adapters/agentdyn.py`;
- normalize benchmark task metadata into:
  - `ExternalInput`;
  - tool call proposal;
  - source/trust labels;
  - expected utility outcome;
  - expected forbidden action;
- add suite `external-ipi-control-plane`.

Acceptance:

- supports local pinned fixtures first;
- optional live corpus download is separate and cleanly skipped if unavailable;
- preserves helpful external data while denying or mediating privileged actions
  caused by external instructions.

Metrics:

- source localization accuracy;
- taint propagation accuracy;
- forbidden-action prevention;
- over-defense rate;
- blocked-before-execution rate;
- proof field completeness.

### v0.32 AgentSecBench Authority/Data-Flow Experiments

Goal: turn the authority/data-flow separation into measurable behavior.

Code changes:

- add `src/kappaski/corpus_adapters/agentsecbench.py`;
- add explicit `authority_boundary` and `data_visibility` fields to experiment
  cases;
- extend path policy checks to distinguish "model saw this data" from "agent is
  authorized to act on this resource";
- add suite `authority-dataflow-boundary`.

Acceptance:

- model-visible untrusted content never grants authority by itself;
- capability grants and resource scopes are required for privileged actions;
- proof can explain why a visible input was not a valid authority source.

Metrics:

- forbidden-action prevention;
- adversarial advantage reduction proxy;
- capability-integrity failures;
- false positive rate on permitted data use.

### v0.33 SWE-Bench Utility/Friction Track

Goal: measure benign coding workflow friction separately from security wins.

Code changes:

- extend `src/kappaski/harness.py` and `src/kappaski/evals.py` to support a
  pinned SWE-bench Lite/Verified experiment subset;
- keep official harness execution optional heavy validation;
- add suite `swebench-friction-control-plane`.

Acceptance:

- baseline and Kappaski-wrapped runs compare exit code, artifact list, grading
  result, and allowed metadata drift;
- managed/advisory/enforced modes report different approval and coverage costs;
- Kappaski does not claim higher SWE-bench resolution as its core win.

Metrics:

- resolved-rate delta;
- benign auto-approval rate;
- unnecessary approval rate;
- p50/p95 mediation latency;
- evidence bundle generation success;
- coverage distribution.

### v0.34 SKILL-INJECT And Supply-Chain Experiment Track

Goal: evaluate pre-runtime skill/plugin/supply-chain governance with real
malicious skill patterns.

Code changes:

- add `src/kappaski/corpus_adapters/skill_inject.py`;
- extend pre-runtime scan output with benchmark case ids and expected capability
  surfaces;
- add suite `skill-supply-chain-control-plane`.

Acceptance:

- malicious skill instructions are detected before runtime where possible;
- runtime actions originating from skill instructions carry source/trust labels;
- capability grants are visible in proof and path graph;
- benign skill compliance is measured separately from malicious instruction
  avoidance.

Metrics:

- preflight detection rate;
- runtime block/approval rate;
- benign skill pass rate;
- capability-grant correctness;
- audit reconstruction success.

### v0.35 Secure Coding Gate Track

Goal: show that a functionally passing patch can still be gated for security.

Code changes:

- add `src/kappaski/secure_code_gate.py`;
- add adapters for SusVibes / Agent Security League fixture metadata first;
- represent static analysis, test results, and security oracle outputs as
  post-runtime evidence facts;
- add suite `secure-coding-gate`.

Acceptance:

- functionally passing but insecure patches can produce gate `fail` or
  `require_approval`;
- proof explains test status, security finding, decision, reviewer involvement,
  and residual risk;
- LLM reviewer use is optional and measured, not required for deterministic CI.

Metrics:

- FuncPass;
- SecPass;
- secure-gate precision;
- reviewer call rate;
- reviewer cost;
- false positive rate on safe patches.

### v0.36 Coverage And Enforcement Truthfulness Matrix

Goal: prove Kappaski does not overclaim enforcement.

Code changes:

- add `src/kappaski/coverage_experiments.py`;
- run the same scenario under imported log, post-tool hook, pre-tool hook,
  wrapper, shim/proxy, and bypass surfaces;
- extend `coverage html` with experiment comparison tables.

Acceptance:

- proof reports `observed`, `mediated`, and `enforced` accurately;
- gate fails when a profile requires stronger coverage than the run achieved;
- bypass/degraded-mode cases are reported as coverage gaps, not hidden passes.

Metrics:

- coverage label correctness;
- insufficient-coverage gate correctness;
- blocked-before-execution rate by surface;
- bypass detection;
- proof/replay clarity for coverage gaps.

### v0.37 LLM Reviewer Selectivity And Cost

Goal: measure when LLM review is worth calling.

Code changes:

- add `src/kappaski/reviewer_experiments.py`;
- compare reviewer off, deterministic only, selective reviewer, always-on
  reviewer, and async audit reviewer modes;
- record token/cost/latency metadata in experiment reports.

Acceptance:

- deterministic critical rules remain non-downgradable;
- raw evidence is redacted or folded according to profile;
- reviewer output can upgrade risk or deny, but cannot override critical
  deterministic policy.

Metrics:

- reviewer invocation rate;
- token cost per session;
- p50/p95 reviewer latency;
- risk recall delta;
- false positive delta;
- invalid-output rate;
- redaction failure rate.

### v0.38 Audit Reconstruction And Tamper Evidence Track

Goal: measure Kappaski's post-runtime assurance advantage.

Code changes:

- add `src/kappaski/audit_experiments.py`;
- define audit-question checkers for who, agent, source, resource, policy,
  approval, outcome, and coverage;
- add tamper fixtures for ledger mutation, missing proof fields, mismatched
  proof/ledger, unresolved approvals, and insufficient coverage;
- add suite `audit-tamper-assurance`.

Acceptance:

- audit-question answers are derived from ledger/proof/evidence bundle facts;
- tampered or incomplete artifacts fail verification;
- report includes time-to-answer and missing-field counts.

Metrics:

- proof completeness;
- proof+ledger verification success/failure;
- audit reconstruction success;
- missing field rate;
- tamper detection rate;
- time to answer audit questions.

### v0.39 Paper-Ready Experiment Package

Goal: make the experiment system reproducible enough for a paper or public
technical report.

Code changes:

- add `kappaski experiment paper-suite --out-dir ...`;
- add report generator for tables by experiment bundle E0-E6;
- freeze pinned fixtures and hashes;
- add `docs/paper-experiment-protocol.html`;
- add optional live-run instructions for AgentDojo/AgentDyn/SWE-bench/SusVibes.

Acceptance:

- one command generates a complete local paper-results bundle;
- optional external runs cleanly distinguish skipped, unavailable, failed, and
  passed cases;
- every chart/table can be traced back to case ids and artifact hashes.

Metrics:

- all E0-E6 metrics;
- reproducibility hash;
- fixture version map;
- optional-heavy dependency status.

### Cross-Cutting Implementation Rules

- External benchmark adapters must never become the fact source. They produce
  seeds; Kappaski ledger remains the fact source.
- Every imported case must become a Kappaski event sequence with explicit
  `source`, `trust`, `capability`, `resource`, `sink`, `expected_effect`, and
  `required_evidence` fields.
- Every experiment must include at least one benign control paired with the
  attack case when possible.
- Optional heavy external execution must cleanly skip in CI; pinned local
  fixtures must remain deterministic.
- Reports must separate model/agent task success from Kappaski control-plane
  success.
- Coverage claims must be dimensional and cannot be promoted from `observed` to
  `mediated` or `enforced` without a real pre-side-effect boundary.

### Code Route Summary

| Version | Main module | Benchmark source | Product question answered |
| --- | --- | --- | --- |
| v0.30 | `experiment_cases.py` | Kappaski fixtures | Can we define rigorous control-plane cases? |
| v0.31 | `corpus_adapters/agentdojo.py`, `agentdyn.py` | AgentDojo, AgentDyn | Can we stop IPI without killing utility? |
| v0.32 | `corpus_adapters/agentsecbench.py` | AgentSecBench | Can we separate visible data from authority? |
| v0.33 | `harness.py`, `evals.py` | SWE-bench Lite/Verified | What friction does Kappaski add to benign coding? |
| v0.34 | `corpus_adapters/skill_inject.py` | SKILL-INJECT | Can we govern skill supply-chain risk? |
| v0.35 | `secure_code_gate.py` | SusVibes / ASL | Can we gate insecure but functional patches? |
| v0.36 | `coverage_experiments.py` | Kappaski native matrix | Are coverage/enforcement claims truthful? |
| v0.37 | `reviewer_experiments.py` | Mixed corpora | Is LLM review selective and cost-effective? |
| v0.38 | `audit_experiments.py` | Kappaski tamper fixtures | Can auditors reconstruct and verify the run? |
| v0.39 | experiment paper suite | E0-E6 | Can one command reproduce the paper/demo results? |

## Paper-Framing Implication

The experiment section should not be titled "Benchmark Results" in a generic
sense. A better structure is:

1. Security effectiveness on external adversarial corpora.
2. Utility and friction on normal coding workflows.
3. Coverage truthfulness across observation/mediation/enforcement surfaces.
4. Cost of progressive control, including selective LLM review.
5. Post-runtime assurance: proof, replay, gate, audit reconstruction, and
   tamper detection.

This lets Kappaski make a cleaner claim:

> Existing benchmarks ask whether an agent completed or failed a task. Kappaski
> evaluates whether an enterprise can govern the path: before execution, during
> action, and after the run must be trusted by another team.

## Open Experiment Design Questions

1. Should the first external adapter target AgentDojo because it is established,
   or AgentDyn because it better represents current dynamic/open-ended cases?
2. How many SWE-bench tasks are needed to make friction claims without burning
   too much compute?
3. Should SusVibes/Agent Security League be included in the first paper, or kept
   as a follow-up secure-coding study?
4. What is the minimum enforcement surface needed before claiming
   "blocked-before-execution" beyond wrapper/shim domains?
5. How should Kappaski report user-facing approval burden: per task, per
   session, per risky action, or per hour of agent work?
