# Industry Research And Competitive Comparison

Date: 2026-05-28
Status: working research notes

## Purpose

This document maps Kappaski against current academic research, open-source
projects, product documentation, and benchmark work related to AI agent
observability, runtime governance, guardrails, policy enforcement, auditability,
and enterprise control planes.

The goal is not to prove that every Kappaski component is unique. Many individual
pieces exist elsewhere. The question is whether Kappaski's combination is a
distinct architecture:

> a local-first, ledger-first, coverage-aware control plane for AI coding agents,
> structured around five layers and three lifecycle stages.

## High-Level Landscape

| Category | Representative work | Main focus | Typical gap relative to Kappaski |
| --- | --- | --- | --- |
| Agent observability and tracing | OpenTelemetry GenAI agent spans, OpenAI Agents SDK tracing, LangSmith, AgentTrace | Capture traces, spans, tool calls, state, errors, evaluations, and telemetry. | Usually trace-first, not ledger-first; often weaker on policy mediation and tamper-evident proof. |
| Workflow runtime and human-in-the-loop | LangGraph persistence and interrupts, OpenAI Agents SDK guardrails | Durable execution, checkpoints, interrupts, approval workflows, framework-level guardrails. | Often tied to a runtime/framework; less focused on cross-agent local evidence and coverage claims. |
| Pre-execution firewall / guardrails | AEGIS, Symbolic Guardrails, OpenAI tool guardrails | Check tool calls before execution, enforce policy, sometimes hold for approval. | Strong at action checks, but often less complete on pre-runtime discovery, post-runtime proof, and coverage-aware assurance. |
| Enterprise governance toolkits | Microsoft Agent Governance Toolkit | Policy enforcement, identity, sandboxing, audit evidence, multi-language SDKs. | Strong enterprise posture; Kappaski can differentiate through coding-agent local workflows, ledger/proof/gate, and explicit five-layer/pre-runtime/runtime/post-runtime framing. |
| Audit graph and agent BOM | Agent-BOM / unified graph representation | Security-auditable representation of agents, tools, capabilities, memory/context, and attack chains. | Strong representation direction; Kappaski can implement a practical ledger-derived control loop. |
| Benchmarks and risk taxonomy | AgentDojo, OWASP Agentic Top 10 | Prompt injection, tool misuse, agentic risk classes, evaluation scenarios. | They define threats and tests, not a complete control plane implementation. |
| Protocols and ecosystem surfaces | MCP, A2A, native hooks/plugins/extensions | Standardize tool/context/agent interoperability. | They are integration surfaces, not control planes. Kappaski should keep adapter slots without making them short-term core. |

## Synthesis From Awesome Agent Security Lists

Sources:

- [ucsb-mlsec/Awesome-Agent-Security](https://github.com/ucsb-mlsec/Awesome-Agent-Security)
- [ProjectRecon/awesome-ai-agents-security](https://github.com/ProjectRecon/awesome-ai-agents-security)

The two lists are useful because they organize the field from different angles.
The UCSB list is closer to an academic threat-and-defense map. It separates
agent attacks by whether attackers compromise the model through external
components or compromise external components through model-mediated actions. The
ProjectRecon list is closer to a security lifecycle map: firewalls/gateways,
red-team scanners, static analysis, sandboxing, guardrails/compliance,
benchmarks, and identity.

Combined, they suggest a sharper Kappaski framing:

> Agent security is not one defense. It is a control loop across attack entry
> points, authority boundaries, side-effect surfaces, and post-hoc evidence.

### Two Threat Directions

| Direction | Typical examples | Why it matters to Kappaski |
| --- | --- | --- |
| Attack the model through components | Indirect prompt injection, memory poisoning, malicious tool output, web/CUA environmental injection, skill/tool metadata poisoning. | These threats enter through L1 surfaces and must become L2 `source`, `trust`, `taint`, and path facts. |
| Attack components through the model | RCE through code tools, unauthorized tool use, secret exfiltration, unsafe shell/file/network actions, CI/deploy mutation. | These threats require L3 decision, L4 mediation/enforcement, and L5 evidence of side effects or blocked side effects. |

This distinction is a better threat model than "prompt injection" alone. It
also explains why Kappaski should not be only a guardrail or scanner: the risky
object is the whole execution path from untrusted context to privileged action.

### Security Lifecycle Mapping

| Lifecycle category from the lists | Representative work/tools | Kappaski interpretation |
| --- | --- | --- |
| Red teaming and vulnerability scanning | PyRIT, Garak, Agentic Security, Strix, agent-specific attack benchmarks. | Input corpora for Kappaski-ControlPlane-Bench; useful for generating regression cases, not a replacement for runtime control. |
| Static analysis and linters | Agentic Radar, Agent Bound, Checkov-like config scanning. | Belongs in pre-runtime discovery: capability surfaces, risky workflows, broad permissions, and policy drift. |
| Runtime firewalls and gateways | AgentGateway, Envoy AI Gateway, AEGIS-like tool firewalls. | L1/L4 execution surfaces that can provide mediated or enforced coverage. Kappaski should consume their decisions/evidence when present. |
| Guardrails and compliance | NeMo Guardrails, Guardrails AI, LiteLLM guardrails, Prompt Shields. | L3 reviewer/policy components. They are useful but should not be the root of trust. |
| Sandboxing and isolation | SandboxAI, Kubernetes Agent Sandbox, Agent-Infra Sandbox, OpenHands runtime. | L1/L4 enforcement domains. Kappaski should label these as stronger coverage when side effects are truly blocked by the boundary. |
| Identity and authentication | Agent identity, delegation tokens, OAuth-based agent IAM, non-human identity systems. | Cross-cutting identity/principal/capability facts. This is a must-have for enterprise control-plane credibility. |
| Monitoring and auditing | AgentTrace-like logs, graph anomaly detectors, Agent-BOM-style representations. | L5 evidence consumers and derived views. Kappaski should keep ledger as source of truth and derive graphs/traces from it. |

### What This Changes In Our Priorities

| Area | Earlier view | Deeper view after the two lists |
| --- | --- | --- |
| MCP/A2A | Not short-term product core. | Still not product core, but protocol/tool metadata poisoning is a real threat class. Model it generically as tool/provider/capability-surface poisoning. |
| Guardrails | Useful semantic reviewer/checker. | Treat as pluggable L3 signals with explicit cost and bypass risk. Deterministic policy and mediation stay primary. |
| Sandboxing | Future stronger enforcement surface. | Becomes one of the clearest ways to prove `enforced` coverage. Wrapper-only claims must remain modest. |
| Static analysis | Nice pre-runtime scan. | Becomes the pre-runtime half of agent security: broad permissions, skill/tool risk, unsafe workflow topology, and policy drift. |
| Identity | Important gap. | Becomes a first-order enterprise requirement: principal, agent, credential, delegation, and resource scope must be provable. |
| Benchmarks | External corpora plus Kappaski metrics. | Add benchmark families for skill/tool poisoning, CUA/web environmental attacks, risky code execution, and authority/data-flow separation. |

### Design Implication

Kappaski should position itself as an orchestration and evidence layer over
point defenses:

```text
scanner / guardrail / gateway / sandbox / identity provider
  -> Kappaski canonical facts
  -> policy and mediation
  -> ledger-backed proof, replay, coverage, and gate
```

That gives Kappaski a distinct role in a crowded landscape. It does not need to
outperform every scanner, sandbox, or guardrail. It needs to make their control
position explicit, compose them into a path-aware policy model, and produce
enterprise-grade evidence about what actually happened.

## Academic And Research Work

### Runtime Governance For AI Agents: Policies On Paths

Source: [arXiv:2603.16586](https://arxiv.org/abs/2603.16586)

Core idea:

- Agent governance should be runtime governance, not only design-time or
  deployment-time review.
- The policy object is an execution path: prior actions, current state, proposed
  next action, agent identity, and organizational context.

Relevance to Kappaski:

- Strongly supports Kappaski's `Invocation + input_refs + taint + decision_trace`
  direction.
- Suggests Kappaski should evolve from event-by-event decisions into
  path-aware policy.

Kappaski differentiation:

- Kappaski already has concrete ledger, proof, approval, gate, replay, and
  local adapter workflows.
- The paper direction can position Kappaski as an implementation of a practical
  path-aware control plane for coding agents.

Gap to close:

- Formalize path graph reconstruction from ledger facts.
- Evaluate policy decisions on path-level attack chains rather than isolated
  invocations.

### AgentTrace

Source: [AgentTrace: A Structured Logging Framework for Agent System Observability](https://arxiv.org/abs/2602.10133)

Core idea:

- High-stakes adoption is limited by poor traceability into agent reasoning,
  state changes, and environmental interactions.
- Structured logs across operational, cognitive, and contextual surfaces can
  support security, accountability, and monitoring.

Relevance to Kappaski:

- Validates the need for structured agent facts beyond raw logs.
- Supports Kappaski's normalized invocation and replay direction.

Kappaski differentiation:

- Kappaski should be described as ledger-first rather than trace-first.
- Kappaski evidence is intended for proof, CI gates, approvals, and tamper
  detection, not only monitoring and debugging.

Gap to close:

- Improve introspectability of reconstructed execution paths.
- Add clearer trace/export compatibility without making OTel/LangSmith the fact
  source.

### AEGIS

Source: [AEGIS: No Tool Call Left Unchecked -- A Pre-Execution Firewall and Audit Layer for AI Agents](https://arxiv.org/abs/2603.12621)

Core idea:

- Post-execution observability cannot stop side effects.
- A framework-agnostic pre-execution firewall can interpose on tool calls,
  apply risk scanning, validate policy, hold high-risk calls for approval, and
  record decisions in a tamper-evident audit trail.
- The paper reports a curated attack suite, benign tool-call false positive
  measurements, and low median interception latency.

Relevance to Kappaski:

- Strongly supports Kappaski's Mediation Plane and enforcement direction.
- Shows that pre-execution control can be practical and low overhead.

Kappaski differentiation:

- AEGIS is primarily a pre-execution firewall and audit layer.
- Kappaski's intended scope is broader: pre-runtime discovery, runtime fact
  model, policy/reviewer/approval/outcome separation, post-runtime proof/gate,
  and coverage reporting across multiple execution surfaces.

Gap to close:

- Kappaski needs better pre-execution enforcement coverage to be competitive
  with firewall-style systems.
- File-write, secrets/env, network egress, and destructive shell should become
  credible enforcement domains.

### Symbolic Guardrails For Domain-Specific Agents

Source: [arXiv:2604.15579](https://arxiv.org/abs/2604.15579)

Core idea:

- Neural or prompt-based mitigations do not provide strong guarantees.
- Many domain-specific safety/security policies can be enforced with symbolic
  guardrails while preserving utility.

Relevance to Kappaski:

- Supports the design choice that deterministic rules and policy profiles should
  run before LLM review.
- LLM Reviewer should be a selective semantic reviewer, not the root control
  mechanism.

Kappaski differentiation:

- Kappaski combines symbolic decisions with path/taint state, approvals,
  evidence, and coverage.

Gap to close:

- Add more explicit symbolic policy language or compatibility with established
  policy-as-code models.
- Benchmark LLM review only where symbolic policy is insufficient.

### From Governance Norms To Enforceable Controls

Source: [arXiv:2604.05229](https://arxiv.org/abs/2604.05229)

Core idea:

- High-level governance norms do not automatically become runtime guardrails.
- There needs to be a layered translation from governance objective to runtime
  controls and assurance evidence.

Relevance to Kappaski:

- Directly supports Kappaski's separation between Decision Plane, Mediation
  Plane, and Evidence & Assurance Plane.
- Helps explain why policy, execution control, and proof should not be conflated.

Kappaski differentiation:

- Kappaski can ground the layered translation in coding-agent workflows, local
  sessions, ledger entries, and CI gates.

Gap to close:

- Map enterprise controls to Kappaski policy profiles and proof fields.
- Show examples: "no secret egress" -> taint/path rule -> mediation ->
  proof/gate evidence.

### Towards Security-Auditable LLM Agents: A Unified Graph Representation

Source: [arXiv:2605.06812](https://arxiv.org/abs/2605.06812)

Core idea:

- Static SBOM, AIBOM, runtime logs, traces, and generic provenance are
  fragmented evidence sources for agent security auditing.
- Agent execution introduces a semantic gap between low-level physical events
  and high-level intent: goal formation, context construction, reasoning,
  decision, capability selection, memory use, and cross-agent propagation.
- Agent-BOM proposes a hierarchical attributed directed graph that separates a
  static capability layer from a runtime semantic layer and connects them with
  semantic edges and security attributes.

Relevance to Kappaski:

- Strongly supports Kappaski's claim that ordinary traces are not enough.
- Validates our emphasis on capability binding, taint/source tracking,
  long-term memory, handoff, and path-level auditing.
- Gives Kappaski a useful post-runtime representation target: a ledger-derived
  agent security graph.

Kappaski differentiation:

- Agent-BOM is a security-auditable representation and rule-query substrate. It
  explicitly says it is not a standalone defense or policy enforcement
  mechanism.
- Kappaski is a runtime control plane: it includes pre-runtime discovery,
  runtime decision and mediation, approval, enforcement surfaces, tamper-evident
  ledger, proof verification, replay, and gate consumption.
- Agent-BOM assumes the telemetry collection and storage infrastructure are
  secure and tamper-proof. Kappaski makes tamper evidence part of the core
  architecture through hash-chain ledgers and proof+ledger verification.
- Agent-BOM discusses incomplete instrumentation as a limitation. Kappaski turns
  this into a first-class coverage model: `none`, `declared`, `observed`,
  `mediated`, and `enforced`.

Gap to close:

- Add ledger-derived Agent-BOM-style graph export or path query API.
- Explicitly represent goal/context/reasoning/decision states where available,
  while preserving Kappaski's canonical `Invocation` model.
- Express attack chains in replay and proof more clearly with entry
  localization, backward tracing, forward tracing, and adjudication.

Detailed model:

| Agent-BOM element | Description | Kappaski mapping |
| --- | --- | --- |
| Static capability layer | Agent, code, LLM, prompt, tool, skill, long-term memory. | Preflight assets, `CapabilitySurface`, adapter profiles, Skill/tool/native integration records. |
| Runtime semantic layer | External input, goal, context, reasoning, decision, action, observation. | `Invocation` today; future path graph can add explicit goal/context/reasoning/decision nodes. |
| Structural dependency edges | Agent-to-prompt/model/tool/skill/code dependencies. | Preflight baseline, capability grants, adapter inventory. |
| Runtime evolution edges | State transitions and semantic influence among runtime nodes. | `input_refs`, `output_refs`, `correlation_id`, taint transitions, decision trace. |
| Cross-layer binding edges | Runtime states select/invoke/read/write static capability objects. | Capability grant id, resource refs, tool/skill refs, action evidence. |
| Cross-agent propagation edges | Message passing, delegation, shared context, shared memory. | TeamRun, Handoff, Blackboard, restrict-only delegation. |
| Security attributes | Source, trust, integrity, authorization, confirmation, side effects. | `source`, `trust_level`, `taint_tags`, approval evidence, outcome, coverage grade, evidence refs. |

Agent-BOM's auditing template is also useful for Kappaski post-runtime analysis:

| Agent-BOM audit stage | Meaning | Kappaski use |
| --- | --- | --- |
| Entry localization | Identify anomalous semantics, dangerous behavior, or untrusted capability. | Find suspicious invocation, external content, capability grant, taint source, or risky decision. |
| Backward tracing | Trace upstream to source, dependency, memory, or context origin. | Follow input refs, source/trust, preflight assets, capability grants, handoff links. |
| Forward tracing | Trace downstream to decisions, actions, memory persistence, or other agents. | Follow output refs, outcomes, taint propagation, TeamRun/Handoff, replay frames. |
| Attribute adjudication | Check path attributes for authorization, confirmation, integrity, and impact. | Evaluate policy, approval, outcome, coverage, redaction, and gate findings. |

Core difference:

```text
Agent-BOM explains what happened and why through an auditable graph.
Kappaski aims to govern what happens before, during, and after execution.
```

### AgentDojo

Source: [NeurIPS 2024 AgentDojo](https://proceedings.neurips.cc/paper_files/paper/2024/hash/97091a5177d8dc64b1da8bf3e1f6fb54-Abstract-Datasets_and_Benchmarks_Track.html)

Core idea:

- Tool-using agents are vulnerable to indirect prompt injection through data
  returned by tools and external environments.
- Realistic agent tasks and injected security tasks are needed to evaluate
  defenses.

Relevance to Kappaski:

- Provides benchmark-style scenarios for external content -> taint -> risky
  downstream action.
- Strong match for Kappaski's source/trust/taint/path logic.

Kappaski differentiation:

- Kappaski can evaluate not only whether an attack succeeds, but whether the
  system produced complete evidence: invocation, taint, decision, approval,
  outcome, proof, and coverage.

Gap to close:

- Build a Kappaski benchmark suite mapped to AgentDojo-like tasks.
- Measure false positives on benign workflows beside attack block rate.

## Product And Open-Source Comparison

### OpenTelemetry GenAI Agent Spans

Source: [OpenTelemetry GenAI agent semantic conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-agent-spans/)

What it covers:

- Agent creation/invocation spans;
- workflow and tool execution spans;
- attributes for agent name/id/version, provider, model, and system
  instructions;
- standardization for telemetry interoperability.

Kappaski view:

- OTel is an excellent export target and ecosystem standard.
- OTel should not be Kappaski's internal fact source because spans are not
  inherently policy decisions, approvals, outcomes, or tamper-evident proof.

Design implication:

- Add OTel export from ledger/proof later.
- Preserve ledger-first internal semantics.

### OpenAI Agents SDK

Sources:

- [Tracing](https://openai.github.io/openai-agents-python/tracing/)
- [Guardrails](https://openai.github.io/openai-agents-js/guides/guardrails/)

What it covers:

- Built-in tracing for generations, tool calls, handoffs, guardrails, and custom
  events;
- input/output/tool guardrails inside the SDK;
- practical developer ergonomics for agent apps.

Kappaski view:

- Strong framework-level developer experience.
- Guardrails are valuable but should be treated as one execution surface, not
  the whole control plane.

Design implication:

- Kappaski should integrate with SDK traces where available.
- Kappaski must still own ledger, proof, policy state, and coverage claims.

### LangSmith And LangGraph

Sources:

- [LangSmith Observability](https://docs.langchain.com/langsmith/observability)
- [LangSmith Evaluation](https://docs.langchain.com/langsmith/evaluation)
- [LangGraph persistence / durable execution](https://docs.langchain.com/oss/python/langgraph/durable-execution)
- [Human-in-the-loop](https://docs.langchain.com/langgraph-platform/add-human-in-the-loop)

What they cover:

- Traces, dashboards, production monitoring, evaluations, annotation, online
  evaluators, and feedback loops;
- durable graph execution and human-in-the-loop workflows.

Kappaski view:

- Very strong observability/evaluation/runtime ecosystem.
- Kappaski differs by focusing on local coding-agent governance, ledger/proof,
  CI gate, coverage grade, and tamper-evident assurance.

Design implication:

- Kappaski can export or interoperate, but should not compete as a generic LLM
  observability dashboard first.

### Microsoft Agent Governance Toolkit

Sources:

- [GitHub repository](https://github.com/microsoft/agent-governance-toolkit)
- [Microsoft Open Source announcement](https://opensource.microsoft.com/blog/2026/04/02/introducing-the-agent-governance-toolkit-open-source-runtime-security-for-ai-agents/)

What it covers:

- Policy enforcement;
- identity;
- sandboxing;
- SRE/reliability engineering;
- multi-language SDKs;
- tamper-evident evidence;
- OWASP Agentic Top 10 alignment.

The repository frames three core enterprise questions:

- Is this action allowed?
- Which agent did this?
- Can you prove what happened?

Kappaski view:

- This is a serious enterprise-grade comparison point.
- It validates the market category: runtime security/governance for autonomous
  agents.

Kappaski differentiation:

- Kappaski can be more explicit about the five-layer model and
  pre-runtime/runtime/post-runtime lifecycle.
- Kappaski is local-first and coding-agent-first, with proof/replay/gate tightly
  aligned to developer workflows.
- Kappaski's coverage grade can make it more honest about partial observation,
  mediation, enforcement, and bypass.

Gap to close:

- Formal identity and principal binding.
- Broader policy-as-code and enterprise profile distribution.
- More credible enforcement domains.
- Evidence export for enterprise security systems.

### OWASP Agentic AI Top 10

Source: [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)

What it covers:

- Agentic risk taxonomy, including tool misuse, identity and permission issues,
  memory/context risks, rogue behavior, and governance gaps.

Kappaski view:

- OWASP is a useful external taxonomy for threat coverage claims.
- Kappaski proof and audit reports should map findings and coverage gaps to
  OWASP-style risk categories.

Design implication:

- Add OWASP mapping fields to policy profiles, proof summaries, and audit
  reports.

## Detailed Comparison Matrix

| Dimension | Kappaski target | OpenTelemetry / LangSmith | OpenAI Agents SDK | LangGraph | AEGIS | Microsoft AGT |
| --- | --- | --- | --- | --- | --- | --- |
| Primary object | Accountable execution path | Trace/run/span | Agent app trace and guardrail events | Stateful workflow graph | Tool call | Governed action/tool call |
| Core lifecycle | Pre-runtime, runtime, post-runtime | Mostly runtime/post-runtime telemetry | Runtime SDK behavior | Runtime workflow | Runtime pre-execution | Runtime/enterprise governance |
| Evidence source | Hash-chain ledger | Trace store | SDK trace store | Checkpoint/state store | Audit trail | Audit/evidence logs |
| Tamper evidence | Core design | Not usually core | Not usually core | Not core | Core | Core |
| Pre-runtime discovery | Core design | Limited | Limited | Limited | Limited | Some policy/setup validation |
| Runtime mediation | Core design | Usually no | SDK-level guardrails | Interrupt/human-in-loop | Core | Core |
| Enforcement | Wrapper/shim/proxy/sandbox where available | No | Framework/tool dependent | Runtime dependent | Tool-call firewall | Policy/sandbox/governance SDK |
| Coverage honesty | Explicit grade | Usually implicit | Guardrail surface documented but not a general grade | Runtime-specific | Usually yes/no interception | Enterprise evidence-oriented |
| LLM reviewer | Selective L3 component | Eval/LLM-as-judge common | Guardrail/evaluator possible | Possible node/component | Not central | Policy-first, not central |
| Coding-agent local workflow | First wedge | Generic app telemetry | Generic agent app SDK | Generic workflow | Generic agent tool calls | Generic enterprise agents |
| CI proof gate | Core direction | Possible export but not core | Not core | Not core | Not primary | Evidence verification possible |
| Differentiation risk | Must prove enforcement and identity | Strong ecosystem | Strong SDK UX | Strong workflow runtime | Strong pre-execution firewall | Strong enterprise governance |

## Kappaski's Distinct Design Understanding

Kappaski's strongest claim is not that it invented every mechanism. Its
distinct understanding is the combination:

```text
Five-layer architecture
  x
Pre-runtime / runtime / post-runtime lifecycle
  x
Ledger-first evidence
  x
Coverage-aware control strength
  x
Progressive cost model
```

This lets Kappaski answer questions that isolated systems often answer only
partially:

- What did the agent attempt?
- What source or path caused the action?
- What resource and capability did it touch?
- Was context already tainted?
- What policy was active?
- Did deterministic policy, semantic review, or profile merger decide?
- Was approval required and resolved?
- What actually happened?
- Was the ledger intact?
- Was the event merely observed, mediated, or enforced?

## Industry Pain Points And Kappaski Fit

| Pain point | Existing approaches | Remaining problem | Kappaski fit |
| --- | --- | --- | --- |
| Multi-agent sprawl | Vendor traces, framework dashboards, per-agent logs. | No common local control model across Codex/Claude/Cursor/CI and future agents. | Adapter-normalized invocation and session ledger. |
| Tool-call overreach | IAM/OAuth scopes, SDK guardrails. | Permissions say what service is reachable, not what the agent should do inside the service. | Capability grants, policy decisions, mediation. |
| Indirect prompt injection | Prompt filtering, model alignment, benchmark defenses. | Untrusted tool/external content can affect later actions. | Source/trust/taint/path model with downstream escalation. |
| Audit unreliability | Logs and traces. | Logs can be detached from policy and approvals or mutated. | Hash-chain ledger, proof, verification. |
| Approval ambiguity | Chat/terminal confirmation. | Missing context, weak identity, no durable reason/outcome. | Approval evidence tied to decision and invocation. |
| Overclaimed protection | "We have guardrails." | Which actions were actually observed, mediated, or enforced is unclear. | Coverage grade and degraded reasons. |
| CI blind spot | PR tests and code review. | Runtime behavior of the coding agent is not attached to the PR. | Proof export, replay, gate report. |
| Cost of semantic review | LLM-as-judge or always-on reviewer. | High token/latency/privacy cost. | Selective LLM reviewer after deterministic/path gating. |

## MCP And A2A Position

MCP and A2A should not be treated as Kappaski's short-term center.

Recommended position:

- They are execution surfaces and adapter protocols.
- They are useful when a customer or agent ecosystem requires them.
- They should not define the control plane.
- Kappaski's core model should work even if MCP/A2A adoption weakens, because
  the control plane is about actions, paths, policy, mediation, and evidence.

Practical implication:

- Keep MCP/A2A adapter slots in L1 Execution Surface.
- Prioritize native coding-agent integrations, wrappers, and enforcement
  domains before deep protocol investment.

## Required Capabilities For Enterprise-Level Control Plane

| Capability | Priority | Why it is required | Current Kappaski status |
| --- | --- | --- | --- |
| Identity / principal binding | P0 | Enterprises need to know who the agent represents and which credential/authority was used. | Partial actor/agent/session facts; needs formal model. |
| Capability grants and delegation proof | P0 | Tool and resource access must be justified and constrained. | Capability grant events exist; delegation needs hardening. |
| Pre-execution policy mediation | P0 | Audit alone cannot stop side effects. | Wrapper/shim slices exist; needs broader domains. |
| Tamper-evident ledger | P0 | Cross-boundary trust requires integrity checks. | Strong current foundation. |
| Coverage-aware assurance | P0 | Enterprises need honest control claims. | Coverage model exists; needs full productization. |
| Approval, exception, break-glass | P0 | Human override must be auditable and reviewable. | Approval evidence exists; enterprise workflows need depth. |
| Policy profiles / policy-as-code | P0/P1 | Teams need versioned, inherited, reviewable policy. | TOML/JSON profile support exists; needs enterprise distribution. |
| Secret/data/egress governance | P1 | Data leakage is a central agent risk. | Taint and basic guard checks exist; needs richer resource classification. |
| Enterprise export | P1 | SOC, SIEM, OTel, audit, and compliance workflows need outputs. | Proof/replay/gate exist; SIEM/OTel export later. |
| MCP/A2A broker | P2 | Useful ecosystem support, not core thesis. | Adapter slot and MCP broker slice exist; deprioritize short term. |

## Is There Enough For A Paper?

Yes, if the paper is framed as a system and model contribution rather than a
feature checklist.

Good paper framing:

> A five-layer, three-stage, ledger-first, coverage-aware runtime control plane
> for AI coding agents.

Weak paper framing:

> Another agent guardrails tool.

Minimum paper-worthy implementation bar:

- canonical invocation model;
- path/taint state;
- deterministic policy and selective LLM reviewer;
- mediation/approval/outcome;
- tamper-evident ledger and proof verification;
- replay/gate/audit consumption;
- coverage grade exported in proof/replay/gate;
- at least two execution surfaces, such as native hook/wrapper and shim;
- benchmark data for attacks, benign workflows, latency, false positives,
  approval rate, and LLM cost.

Strong novelty candidates:

1. The five-layer control plane model paired with the three-stage lifecycle.
2. Coverage grade as a first-class assurance concept.
3. Fact separation: finding, taint, decision, approval, outcome, evidence.
4. Ledger-first proof and CI gate for local coding-agent workflows.
5. Progressive control: observed -> mediated -> enforced, with explicit cost
   and friction tradeoffs.

## Recommended Research Roadmap

1. Write a formal model doc from
   `agent-control-plane-model-and-paper-direction.md`.
2. Extend Kappaski's ledger into an execution-path graph export.
3. Complete coverage-aware proof/replay/gate behavior.
4. Harden pre-execution mediation for file-write, secret/env, network egress,
   and destructive shell.
5. Add identity/principal/capability/delegation facts.
6. Build an external benchmark harness:
   - AgentDojo-like indirect injection cases;
   - SWE-Bench-like benign coding workflows;
   - Kappaski enterprise demo cases.
7. Measure:
   - block rate;
   - false positive rate;
   - latency;
   - LLM review cost;
   - approval interruption rate;
   - proof completeness;
   - coverage distribution;
   - audit reconstruction success.

## Source List

- Runtime Governance for AI Agents: Policies on Paths:
  <https://arxiv.org/abs/2603.16586>
- AgentTrace:
  <https://arxiv.org/abs/2602.10133>
- AEGIS:
  <https://arxiv.org/abs/2603.12621>
- Symbolic Guardrails:
  <https://arxiv.org/abs/2604.15579>
- From Governance Norms to Enforceable Controls:
  <https://arxiv.org/abs/2604.05229>
- Towards Security-Auditable LLM Agents:
  <https://arxiv.org/abs/2605.06812>
- AgentDojo:
  <https://proceedings.neurips.cc/paper_files/paper/2024/hash/97091a5177d8dc64b1da8bf3e1f6fb54-Abstract-Datasets_and_Benchmarks_Track.html>
- OpenTelemetry GenAI agent spans:
  <https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-agent-spans/>
- OpenAI Agents SDK tracing:
  <https://openai.github.io/openai-agents-python/tracing/>
- OpenAI Agents SDK guardrails:
  <https://openai.github.io/openai-agents-js/guides/guardrails/>
- LangSmith observability:
  <https://docs.langchain.com/langsmith/observability>
- LangSmith evaluation:
  <https://docs.langchain.com/langsmith/evaluation>
- LangGraph persistence:
  <https://docs.langchain.com/oss/python/langgraph/durable-execution>
- LangGraph human-in-the-loop:
  <https://docs.langchain.com/langgraph-platform/add-human-in-the-loop>
- Microsoft Agent Governance Toolkit:
  <https://github.com/microsoft/agent-governance-toolkit>
- Microsoft AGT announcement:
  <https://opensource.microsoft.com/blog/2026/04/02/introducing-the-agent-governance-toolkit-open-source-runtime-security-for-ai-agents/>
- OWASP Top 10 for Agentic Applications 2026:
  <https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/>
