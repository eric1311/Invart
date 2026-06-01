# Enterprise Value Loops

Date: 2026-05-26
Status: discussion record

## Purpose

This document records candidate enterprise demos and value loops. It is separate
from the implementation roadmap because the best first demo should be discussed
carefully.

The product question is:

> What closed loop makes an enterprise user immediately understand why Kappaski
> enables safer AI coding agent adoption?

## Candidate Loop A: Sensitive Read To Outbound

Story:

1. Agent reads `.env` or cloud credentials.
2. Later the same session attempts a network request, post, upload, or MCP/Skill send action.
3. Rules detect the sensitive read.
4. Taint elevates the outbound action.
5. Semantic reviewer determines whether the outbound action looks benign or exfiltrative.
6. Low-risk outbound can be auto-approved; high-risk outbound requires human approval.
7. Proof shows the chain and verification status.

Why it works:

- Easy to understand.
- Demonstrates taint.
- Demonstrates rules plus semantic review.
- Maps directly to enterprise fear: secret exfiltration.

Risk:

- Needs careful redaction so secrets are never sent to LLM.

## Candidate Loop B: External Issue Comment Goal Hijack

Story:

1. Agent ingests an untrusted issue comment.
2. Comment asks the agent to change CI, print secrets, or upload logs.
3. Semantic reviewer flags goal hijack or external instruction injection.
4. Later write/exec/network actions inherit untrusted-source taint.
5. Policy requires approval or blocks depending mode.
6. Proof explains source -> action -> decision.

Why it works:

- Shows why deterministic rules are not enough.
- Strong GitHub/PR workflow relevance.
- Good demo for semantic reviewer.

Risk:

- Requires modeling external content source and input refs well.

## Candidate Loop C: Skill Instruction Poisoning

Story:

1. Preflight detects a Skill or instruction file.
2. Semantic reviewer identifies hidden tool escalation or suspicious instructions.
3. Skill load becomes a reviewed invocation.
4. Any write/exec/network action caused by that Skill inherits taint.
5. Proof shows Skill source and downstream actions.

Why it works:

- Aligns with observation that Skills may be more important than MCP.
- Differentiates Kappaski from simple command scanners.

Risk:

- Needs a clear Skill fixture and threat pattern.

## Candidate Loop D: CI/CD Poisoning

Story:

1. Agent attempts to edit `.github/workflows`, deployment scripts, or build config.
2. Rules flag sensitive CI/CD path.
3. Semantic reviewer evaluates whether the diff changes permissions, secrets, remote scripts, or deploy behavior.
4. Policy grades risk and requires approval for dangerous changes.
5. Proof attaches redacted diff summary and decision trace.

Why it works:

- Strong enterprise AppSec relevance.
- Demonstrates beyond secret exfiltration.

Risk:

- Needs diff evidence builder, not just path rules.

## Candidate Loop E: Force Push Or Release Mutation

Story:

1. Agent attempts `git push --force`, release publishing, or package deployment.
2. Rules detect hard risky command.
3. LLM cannot downgrade deterministic critical rule.
4. Managed mode blocks or requires approval.
5. Proof verifies the decision.

Why it works:

- Simple and robust.
- Good for policy demonstration.

Risk:

- Less distinctive than semantic attack demos.

## Current Recommendation

Use Loop A and Loop B together for v0.2 demos:

- Loop A demonstrates taint and data-flow-style reasoning.
- Loop B demonstrates why semantic review is needed.

Keep Loop C as a near follow-up because Skill security may be more strategically
important than MCP proxy.

## Open Discussion Questions

- Which demo best matches the first target buyer: AppSec, platform engineering,
  or developer tooling leadership?
- Should the first demo run entirely from CLI fixtures, or should it integrate
  with a real GitHub issue/PR flow?
- What approval outcome should the demo show: auto-approve low risk, human
  approval high risk, or both?
- What evidence is compelling without exposing raw secrets or raw user content?
