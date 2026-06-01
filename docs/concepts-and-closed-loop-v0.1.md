# Kappaski v0.1 Concepts And Closed Loop

Date: 2026-05-25
Status: product and engineering clarification

## Purpose

Kappaski is not just a session proof generator. The product goal is an effective
closed loop for AI coding agents:

1. discover the local agent, repo, MCP, Skill, CI, and sensitive-resource context;
2. start a managed runtime session with explicit goal, policy, actors, and grants;
3. normalize every attempted action into an `Invocation`;
4. evaluate the invocation with source, trust, taint, capability, policy, and evidence context;
5. present a decision that a user, agent, policy, or future daemon can act on;
6. record the decision, result, approvals, and evidence in an append-only ledger;
7. export and verify a proof report that another trust boundary can consume.

The proof is not the whole product. It is the artifact produced by a managed
runtime loop.

## Product Contract

Kappaski should help a team answer:

- What did the agent attempt to do?
- What source or prior event caused that action?
- What resource, capability, or trust boundary did it touch?
- Was the session already tainted by sensitive or untrusted context?
- What decision did policy produce?
- Who or what accepted, rejected, ignored, or overrode that decision?
- Is the ledger intact enough to trust the replay?

The first version should stay local-first. It should not require a central
server, enterprise dashboard, or OS-level enforcement to be useful.

## Closed Loop

An effective v0.1 loop is:

```text
Preflight
  -> Managed Session
  -> Invocation Draft
  -> Policy Decision
  -> User / Agent / Policy Choice
  -> Execution Or Block
  -> Evidence Ledger
  -> Replay / Proof
  -> PR / CI / Reviewer Gate
```

### 1. Preflight

Preflight scans the target before the agent starts. It should persist a local
baseline, for example `.kappaski/preflight.json`, so later runtime and proof
steps can reference it.

Preflight should include:

- detected agent configs;
- target repo state;
- MCP server configs;
- Skills and instruction files;
- sensitive paths;
- CI/CD and deployment assets;
- static prompt-injection or suspicious instruction findings;
- recommended starting capability grants.

Preflight is not a final security decision. It is launch context.

### 2. Managed Session

A session is one managed agent run or team run. It records:

- `session_id`;
- target;
- goal;
- actor or agent;
- adapter;
- policy version;
- capability grants;
- ledger path;
- preflight reference.

In a later multi-agent version, a `TeamRun` can contain multiple sessions,
actors, handoffs, and blackboard entries. The same event envelope should still
apply.

### 3. Invocation

Use `Invocation` as the canonical runtime object.

An invocation is an attempted action, not only a completed action. It can be:

- shell execution;
- file read or write;
- network request;
- MCP tool call or result;
- Skill load;
- Git operation;
- issue or PR update;
- external content ingest;
- handoff;
- blackboard write;
- approval request or result.

`RuntimeEvent` can remain a compatibility input shape, but the managed runtime
should normalize it into `Invocation` before policy evaluation and ledger write.

## Mandatory Invocation Fields

These fields are mandatory for the closed-loop product because they explain
causality and authority, not just activity:

- `session_id`: owning session.
- `invocation_id`: stable id for this attempted action.
- `seq`: monotonic session sequence.
- `timestamp`: daemon/runtime timestamp.
- `actor`: user, agent, subprocess, MCP server, adapter, or policy actor.
- `adapter`: codex wrapper, claude hook, MCP proxy, CI adapter, manual record, etc.
- `operation`: normalized action class, such as `shell`, `file_read`, `mcp_write`.
- `resource_refs`: files, URLs, commands, tools, issues, PRs, artifacts, or secrets touched.
- `source`: user prompt, local repo, external web, MCP result, Skill instruction, issue comment, attachment, unknown.
- `trust_level`: trusted, internal, untrusted, or unknown.
- `input_refs`: upstream event/content/resource ids that influenced this invocation.
- `output_refs`: downstream artifacts, files, tool results, network destinations, or messages.
- `taint_tags`: sensitive read, external instruction, credential, repo secret, user PII, etc.
- `correlation_id`: links related invocations across adapters and event types.
- `capability_grant_id`: grant that supposedly authorizes this action.
- `policy_version`: policy used at decision time.
- `evidence_refs`: local digests, redacted payloads, diffs, stdout/stderr summaries, or tool summaries.

Unknown values should be explicit, not silently omitted.

## Taint And Decisions

Taint should not automatically mean "stop everything." Taint means the session
or context has crossed a sensitive or untrusted boundary, so later actions need
more scrutiny.

Examples:

- reading `.env` adds `sensitive_read` / `credential` taint;
- ingesting an external issue comment adds `external_instruction` taint;
- receiving a suspicious MCP result adds `mcp_result_untrusted` taint;
- a tainted context triggering network, write, Git push, or MCP write should escalate decision severity.

Policy produces a decision. The user, agent, or runtime then decides whether and
how to act on that decision.

This gives us four separate facts:

- **finding**: what matched a rule;
- **taint**: what sensitive or untrusted context is now present;
- **decision**: what policy recommends or requires;
- **outcome**: what actually happened next.

Those facts must stay separate in the ledger.

## Decision Model

The v0.1 decision vocabulary should support the future control plane:

- `allow`: action may proceed.
- `audit_only`: action may proceed but is important to record.
- `require_approval`: action should pause until a user, policy, or trusted controller resolves it.
- `deny`: action should not proceed.
- `redact`: action/result can proceed only with sensitive content removed from evidence.
- `quarantine`: action or capability should be isolated pending review.

The current simplified `allow / ask / deny` model maps to:

- `allow` -> `allow`;
- `ask` -> `require_approval`;
- `deny` -> `deny`.

## Who Decides Whether To Continue?

There are several control modes. Kappaski should model all of them clearly.

### Advisory Mode

Kappaski records findings, taint, and decisions, but does not block. The user or
agent sees the decision and chooses whether to continue.

Use this for early adoption and low-friction local development.

### Managed Wrapper Mode

Kappaski launches the agent or command through a wrapper. The wrapper can pause
or block actions based on policy. Human approval can resume the action.

Use this for the first meaningful runtime closed loop.

### Policy Gate Mode

Kappaski records the session locally, then PR review or CI verifies the proof and
enforces team policy.

Use this when real-time blocking is not yet complete but trust transfer matters.

### Daemon-Enforced Mode

A local daemon owns policy decisions, approval state, ledger append, and future
MCP/file/network shims. Adapters and hooks report to the daemon but do not own
trust.

Use this as the v0.1+ architecture direction.

## Approval Evidence

Approval is evidence, not just a boolean.

Approval records should include:

- approval id;
- decision id;
- invocation id;
- approver;
- status: approved, rejected, expired, missing, blocked, not_required;
- reason;
- requested and resolved timestamps;
- context shown to the approver;
- grant or capability affected, if any.

If an action requires approval but no approval exists, proof export must say
`missing`. If policy denied execution before approval, proof export should say
`blocked`.

## Ledger

The ledger is the append-only local evidence stream.

It should contain:

- session events;
- preflight references;
- invocations;
- policy decisions;
- taint updates;
- approval requests and results;
- execution results;
- evidence references;
- proof export or verification metadata, where useful.

Each ledger entry should include sequence, previous hash, and entry hash. The
hash chain lets another consumer detect tampering, reordering, and mutation.

The ledger does not prove that the agent could not bypass Kappaski. It proves
the integrity of what Kappaski observed and recorded.

## Proof

The proof is the portable summary artifact.

It should be small enough for PR comments, CI artifacts, vendor delivery, or
team review. It should not include raw secret-like content.

A proof should include:

- schema version;
- generated timestamp;
- session summary;
- preflight reference;
- ledger path and root hash;
- hash-chain verification status;
- decisions by effect and risk;
- taint summary;
- approval summary;
- action timeline;
- findings;
- risk statement;
- warnings and missing evidence.

## Proof Verification Options

Proof verification has a real design choice. There are three useful modes.

### Option A: Verify Ledger Only

Command shape:

```bash
kappaski proof verify --ledger ledger.jsonl
```

What it checks:

- ledger parses;
- every entry hash recomputes;
- every `prev_hash` links to the prior entry;
- final root hash is available.

Pros:

- simplest;
- strongest integrity check over raw evidence;
- no need to trust a generated proof summary.

Cons:

- reviewer must have the full ledger;
- does not verify that a proof JSON summary is accurate;
- less convenient for PR comments or CI artifacts.

Use this for local debugging and low-level integrity verification.

### Option B: Verify Proof Only

Command shape:

```bash
kappaski proof verify --proof proof.json
```

What it checks:

- proof parses;
- schema version is known;
- required sections exist;
- embedded `hash_chain_valid` is true;
- summary fields are internally consistent.

Pros:

- easiest for reviewers;
- one file can travel through PR, CI, or vendor workflows;
- useful when the ledger is unavailable.

Cons:

- weaker unless the proof embeds enough ledger-derived facts;
- cannot independently recompute the ledger root;
- a malicious proof producer could lie if no ledger or signature is available.

Use this for lightweight review, but mark the result as summary-only unless a
ledger root, signature, or attached ledger can be checked.

### Option C: Verify Proof And Ledger Together

Command shape:

```bash
kappaski proof verify --proof proof.json --ledger ledger.jsonl
```

What it checks:

- proof parses and schema is known;
- referenced ledger exists;
- ledger hash chain verifies;
- proof `ledger.last_hash` matches ledger root hash;
- proof counts match ledger-derived actions, decisions, approvals, taint, and findings;
- decision references are well formed;
- required approvals are present or explicitly marked missing/blocked.

Pros:

- best trust model for v0.1;
- proof is convenient, ledger is authoritative;
- CI can make deterministic pass/fail decisions.

Cons:

- needs both artifacts;
- more implementation work;
- summaries must be deterministic enough to compare.

Recommended v0.1 default: support Option C as the trusted path, keep Option A
for diagnostics, and allow Option B as a degraded "proof summary only" mode with
clear warnings.

## Preflight References

Preflight should be persisted and referenced by runtime and proof.

Recommended shape:

```text
.kappaski/
  preflight.json
  sessions/
    <session_id>/
      ledger.jsonl
      proof.json
```

Session start should record:

- preflight path;
- preflight hash;
- policy template;
- detected agent;
- initial grants.

Proof export should include the preflight reference and whether the preflight
artifact was available during export or verification.

## TeamRun, Blackboard, And Handoff

These are part of the intended closed loop, but they should be built on the same
runtime envelope.

### TeamRun

A TeamRun is a higher-level session that may contain multiple agents and roles.
It should not create a separate trust model. It should reuse invocations,
decisions, evidence, grants, and ledger entries.

### Blackboard

A blackboard entry is a derived view over ledger events:

- claim;
- evidence;
- open question;
- decision;
- warning.

The daemon or runtime computes source, trust, taint depth, and confidence. Agents
should not self-declare high confidence across trust boundaries.

### Handoff

A handoff is an invocation and an evidence event. It should include:

- delegator;
- delegatee;
- goal delta;
- context references;
- inherited taint;
- grant delta;
- approval policy.

Grant delegation should be restrict-only by default. Any expansion requires a
separate capability grant approval.

## Current v0.1 Direction

The implementation should move from the current proof-generator slice toward an
effective closed loop in this order:

1. rename and extend the canonical runtime object from `ActionEvent` to `Invocation`;
2. add mandatory provenance, trust, taint tag, correlation, and grant fields;
3. persist preflight and reference it from session start and proof export;
4. implement proof+ledger verification;
5. separate policy decision from execution outcome;
6. support advisory and managed-wrapper modes explicitly;
7. add adapter skeletons for Codex, Claude Code, and Cursor;
8. add a minimal MCP proxy path using the same invocation envelope;
9. add TeamRun, Blackboard, and Handoff as ledger-backed derived product views.

The key product rule is: every meaningful action must become an invocation with
source, trust, taint, decision, outcome, and evidence.

