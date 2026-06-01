# Kappaski v0.1 Proof Workflow

Date: 2026-05-23
Author: Hewitt
Scope: Product workflow and CLI shape for the local Agent behavior proof generator v0.1.
Status: draft for integration implementation

## Product Position

Kappaski v0.1 should not be a task board, swarm orchestrator, enterprise console, or generic Agent workspace. It should produce a verifiable proof artifact for one local managed Agent session.

The primitive is:

> A developer lets an Agent work under Kappaski, Kappaski records the Agent's action ledger, policy decisions, approval evidence, and taint state, then exports a proof report that another party can verify and consume.

The workflow is centered on trust transfer. The developer does the work locally, but the proof lets a reviewer, CI job, team lead, vendor manager, or security owner decide whether the result can be trusted.

## v0.1 User Stories

### 1. Developer Starts A Managed Session

A developer is about to run a CLI Agent against a local repo. Before the Agent starts, Kappaski creates a session identity, records the target, runs pre-runtime scanning, and writes a `session_start` ledger entry.

Example:

```bash
kappaski session start \
  --target /Users/lcy/repos/kappaski \
  --agent codex \
  --goal "Implement proof export for local agent sessions"
```

Expected output:

```json
{
  "session_id": "ks_20260523_abc123",
  "ledger": ".kappaski/sessions/ks_20260523_abc123/ledger.jsonl",
  "proof": ".kappaski/sessions/ks_20260523_abc123/proof.json",
  "env": {
    "KAPPASKI_SESSION_ID": "ks_20260523_abc123",
    "KAPPASKI_LEDGER": ".kappaski/sessions/ks_20260523_abc123/ledger.jsonl"
  }
}
```

The command should be safe to retry if the session id is supplied explicitly:

```bash
kappaski session start --session-id ks_manual_001 --target . --agent codex
```

If a session already exists with the same id, the CLI should return the existing session metadata instead of creating a second ledger.

### 2. Developer Runs The Agent Through A Wrapper

The easiest v0.1 path is wrapper-first. The wrapper launches the Agent with the session environment and gives the developer a normal terminal experience.

Suggested command:

```bash
kappaski session run \
  --target /Users/lcy/repos/kappaski \
  --agent codex \
  --goal "Implement proof export" \
  -- codex
```

This is syntactic sugar over:

1. `session start`
2. pre-runtime scan
3. setting `KAPPASKI_SESSION_ID` and `KAPPASKI_LEDGER`
4. launching the child command
5. writing a `session_end` event when the child exits

For the current prototype, `runtime shell` can remain the first concrete controlled action path:

```bash
kappaski runtime shell \
  --session ks_20260523_abc123 \
  --log .kappaski/session.jsonl \
  --ledger .kappaski/sessions/ks_20260523_abc123/ledger.jsonl \
  --agent codex \
  --target /Users/lcy/repos/kappaski \
  -- git status
```

The wrapper does not need to solve all bypass problems in v0.1. It must make the managed path explicit and produce a proof that says whether the session was managed, whether the ledger verified, and whether any required evidence is missing.

### 3. Runtime Records Action Events

Every observed Agent action should become a normalized action event before policy evaluation. Sources can include shell wrapper calls, file events reported by adapters, network events, MCP tool calls, skill loads, and manual record-event payloads.

Suggested command:

```bash
kappaski runtime record-event \
  --session ks_20260523_abc123 \
  --ledger .kappaski/sessions/ks_20260523_abc123/ledger.jsonl \
  --event '{"type":"file_read","path":"/repo/.env","agent":"codex","target":"/repo"}'
```

Minimum event contract:

- `type`: action type, such as `shell`, `file_read`, `file_write`, `network`, `mcp_tool`, `skill`, or `content`.
- `session_id`: supplied by `--session` if absent from payload.
- `agent`: Agent/client label.
- `target`: repo or workspace target.
- one action-specific field: `command`, `path`, `url`, `tool`, `skill`, or `content`.
- `metadata`: optional structured context.

The runtime should append a ledger entry containing:

- normalized action event;
- policy decision;
- findings;
- taint snapshot if the action changes taint;
- result, such as blocked, allowed, exit code, or approval state.

### 4. Policy Decisions Are Proof Events, Not Internal Logs

The proof consumer should not have to infer policy behavior from raw findings. Every action must have a decision object:

- `allow`: action was permitted without approval.
- `ask`: action required approval before continuing.
- `deny`: action was blocked by policy.

For v0.1, a deterministic mapping is enough:

- critical shell or exfiltration patterns: `deny`;
- high-risk shell/file/network/MCP actions: `ask` or `deny`, depending rule category;
- sensitive file read: `allow` or `ask`, but taints the session;
- tainted session plus write-like action: at least `ask`, with risk no lower than `high`;
- no matched rules and no taint conflict: `allow`.

The CLI should expose decisions for debugging:

```bash
kappaski runtime analyze-event \
  --session ks_20260523_abc123 \
  --event '{"type":"network","url":"https://webhook.site/example"}'
```

Expected high-level result:

```json
{
  "decision": {
    "effect": "ask",
    "risk": "high",
    "matched_rules": ["network.suspicious_destination"],
    "reason": "Suspicious external destination requires approval"
  }
}
```

### 5. Sensitive Reads Create Session-Level Taint

Taint is the bridge between local audit and collaboration trust. A proof report that says "the Agent read `.env`, then posted to Slack" is materially different from one that says "the Agent only read source files and ran tests."

v0.1 should use session-level taint:

- reading `.env`, SSH keys, cloud credentials, kubeconfig, deployment secrets, or CI/CD secrets sets `taint.is_tainted = true`;
- taint records the source event id, path, category, and timestamp;
- taint does not automatically clear during the session;
- all later write-like actions inherit taint context.

Proof language should be direct:

- clean session: "No sensitive source was observed before outbound or write-like actions."
- tainted session: "This session read sensitive resources. Later outbound/write-like actions require review."
- unknown session: "The ledger is incomplete or unverifiable; no clean proof can be asserted."

### 6. Approval Evidence Makes Exceptions Reviewable

v0.1 does not need a full approval server, but it should model approval evidence from the start.

Suggested manual approval command:

```bash
kappaski runtime approve \
  --session ks_20260523_abc123 \
  --decision dec_123 \
  --approver "$USER" \
  --reason "Pushing feature branch after local tests passed"
```

Suggested rejection command:

```bash
kappaski runtime reject \
  --session ks_20260523_abc123 \
  --decision dec_123 \
  --approver "$USER" \
  --reason "Destination is not approved for tainted sessions"
```

If manual approval is not implemented in the first code pass, the proof report must still distinguish:

- `not_required`: action did not require approval;
- `missing`: action required approval but no evidence was recorded;
- `approved`: explicit approval evidence exists;
- `rejected`: explicit rejection evidence exists;
- `blocked`: policy denied execution before approval.

This prevents "yes/no approval" from becoming an invisible side effect.

## Proof Export

### Developer Command

After the Agent finishes, the developer exports a proof report:

```bash
kappaski proof export \
  --session ks_20260523_abc123 \
  --ledger .kappaski/sessions/ks_20260523_abc123/ledger.jsonl \
  --out .kappaski/sessions/ks_20260523_abc123/proof.json
```

The command should:

1. load the ledger;
2. verify the hash chain;
3. synthesize session metadata;
4. summarize action events;
5. summarize decisions by risk and effect;
6. include final taint state;
7. include approval evidence;
8. redact or omit unbounded content;
9. write a deterministic JSON report.

For backward compatibility, `post-runtime` can initially call the same proof exporter:

```bash
kappaski post-runtime --events .kappaski/session.jsonl
```

But the preferred v0.1 command should be `proof export`, because the product object is no longer just a summary. It is an artifact meant to be consumed by other trust boundaries.

### Proof Report Shape

Minimum JSON fields:

```json
{
  "schema_version": "kappaski.proof.v0.1",
  "generated_at": "2026-05-23T00:00:00+00:00",
  "session": {
    "session_id": "ks_20260523_abc123",
    "agent": "codex",
    "target": "/Users/lcy/repos/kappaski",
    "goal": "Implement proof export",
    "started_at": "...",
    "ended_at": "..."
  },
  "ledger": {
    "path": ".kappaski/sessions/ks_20260523_abc123/ledger.jsonl",
    "entries": 42,
    "first_hash": "...",
    "last_hash": "...",
    "hash_chain_valid": true
  },
  "summary": {
    "total_actions": 18,
    "decisions": {
      "allow": 14,
      "ask": 3,
      "deny": 1
    },
    "risks": {
      "critical": 1,
      "high": 3,
      "medium": 2,
      "low": 0,
      "info": 12
    },
    "blocked_actions": 1,
    "approval_required": 3,
    "approval_missing": 0,
    "tainted": true
  },
  "taint": {
    "is_tainted": true,
    "level": "secret",
    "sources": [
      {
        "event_id": "evt_123",
        "category": "secrets",
        "path_or_url": "/repo/.env"
      }
    ]
  },
  "actions": [],
  "policy_decisions": [],
  "approval_evidence": [],
  "findings": [],
  "risk_statement": "This session read sensitive resources and later attempted a high-risk outbound action. The ledger hash chain verified."
}
```

The report must never include full secret-like content. It can include paths, hashes, rule ids, event ids, redacted payload summaries, and decision reasons.

### Verify Command

Consumers need a cheap verification path:

```bash
kappaski proof verify --proof .kappaski/sessions/ks_20260523_abc123/proof.json
```

Minimum checks:

- proof JSON parses;
- schema version is known;
- referenced ledger exists if verification is local;
- ledger hash chain verifies;
- `proof.ledger.last_hash` matches the ledger root hash;
- summary counts match ledger-derived facts;
- proof contains no malformed decision references.

Suggested output:

```json
{
  "valid": true,
  "hash_chain_valid": true,
  "last_hash": "...",
  "warnings": []
}
```

If the ledger is missing, the verifier should return an agentic error:

```json
{
  "valid": false,
  "error": "ledger_missing",
  "agent_instruction": "The proof references a ledger that is not available locally. Re-run verification with --ledger, or ask the producer to attach the ledger.jsonl artifact."
}
```

## PR, CI, And Team Consumption

### Pull Request Consumption

The first team workflow should be PR attachment, not a dashboard.

Developer flow:

```bash
kappaski session run --target . --agent codex --goal "Fix parser bug" -- codex
kappaski proof export --session "$KAPPASKI_SESSION_ID" --out .kappaski/proof.json
git add src tests .kappaski/proof.json
```

Reviewer flow:

```bash
kappaski proof verify --proof .kappaski/proof.json
```

The reviewer should be able to answer:

- Did this Agent session touch sensitive resources?
- Were outbound/network/MCP write-like actions attempted?
- Were dangerous shell commands blocked?
- Which high-risk actions were approved, rejected, denied, or missing evidence?
- Is the ledger intact?

The proof should be small enough to attach to a PR comment, CI artifact, or release evidence bundle.

### CI Consumption

CI should treat proof as a policy gate.

Suggested command:

```bash
kappaski proof verify \
  --proof .kappaski/proof.json \
  --require-clean-ledger \
  --deny-tainted-outbound \
  --deny-missing-approvals
```

v0.1 CI rules should stay deterministic:

- fail if `hash_chain_valid` is false;
- fail if `approval_missing > 0`;
- fail if critical decisions exist and were not denied;
- optionally fail if session is tainted and includes network/MCP/file-write events after taint;
- warn, do not fail, if proof schema is older but still parseable.

CI should not require a Kappaski server in v0.1. The local JSON proof plus ledger is enough for the first trust loop.

### Team Consumption

Teams can start with a repo-level policy:

```yaml
proof:
  required_for_agent_generated_prs: true
  require_hash_chain_valid: true
  deny_missing_approvals: true
  deny_tainted_outbound: true
  allowed_agents:
    - codex
    - claude-code
```

This policy should be consumed by local CLI and CI in the same way. The product principle is one policy language, multiple enforcement points.

Team-facing summaries should avoid raw logs and expose a compact decision ledger:

- session identity;
- goal;
- Agent/client;
- clean/tainted state;
- blocked actions;
- approvals;
- outbound destinations;
- files touched;
- ledger root hash.

## Workflow Boundaries

### In Scope For v0.1

- One local session at a time.
- CLI-first developer workflow.
- JSONL hash-chain ledger.
- JSON proof export.
- Deterministic policy decisions.
- Session-level taint.
- Manual or placeholder approval evidence.
- Local verification by developer, reviewer, or CI.
- Proof artifact designed for PR and CI attachment.

### Out Of Scope For v0.1

- Enterprise dashboard.
- Multi-agent task orchestration.
- Task boards or project management.
- Central policy server.
- Cross-device identity.
- Real-time OS-level sandboxing.
- Full content-level DLP.
- Vendor-specific IDE plugin UX.
- Long-term proof registry.

## CLI Command Surface Recommendation

Keep the v0.1 surface small:

```text
kappaski pre-runtime --target . --output json

kappaski session start --target . --agent codex --goal "..."
kappaski session run --target . --agent codex --goal "..." -- codex
kappaski session close --session <id>

kappaski runtime analyze-event --session <id> --event '<json>'
kappaski runtime record-event --session <id> --ledger <path> --event '<json>'
kappaski runtime shell --session <id> --ledger <path> -- <cmd...>
kappaski runtime approve --session <id> --decision <id> --approver <name> --reason "..."
kappaski runtime reject --session <id> --decision <id> --approver <name> --reason "..."

kappaski proof export --session <id> --ledger <path> --out <path>
kappaski proof verify --proof <path> [--ledger <path>]
```

Backward compatible aliases can remain:

```text
kappaski post-runtime --events .kappaski/session.jsonl
```

But new implementation should make `proof export` the canonical post-session command.

## Acceptance Flow

The v0.1 end-to-end demo should be:

```bash
kappaski pre-runtime --target /Users/lcy/repos/kappaski --output json

kappaski session start \
  --target /Users/lcy/repos/kappaski \
  --agent codex \
  --goal "Demonstrate local proof generation"

kappaski runtime record-event \
  --session "$KAPPASKI_SESSION_ID" \
  --ledger "$KAPPASKI_LEDGER" \
  --event '{"type":"file_read","path":"/Users/lcy/repos/kappaski/.env","agent":"codex"}'

kappaski runtime record-event \
  --session "$KAPPASKI_SESSION_ID" \
  --ledger "$KAPPASKI_LEDGER" \
  --event '{"type":"network","url":"https://webhook.site/example","agent":"codex"}'

kappaski proof export \
  --session "$KAPPASKI_SESSION_ID" \
  --ledger "$KAPPASKI_LEDGER" \
  --out .kappaski/proof.json

kappaski proof verify --proof .kappaski/proof.json --ledger "$KAPPASKI_LEDGER"
```

Expected result:

- pre-runtime scan reports local risk context;
- session has a stable id and ledger path;
- sensitive file read taints the session;
- later suspicious network action is elevated by taint;
- policy decision is explicit;
- ledger verifies as a hash chain;
- proof JSON states what happened, what was blocked or approved, and whether sensitive outbound risk exists.

## Design Principle

The proof is the product boundary for v0.1.

Wrappers, rules, taint, approvals, and ledgers are implementation mechanisms. The user-visible promise is that a local Agent run can produce a compact, verifiable artifact that transfers trust from the developer's machine into PR review, CI, vendor delivery, and later enterprise governance.
