# Kappaski v0.1 Minimal Technical Plan

This plan upgrades the current lightweight runtime audit prototype into a local Agent behavior proof generator. The implementation should stay dependency-free for v0.1 and preserve the current module shape:

- `models.py`: typed dataclasses and serialization helpers.
- `runtime.py`: event normalization, policy evaluation, ledger append, optional shell wrapper.
- `rules.py`: deterministic risk rules and policy decision construction.
- `postruntime.py`: ledger verification and proof report export.
- `cli.py`: thin command surface for session, runtime, and proof flows.

The first implementation target is not a daemon, enterprise dashboard, or multi-agent orchestrator. It is one managed local session that produces a verifiable JSONL ledger and a readable proof report.

## Current Prototype Baseline

The repository currently has:

- `Finding`: rule output with `rule_id`, `title`, `severity`, `phase`, `category`, and optional evidence.
- `RuntimeEvent`: loose runtime payload with event type, command/path/url/tool/skill/content, and metadata.
- `append_event`: analyzes a `RuntimeEvent`, attaches findings, and appends plain JSONL.
- `summarize_session`: loads JSONL, aggregates event types, agents, paths, tools, urls, findings, and embeds raw events.

The gap is that runtime facts, decisions, taint, approvals, and evidence integrity are implicit. v0.1 should make those objects explicit while keeping the current code easy to reason about.

## v0.1 Data Model

### 1. Session

Represents one managed Agent run.

Required fields for v0.1:

- `session_id: str`: stable id generated at session start.
- `started_at: str`: UTC ISO timestamp.
- `status: str`: `active`, `closed`, or `aborted`.
- `target: str`: absolute or display path for the workspace/repo.
- `agent: str | None`: human-readable Agent/client name, for example `codex`, `claude-code`, or `unknown`.
- `user: str | None`: local username or supplied actor id.
- `policy_version: str`: policy/ruleset identifier used for decisions.
- `ledger_path: str`: JSONL path for this session.

Optional but useful in v0.1:

- `goal: str | None`: user-supplied task summary.
- `created_by: str | None`: wrapper/CLI/adapter that created the session.
- `metadata: dict[str, Any]`: extension area for future daemon or enterprise fields.

Implementation note: store a `session_start` ledger entry first and a `session_end` entry when proof export closes a run. Avoid a separate database.

### 2. ActionEvent

Replaces or wraps the current `RuntimeEvent` as the normalized action being judged.

Required fields for v0.1:

- `event_id: str`: stable id per action event.
- `session_id: str`: owning session.
- `timestamp: str`: UTC ISO timestamp.
- `sequence: int`: monotonic sequence within the session.
- `action_type: str`: `shell`, `file_read`, `file_write`, `network`, `mcp_tool`, `skill`, `content`, `approval`, `session`.
- `actor: str | None`: Agent/client/user performing the action.
- `target: str | None`: workspace/repo or system target.
- `command: str | None`: shell command when applicable.
- `path: str | None`: file path when applicable.
- `url: str | None`: network target when applicable.
- `tool: str | None`: MCP/tool name when applicable.
- `payload_summary: str | None`: short redacted summary of payload/content.
- `metadata: dict[str, Any]`: structured extension field.

Optional but useful in v0.1:

- `parent_event_id: str | None`: links approval, block, exit, or derived events.
- `content_hash: str | None`: hash of large/redacted content without storing full text.

Compatibility: `RuntimeEvent` can remain as the CLI input object initially, but `runtime.py` should convert it into `ActionEvent` before policy and ledger writing.

### 3. PolicyDecision

Makes rule evaluation explicit instead of relying on raw findings.

Required fields for v0.1:

- `decision_id: str`: stable id.
- `event_id: str`: action being evaluated.
- `session_id: str`: owning session.
- `timestamp: str`: UTC ISO timestamp.
- `effect: str`: `allow`, `deny`, or `ask`.
- `risk: str`: `info`, `low`, `medium`, `high`, or `critical`.
- `matched_rules: list[str]`: rule ids that produced the decision.
- `findings: list[Finding]`: current finding objects for compatibility.
- `reason: str`: short human-readable explanation.
- `requires_approval: bool`: true when `effect == "ask"` or risk exceeds local threshold.

Optional but useful in v0.1:

- `taint_influenced: bool`: true when session taint elevated the action.
- `default_policy: str | None`: for example `deny_high`, `ask_high`, `allow_medium`.

Initial rule mapping:

- Any critical finding -> `deny` by default.
- Any high finding -> `ask` or `deny` depending action category.
- Tainted session plus write/network/MCP action -> at least `ask` and risk no lower than `high`.
- No findings and no taint conflict -> `allow`.

### 4. ApprovalEvidence

Records why a high-risk action was allowed or rejected.

Required fields for v0.1:

- `approval_id: str`: stable id.
- `decision_id: str`: related policy decision.
- `event_id: str`: related action.
- `session_id: str`: owning session.
- `status: str`: `approved`, `rejected`, `expired`, or `not_required`.
- `requested_at: str`: UTC ISO timestamp.
- `resolved_at: str | None`: UTC ISO timestamp when resolved.
- `approver: str | None`: local user or actor that approved/rejected.
- `reason: str | None`: optional user-supplied justification.

Optional but useful in v0.1:

- `prompt: str | None`: redacted approval prompt shown to the user.
- `expires_at: str | None`: approval timeout.
- `context_event_ids: list[str]`: recent events shown during approval.

Implementation note: v0.1 can support manual CLI approval later. Until that exists, denied/blocked actions should still produce `ApprovalEvidence(status="not_required")` or omit the object, but proof export must clearly show no approval occurred.

### 5. TaintState

Tracks session-level sensitive-resource exposure.

Required fields for v0.1:

- `session_id: str`: owning session.
- `is_tainted: bool`: whether any active taint exists.
- `level: str`: `none`, `sensitive`, or `secret`.
- `sources: list[dict[str, str]]`: source records with `event_id`, `kind`, `path_or_url`, and `category`.
- `updated_at: str`: UTC ISO timestamp.

Optional but useful in v0.1:

- `cleared_at: str | None`: future escape hatch; not needed for automatic clearing yet.
- `notes: list[str]`: short explanations such as `file_read matched path.cloud-credentials`.

Minimum behavior:

- Reading `.env`, SSH keys, cloud credentials, kubeconfig, deployment secrets, or CI/CD secrets taints the session.
- After taint, all write-like actions (`file_write`, `network`, `mcp_tool`, shell commands with upload/post/push/curl semantics) are evaluated with taint context.
- v0.1 does not need byte-level DLP or content propagation analysis.

### 6. LedgerEntry

The append-only evidence envelope written to JSONL.

Required fields for v0.1:

- `sequence: int`: starts at 1 and increments by one.
- `entry_id: str`: stable id for the ledger row.
- `session_id: str`: owning session.
- `timestamp: str`: UTC ISO timestamp.
- `entry_type: str`: `session`, `action`, `decision`, `approval`, `taint`, or `result`.
- `event: dict[str, Any] | None`: serialized `ActionEvent`.
- `decision: dict[str, Any] | None`: serialized `PolicyDecision`.
- `approval: dict[str, Any] | None`: serialized `ApprovalEvidence`.
- `taint: dict[str, Any] | None`: serialized `TaintState` snapshot when changed.
- `findings: list[dict[str, Any]]`: compatibility field for current summaries.
- `prev_hash: str`: previous ledger entry hash, or a fixed zero hash for the first entry.
- `entry_hash: str`: SHA-256 over canonical JSON excluding `entry_hash`.

Optional but useful in v0.1:

- `schema_version: str`: start with `kappaski.ledger.v0.1`.
- `result: dict[str, Any] | None`: shell exit code, block reason, proof export result, or verification result.

Hashing rule:

- Serialize with deterministic JSON: UTF-8, sorted keys, compact separators.
- Compute `entry_hash = sha256(canonical(entry_without_entry_hash))`.
- Verification recomputes each hash and checks that `prev_hash` equals the prior `entry_hash`.
- No signatures in the first code pass unless security design requires it; keep the schema ready for `signature` later.

### 7. ProofReport

The exported artifact that a developer, reviewer, CI job, or team can consume.

Required fields for v0.1:

- `schema_version: str`: start with `kappaski.proof.v0.1`.
- `generated_at: str`: UTC ISO timestamp.
- `session: dict[str, Any]`: serialized `Session` or derived session summary.
- `ledger: dict[str, Any]`: `path`, `entries`, `first_hash`, `last_hash`, `hash_chain_valid`.
- `summary: dict[str, Any]`: total actions, decisions by effect/risk, blocked actions, approvals, taint status.
- `actions: list[dict[str, Any]]`: normalized action summaries, not raw unbounded content.
- `policy_decisions: list[dict[str, Any]]`: explicit decisions.
- `taint: dict[str, Any]`: final taint state.
- `findings: list[dict[str, Any]]`: flattened findings for current compatibility.

Optional but useful in v0.1:

- `approval_evidence: list[dict[str, Any]]`: approval records.
- `risk_statement: str`: one-paragraph generated summary from deterministic facts.
- `export_warnings: list[str]`: malformed JSONL lines, hash errors, missing session start/end.

Proof report rule: never include full secret-like content. Include paths, rule ids, hashes, and redacted payload summaries.

## Minimal Module Changes

### `models.py`

Add dataclasses for:

- `Session`
- `ActionEvent`
- `PolicyDecision`
- `ApprovalEvidence`
- `TaintState`
- `LedgerEntry`
- `ProofReport`

Keep `RuntimeEvent` for backward-compatible CLI parsing in v0.1. Add `to_dict()` on all new objects and small `from_dict()` helpers only where needed by CLI input or JSONL loading.

### `runtime.py`

Change the write path from:

`RuntimeEvent -> findings -> plain JSONL`

to:

`RuntimeEvent -> ActionEvent -> PolicyDecision -> TaintState update -> LedgerEntry JSONL`

Required functions:

- `start_session(target: Path, ledger_path: Path, agent: str | None, goal: str | None) -> Session`
- `record_action(event: RuntimeEvent | ActionEvent, ledger_path: Path) -> PolicyDecision`
- `append_ledger_entry(entry: LedgerEntry, ledger_path: Path) -> None`
- `verify_ledger(ledger_path: Path) -> dict[str, Any]`

`append_event` can remain as a compatibility wrapper around `record_action`.

### `rules.py`

Keep existing deterministic pattern rules. Add a small policy layer:

- `evaluate_policy(event: ActionEvent, findings: list[Finding], taint: TaintState) -> PolicyDecision`
- `updates_taint(event: ActionEvent, findings: list[Finding], previous: TaintState) -> TaintState`

The first pass should not introduce a general policy language. Rule ids and severity mapping are enough.

### `postruntime.py`

Extend from aggregation to proof export:

- Load ledger entries.
- Verify hash chain.
- Extract session, actions, decisions, approvals, taint snapshots, and findings.
- Produce a `ProofReport`.

Keep `summarize_session` as a compatibility entry point, but let it call the same loader used by proof export when the file is a v0.1 ledger.

### `cli.py`

Minimum command shape:

- `kappaski session start --target . --agent codex --goal "..." --log .kappaski/session.jsonl`
- `kappaski runtime record-event --event '{...}' --log .kappaski/session.jsonl`
- `kappaski proof export --events .kappaski/session.jsonl --output proof.json`
- Keep existing `pre-runtime`, `runtime analyze-event`, `runtime shell`, and `post-runtime` commands working.

## First-Pass Acceptance Tests

Required tests in `tests/test_core.py`:

- Dangerous command produces a `PolicyDecision` with high/critical risk and deny/ask effect.
- Sensitive file read updates `TaintState.is_tainted` and records taint source.
- Tainted session plus network/MCP/write action raises risk and requires approval.
- Ledger entries form a valid hash chain.
- Tampering with a ledger line makes verification fail.
- Proof export includes session, actions, decisions, taint, findings, and `hash_chain_valid`.
- Existing tests for `analyze_command`, pre-runtime scan, and post-runtime summary continue to pass.

## Fields That Must Ship in v0.1

Do not defer these fields because later code depends on them:

- `session_id` on every session/action/decision/approval/taint/ledger/proof object.
- `event_id` on every action and policy decision.
- `sequence`, `prev_hash`, and `entry_hash` on every ledger entry.
- `effect`, `risk`, `matched_rules`, and `reason` on every policy decision.
- `is_tainted`, `level`, and `sources` on taint state.
- `hash_chain_valid`, `first_hash`, and `last_hash` in proof export.
- Redacted `payload_summary` instead of raw unbounded payload content in proof-facing objects.

## Explicit Non-Goals for v0.1

- No enterprise control plane.
- No web UI.
- No multi-agent scheduler.
- No OS-level sandbox claim.
- No byte-level DLP.
- No cryptographic signing unless it fits without new heavy dependencies.
- No broad policy language before the event/decision/ledger schema stabilizes.

The engineering priority is a small, testable evidence chain: managed session, normalized action, explicit policy decision, session-level taint, hash-chain JSONL, and proof JSON export.
