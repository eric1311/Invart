# The command groups users need first.

[HTML version](html/cli-reference.html)


Run `invart --help` for the complete parser. These are the entry points most people should start with. For a guided L1-L5 workflow, use the [five-layer operator guide](five-layer-operator-guide.md).

## User intent to command

| I want to... | Start with |
| --- | --- |
| Scan before an agent runs | `invart pre-runtime --target . --save` |
| Run one managed session | `invart run --target . --agent codex --goal "..." -- <command>` |
| Inspect L1-L5 for a ledger | `invart runtime layers --ledger ledger.jsonl --out-dir .invart/layers` |
| Explain a risky path | `invart policy check-path --ledger ledger.jsonl --out path-policy.json` |
| Inspect mediation state | `invart mediation inspect --ledger ledger.jsonl` |
| Export reviewable evidence | `invart evidence export --ledger ledger.jsonl --out-dir .invart/evidence` |
| Validate real-agent integration | `invart real-agent check --agent claude-code --out-dir .invart/real-agent` |
| Run product benchmarks | `invart eval benchmark --suite full-product-readiness` |

### Pre-runtime

```bash
invart pre-runtime --target . --save
```

### Managed session

```bash
invart session start --target . --agent codex --goal "..."
invart run --target . --agent codex --goal "..." -- <command>
```

### Runtime event

```bash
invart runtime analyze-event --event '{"type":"shell","command":"rm -rf ."}'
invart runtime shell --session demo --ledger .invart/demo.jsonl -- <command>
invart runtime layers --ledger .invart/demo.jsonl --out-dir .invart/layers
```

`runtime layers` exports a L1-L5 operation workflow for an existing ledger. It writes JSON and HTML that link proof, replay, path graph, coverage, audit, and evidence manifest artifacts.

### Proof and gate

```bash
invart proof export --ledger ledger.jsonl --out proof.json
invart proof verify --proof proof.json --ledger ledger.jsonl
invart gate verify --proof proof.json --ledger ledger.jsonl --mode ci
```

### Replay and audit

```bash
invart replay export --ledger ledger.jsonl --out replay.html
invart audit report --ledger ledger.jsonl --out-dir .invart/audit
```

### Evidence workspace

```bash
invart evidence export --ledger ledger.jsonl --out-dir .invart/evidence
invart evidence verify --bundle .invart/evidence/manifest.json
invart evidence inspect \
  --manifest .invart/evidence/manifest.json \
  --out-dir .invart/evidence-workspace \
  --require-layer-workflow
```

`evidence inspect` treats the bundle as an L5 review workspace. It verifies artifact hashes, checks required bundle contents, and reports whether the run can answer who, what, why, policy, approval, outcome, and coverage. Optional requirements such as `--require-layer-workflow` and `--require-adapter-package` turn missing links into gate failures.

### Real agent conformance

```bash
invart adapter profile --kind claude-code
invart adapter profiles
invart adapter profiles --track managed_wrapper
invart real-agent check --agent claude-code --out-dir .invart/real-agent
invart real-agent run --agent claude-code --require-live --out-dir .invart/live-claude -- <claude-or-fixture-command>
invart real-agent run --agent opencode --require-live --out-dir .invart/live-opencode -- <opencode-or-fixture-command>
invart real-agent run --agent gemini-cli --require-live --out-dir .invart/live-gemini -- <gemini-or-fixture-command>
invart real-agent run --agent aider --require-live --out-dir .invart/live-aider -- <aider-or-fixture-command>
invart real-agent report --run-dir .invart/real-agent --out .invart/real-agent/report.html
```

Use `--require-live` when you want missing local agent binaries to fail the run instead of being recorded as blocked evidence. Fixture-backed runs validate the Invart adapter contract; live runs validate the installed product surface.
The plural `adapter profiles` command lists priority agent tracks: reference full adapter, managed wrapper, native bridge, vendor/cloud evidence import, and framework trace import. Vendor import tracks are audit evidence, not Invart mediation. `real-agent check` emits a conformance contract row for each product so imported, discovered, fixture-backed, and live evidence cannot be mixed into a stronger claim.

### Claude Code reference adapter

```bash
invart adapter claude-code \
  --target . \
  --out-dir .invart/claude-reference \
  --binary claude \
  --require-live \
  --hook-events .invart/claude-hooks.jsonl \
  --policy-mode managed \
  -- <claude-or-harness-command>
```

This reference adapter records Claude-style hook events, mediates the child command, and exports an adapter package containing ledger, proof, replay, path graph, coverage, audit, and evidence manifest. In managed/ci mode, deterministic risky actions pause or block before the child command is launched; advisory mode preserves autonomy and records evidence. Portable subprocess supervision is explicitly marked as degraded process-tree coverage unless native supervision is enabled.

Use `--require-live` when the Claude Code binary must be resolvable and invokable. Missing binaries fail instead of being treated as successful validation. Local tests may use binary-shaped fixtures to verify the adapter path; those fixtures are recorded as binary-backed validation, not proof that a vendor-installed Claude Code run was exercised.

### Evaluation

```bash
invart eval list
invart eval benchmark --suite full-product-readiness
invart eval benchmark --suite v0.9.3-agent-adapter-contract
invart eval benchmark --suite v0.9.4-claude-reference-adapter
invart eval benchmark --suite v0.9.5-priority-agent-tracks
invart eval benchmark --suite v0.9.6-layer-runtime-workflow
invart eval benchmark --suite v0.9.7-evidence-workspace-gate
invart eval benchmark --suite v0.9.8-claude-full-live-adapter
invart eval benchmark --suite v0.9.9-conformance-contract-v2
invart eval benchmark --suite v0.9.10-opencode-real-adapter
invart eval benchmark --suite v0.9.11-terminal-agent-managed-wrappers
invart roadmap status --require-full
```
