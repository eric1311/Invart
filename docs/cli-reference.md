# The command groups users need first.

[HTML version](html/cli-reference.html)


Run invart --help for the complete parser. These are the entry points most people should start with.

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
```

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

### Real agent conformance

```bash
invart adapter profile --kind claude-code
invart adapter profiles
invart adapter profiles --track managed_wrapper
invart real-agent check --agent claude-code --out-dir .invart/real-agent
invart real-agent report --run-dir .invart/real-agent --out .invart/real-agent/report.html
```

Use `--require-live` when you want missing local agent binaries to fail the run instead of being recorded as blocked evidence. Fixture-backed runs validate the Invart adapter contract; live runs validate the installed product surface.
The plural `adapter profiles` command lists priority agent tracks: reference full adapter, managed wrapper, native bridge, vendor/cloud evidence import, and framework trace import. Vendor import tracks are audit evidence, not Invart mediation.

### Claude Code reference adapter

```bash
invart adapter claude-code \
  --target . \
  --out-dir .invart/claude-reference \
  --hook-events .invart/claude-hooks.jsonl \
  --policy-mode managed \
  -- <claude-or-harness-command>
```

This reference adapter records Claude-style hook events, mediates the child command, and exports an adapter package containing ledger, proof, replay, path graph, coverage, audit, and evidence manifest. In managed/ci mode, deterministic risky actions pause or block before the child command is launched; advisory mode preserves autonomy and records evidence. Portable subprocess supervision is explicitly marked as degraded process-tree coverage unless native supervision is enabled.

### Evaluation

```bash
invart eval list
invart eval benchmark --suite full-product-readiness
invart eval benchmark --suite v0.9.3-agent-adapter-contract
invart eval benchmark --suite v0.9.4-claude-reference-adapter
invart eval benchmark --suite v0.9.5-priority-agent-tracks
invart roadmap status --require-full
```
