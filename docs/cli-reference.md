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

### Evaluation

```bash
invart eval list
invart eval benchmark --suite full-product-readiness
invart roadmap status --require-full
```
