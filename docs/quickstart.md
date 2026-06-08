# Run one managed Invart session.

[HTML version](html/quickstart.html)


This path creates a ledger, records a runtime command, exports proof, and verifies the proof against the ledger.

## Install

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
invart --help
```

## Run

```bash
mkdir -p .invart/quickstart

invart session start \
  --target . \
  --agent demo-agent \
  --goal "Inspect the repository without risky changes" \
  --session-id invart_quickstart \
  --ledger .invart/quickstart/ledger.jsonl

invart runtime shell \
  --session invart_quickstart \
  --ledger .invart/quickstart/ledger.jsonl \
  -- python -c "from pathlib import Path; print(len(list(Path('.').iterdir())))"

invart session close --ledger .invart/quickstart/ledger.jsonl
```

## Verify

```bash
invart proof export \
  --ledger .invart/quickstart/ledger.jsonl \
  --out .invart/quickstart/proof.json

invart proof verify \
  --proof .invart/quickstart/proof.json \
  --ledger .invart/quickstart/ledger.jsonl
```

The ledger is the fact source. The proof is a portable summary that can be shared with a gate, reviewer, or audit process.
