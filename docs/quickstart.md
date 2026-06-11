# Run one managed Invart session.

[HTML version](html/quickstart.html)


This path creates a ledger, records a runtime command, exports proof, verifies the proof against the ledger, and points you to the five-layer inspection workflow.

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

## Inspect L1-L5

```bash
invart runtime layers \
  --ledger .invart/quickstart/ledger.jsonl \
  --out-dir .invart/quickstart/layers

invart evidence inspect \
  --manifest .invart/quickstart/layers/evidence/manifest.json \
  --out-dir .invart/quickstart/evidence-workspace \
  --require-layer-workflow
```

Open `.invart/quickstart/layers/layer-runtime-workflow.html` to see before-runtime, during-runtime, and after-runtime across L1-L5. Open `.invart/quickstart/evidence-workspace/evidence-workspace.html` to verify whether the run can answer who, what, why, policy, approval, outcome, and coverage.

For layer-by-layer interpretation rules, read the [five-layer operator guide](five-layer-operator-guide.md). For small copyable fixtures, see [Examples](examples.md).
