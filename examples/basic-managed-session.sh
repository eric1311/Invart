#!/usr/bin/env bash
set -euo pipefail

mkdir -p .invart/examples/basic

invart session start \
  --target . \
  --agent example-agent \
  --goal "Run a low-risk repository inspection" \
  --session-id invart_example_basic \
  --ledger .invart/examples/basic/ledger.jsonl

invart runtime shell \
  --session invart_example_basic \
  --ledger .invart/examples/basic/ledger.jsonl \
  -- python -c "from pathlib import Path; print('files', len(list(Path('.').iterdir())))"

invart session close --ledger .invart/examples/basic/ledger.jsonl

invart proof export \
  --ledger .invart/examples/basic/ledger.jsonl \
  --out .invart/examples/basic/proof.json

invart proof verify \
  --proof .invart/examples/basic/proof.json \
  --ledger .invart/examples/basic/ledger.jsonl

echo "Invart example complete: .invart/examples/basic"
