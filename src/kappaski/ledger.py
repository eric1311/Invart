from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .models import LedgerEntry


ZERO_HASH = "0" * 64


def canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def compute_entry_hash(entry_payload: dict[str, Any]) -> str:
    material = {key: value for key, value in entry_payload.items() if key != "entry_hash"}
    return hashlib.sha256(canonical_json(material).encode("utf-8")).hexdigest()


def load_ledger_entries(ledger_path: Path) -> tuple[list[LedgerEntry], list[str]]:
    entries: list[LedgerEntry] = []
    warnings: list[str] = []
    if not ledger_path.exists():
        return entries, warnings
    with ledger_path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                warnings.append(f"line {line_number}: invalid JSON")
                continue
            if not isinstance(payload, dict):
                warnings.append(f"line {line_number}: ledger row is not an object")
                continue
            entries.append(LedgerEntry.from_dict(payload))
    return entries, warnings


def append_ledger_entry(entry: LedgerEntry, ledger_path: Path) -> LedgerEntry:
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    existing, _warnings = load_ledger_entries(ledger_path)
    if existing:
        previous = existing[-1]
        entry.sequence = previous.sequence + 1
        entry.prev_hash = previous.entry_hash
    else:
        entry.sequence = 1
        entry.prev_hash = ZERO_HASH
    payload = entry.to_dict()
    payload["entry_hash"] = ""
    entry.entry_hash = compute_entry_hash(payload)
    with ledger_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry.to_dict(), ensure_ascii=False, sort_keys=True) + "\n")
    return entry


def verify_ledger(ledger_path: Path) -> dict[str, Any]:
    entries, warnings = load_ledger_entries(ledger_path)
    first_violation: int | None = None
    previous_hash = ZERO_HASH
    computed_hashes: list[str] = []
    for entry in entries:
        payload = entry.to_dict()
        stored_hash = entry.entry_hash
        payload["entry_hash"] = ""
        computed_hash = compute_entry_hash(payload)
        computed_hashes.append(computed_hash)
        if first_violation is None and entry.prev_hash != previous_hash:
            first_violation = entry.sequence
        if first_violation is None and stored_hash != computed_hash:
            first_violation = entry.sequence
        previous_hash = stored_hash
    return {
        "valid": first_violation is None and not warnings,
        "entries": len(entries),
        "first_violation": first_violation,
        "first_hash": entries[0].entry_hash if entries else None,
        "last_hash": entries[-1].entry_hash if entries else None,
        "computed_last_hash": computed_hashes[-1] if computed_hashes else None,
        "warnings": warnings,
    }

