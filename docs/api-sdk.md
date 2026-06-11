# Integrate with Invart without guessing the boundary.

[HTML version](html/api-sdk.html)


Invart 0.9 is CLI-first. The stable integration surface is the CLI plus verifiable artifacts. Python helpers are available for local tooling, but only a small set should be treated as provisional SDK entry points before 1.0.

[Docs Home](index.md) · [Quickstart](quickstart.md) · [Operate L1-L5](five-layer-operator-guide.md) · [CLI](cli-reference.md) · [Architecture](architecture.md) · [Examples](examples.md)

## Public Surface

| Surface | Status | Use it for | Boundary |
| --- | --- | --- | --- |
| invart CLI | Stable pre-1.0 surface | Running sessions, exporting proof, generating replay/audit artifacts, benchmarks, and RC checks. | Prefer this for scripts, demos, CI checks, and product validation. |
| Artifact contracts | Stable exchange surface | Sharing ledgers, proofs, replay pages, path graphs, coverage reports, audit reports, and evidence bundles. | Ledger remains the fact source. Proof is a portable summary. |
| Python helpers | Provisional SDK surface | Building local tools around ledger verification, proof export, runtime event normalization, and artifact inspection. | Use named helpers below. Do not assume every module in src/invart is stable. |
| Hosted API | Not available in 0.9 | Remote administration, hosted policy service, IdP integration, or enterprise console workflows. | Planned after the local control-plane boundary is stable. |

## CLI First

The CLI is the safest integration point for most users because it preserves Invart's mediation, ledger, proof, and release-candidate behavior without requiring Python import stability.

```bash
invart session start --target . --agent demo-agent --goal "Inspect safely" --ledger .invart/demo/ledger.jsonl
invart runtime shell --session demo --ledger .invart/demo/ledger.jsonl -- python -c "print('hello')"
invart proof export --ledger .invart/demo/ledger.jsonl --out .invart/demo/proof.json
invart proof verify --proof .invart/demo/proof.json --ledger .invart/demo/ledger.jsonl
```

## Provisional Python SDK

### Ledger integrity

```bash
from pathlib import Path
from invart.core.ledger import load_ledger_entries, verify_ledger

ledger = Path(".invart/quickstart/ledger.jsonl")
entries, warnings = load_ledger_entries(ledger)
integrity = verify_ledger(ledger)
```

### Proof export and verification

```bash
from pathlib import Path
from invart.assurance.postruntime import export_proof_report, verify_proof_report

proof = export_proof_report(Path("ledger.jsonl"), Path("proof.json"))
verification = verify_proof_report(Path("proof.json"), Path("ledger.jsonl"))
```

### Runtime event normalization

```bash
from invart.core.models import RuntimeEvent

event = RuntimeEvent.from_dict({
    "type": "shell",
    "command": "python -m pytest -q",
    "session_id": "demo",
})
payload = event.to_dict()
```

These helpers are suitable for local adapters, experiments, and internal automation. Before 1.0, new SDK users should pin Invart and keep integration tests around these calls.

## Artifact Contracts

| Artifact | Typical producer | Typical consumer | Notes |
| --- | --- | --- | --- |
| Ledger JSONL | invart session, invart runtime, adapters | Proof, replay, gate, audit, path graph, evidence bundle | Append-only fact source with hash-chain verification. |
| Proof JSON | invart proof export | invart proof verify, invart gate verify, audit reviewers | Portable summary derived from the ledger. |
| Runtime event JSON | Wrappers, hooks, adapters, demos | invart runtime analyze-event, mediation, policy checks | Useful when integrating a new execution surface. |
| Policy profile TOML | Security or platform owner | Policy checks, gates, replay display policy | See examples/policy-profile.toml for a compact profile. |
| Evidence bundle | invart evidence export, RC gate, demos | invart evidence verify, enterprise audit review | Manifest plus hashes for proof, ledger-derived artifacts, profile, coverage, and audit material. |
| Paper tables JSON/CSV/HTML | invart experiment paper-tables | Research reports, appendix tables, product validation review | Derived summaries. Each row should link back to ledger/proof/replay/path graph/evidence artifacts. |
| Research readiness report | invart release-candidate verify --paper | Pre-release research review | Separate from product RC. It checks evidence completeness without claiming external benchmark completion. |

For the operational meaning of proof, replay, path graph, coverage, audit, and evidence workspace, use the [five-layer operator guide](five-layer-operator-guide.md). It explains which artifact answers each L1-L5 review question.

## Compatibility Names

New integrations should import invart and use the canonical subpackages such as invart.core, invart.control, and invart.assurance. The older flat invart.ledger style imports and the former kappaski import path remain compatibility aliases during the rename period, but new documentation and examples use the organized Invart layout.

## Not Yet Public API

Internal modules that implement benchmarks, roadmap accounting, release-candidate orchestration, demos, and experimental adapters may change before 1.0. When in doubt, integrate through the CLI or artifact contracts first, then use the provisional Python helpers only where direct imports add clear value.
