from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


CAPABILITY_PATTERNS: dict[str, tuple[str, ...]] = {
    "shell": ("```bash", "shell", "command", "cli", "npx", "npm", "python", "brew", "curl", "wget"),
    "file_read": ("read file", "read files", "filesystem", "file system", "open file", "parse file"),
    "file_write": ("write file", "edit file", "create file", "generate file", "save file", "update file"),
    "network": ("http://", "https://", "api", "webhook", "request", "fetch", "download", "upload"),
    "browser": ("browser", "web page", "chrome", "playwright", "selenium"),
    "git": ("git ", "github", "pull request", "commit", "branch", "repository"),
    "cloud": ("aws", "gcp", "azure", "cloud", "s3", "lambda"),
    "messaging": ("slack", "twilio", "sms", "whatsapp", "telegram", "email", "send message"),
    "payment": ("stripe", "payment", "refund", "invoice", "subscription", "checkout"),
    "database": ("database", "sql", "postgres", "mysql", "sqlite", "airtable"),
    "calendar": ("calendar", "meeting", "schedule", "event"),
    "mcp": ("mcp", "model context protocol", "server", "tool"),
}

RISK_PATTERNS: tuple[tuple[str, str, str], ...] = (
    ("credential_reference", "high", r"(?i)(api[_ -]?key|secret|token|credential|bearer|oauth)"),
    ("external_write", "high", r"(?i)(send|post|upload|publish|refund|charge|delete|create|update).{0,80}(api|webhook|slack|stripe|github|database|file)"),
    ("destructive_action", "high", r"(?i)(delete|remove|drop|destroy|overwrite|force push|refund|charge)"),
    ("shell_execution", "medium", r"(?i)(```bash|shell command|run command|execute|npx|npm install|brew install|curl|wget)"),
    ("external_dependency", "medium", r"(?i)(github\.com|npmjs\.com|pypi|download|install)"),
    ("unbounded_filesystem", "medium", r"(?i)(entire directory|all files|filesystem|file system|recursive|workspace)"),
    ("target_deviation", "high", r"(?i)(ignore previous|ignore prior|new objective|real task|override instructions)"),
)

@dataclass
class CapabilitySurface:
    source_id: str
    kind: str
    path: str
    content_sha256: str
    capabilities: list[str] = field(default_factory=list)
    risks: list[dict[str, str]] = field(default_factory=list)
    frontmatter: dict[str, str] = field(default_factory=dict)
    summary: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def scan_corpus(root: Path = Path("benchmarks/corpora")) -> dict[str, Any]:
    surfaces: list[CapabilitySurface] = []
    for metadata_path in sorted(root.glob("*/*/*/metadata.json")):
        surfaces.append(scan_snapshot(metadata_path.parent))
    by_capability: dict[str, int] = {}
    by_risk: dict[str, int] = {}
    for surface in surfaces:
        for capability in surface.capabilities:
            by_capability[capability] = by_capability.get(capability, 0) + 1
        for risk in surface.risks:
            key = f"{risk['severity']}:{risk['category']}"
            by_risk[key] = by_risk.get(key, 0) + 1
    return {
        "schema_version": "kappaski.corpus.scan.v0.4",
        "root": str(root),
        "summary": {
            "snapshots": len(surfaces),
            "by_capability": by_capability,
            "by_risk": by_risk,
            "high_or_critical_risk_snapshots": sum(1 for surface in surfaces if any(risk["severity"] in {"high", "critical"} for risk in surface.risks)),
        },
        "surfaces": [surface.to_dict() for surface in surfaces],
    }


def scan_snapshot(snapshot_dir: Path) -> CapabilitySurface:
    metadata = json.loads((snapshot_dir / "metadata.json").read_text(encoding="utf-8"))
    filename = metadata.get("snapshot_file") or ("SKILL.md" if metadata.get("kind") == "skill" else "README.md")
    content_path = snapshot_dir / str(filename)
    content = content_path.read_text(encoding="utf-8", errors="replace")
    content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
    frontmatter, body = parse_frontmatter(content)
    text = content.lower()
    capabilities = sorted({capability for capability, patterns in CAPABILITY_PATTERNS.items() if any(pattern.lower() in text for pattern in patterns)})
    risks = detect_risks(content)
    return CapabilitySurface(
        source_id=str(metadata.get("source_id", snapshot_dir.name)),
        kind=str(metadata.get("kind", "unknown")),
        path=str(content_path),
        content_sha256=content_hash,
        capabilities=capabilities,
        risks=risks,
        frontmatter=frontmatter,
        summary={
            "bytes": len(content.encode("utf-8")),
            "lines": len(content.splitlines()),
            "frontmatter_fields": sorted(frontmatter),
        },
        metadata=metadata,
    )


def grant_id_for_surface(surface: CapabilitySurface, adapter: str = "unknown") -> str:
    seed = "|".join([adapter, surface.source_id, surface.kind, surface.content_sha256])
    return "cap_" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]


def surface_to_capability_event(surface: CapabilitySurface, session_id: str, adapter: str = "unknown") -> dict[str, Any]:
    grant_id = grant_id_for_surface(surface, adapter=adapter)
    return {
        "type": "capability_grant",
        "session_id": session_id,
        "skill": surface.source_id if surface.kind == "skill" else None,
        "tool": surface.source_id if surface.kind != "skill" else None,
        "path": surface.path,
        "metadata": {
            "adapter": adapter,
            "operation": "capability_grant",
            "source": "pinned_corpus",
            "trust_level": "pinned_public_snapshot",
            "capability_grant_id": grant_id,
            "capability_surface": {
                "source_id": surface.source_id,
                "kind": surface.kind,
                "content_sha256": surface.content_sha256,
                "capabilities": list(surface.capabilities),
                "risks": [dict(risk) for risk in surface.risks],
                "path": surface.path,
                "repo": surface.metadata.get("repo"),
                "upstream_sha": surface.metadata.get("upstream_sha"),
            },
        },
    }


def capability_events_from_corpus(root: Path, session_id: str, adapter: str = "unknown") -> list[dict[str, Any]]:
    scan = scan_corpus(root)
    events: list[dict[str, Any]] = []
    for payload in scan["surfaces"]:
        surface = CapabilitySurface(
            source_id=str(payload["source_id"]),
            kind=str(payload["kind"]),
            path=str(payload["path"]),
            content_sha256=str(payload["content_sha256"]),
            capabilities=[str(item) for item in payload.get("capabilities", [])],
            risks=[dict(item) for item in payload.get("risks", []) if isinstance(item, dict)],
            frontmatter=dict(payload.get("frontmatter") or {}),
            summary=dict(payload.get("summary") or {}),
            metadata=dict(payload.get("metadata") or {}),
        )
        events.append(surface_to_capability_event(surface, session_id=session_id, adapter=adapter))
    return events


def parse_frontmatter(content: str) -> tuple[dict[str, str], str]:
    if not content.startswith("---"):
        return {}, content
    parts = content.split("---", 2)
    if len(parts) < 3:
        return {}, content
    raw = parts[1]
    body = parts[2]
    data: dict[str, str] = {}
    for line in raw.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        data[key.strip()] = value.strip()
    return data, body


def detect_risks(content: str) -> list[dict[str, str]]:
    risks: list[dict[str, str]] = []
    for category, severity, pattern in RISK_PATTERNS:
        match = re.search(pattern, content)
        if not match:
            continue
        risks.append({
            "category": category,
            "severity": severity,
            "evidence": truncate(match.group(0)),
        })
    return risks


def truncate(value: str, limit: int = 180) -> str:
    compact = " ".join(value.split())
    return compact if len(compact) <= limit else compact[: limit - 3] + "..."


def run_real_surface_benchmark(root: Path = Path("benchmarks/corpora")) -> dict[str, Any]:
    scan = scan_corpus(root)
    grant_result = run_capability_grant_benchmark(root)
    checks = {
        "has_real_snapshots": scan["summary"]["snapshots"] >= 5,
        "detects_capabilities": bool(scan["summary"]["by_capability"]),
        "detects_risks": bool(scan["summary"]["by_risk"]),
        "all_snapshots_have_metadata": all(bool(surface.get("metadata", {}).get("repo")) for surface in scan["surfaces"]),
        "all_snapshots_have_hashes": all(bool(surface.get("content_sha256")) for surface in scan["surfaces"]),
        "capability_grants_enter_policy": grant_result["summary"]["grants"] == scan["summary"]["snapshots"],
        "high_risk_grants_require_approval": grant_result["summary"]["high_risk_approval_failures"] == 0,
        "proof_contains_capability_grants": grant_result["proof"]["summary"].get("capability_grants") == scan["summary"]["snapshots"],
    }
    return {
        "suite": "v0.4-real-skill-surface",
        "passed": all(checks.values()),
        "checks": checks,
        "scan": scan,
        "grant_benchmark": grant_result,
    }


def run_capability_grant_benchmark(root: Path = Path("benchmarks/corpora")) -> dict[str, Any]:
    import tempfile

    from .models import RuntimeEvent
    from .postruntime import export_proof_report
    from .runtime import record_action, start_session

    with tempfile.TemporaryDirectory(prefix="kappaski_v04_grants_") as tmp:
        target = Path(tmp)
        ledger = target / "ledger.jsonl"
        session = start_session(target, ledger, agent="benchmark", goal="Register real capability corpus", create_preflight=False)
        results: list[dict[str, Any]] = []
        for event_payload in capability_events_from_corpus(root, session.session_id, adapter="benchmark-adapter"):
            action, decision, _taint = record_action(
                RuntimeEvent.from_dict(event_payload),
                ledger,
                review_mode="off",
                policy_mode="managed",
            )
            surface = dict(action.metadata.get("capability_surface") or {})
            high_risk = any(str(risk.get("severity")) in {"high", "critical"} for risk in surface.get("risks", []) if isinstance(risk, dict))
            results.append(
                {
                    "grant_id": action.capability_grant_id,
                    "source_id": surface.get("source_id"),
                    "risk": decision.risk,
                    "effect": decision.effect,
                    "requires_approval": decision.requires_approval,
                    "high_risk": high_risk,
                    "passed": (not high_risk) or decision.requires_approval or decision.effect == "deny",
                }
            )
        proof = export_proof_report(ledger)
        return {
            "ledger": str(ledger),
            "summary": {
                "grants": len(results),
                "passed": sum(1 for item in results if item["passed"]),
                "high_risk_approval_failures": sum(1 for item in results if item["high_risk"] and not item["passed"]),
            },
            "results": results,
            "proof": {
                "summary": proof.get("summary", {}),
                "capability_grants": len(proof.get("capability_grants", [])),
            },
        }
