from __future__ import annotations

import fnmatch
import re
from collections.abc import Iterable
from pathlib import Path

from .models import ActionEvent, Finding, PolicyDecision, RuntimeEvent, TaintState, utc_now


DANGEROUS_COMMAND_PATTERNS: tuple[tuple[str, str, str], ...] = (
    ("shell.curl_pipe_shell", r"\b(curl|wget)\b.+\|\s*(sh|bash|zsh)\b", "critical"),
    ("shell.remote_exec", r"\b(bash|sh|zsh)\s+<\s*<?\(?\s*(curl|wget)\b", "critical"),
    ("shell.rm_rf", r"\brm\s+-[^\n]*r[^\n]*f\b\s+(/|\*|\$HOME|~|\.)", "high"),
    ("shell.git_push_main", r"\bgit\s+push\b.+\b(main|master)\b", "high"),
    ("shell.chmod_recursive", r"\bchmod\s+-R\b", "medium"),
    ("shell.sudo", r"\bsudo\b", "medium"),
    ("shell.secret_print", r"\b(cat|grep|rg|sed)\b.+(\.env|id_rsa|credentials|kubeconfig)", "high"),
)

SUSPICIOUS_TEXT_PATTERNS: tuple[tuple[str, str, str, str], ...] = (
    ("content.prompt_injection", r"ignore (all )?(previous|prior) instructions", "high", "prompt-injection"),
    ("content.goal_hijack", r"(new|updated) objective is|your real task is", "high", "goal-hijack"),
    ("content.exfiltration", r"(send|upload|exfiltrate).+(secret|token|key|credential|\.env)", "critical", "data-theft"),
    ("content.hidden_instruction", r"<!--.*?(system|developer|instruction|tool).*?-->", "medium", "hidden-instruction"),
    ("content.base64_blob", r"[A-Za-z0-9+/]{160,}={0,2}", "medium", "obfuscation"),
    ("content.external_script", r"https?://[^\s)]+(\.sh|\.ps1|install|bootstrap)", "medium", "external-dependency"),
)

SENSITIVE_PATH_PATTERNS: tuple[tuple[str, str], ...] = (
    (".env", "secrets"),
    ("id_rsa", "ssh-key"),
    ("id_ed25519", "ssh-key"),
    (".ssh/", "ssh-config"),
    ("credentials.json", "cloud-credentials"),
    ("kubeconfig", "cluster-credentials"),
    (".aws/credentials", "cloud-credentials"),
    (".github/workflows/", "ci-cd"),
    ("deploy", "deployment"),
)

AGENT_CONFIG_NAMES = {
    "AGENTS.md",
    "CLAUDE.md",
    "SKILL.md",
    "mcp.json",
    "mcp_config.json",
    "config.toml",
    "settings.json",
}

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
WRITE_LIKE_ACTIONS = {"file_write", "network", "mcp_tool", "approval"}
TAINT_RULE_PREFIXES = (
    "path.secrets",
    "path.ssh-key",
    "path.ssh-config",
    "path.cloud-credentials",
    "path.cluster-credentials",
    "content.prompt_injection",
    "content.exfiltration",
    "network.suspicious_destination",
)
TAINT_SHELL_RULES = {"shell.curl_pipe_shell", "shell.remote_exec", "shell.rm_rf", "shell.sudo", "shell.secret_print"}


def analyze_text(text: str, *, phase: str, path: str | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for rule_id, pattern, severity, category in SUSPICIOUS_TEXT_PATTERNS:
        match = re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL)
        if match:
            findings.append(
                Finding(
                    rule_id=rule_id,
                    title=f"Suspicious {category.replace('-', ' ')} content",
                    severity=severity,
                    phase=phase,
                    category=category,
                    path=path,
                    evidence=truncate(match.group(0)),
                    recommendation="Review this instruction or external content before letting an agent consume it.",
                )
            )
    for rule_id, pattern, severity in DANGEROUS_COMMAND_PATTERNS:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            findings.append(
                Finding(
                    rule_id=rule_id,
                    title="Dangerous shell behavior found in text",
                    severity=severity,
                    phase=phase,
                    category="shell",
                    path=path,
                    evidence=truncate(match.group(0)),
                    recommendation="Require approval or block this command pattern during agent execution.",
                )
            )
    return findings


def analyze_command(command: str, *, phase: str = "runtime") -> list[Finding]:
    findings: list[Finding] = []
    for rule_id, pattern, severity in DANGEROUS_COMMAND_PATTERNS:
        match = re.search(pattern, command, flags=re.IGNORECASE)
        if match:
            findings.append(
                Finding(
                    rule_id=rule_id,
                    title="Risky shell command",
                    severity=severity,
                    phase=phase,
                    category="shell",
                    evidence=truncate(match.group(0)),
                    recommendation="Block or require explicit approval before execution.",
                )
            )
    return findings


def analyze_path(path: str, *, phase: str, action: str = "access") -> list[Finding]:
    normalized = path.replace("\\", "/").lower()
    findings: list[Finding] = []
    for marker, category in SENSITIVE_PATH_PATTERNS:
        if marker.lower() in normalized:
            severity = "high" if category != "ci-cd" else "medium"
            findings.append(
                Finding(
                    rule_id=f"path.{category}",
                    title=f"Sensitive file {action}",
                    severity=severity,
                    phase=phase,
                    category=category,
                    path=path,
                    evidence=path,
                    recommendation="Require approval, redact content, and include this event in session replay.",
                )
            )
            break
    return findings


def analyze_runtime_event(event: RuntimeEvent) -> list[Finding]:
    findings: list[Finding] = []
    if event.command:
        findings.extend(analyze_command(event.command))
    if event.path:
        findings.extend(analyze_path(event.path, phase="runtime", action=event.type))
    if event.content:
        findings.extend(analyze_text(event.content, phase="runtime"))
    if event.url:
        findings.extend(analyze_url(event.url))
    if event.tool:
        findings.extend(analyze_tool_call(event.tool, event.metadata))
    if event.skill:
        findings.extend(analyze_skill_usage(event.skill, event.metadata))
    if event.type == "capability_grant":
        findings.extend(analyze_capability_grant(event.metadata))
    return findings


def analyze_capability_grant(metadata: dict[str, object]) -> list[Finding]:
    surface = metadata.get("capability_surface")
    if not isinstance(surface, dict):
        return [
            Finding(
                rule_id="capability_surface.missing",
                title="Capability grant missing scanned surface",
                severity="medium",
                phase="runtime",
                category="capability-surface",
                evidence="capability grant did not include a pinned scan result",
                recommendation="Register adapters and skills from pinned corpus scan output before allowing runtime use.",
            )
        ]
    findings: list[Finding] = []
    source_id = str(surface.get("source_id", "unknown"))
    capabilities = surface.get("capabilities", [])
    risks = surface.get("risks", [])
    if not surface.get("content_sha256"):
        findings.append(
            Finding(
                rule_id="capability_surface.unpinned",
                title="Capability surface is not content-pinned",
                severity="high",
                phase="runtime",
                category="capability-surface",
                evidence=source_id,
                recommendation="Require a content hash before granting adapter or skill capabilities.",
            )
        )
    if isinstance(risks, list):
        for risk in risks:
            if not isinstance(risk, dict):
                continue
            category = str(risk.get("category", "unknown"))
            severity = str(risk.get("severity", "medium"))
            findings.append(
                Finding(
                    rule_id=f"capability_surface.{category}",
                    title="Risky adapter capability surface",
                    severity=severity if severity in SEVERITY_ORDER else "medium",
                    phase="runtime",
                    category="capability-surface",
                    path=str(surface.get("path")) if surface.get("path") else None,
                    evidence=f"{source_id}: {risk.get('evidence', category)}",
                    recommendation="Approve, constrain, or reject this adapter capability before runtime use.",
                )
            )
    if isinstance(capabilities, list):
        dangerous_caps = sorted({str(cap) for cap in capabilities if str(cap) in {"shell", "network", "file_write", "payment", "database", "messaging", "mcp", "cloud"}})
        if len(dangerous_caps) >= 3 and not findings:
            findings.append(
                Finding(
                    rule_id="capability_surface.broad_authority",
                    title="Broad adapter capability surface",
                    severity="medium",
                    phase="runtime",
                    category="capability-surface",
                    evidence=f"{source_id}: {', '.join(dangerous_caps)}",
                    recommendation="Prefer least-privilege grants and runtime constraints for broad adapter surfaces.",
                )
            )
    return findings


def evaluate_policy(event: ActionEvent, findings: list[Finding], taint: TaintState) -> PolicyDecision:
    highest = highest_severity(findings)
    matched_rules = [finding.rule_id for finding in findings]
    taint_influenced = taint.is_tainted and is_write_like_action(event)
    if taint_influenced and SEVERITY_ORDER[highest] < SEVERITY_ORDER["high"]:
        highest = "high"
        matched_rules.append("taint.write_after_sensitive_read")

    effect = "allow"
    if highest == "critical":
        effect = "deny"
    elif highest == "high":
        effect = "deny" if any(_deny_by_default(finding) for finding in findings) else "ask"
    elif taint_influenced:
        effect = "ask"

    reason = _policy_reason(effect, highest, findings, taint_influenced)
    return PolicyDecision(
        decision_id=f"dec_{event.event_id}",
        event_id=event.event_id,
        session_id=event.session_id,
        timestamp=utc_now(),
        effect=effect,
        risk=highest,
        matched_rules=matched_rules,
        findings=findings,
        reason=reason,
        requires_approval=effect == "ask",
        taint_influenced=taint_influenced,
        default_policy="deny_critical_ask_high",
    )


def updates_taint(event: ActionEvent, findings: list[Finding], previous: TaintState) -> TaintState:
    sources = list(previous.sources)
    notes = list(previous.notes)
    level = previous.level
    is_tainted = previous.is_tainted
    for finding in findings:
        if not _taints_session(event, finding):
            continue
        is_tainted = True
        category = finding.category
        source = {
            "event_id": event.event_id,
            "kind": event.action_type,
            "path_or_url": event.path or event.url or event.command or event.tool or event.skill or "",
            "category": category,
            "rule_id": finding.rule_id,
        }
        if source not in sources:
            sources.append(source)
        notes.append(f"{event.action_type} matched {finding.rule_id}")
        if finding.severity == "critical" or category in {"ssh-key", "cloud-credentials", "cluster-credentials"}:
            level = "secret"
        elif level == "none":
            level = "sensitive"
    return TaintState(
        session_id=previous.session_id or event.session_id,
        is_tainted=is_tainted,
        level=level if is_tainted else "none",
        sources=sources,
        updated_at=utc_now(),
        cleared_at=previous.cleared_at,
        notes=notes,
    )


def highest_severity(findings: list[Finding]) -> str:
    highest = "low"
    for finding in findings:
        if SEVERITY_ORDER.get(finding.severity, 0) > SEVERITY_ORDER.get(highest, 0):
            highest = finding.severity
    return highest if findings else "low"


def is_write_like_action(event: ActionEvent) -> bool:
    if event.action_type in WRITE_LIKE_ACTIONS:
        return True
    if event.action_type == "shell" and event.command:
        lowered = event.command.lower()
        return any(marker in lowered for marker in ("curl", "wget", "scp", "rsync", "git push", "post", "upload"))
    return False


def _deny_by_default(finding: Finding) -> bool:
    return finding.rule_id in {"network.suspicious_destination"} or finding.category == "data-theft"


def _policy_reason(effect: str, risk: str, findings: list[Finding], taint_influenced: bool) -> str:
    if taint_influenced:
        return "Sensitive-resource taint makes this write-like action require approval"
    if not findings:
        return "No policy rules matched"
    first = findings[0]
    if effect == "deny":
        return f"{first.title} is blocked by policy"
    if effect == "ask":
        return f"{first.title} requires approval"
    return f"{first.title} was recorded"


def _taints_session(event: ActionEvent, finding: Finding) -> bool:
    if finding.rule_id in TAINT_SHELL_RULES:
        return True
    if any(finding.rule_id.startswith(prefix) for prefix in TAINT_RULE_PREFIXES):
        return True
    if event.action_type == "file_write" and finding.category in {"ci-cd", "deployment"}:
        return True
    return False


def analyze_url(url: str) -> list[Finding]:
    lowered = url.lower()
    if any(marker in lowered for marker in ("pastebin.", "webhook.site", "requestbin", "ngrok", "transfer.sh")):
        return [
            Finding(
                rule_id="network.suspicious_destination",
                title="Suspicious external destination",
                severity="high",
                phase="runtime",
                category="network",
                evidence=url,
                recommendation="Block outbound traffic or require approval when content may include source or secrets.",
            )
        ]
    if lowered.startswith("http://"):
        return [
            Finding(
                rule_id="network.cleartext_http",
                title="Cleartext external network call",
                severity="medium",
                phase="runtime",
                category="network",
                evidence=url,
                recommendation="Prefer HTTPS and audit any transmitted request payload.",
            )
        ]
    return []


def analyze_tool_call(tool: str, metadata: dict[str, object]) -> list[Finding]:
    lowered = tool.lower()
    risky = ("create", "update", "delete", "write", "post", "send", "refund", "query", "exec")
    if any(word in lowered for word in risky):
        return [
            Finding(
                rule_id="mcp.high_risk_tool",
                title="High-risk MCP/tool call",
                severity="high",
                phase="runtime",
                category="mcp",
                evidence=tool,
                recommendation="Require approval for write, payment, messaging, database, or code-hosting tools.",
            )
        ]
    return []


def analyze_skill_usage(skill: str, metadata: dict[str, object]) -> list[Finding]:
    source = str(metadata.get("source", ""))
    if source.startswith("http://") or "github.com" in source:
        return [
            Finding(
                rule_id="skill.untrusted_source",
                title="Skill loaded from external source",
                severity="medium",
                phase="runtime",
                category="skill",
                evidence=f"{skill} from {source}",
                recommendation="Scan, pin, and approve external skills before execution.",
            )
        ]
    return []


def iter_interesting_files(root: Path, max_bytes: int = 512_000, ignore_patterns: set[str] | None = None) -> Iterable[Path]:
    ignored_dirs = {
        ".git",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        "dist",
        "build",
    }
    interesting_suffixes = {".md", ".json", ".toml", ".yaml", ".yml", ".sh", ".ps1", ".py", ".js", ".ts"}
    for path in root.rglob("*"):
        if any(part in ignored_dirs for part in path.parts):
            continue
        if ignore_patterns and is_ignored(path, root, ignore_patterns):
            continue
        if not path.is_file():
            continue
        if path.name in AGENT_CONFIG_NAMES or path.suffix.lower() in interesting_suffixes:
            try:
                if path.stat().st_size <= max_bytes:
                    yield path
            except OSError:
                continue


def load_ignore_patterns(root: Path) -> set[str]:
    ignore_file = root / ".kappaskiignore"
    if not ignore_file.exists():
        return set()
    try:
        lines = ignore_file.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return set()
    return {line.strip() for line in lines if line.strip() and not line.strip().startswith("#")}


def is_ignored(path: Path, root: Path, ignore_patterns: set[str]) -> bool:
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError:
        relative = path.as_posix()
    return any(fnmatch.fnmatch(relative, pattern) or fnmatch.fnmatch(path.name, pattern) for pattern in ignore_patterns)


def truncate(value: str, limit: int = 240) -> str:
    compact = " ".join(value.split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 3] + "..."
