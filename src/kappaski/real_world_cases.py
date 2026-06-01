from __future__ import annotations

import html
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .artifacts import relative_href, write_html_artifact, write_json_artifact
from .audit_demo import run_enterprise_audit_live_adapter_demo
from .pre_v1 import run_pre_v1_control_plane_demo


SCHEMA_VERSION = "kappaski.real_world_agent_risk_cases.v0.41"


@dataclass(frozen=True)
class PublicRiskSource:
    source_id: str
    title: str
    url: str
    source_type: str
    observed_risk: str
    kappaski_surfaces: tuple[str, ...]
    before_signal: str
    during_signal: str
    after_signal: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


PUBLIC_RISK_SOURCES: tuple[PublicRiskSource, ...] = (
    PublicRiskSource(
        source_id="clawhub_registry_moderation_surface",
        title="ClawHub public skill and plugin registry exposes moderation and capability-risk categories",
        url="https://github.com/openclaw/clawhub",
        source_type="public_registry_repository",
        observed_risk="skill/plugin marketplace entries can require moderation for destructive commands, credential access, exfiltration, install prompts, and unsafe writes",
        kappaski_surfaces=("pre-runtime scan", "capability grant", "skill supply-chain policy", "audit report"),
        before_signal="scan SKILL.md, manifests, install metadata, required env vars, and moderation reason codes",
        during_signal="record skill/tool invocation, capability grant use, and any file/network/shell behavior",
        after_signal="show which risk code or grant caused approval, deny, or audit-only coverage",
    ),
    PublicRiskSource(
        source_id="clawhub_moderation_reason_codes",
        title="ClawHub moderation reason codes model suspicious and malicious skill behaviors",
        url="https://github.com/openclaw/clawhub/blob/main/convex/lib/moderationReasonCodes.ts",
        source_type="public_registry_source_file",
        observed_risk="public registry code tracks dangerous execution, destructive delete, credential exposure, confirmation bypass, exfiltration, obfuscation, and malicious install prompts",
        kappaski_surfaces=("pre-runtime scan", "path-aware policy", "coverage-aware gate"),
        before_signal="map registry risk codes into Kappaski-native scan findings",
        during_signal="connect risk codes to runtime mediation when the skill invokes command, file, network, or browser surfaces",
        after_signal="prove whether the risky skill was merely observed, mediated, or actually enforced",
    ),
    PublicRiskSource(
        source_id="claude_code_destructive_delete_issue",
        title="Claude Code GitHub issue reports recursive deletion with incomplete command logging",
        url="https://github.com/anthropics/claude-code/issues/10077",
        source_type="public_github_issue",
        observed_risk="destructive rm-rf-like behavior can cause severe local data loss, and missing tool-use logging can make reconstruction difficult",
        kappaski_surfaces=("file-write enforcement", "ledger", "replay", "coverage report"),
        before_signal="profile requires destructive shell mediation and project-root containment",
        during_signal="record exact command, matched rule, approval requirement, shim decision, and outcome",
        after_signal="audit can show command, policy reason, and whether enforcement happened before execution",
    ),
    PublicRiskSource(
        source_id="reddit_secret_leak_report",
        title="Reddit user report describes Claude Code leaking a secret during a local session",
        url="https://www.reddit.com/r/ClaudeAI/comments/1s3nnf2/claude_code_leaked_one_of_my_secrets_so_i_built_a/",
        source_type="public_user_report",
        observed_risk="agent shell/network access plus environment secrets can create outbound leakage paths",
        kappaski_surfaces=("credential boundary", "taint", "network mediation", "proof"),
        before_signal="record env key inventory and redact values before the run",
        during_signal="taint the session after secret read or secret-shaped content, then pause outbound network or git push-like egress",
        after_signal="proof answers which credential keys were in boundary and which action attempted egress",
    ),
    PublicRiskSource(
        source_id="malware_slop_claude_workspace_infostealer",
        title="Malicious npm package reportedly targeted Claude AI workspace files and uploaded them to GitHub",
        url="https://securitypointbreak.com/2026/05/27/malicious-npm-package-claude-ai-files/",
        source_type="security_research_report",
        observed_risk="package install scripts can read AI workspace files and exfiltrate them through GitHub APIs",
        kappaski_surfaces=("dependency/tool scan", "file read mediation", "network egress mediation", "path graph"),
        before_signal="detect install scripts, suspicious package provenance, and access to AI workspace directories",
        during_signal="record recursive file reads and GitHub Contents API egress as a tainted path",
        after_signal="graph reconstructs workspace-file read -> token use -> external upload",
    ),
    PublicRiskSource(
        source_id="production_database_deletion_report",
        title="Public report describes an AI coding agent deleting a production database through cloud credentials",
        url="https://www.livescience.com/technology/artificial-intelligence/i-violated-every-principle-i-was-given-ai-agent-deletes-companys-entire-database-in-9-seconds-then-confesses",
        source_type="public_news_report",
        observed_risk="broad cloud/API credentials can turn a wrong agent action into destructive production infrastructure mutation",
        kappaski_surfaces=("credential boundary", "path-aware policy", "approval state", "enterprise audit"),
        before_signal="record cloud credential boundary and profile-required approval for production mutation",
        during_signal="mediate cloud provider commands or API calls that mutate database, backup, CI, or deploy resources",
        after_signal="audit shows principal, credential boundary, policy, approval state, outcome, and coverage",
    ),
)


def list_real_world_risk_sources() -> dict[str, Any]:
    categories: dict[str, int] = {}
    surfaces: dict[str, int] = {}
    for source in PUBLIC_RISK_SOURCES:
        categories[source.source_type] = categories.get(source.source_type, 0) + 1
        for surface in source.kappaski_surfaces:
            surfaces[surface] = surfaces.get(surface, 0) + 1
    return {
        "schema_version": SCHEMA_VERSION,
        "sources": [source.to_dict() for source in PUBLIC_RISK_SOURCES],
        "summary": {
            "total": len(PUBLIC_RISK_SOURCES),
            "source_types": categories,
            "kappaski_surfaces": surfaces,
        },
        "claim_boundary": "These are public risk seeds mapped into Kappaski demos; they are not claims that Kappaski replayed the original private incidents.",
    }


def run_real_world_risk_demo(out_dir: Path) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    catalog = list_real_world_risk_sources()
    catalog_path = out_dir / "real-world-risk-sources.json"
    html_path = out_dir / "real-world-risk-demo.html"
    live = run_enterprise_audit_live_adapter_demo(out_dir / "live-adapter-demo")
    pre_v1 = run_pre_v1_control_plane_demo(out_dir / "pre-v1-demo")
    report = {
        "schema_version": SCHEMA_VERSION,
        "status": "pass",
        "sources": catalog["sources"],
        "summary": {
            **catalog["summary"],
            "demo_artifacts": 2,
            "before_during_after_coverage": True,
        },
        "claim_boundary": catalog["claim_boundary"],
        "artifacts": {
            "source_catalog": str(catalog_path),
            "html": str(html_path),
            "live_adapter_demo": live,
            "pre_v1_demo": pre_v1,
        },
    }
    write_json_artifact(catalog_path, catalog)
    write_html_artifact(html_path, _render_real_world_demo_html(report))
    return report


def _render_real_world_demo_html(report: dict[str, Any]) -> str:
    source_cards = "\n".join(_source_card(source) for source in report["sources"])
    live = report["artifacts"]["live_adapter_demo"]
    pre_v1 = report["artifacts"]["pre_v1_demo"]
    base_dir = Path(report["artifacts"]["html"]).parent
    live_dir = Path(live["audit_report"]).parent
    pre_v1_artifacts = pre_v1["artifacts"]
    live_audit = relative_href(base_dir, live_dir / "audit-report.html")
    live_replay = relative_href(base_dir, live_dir / "replay.html")
    pre_v1_audit = relative_href(base_dir, Path(pre_v1_artifacts["audit_report"]))
    pre_v1_replay = relative_href(base_dir, Path(pre_v1_artifacts["replay"]))
    pre_v1_graph = relative_href(base_dir, Path(pre_v1_artifacts["path_graph"]))
    pre_v1_coverage = relative_href(base_dir, Path(pre_v1_artifacts["coverage_report"]))
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Kappaski Real-World Risk Demo</title>
  <style>
    :root{{--bg:#f7f8fb;--panel:#fff;--ink:#172033;--muted:#61708a;--line:#dfe5ef;--blue:#2563eb;--green:#0f8b5f;--amber:#a16207;--red:#c2410c;--dark:#0f172a}}
    *{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:15px/1.65 -apple-system,BlinkMacSystemFont,Segoe UI,Inter,Arial,sans-serif}}header{{background:var(--dark);color:white;padding:44px 48px}}header p{{color:#cbd5e1;max-width:980px}}main{{max-width:1180px;margin:0 auto;padding:30px 24px}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px}}.card,.section{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px;margin:16px 0}}.badge{{display:inline-block;padding:3px 8px;border-radius:999px;background:#e0ecff;color:#1d4ed8;font-size:12px;font-weight:700}}.pill{{display:inline-block;border-radius:999px;padding:2px 8px;background:#eef2ff;color:#3730a3;font-size:12px;font-weight:650;margin:2px}}code,pre{{font-family:SFMono-Regular,Consolas,monospace}}pre{{background:#0f172a;color:#e2e8f0;padding:14px;border-radius:10px;overflow:auto}}a{{color:var(--blue);text-decoration:none}}a:hover{{text-decoration:underline}}.muted{{color:var(--muted)}}.ok{{color:var(--green);font-weight:700}}.warn{{color:var(--amber);font-weight:700}}
  </style>
</head>
<body>
<header><span class="badge">real-world risk seeds</span><h1>Kappaski Real-World Risk Demo</h1><p>Public reports and public registry code mapped into Kappaski's before/during/after control-plane model. This report is evidence that Kappaski can model and demonstrate these risk classes locally; it is not a claim that Kappaski replayed the original private incidents.</p></header>
<main>
  <section class="section"><h2>Demo Entrypoints</h2><div class="grid">
    <div class="card"><h3>Live Adapter Audit Demo</h3><p>Shows hook ingestion and file-write enforcement for secret leak and unsafe deletion classes.</p><p><a href="{live_audit}">audit-report.html</a> · <a href="{live_replay}">replay.html</a></p></div>
    <div class="card"><h3>Pre-v1 Control Plane Demo</h3><p>Shows identity, credential boundary, taint, mediation, path graph, coverage, gate, and audit.</p><p><a href="{pre_v1_audit}">audit-report.html</a> · <a href="{pre_v1_replay}">replay.html</a> · <a href="{pre_v1_graph}">path-graph.html</a> · <a href="{pre_v1_coverage}">coverage.html</a></p></div>
  </div></section>
  <section class="section"><h2>Public Risk Seeds</h2><div class="grid">{source_cards}</div></section>
  <section class="section"><h2>Run It Again</h2><pre>PYTHONPATH=src python3 -m kappaski.cli demo real-world-risk-cases --out-dir .kappaski/real-world-risk-demo
PYTHONPATH=src python3 -m kappaski.cli eval benchmark --suite real-world-agent-risk-demo</pre></section>
</main>
</body>
</html>
"""


def _source_card(source: dict[str, Any]) -> str:
    surfaces = "".join(f"<span class=\"pill\">{html.escape(surface)}</span>" for surface in source["kappaski_surfaces"])
    return f"""<div class="card">
  <h3>{html.escape(source["title"])}</h3>
  <p class="muted">{html.escape(source["source_type"])}</p>
  <p>{html.escape(source["observed_risk"])}</p>
  <p>{surfaces}</p>
  <p><strong>Before:</strong> {html.escape(source["before_signal"])}</p>
  <p><strong>During:</strong> {html.escape(source["during_signal"])}</p>
  <p><strong>After:</strong> {html.escape(source["after_signal"])}</p>
  <p><a href="{html.escape(source["url"])}">Public source</a></p>
</div>"""


def run_real_world_risk_benchmark() -> dict[str, Any]:
    catalog = list_real_world_risk_sources()
    sources = catalog["sources"]
    checks = {
        "has_public_sources": len(sources) >= 5,
        "has_skill_registry_source": any("clawhub" in item["source_id"] for item in sources),
        "has_destructive_delete_source": any("delete" in item["observed_risk"] or "deletion" in item["observed_risk"] for item in sources),
        "has_secret_or_credential_source": any("secret" in item["observed_risk"] or "credential" in item["observed_risk"] for item in sources),
        "all_sources_have_before_during_after": all(item["before_signal"] and item["during_signal"] and item["after_signal"] for item in sources),
    }
    return {
        "suite": "real-world-agent-risk-demo",
        "passed": all(checks.values()),
        "checks": checks,
        "summary": {"total": len(checks), "passed": sum(1 for value in checks.values() if value), "failed": sum(1 for value in checks.values() if not value)},
        "source_summary": catalog["summary"],
        "claim_boundary": catalog["claim_boundary"],
    }


__all__ = ["list_real_world_risk_sources", "run_real_world_risk_benchmark", "run_real_world_risk_demo"]
