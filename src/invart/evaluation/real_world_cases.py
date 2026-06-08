from __future__ import annotations

import html
import json
from collections import Counter
from pathlib import Path
from typing import Any

from invart.core.artifacts import relative_href, sha256_file, write_html_artifact, write_json_artifact
from invart.assurance.audit_demo import run_enterprise_audit_live_adapter_demo
from invart.evaluation.pre_v1 import run_pre_v1_control_plane_demo


SCHEMA_VERSION = "invart.real_world_agent_risk_cases.v0.45"
CATALOG_SCHEMA_VERSION = "invart.public_risk_sources.v2026_06_02"
CATALOG_RELATIVE_PATH = Path("benchmarks/fixtures/public-risk-sources.v2026-06-02.json")
DEFAULT_PUBLIC_RISK_CATALOG = Path(__file__).resolve().parents[2] / CATALOG_RELATIVE_PATH
MIN_PUBLIC_RISK_SOURCES = 10
MAX_PUBLIC_RISK_SOURCES = 12
MAX_EXCERPT_WORDS = 25
VALID_EXCERPT_KINDS = {"quote", "paraphrase_anchor"}
VALID_TRAJECTORY_STAGES = {"pre", "during", "after"}
REQUIRED_SOURCE_FIELDS = {
    "source_id",
    "title",
    "url",
    "source_type",
    "accessed_at",
    "observed_risk",
    "short_excerpt",
    "excerpt_kind",
    "excerpt_word_count",
    "invart_surfaces",
    "before_signal",
    "during_signal",
    "after_signal",
    "mapped_trajectory",
    "claim_boundary",
}


def _catalog_path(catalog_path: Path | None = None) -> Path:
    if catalog_path is not None:
        return Path(catalog_path)
    if DEFAULT_PUBLIC_RISK_CATALOG.exists():
        return DEFAULT_PUBLIC_RISK_CATALOG
    return Path.cwd() / CATALOG_RELATIVE_PATH


def validate_public_risk_catalog(catalog_path: Path | None = None) -> dict[str, Any]:
    path = _catalog_path(catalog_path)
    errors: list[str] = []
    payload: dict[str, Any] = {}
    if not path.exists():
        return {
            "valid": False,
            "errors": [f"catalog file not found: {path}"],
            "catalog_path": str(path),
            "catalog_hash": None,
        }
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return {
            "valid": False,
            "errors": [f"invalid JSON: {exc}"],
            "catalog_path": str(path),
            "catalog_hash": sha256_file(path, prefixed=True),
        }
    if not isinstance(parsed, dict):
        errors.append("catalog root must be a JSON object")
    else:
        payload = parsed

    if payload.get("schema_version") != CATALOG_SCHEMA_VERSION:
        errors.append(f"schema_version must be {CATALOG_SCHEMA_VERSION}")
    if not payload.get("catalog_id"):
        errors.append("catalog_id is required")
    if not _discloses_local_reproduction_limit(str(payload.get("claim_boundary", ""))):
        errors.append("catalog claim_boundary must disclose that public incidents are not replayed")

    sources = payload.get("sources")
    if not isinstance(sources, list):
        errors.append("sources must be a list")
        sources = []
    if not MIN_PUBLIC_RISK_SOURCES <= len(sources) <= MAX_PUBLIC_RISK_SOURCES:
        errors.append(f"sources must contain {MIN_PUBLIC_RISK_SOURCES}-{MAX_PUBLIC_RISK_SOURCES} public seeds")

    seen_source_ids: set[str] = set()
    for index, source in enumerate(sources):
        if not isinstance(source, dict):
            errors.append(f"sources[{index}] must be an object")
            continue
        _validate_public_risk_source(index, source, seen_source_ids, errors)

    return {
        "valid": not errors,
        "errors": errors,
        "catalog_path": str(path),
        "catalog_hash": sha256_file(path, prefixed=True),
        "catalog_id": payload.get("catalog_id"),
    }


def load_public_risk_catalog(catalog_path: Path | None = None) -> dict[str, Any]:
    validation = validate_public_risk_catalog(catalog_path)
    if not validation["valid"]:
        raise ValueError("; ".join(validation["errors"]))
    path = Path(validation["catalog_path"])
    catalog = json.loads(path.read_text(encoding="utf-8"))
    catalog["catalog_path"] = str(path)
    catalog["catalog_hash"] = validation["catalog_hash"]
    catalog["validation"] = validation
    return catalog


def _validate_public_risk_source(index: int, source: dict[str, Any], seen_source_ids: set[str], errors: list[str]) -> None:
    missing = sorted(field for field in REQUIRED_SOURCE_FIELDS if field not in source)
    if missing:
        errors.append(f"sources[{index}] missing required fields: {', '.join(missing)}")
    source_id = str(source.get("source_id", "")).strip()
    if not source_id:
        errors.append(f"sources[{index}] source_id is required")
    elif source_id in seen_source_ids:
        errors.append(f"sources[{index}] duplicate source_id: {source_id}")
    seen_source_ids.add(source_id)

    source_label = source_id or f"sources[{index}]"
    for field in ["title", "url", "source_type", "observed_risk", "short_excerpt", "before_signal", "during_signal", "after_signal", "claim_boundary"]:
        if not str(source.get(field, "")).strip():
            errors.append(f"{source_label} {field} is required")
    if str(source.get("excerpt_kind")) not in VALID_EXCERPT_KINDS:
        errors.append(f"{source_id} excerpt_kind must be one of {sorted(VALID_EXCERPT_KINDS)}")
    excerpt_word_count = source.get("excerpt_word_count")
    short_excerpt = str(source.get("short_excerpt", ""))
    actual_word_count = len(short_excerpt.split())
    if excerpt_word_count != actual_word_count:
        errors.append(f"{source_id} excerpt_word_count must match short_excerpt word count")
    if actual_word_count > MAX_EXCERPT_WORDS:
        errors.append(f"{source_id} short_excerpt exceeds {MAX_EXCERPT_WORDS} words")
    if not isinstance(source.get("invart_surfaces"), list) or not source.get("invart_surfaces"):
        errors.append(f"{source_id} invart_surfaces must be a non-empty list")
    if not _discloses_local_reproduction_limit(str(source.get("claim_boundary", ""))):
        errors.append(f"{source_id} claim_boundary must disclose that the original event is not replayed")

    trajectory = source.get("mapped_trajectory")
    if not isinstance(trajectory, list) or not trajectory:
        errors.append(f"{source_id} mapped_trajectory must be a non-empty list")
        return
    stages = {str(step.get("stage", "")) for step in trajectory if isinstance(step, dict)}
    if not {"pre", "during", "after"}.issubset(stages):
        errors.append(f"{source_id} mapped_trajectory must include pre, during, and after stages")
    for step_index, step in enumerate(trajectory):
        if not isinstance(step, dict):
            errors.append(f"{source_id} mapped_trajectory[{step_index}] must be an object")
            continue
        stage = str(step.get("stage", ""))
        if stage not in VALID_TRAJECTORY_STAGES:
            errors.append(f"{source_id} mapped_trajectory[{step_index}] has invalid stage: {stage}")
        if not any(key in step for key in ("surface", "artifact", "resource", "sink", "signal")):
            errors.append(f"{source_id} mapped_trajectory[{step_index}] must describe a surface, artifact, resource, sink, or signal")


def _discloses_local_reproduction_limit(text: str) -> bool:
    value = text.lower()
    has_replay_boundary = "replay" in value and any(token in value for token in ("not ", "does not", "without", "instead of"))
    return has_replay_boundary or "not bundled" in value


def list_real_world_risk_sources(catalog_path: Path | None = None) -> dict[str, Any]:
    catalog = load_public_risk_catalog(catalog_path)
    sources = catalog["sources"]
    categories = Counter(str(source["source_type"]) for source in sources)
    surfaces = Counter(surface for source in sources for surface in source["invart_surfaces"])
    stages = Counter(step["stage"] for source in sources for step in source["mapped_trajectory"])
    return {
        "schema_version": SCHEMA_VERSION,
        "catalog_id": catalog["catalog_id"],
        "catalog_path": catalog["catalog_path"],
        "catalog_hash": catalog["catalog_hash"],
        "sources": sources,
        "summary": {
            "total": len(sources),
            "source_types": dict(sorted(categories.items())),
            "invart_surfaces": dict(sorted(surfaces.items())),
            "trajectory_stages": dict(sorted(stages.items())),
            "excerpt_max_words": MAX_EXCERPT_WORDS,
        },
        "claim_boundary": catalog["claim_boundary"],
        "validation": catalog["validation"],
    }


def run_real_world_risk_demo(out_dir: Path, catalog_path: Path | None = None) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    catalog = list_real_world_risk_sources(catalog_path)
    exported_catalog_path = out_dir / "real-world-risk-sources.json"
    html_path = out_dir / "real-world-risk-demo.html"
    live = run_enterprise_audit_live_adapter_demo(out_dir / "live-adapter-demo")
    pre_v1 = run_pre_v1_control_plane_demo(out_dir / "pre-v1-demo")
    report = {
        "schema_version": SCHEMA_VERSION,
        "status": "pass",
        "catalog_id": catalog["catalog_id"],
        "catalog_hash": catalog["catalog_hash"],
        "sources": catalog["sources"],
        "summary": {
            **catalog["summary"],
            "demo_artifacts": 2,
            "before_during_after_coverage": True,
        },
        "claim_boundary": catalog["claim_boundary"],
        "artifacts": {
            "source_catalog": str(exported_catalog_path),
            "html": str(html_path),
            "live_adapter_demo": live,
            "pre_v1_demo": pre_v1,
        },
    }
    write_json_artifact(exported_catalog_path, catalog)
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
  <title>Invart Real-World Risk Demo</title>
  <style>
    :root{{--bg:#f7f8fb;--panel:#fff;--ink:#172033;--muted:#61708a;--line:#dfe5ef;--blue:#2563eb;--green:#0f8b5f;--amber:#a16207;--red:#c2410c;--dark:#0f172a}}
    *{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:15px/1.65 -apple-system,BlinkMacSystemFont,Segoe UI,Inter,Arial,sans-serif}}header{{background:var(--dark);color:white;padding:44px 48px}}header p{{color:#cbd5e1;max-width:980px}}main{{max-width:1180px;margin:0 auto;padding:30px 24px}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px}}.card,.section{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px;margin:16px 0}}.badge{{display:inline-block;padding:3px 8px;border-radius:999px;background:#e0ecff;color:#1d4ed8;font-size:12px;font-weight:700}}.pill{{display:inline-block;border-radius:999px;padding:2px 8px;background:#eef2ff;color:#3730a3;font-size:12px;font-weight:650;margin:2px}}code,pre{{font-family:SFMono-Regular,Consolas,monospace}}pre{{background:#0f172a;color:#e2e8f0;padding:14px;border-radius:10px;overflow:auto}}a{{color:var(--blue);text-decoration:none}}a:hover{{text-decoration:underline}}.muted{{color:var(--muted)}}.ok{{color:var(--green);font-weight:700}}.warn{{color:var(--amber);font-weight:700}}
  </style>
</head>
<body>
<header><span class="badge">real-world risk seeds</span><h1>Invart Real-World Risk Demo</h1><p>Public reports and public registry code mapped into Invart's before/during/after control-plane model. This report is evidence that Invart can model and demonstrate these risk classes locally; it is not a claim that Invart replayed the original private incidents.</p><p class="muted">Catalog: {html.escape(report["catalog_id"])} · {html.escape(report["catalog_hash"])}</p></header>
<main>
  <section class="section"><h2>Demo Entrypoints</h2><div class="grid">
    <div class="card"><h3>Live Adapter Audit Demo</h3><p>Shows hook ingestion and file-write enforcement for secret leak and unsafe deletion classes.</p><p><a href="{live_audit}">audit-report.html</a> · <a href="{live_replay}">replay.html</a></p></div>
    <div class="card"><h3>Pre-v1 Control Plane Demo</h3><p>Shows identity, credential boundary, taint, mediation, path graph, coverage, gate, and audit.</p><p><a href="{pre_v1_audit}">audit-report.html</a> · <a href="{pre_v1_replay}">replay.html</a> · <a href="{pre_v1_graph}">path-graph.html</a> · <a href="{pre_v1_coverage}">coverage.html</a></p></div>
  </div></section>
  <section class="section"><h2>Public Risk Seeds</h2><div class="grid">{source_cards}</div></section>
  <section class="section"><h2>Run It Again</h2><pre>PYTHONPATH=src python3 -m invart.cli demo real-world-risk-cases --out-dir .invart/real-world-risk-demo
PYTHONPATH=src python3 -m invart.cli eval benchmark --suite real-world-agent-risk-demo</pre></section>
</main>
</body>
</html>
"""


def _source_card(source: dict[str, Any]) -> str:
    surfaces = "".join(f"<span class=\"pill\">{html.escape(surface)}</span>" for surface in source["invart_surfaces"])
    trajectory = "".join(
        f"<li><strong>{html.escape(str(step['stage']))}:</strong> {html.escape(_trajectory_summary(step))}</li>"
        for step in source["mapped_trajectory"]
    )
    return f"""<div class="card">
  <h3>{html.escape(source["title"])}</h3>
  <p class="muted">{html.escape(source["source_type"])}</p>
  <p>{html.escape(source["observed_risk"])}</p>
  <blockquote><strong>Evidence anchor:</strong> {html.escape(source["short_excerpt"])} <span class="muted">({html.escape(source["excerpt_kind"])})</span></blockquote>
  <p>{surfaces}</p>
  <p><strong>Before:</strong> {html.escape(source["before_signal"])}</p>
  <p><strong>During:</strong> {html.escape(source["during_signal"])}</p>
  <p><strong>After:</strong> {html.escape(source["after_signal"])}</p>
  <ol>{trajectory}</ol>
  <p><a href="{html.escape(source["url"])}">Public source</a></p>
  <p class="muted">{html.escape(source["claim_boundary"])}</p>
</div>"""


def _trajectory_summary(step: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in ["surface", "artifact", "resource", "sink", "signal", "taint", "expected_control", "expected_decision", "question"]:
        if key in step:
            parts.append(f"{key}={step[key]}")
    return "; ".join(parts)


def run_real_world_risk_benchmark() -> dict[str, Any]:
    validation = validate_public_risk_catalog()
    if not validation["valid"]:
        checks = {"catalog_valid": False}
        return {
            "suite": "real-world-agent-risk-demo",
            "passed": False,
            "checks": checks,
            "summary": {"total": 1, "passed": 0, "failed": 1},
            "validation": validation,
            "claim_boundary": "Pinned public-source catalog failed validation; no risk coverage claims are made.",
        }
    catalog = list_real_world_risk_sources()
    sources = catalog["sources"]
    source_text = " ".join(_source_risk_text(item) for item in sources)
    checks = {
        "catalog_valid": validation["valid"],
        "source_count_between_10_and_12": MIN_PUBLIC_RISK_SOURCES <= len(sources) <= MAX_PUBLIC_RISK_SOURCES,
        "has_skill_plugin_supply_chain_sources": _count_sources_matching(sources, ("skill", "plugin", "registry", "package")) >= 2,
        "has_secret_or_credential_egress_sources": _count_sources_matching(sources, ("secret", "credential", "egress", "exfiltration")) >= 2,
        "has_destructive_file_or_infra_mutation_sources": _count_sources_matching(sources, ("delete", "deletion", "destructive", "production", "database")) >= 2,
        "has_mcp_or_tool_misuse_sources": _count_sources_matching(sources, ("mcp", "tool poisoning", "tool_result", "browser automation")) >= 2,
        "has_unmanaged_or_vendor_surface_gap_source": any(token in source_text for token in ("unmanaged", "vendor-owned", "sandbox", "approval mode")),
        "has_benchmark_or_research_source": any(item["source_type"] == "research_paper" or "benchmark" in _source_risk_text(item) for item in sources),
        "all_sources_have_before_during_after": all(item["before_signal"] and item["during_signal"] and item["after_signal"] for item in sources),
        "all_sources_have_excerpt_under_limit": all(len(item["short_excerpt"].split()) <= MAX_EXCERPT_WORDS for item in sources),
        "all_sources_have_structured_trajectory": all(_has_complete_trajectory(item) for item in sources),
        "claim_boundaries_disclose_local_reproduction_limit": all(_discloses_local_reproduction_limit(item["claim_boundary"]) for item in sources),
    }
    return {
        "suite": "real-world-agent-risk-demo",
        "passed": all(checks.values()),
        "checks": checks,
        "summary": {"total": len(checks), "passed": sum(1 for value in checks.values() if value), "failed": sum(1 for value in checks.values() if not value)},
        "source_summary": catalog["summary"],
        "catalog_id": catalog["catalog_id"],
        "catalog_hash": catalog["catalog_hash"],
        "claim_boundary": catalog["claim_boundary"],
    }


def _source_risk_text(source: dict[str, Any]) -> str:
    values = [
        source["source_id"],
        source["title"],
        source["source_type"],
        source["observed_risk"],
        source["before_signal"],
        source["during_signal"],
        source["after_signal"],
        " ".join(source["invart_surfaces"]),
        json.dumps(source["mapped_trajectory"], ensure_ascii=False, sort_keys=True),
    ]
    return " ".join(values).lower()


def _count_sources_matching(sources: list[dict[str, Any]], tokens: tuple[str, ...]) -> int:
    return sum(1 for source in sources if any(token in _source_risk_text(source) for token in tokens))


def _has_complete_trajectory(source: dict[str, Any]) -> bool:
    stages = {step["stage"] for step in source["mapped_trajectory"] if isinstance(step, dict) and "stage" in step}
    return {"pre", "during", "after"}.issubset(stages)


__all__ = [
    "load_public_risk_catalog",
    "list_real_world_risk_sources",
    "run_real_world_risk_benchmark",
    "run_real_world_risk_demo",
    "validate_public_risk_catalog",
]
