from __future__ import annotations

import html
import tempfile
from pathlib import Path
from typing import Any

from invart.core.artifacts import stable_json_hash, write_html_artifact, write_json_artifact
from invart.core.models import utc_now


SCHEMA_VERSION = "invart.product_control_matrix.v0.50"


def run_product_control_matrix(*, out_dir: Path | None = None) -> dict[str, Any]:
    root = (out_dir or Path(tempfile.mkdtemp(prefix="invart_product_control_matrix_"))).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    rows = _product_rows()
    baselines = _baseline_rows()
    checks = {
        "products_covered": len({row["product"] for row in rows}) >= 4,
        "plugin_only_not_mediated": all(
            row["coverage_grade"] in {"observed", "vendor_owned"} and not row["supports_mediation"]
            for row in baselines
            if row["baseline"] == "plugin_only"
        ),
        "managed_launcher_mediated": any(
            row["baseline"] == "invart_managed_launcher" and row["supports_mediation"] and row["coverage_grade"] == "mediated"
            for row in baselines
        ),
        "required_fields_present": all(_required_fields_present(row) for row in rows),
    }
    matrix_json = root / "product-control-matrix.json"
    matrix_html = root / "product-control-matrix.html"
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "suite": "product-control-matrix",
        "status": "pass" if all(checks.values()) else "fail",
        "passed": all(checks.values()),
        "generated_at": utc_now(),
        "summary": {
            "products": len({row["product"] for row in rows}),
            "surfaces": len(rows),
            "baselines": len(baselines),
            "claim": "Plugin/extension features can improve visibility, but Invart only labels coverage mediated or enforced when a runtime mediation surface actually participates.",
        },
        "checks": checks,
        "rows": rows,
        "baselines": baselines,
        "artifacts": {"matrix_json": str(matrix_json), "matrix_html": str(matrix_html)},
        "evidence_hash": stable_json_hash({"rows": rows, "baselines": baselines}),
    }
    write_json_artifact(matrix_json, report)
    write_html_artifact(matrix_html, _matrix_html(report))
    return report


def _required_fields_present(row: dict[str, Any]) -> bool:
    required = ("product", "surface", "source", "source_kind", "source_urls", "native_control", "invart_layer", "coverage_grade", "limitation")
    return all(row.get(key) for key in required) and all(str(url).startswith("https://") for url in row.get("source_urls", []))


def _product_rows() -> list[dict[str, Any]]:
    return [
        {
            "product": "Claude Code",
            "surface": "hooks / permissions / slash-command workflow",
            "source": "vendor_docs:claude_code_security_hooks_permissions",
            "source_kind": "official_vendor_docs",
            "source_urls": [
                "https://code.claude.com/docs/en/security",
                "https://code.claude.com/docs/en/permissions",
                "https://code.claude.com/docs/en/hooks",
                "https://www.anthropic.com/engineering/claude-code-auto-mode",
            ],
            "native_control": "pre/post tool hooks and permission prompts",
            "invart_layer": "adapter-managed command/file mediation",
            "coverage_grade": "mediated",
            "supports_mediation": True,
            "limitation": "Native hooks are product-owned and can miss lower-level process/network effects unless execution is routed through Invart-managed surfaces.",
            "reference_meaning": "Useful integration point, not sufficient as the only safety boundary.",
        },
        {
            "product": "OpenAI Codex",
            "surface": "sandbox / approval / managed network / telemetry",
            "source": "vendor_docs:codex_safety",
            "source_kind": "official_vendor_docs",
            "source_urls": ["https://openai.com/index/running-codex-safely/"],
            "native_control": "isolated execution, approval workflows, managed network policy, credential handling, and telemetry",
            "invart_layer": "generic wrapper plus ledger/proof/evidence export",
            "coverage_grade": "vendor_owned",
            "supports_mediation": False,
            "limitation": "Vendor-owned sandbox and approval controls are valuable but cannot be labeled Invart-mediated unless the action is routed through an Invart mediation surface.",
            "reference_meaning": "Good product-level control signal and baseline for native evidence import.",
        },
        {
            "product": "OpenAI Agents SDK",
            "surface": "guardrails / human-in-the-loop / tracing",
            "source": "vendor_docs:agents_sdk_guardrails_hitl_tracing",
            "source_kind": "official_vendor_docs",
            "source_urls": [
                "https://openai.github.io/openai-agents-python/guardrails/",
                "https://openai.github.io/openai-agents-python/human_in_the_loop/",
                "https://openai.github.io/openai-agents-python/tracing/",
            ],
            "native_control": "input/output guardrails, tool approval interruptions, and run tracing",
            "invart_layer": "native evidence import plus optional mediated adapter",
            "coverage_grade": "vendor_owned",
            "supports_mediation": False,
            "limitation": "SDK callbacks can mediate inside an application, but Invart should record them as vendor-owned until an adapter binds them to the ledger and mediation contract.",
            "reference_meaning": "Framework-level proof that approvals and traces are first-class agent runtime concepts.",
        },
        {
            "product": "Hermes Agent",
            "surface": "terminal safety / backend isolation / credential filtering",
            "source": "vendor_docs:hermes_agent_security",
            "source_kind": "official_vendor_docs",
            "source_urls": ["https://hermes-agent.nousresearch.com/docs/user-guide/security"],
            "native_control": "dangerous command approval, hardline blocklist, container backends, environment filtering, SSRF protection, and context scanning",
            "invart_layer": "managed launcher / wrapper coordination plus native evidence import",
            "coverage_grade": "vendor_owned",
            "supports_mediation": False,
            "limitation": "Self-hosted runtime controls are strong inside the selected backend, but Invart should not claim mediation until backend events are bound to Invart decisions and ledger entries.",
            "reference_meaning": "Open self-hosted runtime with a visible defense-in-depth control vocabulary.",
        },
        {
            "product": "OpenClaw",
            "surface": "host-exec permission modes / plugin and skill registry",
            "source": "vendor_docs:openclaw_permission_modes",
            "source_kind": "official_project_docs",
            "source_urls": ["https://docs.openclaw.ai/tools/permission-modes"],
            "native_control": "host-exec deny, allowlist, human approval, automatic review, and no-prompt modes",
            "invart_layer": "skill/tool scanner plus runtime mediation contract",
            "coverage_grade": "vendor_owned",
            "supports_mediation": False,
            "limitation": "Host-exec modes describe product-owned command control. Invart should import or wrap those events before claiming cross-agent mediated coverage.",
            "reference_meaning": "Good design probe for comparing no-prompt, allowlist, review, and human approval modes.",
        },
    ]


def _baseline_rows() -> list[dict[str, Any]]:
    return [
        {
            "baseline": "plugin_only",
            "coverage_grade": "observed",
            "supports_mediation": False,
            "can_block": False,
            "can_pause_resume": False,
            "evidence_quality": "vendor_or_plugin_log",
            "limitation": "A plugin-only path may record intent or tool metadata but cannot by itself prove runtime command/file/network mediation.",
        },
        {
            "baseline": "trace_only",
            "coverage_grade": "observed",
            "supports_mediation": False,
            "can_block": False,
            "can_pause_resume": False,
            "evidence_quality": "after-the-fact trace",
            "limitation": "Trace-only evidence supports audit reconstruction but not live intervention.",
        },
        {
            "baseline": "invart_managed_launcher",
            "coverage_grade": "mediated",
            "supports_mediation": True,
            "can_block": True,
            "can_pause_resume": True,
            "evidence_quality": "ledger_plus_policy_decision",
            "limitation": "Requires adoption of the managed launch path or stronger host integration.",
        },
        {
            "baseline": "invart_native_hook",
            "coverage_grade": "enforced",
            "supports_mediation": True,
            "can_block": True,
            "can_pause_resume": True,
            "evidence_quality": "ledger_plus_enforced_outcome",
            "limitation": "Native hook coverage is surface-specific and must never be generalized to uncovered execution paths.",
        },
    ]


def _matrix_html(report: dict[str, Any]) -> str:
    rows = []
    for row in report["rows"]:
        rows.append(
            "<tr>"
            f"<td>{html.escape(row['product'])}</td>"
            f"<td>{html.escape(row['surface'])}<br><small>{html.escape('; '.join(row.get('source_urls', [])))}</small></td>"
            f"<td>{html.escape(row['coverage_grade'])}</td>"
            f"<td>{html.escape(row['invart_layer'])}</td>"
            f"<td>{html.escape(row['limitation'])}</td>"
            "</tr>"
        )
    baselines = []
    for row in report["baselines"]:
        baselines.append(
            "<tr>"
            f"<td>{html.escape(row['baseline'])}</td>"
            f"<td>{html.escape(row['coverage_grade'])}</td>"
            f"<td>{row['supports_mediation']}</td>"
            f"<td>{row['can_block']}</td>"
            f"<td>{html.escape(row['limitation'])}</td>"
            "</tr>"
        )
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Product Control Matrix</title><style>body{{font-family:Inter,Arial,sans-serif;margin:0;background:#f8fafc;color:#172033}}main{{max-width:1160px;margin:0 auto;padding:32px 24px}}table{{width:100%;border-collapse:collapse;background:white;border:1px solid #dfe5ef;margin:16px 0}}td,th{{border-bottom:1px solid #e5e7eb;padding:8px;text-align:left;vertical-align:top}}</style></head><body><main><h1>Product Control Matrix</h1><p>Status: <strong>{html.escape(str(report.get("status")))}</strong></p><h2>Agent Product Surfaces</h2><table><tr><th>Product</th><th>Surface</th><th>Coverage</th><th>Invart Layer</th><th>Limitation</th></tr>{''.join(rows)}</table><h2>Baselines</h2><table><tr><th>Baseline</th><th>Coverage</th><th>Mediation</th><th>Can Block</th><th>Limitation</th></tr>{''.join(baselines)}</table></main></body></html>"""


__all__ = ["run_product_control_matrix"]
