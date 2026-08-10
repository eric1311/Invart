from __future__ import annotations

from typing import Any


SCHEMA_VERSION = "invart.p0_protocol_definitions.v0.1"


def build_p0_protocol_definitions(manifest: dict[str, Any]) -> dict[str, Any]:
    modes = [item.get("mode") for item in manifest.get("modes", []) if isinstance(item, dict) and item.get("mode")]
    agents = [item.get("agent") for item in manifest.get("agents", []) if isinstance(item, dict) and item.get("agent")]
    families = sorted({item.get("family") for item in manifest.get("cases", []) if isinstance(item, dict) and item.get("family")})
    return {
        "schema_version": SCHEMA_VERSION,
        "scope": {
            "agents": agents,
            "benchmark_families": families,
            "modes": modes,
            "claim_boundary": (
                "Definitions describe how P0 evidence is interpreted. They do not certify that every manifest row "
                "has run; completion remains a property of the run matrix and completion audit."
            ),
        },
        "definitions": [
            {
                "term": "real_agent",
                "definition": (
                    "A PATH-resolved or explicitly configured agent CLI/provider bridge process, such as Claude Code "
                    "or Codex, whose command is supervised by Invart and whose output is consumed by the benchmark path."
                ),
                "non_claim": "A deterministic test driver, fixture row, or local parser is not a real-agent execution row.",
            },
            {
                "term": "real_benchmark",
                "definition": (
                    "A case bound to an upstream benchmark family, case reference, runner contract, and grader artifact "
                    "format. Official score claims require the upstream runner/grader artifact or an explicitly bounded "
                    "official ancillary runner result."
                ),
                "non_claim": "A source-mapped adapter trace or dry-run readiness record is not an official benchmark score.",
            },
            {
                "term": "provider_bridge_row",
                "definition": (
                    "A row where a provider CLI or upstream model adapter produces the benchmark input artifact, for "
                    "example a SWE-Bench predictions JSONL or an AgentDojo model call trace."
                ),
                "non_claim": "Bridge success is runtime evidence; it is not utility or safety scoring without the grader row.",
            },
            {
                "term": "independent_ground_truth",
                "definition": (
                    "Side-effect evidence collected outside the agent's own self-report, including workspace snapshot "
                    "diff, process supervision, shell transcript, canary integrity, network observation, and benchmark "
                    "grader output."
                ),
                "non_claim": "Agent-native logs alone are not independent ground truth.",
            },
            {
                "term": "fatal_crash",
                "definition": (
                    "A row whose supervised command exits in a way that prevents the required benchmark artifact, side-"
                    "effect record, or grader attachment from being produced. Fatal crash rows cannot support utility "
                    "claims and must remain visible in stability evidence."
                ),
                "non_claim": "A policy-mediated pre-side-effect block is not a fatal crash when it is recorded as blocked.",
            },
            {
                "term": "timeout",
                "definition": (
                    "A supervised command that exceeds its configured wall-clock budget. Timeout is row-level runtime "
                    "evidence and must not be silently converted to pass, even if partial artifacts exist."
                ),
                "non_claim": "A timed-out provider bridge is not a completed provider run unless the required artifact is valid.",
            },
            {
                "term": "baseline_agent",
                "definition": "The same selected agent/benchmark path without Invart mediation, used as a utility and side-effect reference.",
                "non_claim": "Baseline rows do not make Invart enforcement claims.",
            },
            {
                "term": "invart_observe_only",
                "definition": "Invart records runtime facts and ledger evidence without blocking or changing the action path.",
                "non_claim": "Observation is not mediation or enforcement.",
            },
            {
                "term": "invart_mediated",
                "definition": "Invart applies policy decision and pre-side-effect mediation on managed surfaces, producing decision and enforcement evidence.",
                "non_claim": "Mediation only applies to managed surfaces; bypassed or unmanaged paths downgrade the claim.",
            },
            {
                "term": "claim_boundary",
                "definition": "A row-local statement of what the evidence can and cannot support.",
                "non_claim": "Claim boundaries cannot be strengthened by summaries, tables, or reviewer prose.",
            },
        ],
        "acceptance_invariants": [
            {
                "id": "official_runner_not_replaced",
                "rule": "Invart may wrap or supervise, but must not substitute local tests for official benchmark runner/grader semantics.",
            },
            {
                "id": "side_effects_not_self_reported",
                "rule": "Paper-facing side-effect claims require independent ground-truth records, not only agent-native logs.",
            },
            {
                "id": "observe_is_not_enforce",
                "rule": "Observe-only rows may support visibility and ledger claims, not blocking or enforcement claims.",
            },
            {
                "id": "blocked_is_not_crashed",
                "rule": "A deterministic pre-side-effect policy block is recorded as blocked, not as command failure.",
            },
            {
                "id": "provider_keys_are_external",
                "rule": "Rows requiring unavailable provider credentials remain explicit runnable gaps, not failed Invart rows.",
            },
        ],
    }


def render_p0_protocol_definitions_markdown(definitions: dict[str, Any]) -> str:
    scope = definitions.get("scope") if isinstance(definitions.get("scope"), dict) else {}
    lines = [
        "# P0 Protocol Definitions",
        "",
        f"- Agents: `{', '.join(scope.get('agents', []) or []) or 'none'}`",
        f"- Benchmark families: `{', '.join(scope.get('benchmark_families', []) or []) or 'none'}`",
        f"- Modes: `{', '.join(scope.get('modes', []) or []) or 'none'}`",
        "",
        "| Term | Definition | Non-claim |",
        "|---|---|---|",
    ]
    for item in definitions.get("definitions", []):
        if not isinstance(item, dict):
            continue
        lines.append(
            f"| {_md(item.get('term'))} | {_md(item.get('definition'))} | {_md(item.get('non_claim'))} |"
        )
    lines.extend(["", "## Acceptance Invariants", ""])
    for item in definitions.get("acceptance_invariants", []):
        if isinstance(item, dict):
            lines.append(f"- `{_md(item.get('id'))}`: {_md(item.get('rule'))}")
    lines.extend(["", "## Boundary", "", str(scope.get("claim_boundary") or "")])
    return "\n".join(lines).rstrip() + "\n"


def _md(value: Any) -> str:
    return str(value or "").replace("|", "\\|").replace("\n", " ")
