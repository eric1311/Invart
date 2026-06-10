from __future__ import annotations

import tempfile
from pathlib import Path

from .common import _suite_result
from invart.evaluation.real_agent_conformance import run_real_agent_conformance
from invart.surfaces.adapter_profiles import list_adapter_profiles, validate_adapter_profile_truthfulness


def run_agent_adapter_contract_benchmark() -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="invart_v093_") as tmp:
        root = Path(tmp)
        fake = root / "fake-agent"
        fake.write_text("#!/usr/bin/env python3\nimport sys\nsys.exit(0)\n", encoding="utf-8")
        fake.chmod(0o755)
        profiles = list_adapter_profiles()
        validation = validate_adapter_profile_truthfulness(profiles)
        conformance = run_real_agent_conformance(
            out_dir=root / "conformance",
            agents=["claude-code", "codex"],
            binary_overrides={"claude-code": str(fake), "codex": str(fake)},
            require_live=True,
        )
        by_agent = {profile["agent_id"]: profile for profile in profiles}
        checks = {
            "profiles_truthful": validation.get("status") == "pass",
            "priority_agents_registered": {"claude-code", "codex", "hermes", "openclaw"}.issubset(by_agent),
            "cloud_import_not_mediated": by_agent.get("github-copilot-cloud-agent", {}).get("supports_mediation") is False,
            "claude_full_requires_evidence": {"ledger", "proof", "evidence_bundle"}.issubset(set(by_agent.get("claude-code", {}).get("required_artifacts", []))),
            "fixture_conformance_passed": conformance.get("status") == "pass",
            "strict_mode_records_managed_run": all(agent.get("managed_run", {}).get("status") == "pass" for agent in conformance.get("agents", [])),
        }
        return _suite_result(
            "v0.9.3-agent-adapter-contract",
            checks,
            artifacts=conformance.get("artifacts", {}),
        )


__all__ = ["run_agent_adapter_contract_benchmark"]
