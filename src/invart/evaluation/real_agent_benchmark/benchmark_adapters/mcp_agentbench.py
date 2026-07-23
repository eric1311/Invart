from __future__ import annotations

from typing import Any

from .base import BenchmarkSourceFreeze


MCP_AGENTBENCH_DOI_URL = "https://doi.org/10.1609/aaai.v40i37.40347"


class MCPAgentBenchAdapter:
    benchmark_id = "mcp_agentbench"

    def __init__(self, *, split: str) -> None:
        self.split = str(split or "").strip()
        if not self.split:
            raise ValueError("MCP-AgentBench split must be nonempty")

    def source_freeze(self) -> BenchmarkSourceFreeze:
        return BenchmarkSourceFreeze(
            benchmark_id=self.benchmark_id,
            source_url=MCP_AGENTBENCH_DOI_URL,
            revision="aaai-2026-volume-40-issue-37-article-40347",
            license="AAAI-publication-copyright-code-license-unresolved",
            split=self.split,
            allowed_network_destinations=(),
        )

    def qualification(self) -> dict[str, Any]:
        return {
            "status": "conditional_missing_official_code",
            "publication": "AAAI 2026",
            "native_metric": "llm_judge_pass_rate",
            "task_count": 600,
            "servers": 33,
            "tools": 188,
            "official_code_url": None,
            "claim_boundary": (
                "The peer-reviewed paper qualifies the benchmark concept, but no official code revision was "
                "identified from the publication source. Runtime utility claims remain blocked until code, license, "
                "server freeze, and MCP-Eval artifacts are qualified."
            ),
        }


def assess_mcp_utility_pairing(
    *,
    security_profile_hash: str,
    utility_profile_hash: str,
    security_condition_hash: str | None = None,
    utility_condition_hash: str | None = None,
) -> dict[str, str]:
    same_profile = bool(security_profile_hash) and security_profile_hash == utility_profile_hash
    same_condition = bool(security_condition_hash) and security_condition_hash == utility_condition_hash
    if same_profile and same_condition:
        return {"status": "paired_profile", "claim_scope": "paired_mcp_security_utility"}
    return {
        "status": "separate_utility_row",
        "claim_scope": "unpaired_mcp_utility",
        "reason": "security and utility rows do not share both an immutable runtime/tool/server profile and task condition",
    }


__all__ = ["MCP_AGENTBENCH_DOI_URL", "MCPAgentBenchAdapter", "assess_mcp_utility_pairing"]
