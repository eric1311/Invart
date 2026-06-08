from __future__ import annotations

import importlib
import importlib.abc
import importlib.util
import sys
from types import ModuleType
from typing import Mapping


LEGACY_MODULE_ALIASES: dict[str, str] = {
    "adapter": "surfaces.adapter",
    "adapter_profiles": "surfaces.adapter_profiles",
    "approval": "control.approval",
    "artifacts": "core.artifacts",
    "audit_demo": "assurance.audit_demo",
    "audit_experiments": "evaluation.audit_experiments",
    "benchmark_registry": "evaluation.benchmark_registry",
    "claude_adapter": "surfaces.claude_adapter",
    "container_demo": "evaluation.container_demo",
    "corpus": "surfaces.corpus",
    "corpus_adapters": "surfaces.corpus_adapters",
    "coverage": "assurance.coverage",
    "coverage_experiments": "evaluation.coverage_experiments",
    "daemon": "control.daemon",
    "enforcement": "surfaces.enforcement",
    "evals": "evaluation.evals",
    "evidence": "control.evidence",
    "evidence_bundle": "assurance.evidence_bundle",
    "experiment_cases": "evaluation.experiment_cases",
    "experiment_fixtures": "evaluation.experiment_fixtures",
    "external_evidence": "evaluation.external_evidence",
    "gate": "control.gate",
    "harness": "evaluation.harness",
    "identity": "governance.identity",
    "launcher": "surfaces.launcher",
    "ledger": "core.ledger",
    "mcp_broker": "surfaces.mcp_broker",
    "mediation": "control.mediation",
    "models": "core.models",
    "native": "surfaces.native",
    "native_bridge": "surfaces.native_bridge",
    "path_graph": "assurance.path_graph",
    "path_policy": "control.path_policy",
    "policy": "control.policy",
    "policy_as_code": "control.policy_as_code",
    "postruntime": "assurance.postruntime",
    "pre_1_0": "evaluation.pre_1_0",
    "pre_v1": "evaluation.pre_v1",
    "preflight": "control.preflight",
    "product_readiness": "evaluation.product_readiness",
    "profiles": "governance.profiles",
    "progressive_validation": "evaluation.progressive_validation",
    "real_world_cases": "evaluation.real_world_cases",
    "release_candidate": "evaluation.release_candidate",
    "replay": "assurance.replay",
    "review": "control.review",
    "reviewer_experiments": "evaluation.reviewer_experiments",
    "roadmap": "evaluation.roadmap",
    "rules": "control.rules",
    "runtime": "control.runtime",
    "scanner": "surfaces.scanner",
    "secure_code_gate": "assurance.secure_code_gate",
    "supervision": "surfaces.supervision",
    "teamrun": "governance.teamrun",
}


class _AliasLoader(importlib.abc.Loader):
    def __init__(self, fullname: str, target: str) -> None:
        self.fullname = fullname
        self.target = target

    def create_module(self, spec: importlib.machinery.ModuleSpec) -> ModuleType:
        module = importlib.import_module(self.target)
        sys.modules[self.fullname] = module
        return module

    def exec_module(self, module: ModuleType) -> None:
        return None


class _AliasFinder(importlib.abc.MetaPathFinder):
    def __init__(self, package_name: str, aliases: Mapping[str, str]) -> None:
        self.package_name = package_name
        self.aliases = dict(aliases)

    def find_spec(
        self,
        fullname: str,
        path: object | None,
        target: ModuleType | None = None,
    ) -> importlib.machinery.ModuleSpec | None:
        prefix = f"{self.package_name}."
        if not fullname.startswith(prefix):
            return None
        alias = fullname[len(prefix):]
        if alias not in self.aliases:
            return None
        target_name = self.aliases[alias]
        if not target_name.startswith("invart."):
            target_name = f"invart.{target_name}"
        return importlib.util.spec_from_loader(fullname, _AliasLoader(fullname, target_name))


def install_module_aliases(package_name: str, aliases: Mapping[str, str]) -> None:
    marker = (package_name, tuple(sorted(aliases.items())))
    for finder in sys.meta_path:
        if isinstance(finder, _AliasFinder) and (finder.package_name, tuple(sorted(finder.aliases.items()))) == marker:
            return
    sys.meta_path.insert(0, _AliasFinder(package_name, aliases))


__all__ = ["LEGACY_MODULE_ALIASES", "install_module_aliases"]
