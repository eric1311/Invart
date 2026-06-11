from __future__ import annotations

import html
import json
import os
import subprocess
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

from invart.core.artifacts import sha256_file, write_html_artifact, write_json_artifact
from invart.assurance.evidence_bundle import export_evidence_bundle
from invart.assurance.coverage import export_coverage_html_report
from invart.control.daemon import RuntimeAuthority
from invart.control.gate import verify_gate
from invart.governance.identity import bind_agent_identity, create_capability_grant, credential_inventory, declare_principal, record_identity_binding
from invart.core.ledger import load_ledger_entries
from invart.control.mediation import mediate_event
from invart.assurance.postruntime import export_proof_report
from invart.assurance.replay import export_replay_html
from invart.assurance.path_graph import export_execution_graph_html
from invart.core.models import utc_now
from invart.core.env import child_env as make_child_env, invart_session_env
from invart.control.runtime import record_outcome
from invart.surfaces.enforcement import run_file_write_intercepted


@dataclass
class AdapterRunResult:
    session_id: str
    status: str
    command: list[str]
    returncode: int
    ledger: str
    proof: str
    gate_report: str | None = None
    gate_status: str | None = None
    package: str | None = None
    capability_registration: dict[str, Any] | None = None
    started_at: str | None = None
    ended_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def run_adapter_command(
    *,
    target: Path,
    command: list[str],
    agent: str | None = None,
    goal: str | None = None,
    session_id: str | None = None,
    out_dir: Path | None = None,
    corpus_root: Path | None = None,
    capabilities: str = "audit",
    gate_mode: str = "off",
    policy_mode: str = "advisory",
    create_preflight: bool = True,
    enforcement: str = "off",
) -> AdapterRunResult:
    if not command:
        raise ValueError("adapter run requires a command")
    target = target.expanduser().resolve()
    authority = RuntimeAuthority.for_target(target)
    resolved_out_dir = out_dir.expanduser().resolve() if out_dir else None
    ledger_path = (resolved_out_dir / "ledger.jsonl") if resolved_out_dir else None
    started_at = utc_now()
    registry = authority.create_session(
        target,
        agent=agent,
        goal=goal,
        session_id=session_id,
        ledger_path=ledger_path,
        create_preflight=create_preflight,
        metadata={"adapter_runner": "invart.adapter.run", "started_by": "invart.cli"},
    )
    ledger = Path(registry.ledger_path)
    proof = ledger.with_name("proof.json")
    gate_report_path = ledger.with_name("gate-report.json") if gate_mode != "off" else None
    capability_registration: dict[str, Any] | None = None
    if capabilities != "off":
        capability_registration = authority.register_capabilities(
            registry.session_id,
            corpus_root or Path("benchmarks/corpora"),
            adapter=agent or "generic-adapter",
            review_mode="off",
            policy_mode="audit" if capabilities == "audit" else "managed",
        )
    if enforcement == "file-write":
        enforced = run_file_write_intercepted(command, ledger_path=ledger, session_id=registry.session_id, target=target)
        returncode = int(enforced.get("returncode") if enforced.get("returncode") is not None else 1)
        child_status = str(enforced.get("status"))
    else:
        plan = authority.record_event(
            registry.session_id,
            {
                "type": "shell",
                "command": " ".join(command),
                "agent": agent,
                "target": str(target),
                "metadata": {"adapter": "invart-adapter-run", "operation": "child_command"},
            },
            review_mode="auto",
            policy_mode=policy_mode,
        )
        if plan["decision"].get("effect") == "deny" or plan["decision"].get("requires_approval"):
            authority.outcome(
                registry.session_id,
                "blocked",
                decision_id=plan["decision"].get("decision_id"),
                actor="invart.adapter.run",
                reason="policy did not allow child command execution",
            )
            authority.transition_session(registry.session_id, "stopped", reason="adapter command blocked")
            export_proof_report(ledger, proof)
            gate_status = None
            package = _export_command_adapter_package(ledger, resolved_out_dir, policy_mode=policy_mode, agent=agent)
            if gate_report_path:
                gate = verify_gate(ledger_path=ledger, proof_path=proof, mode=gate_mode, output_path=gate_report_path)
                gate_status = str(gate.get("status"))
            return AdapterRunResult(
                session_id=registry.session_id,
                status="blocked",
                command=command,
                returncode=126,
                ledger=str(ledger),
                proof=str(proof),
                gate_report=str(gate_report_path) if gate_report_path else None,
                gate_status=gate_status,
                package=package,
                capability_registration=capability_registration,
                started_at=started_at,
                ended_at=utc_now(),
            )
        env = make_child_env(os.environ, session_id=registry.session_id, ledger=str(ledger), target=str(target))
        completed = subprocess.run(command, check=False, cwd=str(target), env=env)
        returncode = completed.returncode
        child_status = "executed" if completed.returncode == 0 else "failed"
        authority.outcome(
            registry.session_id,
            "executed" if completed.returncode == 0 else "failed",
            decision_id=plan["decision"].get("decision_id"),
            actor=agent or "adapter",
            reason=f"child exited with {completed.returncode}",
        )
    authority.transition_session(registry.session_id, "stopped", reason="adapter command completed")
    export_proof_report(ledger, proof)
    gate_status = None
    if gate_report_path:
        gate = verify_gate(ledger_path=ledger, proof_path=proof, mode=gate_mode, output_path=gate_report_path)
        gate_status = str(gate.get("status"))
    package = _export_command_adapter_package(ledger, resolved_out_dir, policy_mode=policy_mode, agent=agent)
    status = "blocked" if child_status in {"blocked", "requires_approval"} else "passed" if returncode == 0 and gate_status not in {"fail"} else "failed"
    return AdapterRunResult(
        session_id=registry.session_id,
        status=status,
        command=command,
        returncode=returncode,
        ledger=str(ledger),
        proof=str(proof),
        gate_report=str(gate_report_path) if gate_report_path else None,
        gate_status=gate_status,
        package=package,
        capability_registration=capability_registration,
        started_at=started_at,
        ended_at=utc_now(),
    )


def run_adapter_runtime(
    *,
    target: Path,
    command: list[str],
    adapter_kind: str = "generic",
    agent: str | None = None,
    principal_id: str | None = None,
    env: dict[str, str] | None = None,
    goal: str | None = None,
    session_id: str | None = None,
    out_dir: Path | None = None,
    profile: dict[str, Any] | None = None,
    create_preflight: bool = True,
) -> dict[str, Any]:
    if adapter_kind not in {"claude-code", "codex", "generic"}:
        raise ValueError("adapter_kind must be claude-code, codex, or generic")
    if not command:
        raise ValueError("adapter runtime requires a command")

    target = target.expanduser().resolve()
    target.mkdir(parents=True, exist_ok=True)
    artifacts = (out_dir or target / ".invart" / "adapter-runtime").expanduser().resolve()
    artifacts.mkdir(parents=True, exist_ok=True)
    resolved_agent = agent or adapter_kind
    principal = declare_principal(principal_id or f"local:{os.getuid()}", display_name=principal_id or "Local User")
    agent_identity = bind_agent_identity(resolved_agent, declared_by=principal.principal_id, adapter_agent=adapter_kind if adapter_kind != "generic" else resolved_agent)
    profile_config = profile or {"mode": "advisory"}

    authority = RuntimeAuthority.for_target(target)
    registry = authority.create_session(
        target,
        agent=resolved_agent,
        goal=goal or f"{adapter_kind} managed runtime",
        session_id=session_id,
        ledger_path=artifacts / "ledger.jsonl",
        create_preflight=create_preflight,
        metadata={
            "policy_profile_config": profile_config,
            "principal": principal.to_dict(),
            "agent_identity": agent_identity.to_dict(),
            "adapter_runtime": {"kind": adapter_kind, "schema_version": "invart.adapter_runtime.v0.25"},
        },
    )
    ledger = Path(registry.ledger_path)
    credentials = credential_inventory(env or _selected_env(os.environ), owner=principal.principal_id)
    grant = create_capability_grant(
        principal_id=principal.principal_id,
        agent_id=agent_identity.agent_id,
        scopes=["command", "file_read", "network", "env"],
        resources=[str(target), "*"],
    )
    record_identity_binding(ledger, session_id=registry.session_id, principal=principal, agent_identity=agent_identity, credentials=credentials, grants=[grant])

    mediated = mediate_event(
        ledger,
        session_id=registry.session_id,
        surface="command",
        event={
            "type": "shell",
            "command": " ".join(command),
            "agent": resolved_agent,
            "target": str(target),
            "metadata": {
                "adapter": f"invart-{adapter_kind}",
                "adapter_kind": adapter_kind,
                "capability_grant_id": grant.grant_id,
                "coverage_layer": "shell_wrapper",
            },
        },
        mode=str(profile_config.get("mode", "managed")),
    )

    returncode = 126
    status = "blocked"
    effect = mediated["decision"]["effect"]
    if effect in {"allow", "audit"}:
        child_env = dict(os.environ)
        child_env.update(env or {})
        child_env.update(
            invart_session_env(
                session_id=registry.session_id,
                ledger=str(ledger),
                adapter_kind=adapter_kind,
                environ=child_env,
            )
        )
        completed = subprocess.run(command, check=False, cwd=str(target), env=child_env, capture_output=True, text=True)
        returncode = int(completed.returncode)
        status = "passed" if completed.returncode == 0 else "failed"
        record_outcome(
            ledger,
            "executed" if completed.returncode == 0 else "failed",
            decision_id=mediated["outcome"].get("decision_id"),
            invocation_id=mediated["outcome"].get("invocation_id"),
            actor=f"invart-{adapter_kind}",
            reason=f"child exited with {completed.returncode}",
            metadata={
                "adapter_kind": adapter_kind,
                "stdout_preview": (completed.stdout or "")[:400],
                "stderr_preview": (completed.stderr or "")[:400],
            },
        )
    elif effect == "require_approval":
        status = "requires_approval"
    else:
        status = "blocked"

    authority.transition_session(registry.session_id, "stopped", reason=f"{adapter_kind} adapter runtime completed")
    proof_path = artifacts / "proof.json"
    proof = export_proof_report(ledger, proof_path)
    replay = export_replay_html(ledger, artifacts / "replay.html", gate_mode="managed")
    graph = export_execution_graph_html(ledger, artifacts / "path-graph.html")
    coverage = export_coverage_html_report(proof_path, artifacts / "coverage.html")
    audit_json = _write_adapter_audit_json(artifacts / "audit.json", adapter_kind, proof, mediated, status)
    audit_html = _write_adapter_audit_html(artifacts / "audit.html", audit_json)
    package = _write_adapter_package(
        artifacts / "adapter-package.json",
        adapter={"kind": adapter_kind, "agent": resolved_agent, "principal": principal.principal_id},
        artifacts={
            "ledger": ledger,
            "proof": proof_path,
            "replay": Path(replay["replay"]),
            "path_graph": Path(graph["output"]),
            "coverage_report": Path(coverage["output"]),
            "audit_json": Path(audit_json["path"]),
            "audit_report": Path(audit_html["path"]),
        },
    )
    return {
        "schema_version": "invart.adapter_runtime.v0.25",
        "status": status,
        "adapter": {"kind": adapter_kind, "agent": resolved_agent},
        "session_id": registry.session_id,
        "returncode": returncode,
        "mediation": mediated,
        "artifacts": {
            "ledger": str(ledger),
            "proof": str(proof_path),
            "replay": replay["replay"],
            "path_graph": graph["output"],
            "coverage_report": coverage["output"],
            "audit_json": audit_json["path"],
            "audit_report": audit_html["path"],
            "package": str(package),
        },
    }


def inspect_adapter_package(package_path: Path) -> dict[str, Any]:
    manifest = json.loads(package_path.read_text(encoding="utf-8"))
    failures = []
    for name, item in manifest.get("artifacts", {}).items():
        path = Path(str(item.get("path", "")))
        if not path.exists():
            failures.append({"artifact": name, "reason": "missing"})
            continue
        if sha256_file(path) != item.get("sha256"):
            failures.append({"artifact": name, "reason": "hash_mismatch"})
    return {
        "schema_version": "invart.adapter_package_inspect.v0.25",
        "status": "pass" if not failures else "fail",
        "manifest": manifest,
        "failures": failures,
    }


def _selected_env(env: dict[str, str]) -> dict[str, str]:
    selected: dict[str, str] = {}
    for key in sorted(env):
        lowered = key.lower()
        if key in {"PATH", "SHELL", "HOME"} or any(marker in lowered for marker in ("key", "token", "secret", "password", "credential")):
            selected[key] = env[key]
    return selected


def _write_adapter_audit_json(path: Path, adapter_kind: str, proof: dict[str, Any], mediation: dict[str, Any], status: str) -> dict[str, Any]:
    payload = {
        "schema_version": "invart.adapter_audit.v0.25",
        "adapter": {"kind": adapter_kind},
        "status": status,
        "accountability": proof.get("accountability", {}),
        "coverage": proof.get("coverage", {}),
        "mediation": mediation,
        "summary": proof.get("summary", {}),
        "generated_at": utc_now(),
    }
    write_json_artifact(path, payload)
    return {"path": str(path), "audit": payload}


def _write_adapter_audit_html(path: Path, audit_json: dict[str, Any]) -> dict[str, Any]:
    audit = audit_json["audit"]
    body = json.dumps(audit, ensure_ascii=False, indent=2, sort_keys=True)
    write_html_artifact(
        path,
        f"""<!doctype html><html><head><meta charset="utf-8"><title>Adapter Runtime Audit</title><style>body{{font-family:Inter,Arial,sans-serif;margin:0;background:#f8fafc;color:#172033}}main{{max-width:1080px;margin:0 auto;padding:32px 24px}}section{{background:white;border:1px solid #d9e2ef;border-radius:8px;padding:16px;margin:14px 0}}pre{{background:#111827;color:#e5e7eb;padding:14px;border-radius:8px;overflow:auto}}</style></head><body><main><h1>Adapter Runtime Audit</h1><section><h2>Accountability</h2><pre>{html.escape(json.dumps(audit.get("accountability", {}), ensure_ascii=False, indent=2))}</pre></section><section><h2>Mediation</h2><pre>{html.escape(json.dumps(audit.get("mediation", {}), ensure_ascii=False, indent=2))}</pre></section><section><h2>Coverage</h2><pre>{html.escape(json.dumps(audit.get("coverage", {}), ensure_ascii=False, indent=2))}</pre></section><section><h2>Raw Audit</h2><details><summary>Show JSON</summary><pre>{html.escape(body)}</pre></details></section></main></body></html>""",
    )
    return {"path": str(path)}


def _write_adapter_package(package_path: Path, *, adapter: dict[str, Any], artifacts: dict[str, Path]) -> Path:
    manifest = {
        "schema_version": "invart.adapter_package.v0.25",
        "adapter": adapter,
        "created_at": utc_now(),
        "artifacts": {
            name: {"path": str(path), "sha256": sha256_file(path), "bytes": path.stat().st_size}
            for name, path in sorted(artifacts.items())
        },
    }
    write_json_artifact(package_path, manifest)
    return package_path


def _export_command_adapter_package(ledger: Path, out_dir: Path | None, *, policy_mode: str, agent: str | None) -> str | None:
    if out_dir is None:
        return None
    bundle = export_evidence_bundle(
        ledger,
        out_dir / "adapter-package",
        profile={"name": "adapter-run", "mode": policy_mode, "agent": agent or "generic"},
    )
    return str(bundle["manifest_path"])


__all__ = ["AdapterRunResult", "inspect_adapter_package", "run_adapter_command", "run_adapter_runtime"]
