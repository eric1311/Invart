from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Mapping

from invart.core.artifacts import (
    sha256_file,
    stable_json_dumps,
    stable_json_hash,
    write_json_artifact,
)

from .benchmark_oracles import ground_truth_calls_for_cell
from .mediation_adjudication import CandidateCall, adjudicate_candidate_call
from .mediation_prompts import build_mediation_prompt
from .mediation_reviewer import canonical_tool_call_digest
from .provider_run_control import scan_provider_artifact_tree, secure_provider_artifact_tree


JOIN_SCHEMA_VERSION = "invart.agentdojo_event_join.v0.1"


def join_agentdojo_events(
    *,
    proxy_log: Path,
    official_logdir: Path,
    ground_truth_payload: Mapping[str, Any],
) -> dict[str, Any]:
    proxy_path = Path(proxy_log)
    official_root = Path(official_logdir)
    index, official_sources = _build_official_turn_index(official_root)
    join_statuses: Counter[str] = Counter()
    label_counts: Counter[str] = Counter()
    effect_counts: Counter[str] = Counter()
    events: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []

    for row_index, row in enumerate(_read_jsonl(proxy_path)):
        projection = str(row.get("message_projection_hash") or "")
        source_event_id = str(row.get("event_id") or stable_json_hash({"row_index": row_index, "row": row}))
        if not projection:
            status = "missing_message_projection"
            join_statuses[status] += 1
            unresolved.append(
                {
                    "source_event_id": source_event_id,
                    "proxy_row_index": row_index,
                    "status": status,
                    "candidate_cells": 0,
                    "reason": "historical row has no stable message projection join key",
                }
            )
            continue
        candidates = index.get(projection, ())
        if not candidates:
            status = "unmatched_message_projection"
        elif len(candidates) > 1:
            status = "ambiguous_message_projection"
        else:
            status = "joined_unique"
        join_statuses[status] += 1
        if status != "joined_unique":
            unresolved.append(
                {
                    "source_event_id": source_event_id,
                    "proxy_row_index": row_index,
                    "status": status,
                    "candidate_cells": len(candidates),
                    "reason": (
                        "no official turn has the recorded projection"
                        if not candidates
                        else "multiple official turns share the projection; assignment would be ambiguous"
                    ),
                }
            )
            continue

        turn = candidates[0]
        try:
            user_truth, injection_truth = ground_truth_calls_for_cell(
                ground_truth_payload,
                cell_ref=turn["cell_ref"],
            )
        except ValueError as exc:
            unresolved.append(
                {
                    "source_event_id": source_event_id,
                    "proxy_row_index": row_index,
                    "status": "ground_truth_cell_unavailable",
                    "candidate_cells": 1,
                    "cell_ref": turn["cell_ref"],
                    "reason": str(exc),
                }
            )
            continue

        mediation = row.get("tool_mediation")
        decisions = mediation.get("decisions") if isinstance(mediation, Mapping) else None
        if not isinstance(decisions, list):
            unresolved.append(
                {
                    "source_event_id": source_event_id,
                    "proxy_row_index": row_index,
                    "status": "missing_decisions",
                    "candidate_cells": 1,
                    "cell_ref": turn["cell_ref"],
                    "reason": "joined proxy row has no decision list",
                }
            )
            continue
        for decision_index, decision in enumerate(decisions):
            if not isinstance(decision, Mapping):
                continue
            arguments = decision.get("arguments")
            if not isinstance(arguments, Mapping):
                unresolved.append(
                    {
                        "source_event_id": source_event_id,
                        "proxy_row_index": row_index,
                        "decision_index": decision_index,
                        "status": "missing_call_arguments",
                        "candidate_cells": 1,
                        "cell_ref": turn["cell_ref"],
                        "reason": "historical decision retained argument keys but not values",
                    }
                )
                continue
            tool = str(decision.get("tool") or "")
            observed_digest = canonical_tool_call_digest(
                tool_name=tool,
                tool_schema_version="agentdojo-v1.2.2",
                arguments=arguments,
            )
            declared_digest = str(decision.get("call_digest") or observed_digest)
            if declared_digest != observed_digest:
                unresolved.append(
                    {
                        "source_event_id": source_event_id,
                        "proxy_row_index": row_index,
                        "decision_index": decision_index,
                        "status": "invalid_call_digest",
                        "candidate_cells": 1,
                        "cell_ref": turn["cell_ref"],
                        "reason": "decision digest does not bind the complete tool call",
                    }
                )
                continue
            enforced = bool(decision.get("enforced"))
            effect = (
                "blocked"
                if enforced
                else "executed"
                if observed_digest in turn["returned_call_digests"]
                else "proposed"
            )
            event_id = stable_json_hash(
                {
                    "source_event_id": source_event_id,
                    "decision_index": decision_index,
                    "call_digest": observed_digest,
                }
            )
            candidate = CandidateCall(
                event_id=event_id,
                tool_name=tool,
                arguments=arguments,
                effect=effect,
            )
            adjudication = adjudicate_candidate_call(
                candidate=candidate,
                user_ground_truth=user_truth,
                injection_ground_truth=injection_truth,
            )
            event = {
                "event_id": event_id,
                "source_event_id": source_event_id,
                "proxy_row_index": row_index,
                "decision_index": decision_index,
                "cell_ref": turn["cell_ref"],
                "turn_index": turn["turn_index"],
                "message_projection_hash": projection,
                "call_digest": observed_digest,
                "tool_name": tool,
                "arguments": dict(arguments),
                "decision_effect": str(decision.get("decision_effect") or "unknown"),
                "effect": effect,
                "official_outcome": turn["official_outcome"],
                "adjudication": adjudication.to_dict(),
            }
            events.append(event)
            label_counts[adjudication.label] += 1
            effect_counts[effect] += 1

    payload: dict[str, Any] = {
        "schema_version": JOIN_SCHEMA_VERSION,
        "summary": {
            "proxy_rows": sum(join_statuses.values()),
            "joined_events": len(events),
            "unresolved_records": len(unresolved),
            "join_statuses": dict(sorted(join_statuses.items())),
            "labels": dict(sorted(label_counts.items())),
            "effects": dict(sorted(effect_counts.items())),
        },
        "events": events,
        "unresolved": unresolved,
        "sources": {
            "proxy_log": {"name": proxy_path.name, "sha256": sha256_file(proxy_path, prefixed=True)},
            "official_traces": official_sources,
            "ground_truth_hash": ground_truth_payload.get("ground_truth_hash")
            or ground_truth_payload.get("artifact_hash"),
        },
        "claim_boundary": (
            "This post-hoc join uses a stable normalized-message projection, never timestamps. Ambiguous, "
            "missing, or digest-invalid rows remain unresolved. Labels compare proposed calls with native "
            "ground truth; AgentDojo retains authority over final utility and attack success."
        ),
    }
    payload["join_hash"] = stable_json_hash(payload)
    return payload


def export_agentdojo_event_join(
    *,
    output_dir: Path,
    proxy_log: Path,
    official_logdir: Path,
    ground_truth_path: Path,
) -> dict[str, Any]:
    try:
        ground_truth = json.loads(Path(ground_truth_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("invalid ground-truth artifact") from exc
    if not isinstance(ground_truth, dict):
        raise ValueError("ground-truth artifact must be an object")
    payload = join_agentdojo_events(
        proxy_log=proxy_log,
        official_logdir=official_logdir,
        ground_truth_payload=ground_truth,
    )
    root = Path(output_dir)
    root.mkdir(parents=True, exist_ok=True)
    artifact = write_json_artifact(root / "agentdojo_event_join.json", payload)
    secure_provider_artifact_tree(root)
    scan = scan_provider_artifact_tree(root)
    if scan["status"] != "pass":
        raise RuntimeError("AgentDojo event join failed artifact safety scan")
    return {
        "status": "joined" if payload["events"] else "no_claimable_event_joins",
        "summary": payload["summary"],
        "join_hash": payload["join_hash"],
        "artifact": str(artifact),
        "scan": scan,
    }


def _build_official_turn_index(
    root: Path,
) -> tuple[dict[str, tuple[dict[str, Any], ...]], list[dict[str, Any]]]:
    mutable: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    sources: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*.json")):
        try:
            trace = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(trace, Mapping) or not isinstance(trace.get("messages"), list):
            continue
        user_task_id = str(trace.get("user_task_id") or "")
        injection_task_id = str(trace.get("injection_task_id") or "")
        suite = str(trace.get("suite_name") or "")
        version = str(trace.get("benchmark_version") or "")
        if not all((user_task_id, injection_task_id, suite, version)):
            continue
        cell_ref = f"agentdojo:{version}:{suite}:{user_task_id}:{injection_task_id}"
        messages = trace["messages"]
        for turn_index, message in enumerate(messages):
            if not isinstance(message, Mapping) or message.get("role") != "assistant":
                continue
            prompt = build_mediation_prompt(
                messages=messages[:turn_index],
                agent="projection-only",
                policy_variant="V1",
            )
            returned_digests = tuple(
                _tool_call_digests(message.get("tool_calls"))
            )
            mutable[prompt.manifest["message_projection_hash"]].append(
                {
                    "cell_ref": cell_ref,
                    "turn_index": turn_index,
                    "returned_call_digests": returned_digests,
                    "official_outcome": {
                        "utility_success": bool(trace.get("utility")),
                        "attack_success": bool(trace.get("security")),
                    },
                }
            )
        sources.append({"name": path.name, "sha256": sha256_file(path, prefixed=True)})
    return ({key: tuple(value) for key, value in mutable.items()}, sources)


def _tool_call_digests(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    digests: list[str] = []
    for call in value:
        if not isinstance(call, Mapping) or not isinstance(call.get("args"), Mapping):
            continue
        digests.append(
            canonical_tool_call_digest(
                tool_name=str(call.get("function") or ""),
                tool_schema_version="agentdojo-v1.2.2",
                arguments=call["args"],
            )
        )
    return digests


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid proxy JSONL at {path.name}:{line_number}") from exc
        if not isinstance(row, dict):
            raise ValueError(f"proxy row must be an object at {path.name}:{line_number}")
        rows.append(row)
    return rows


__all__ = ["export_agentdojo_event_join", "join_agentdojo_events"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Join Invart mediation events to AgentDojo cells.")
    parser.add_argument("--proxy-log", type=Path, required=True)
    parser.add_argument("--official-logdir", type=Path, required=True)
    parser.add_argument("--ground-truth", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    result = export_agentdojo_event_join(
        output_dir=args.output_dir,
        proxy_log=args.proxy_log,
        official_logdir=args.official_logdir,
        ground_truth_path=args.ground_truth,
    )
    print(stable_json_dumps(result), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
