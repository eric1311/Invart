from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence

from invart.core.artifacts import stable_json_hash

from .mediation_reviewer import canonical_tool_call_digest


CONTINUATION_SCHEMA_VERSION = "invart.mediation_continuation.v0.1"
_FUNCTION_CALL_RE = re.compile(
    r"<function=(?P<tool>[A-Za-z0-9_.:-]+)>(?P<arguments>\{.*?\})</function>",
    flags=re.DOTALL,
)


@dataclass(frozen=True)
class ProposedCallDecision:
    effect: str
    reason_code: str
    evidence_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        effect = str(self.effect or "").strip().lower()
        if effect not in {"allow", "deny", "ask"}:
            raise ValueError("effect must be allow, deny, or ask")
        object.__setattr__(self, "effect", effect)
        reason = str(self.reason_code or "").strip()
        if not reason:
            raise ValueError("reason_code must be nonempty")
        object.__setattr__(self, "reason_code", reason)
        refs = tuple(sorted({str(ref).strip() for ref in self.evidence_refs if str(ref).strip()}))
        object.__setattr__(self, "evidence_refs", refs)


@dataclass(frozen=True)
class ContinuationAttempt:
    attempt_id: str
    parent_attempt_id: str | None
    proposal_hash: str
    call_digests: tuple[str, ...]
    decision_effects: tuple[str, ...]
    outcome: str
    reason_code: str
    executed_call_digests: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "attempt_id": self.attempt_id,
            "parent_attempt_id": self.parent_attempt_id,
            "proposal_hash": self.proposal_hash,
            "call_digests": list(self.call_digests),
            "decision_effects": list(self.decision_effects),
            "outcome": self.outcome,
            "reason_code": self.reason_code,
            "executed_call_digests": list(self.executed_call_digests),
        }


@dataclass(frozen=True)
class ContinuationResult:
    status: str
    response_text: str
    authorized_call_digest: str | None
    lineage: tuple[ContinuationAttempt, ...]
    schema_version: str = CONTINUATION_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "status": self.status,
            "response_text": self.response_text,
            "authorized_call_digest": self.authorized_call_digest,
            "lineage": [item.to_dict() for item in self.lineage],
            "claim_boundary": (
                "Continuation authorizes at most one complete call digest for the official runner. "
                "It does not execute tools or fabricate official task success."
            ),
        }


def run_bounded_continuation(
    *,
    initial_response: str,
    original_messages: Sequence[Mapping[str, Any]],
    original_task: str,
    decide_call: Callable[[str, dict[str, Any]], ProposedCallDecision],
    complete: Callable[[list[dict[str, Any]]], str],
    max_replans: int,
    tool_schema_version: str = "agentdojo-v1.2.2",
) -> ContinuationResult:
    if max_replans < 0:
        raise ValueError("max_replans cannot be negative")
    task = str(original_task or "").strip()
    if not task:
        raise ValueError("original_task must be nonempty")
    response = str(initial_response)
    lineage: list[ContinuationAttempt] = []
    policy_results: list[dict[str, Any]] = []

    for attempt_index in range(max_replans + 1):
        attempt_id = f"continuation-{attempt_index}"
        parent_id = f"continuation-{attempt_index - 1}" if attempt_index else None
        calls = _parse_function_calls(response)
        malformed = "<function=" in response and not calls
        call_digests = tuple(
            canonical_tool_call_digest(
                tool_name=call["tool"],
                tool_schema_version=tool_schema_version,
                arguments=call["arguments"],
            )
            for call in calls
        )
        decisions = tuple(decide_call(call["tool"], call["arguments"]) for call in calls)

        if not calls and not malformed:
            lineage.append(
                ContinuationAttempt(
                    attempt_id,
                    parent_id,
                    stable_json_hash({"response": response}),
                    (),
                    (),
                    "safe_final_answer",
                    "no_tool_call",
                )
            )
            return ContinuationResult("safe_final_answer", response, None, tuple(lineage))

        if malformed:
            reason = "unparseable_tool_call"
            effects: tuple[str, ...] = ()
        elif len(calls) != 1:
            reason = "atomic_multiple_calls"
            effects = tuple(item.effect for item in decisions)
        elif decisions[0].effect == "allow":
            lineage.append(
                ContinuationAttempt(
                    attempt_id,
                    parent_id,
                    stable_json_hash({"response": response}),
                    call_digests,
                    ("allow",),
                    "authorized_call",
                    decisions[0].reason_code,
                )
            )
            return ContinuationResult(
                "authorized_call",
                response,
                call_digests[0],
                tuple(lineage),
            )
        else:
            reason = decisions[0].reason_code
            effects = (decisions[0].effect,)

        lineage.append(
            ContinuationAttempt(
                attempt_id,
                parent_id,
                stable_json_hash({"response": response}),
                call_digests,
                effects,
                "replan_required",
                reason,
            )
        )
        if attempt_index >= max_replans:
            return ContinuationResult(
                "budget_exhausted",
                (
                    "I could not find an authorized alternative within the policy continuation budget. "
                    "No denied or approval-routed tool call was executed."
                ),
                None,
                tuple(lineage),
            )
        policy_result = {
            "type": "invart_policy_result",
            "attempt_id": attempt_id,
            "decision_effects": list(effects),
            "reason_code": reason,
            "denied_call_digests": list(call_digests),
            "original_task_reminder": task,
            "instruction": "Continue the original task without the denied or approval-routed action.",
        }
        policy_results.append(policy_result)
        continuation_messages = [dict(message) for message in original_messages]
        continuation_messages.append({"role": "assistant", "content": response})
        continuation_messages.extend(
            {"role": "system", "content": json.dumps(item, sort_keys=True)}
            for item in policy_results
        )
        response = str(complete(continuation_messages))

    raise AssertionError("unreachable continuation state")


def verify_execution_receipt(
    *,
    authorized_digest: str | None,
    tool_name: str,
    tool_schema_version: str,
    arguments: Mapping[str, Any],
) -> dict[str, Any]:
    observed = canonical_tool_call_digest(
        tool_name=tool_name,
        tool_schema_version=tool_schema_version,
        arguments=arguments,
    )
    valid = bool(authorized_digest) and observed == authorized_digest
    return {
        "schema_version": "invart.mediation_execution_receipt.v0.1",
        "status": "valid_execution_digest" if valid else "invalid_execution_digest",
        "execution_allowed": valid,
        "authorized_digest": authorized_digest,
        "observed_digest": observed,
    }


def _parse_function_calls(response_text: str) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []
    for match in _FUNCTION_CALL_RE.finditer(response_text):
        try:
            arguments = json.loads(match.group("arguments"))
        except json.JSONDecodeError:
            continue
        if not isinstance(arguments, dict):
            continue
        calls.append({"tool": match.group("tool"), "arguments": arguments})
    return calls


__all__ = [
    "ContinuationAttempt",
    "ContinuationResult",
    "ProposedCallDecision",
    "run_bounded_continuation",
    "verify_execution_receipt",
]
