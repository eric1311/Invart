from __future__ import annotations

import pytest

from invart.evaluation.real_agent_benchmark.annotation_io import (
    build_blinded_annotation_packet,
    merge_annotation_submissions,
)
from invart.evaluation.real_agent_benchmark.mediation_adjudication import (
    AdjudicationResult,
    CandidateCall,
)


def _records() -> list[tuple[CandidateCall, AdjudicationResult]]:
    result = AdjudicationResult(
        label="ambiguous",
        evidence_strength="annotation_required",
        reason_code="same_tool_nonmatching_arguments",
        user_alignment="same_tool_nonmatching_arguments",
        attack_alignment="same_tool_nonmatching_arguments",
        effect="blocked",
        matched_user_indices=(),
        matched_injection_indices=(),
    )
    return [
        (
            CandidateCall(
                event_id="private-event-1",
                tool_name="send_direct_message",
                arguments={"recipient": "Dora", "body": "private body"},
                effect="blocked",
            ),
            result,
        ),
        (
            CandidateCall(
                event_id="private-event-2",
                tool_name="post_webpage",
                arguments={"url": "https://example.test", "content": "private content"},
                effect="proposed",
            ),
            result,
        ),
    ]


def test_blinded_packet_separates_private_linkage_and_hashes_argument_values() -> None:
    artifact = build_blinded_annotation_packet(_records(), salt="secret-salt")
    packet_text = str(artifact["packet"])

    assert "private-event" not in packet_text
    assert "private body" not in packet_text
    assert "private content" not in packet_text
    assert len(artifact["packet"]["rows"]) == 2
    assert set(artifact["private_linkage"].values()) == {"private-event-1", "private-event-2"}
    assert artifact["packet"]["packet_hash"].startswith("sha256:")


def test_two_annotator_disagreement_is_retained_until_resolution() -> None:
    artifact = build_blinded_annotation_packet(_records(), salt="secret-salt")
    ids = [row["annotation_id"] for row in artifact["packet"]["rows"]]
    first = {
        "annotator_id": "ann-a",
        "rows": [
            {"annotation_id": ids[0], "label": "harmful", "reason": "attack target"},
            {"annotation_id": ids[1], "label": "benign", "reason": "user aligned"},
        ],
    }
    second = {
        "annotator_id": "ann-b",
        "rows": [
            {"annotation_id": ids[0], "label": "benign", "reason": "authorized"},
            {"annotation_id": ids[1], "label": "benign", "reason": "user aligned"},
        ],
    }

    unresolved = merge_annotation_submissions(packet=artifact["packet"], first=first, second=second)
    assert unresolved["agreement"]["agreements"] == 1
    assert unresolved["agreement"]["disagreements"] == 1
    assert unresolved["rows"][0]["final_label"] is None
    assert unresolved["rows"][0]["pre_resolution_labels"] == {
        "ann-a": "harmful",
        "ann-b": "benign",
    }

    resolved = merge_annotation_submissions(
        packet=artifact["packet"],
        first=first,
        second=second,
        resolutions={ids[0]: {"label": "harmful", "reason": "senior adjudication"}},
    )
    assert resolved["rows"][0]["final_label"] == "harmful"
    assert resolved["rows"][0]["resolution"]["reason"] == "senior adjudication"
    assert resolved["agreement"] == unresolved["agreement"]


def test_submission_must_cover_packet_exactly_once() -> None:
    artifact = build_blinded_annotation_packet(_records(), salt="secret-salt")
    annotation_id = artifact["packet"]["rows"][0]["annotation_id"]
    bad = {
        "annotator_id": "ann-a",
        "rows": [
            {"annotation_id": annotation_id, "label": "harmful", "reason": "one"},
        ],
    }

    with pytest.raises(ValueError, match="exactly cover"):
        merge_annotation_submissions(packet=artifact["packet"], first=bad, second=bad)
