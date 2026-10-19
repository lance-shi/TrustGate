"""Deterministic span conflicts and empty/shared JSON boundary regressions."""

import re
from copy import deepcopy
from itertools import permutations

import pytest
from security_assertions import assert_no_raw_sensitive_values

from trustgate import (
    CrossSessionTokenError,
    DataReleaseDenied,
    SensitiveEntity,
    ToolCall,
    TrustPolicy,
    TrustSession,
)

RAW_VALUE = "123456789012"


class Detector:
    def __init__(self, spans=()):
        self.spans = spans

    def detect(self, text):
        return self.spans if text == RAW_VALUE else ()


@pytest.mark.parametrize(
    ("spans", "kind"),
    [
        ([("PERSON", 0, 12, 0.9), ("ACCOUNT_NUMBER", 0, 12, 0.9)], "PERSON"),
        ([("ACCOUNT_NUMBER", 0, 12, 0.4), ("PERSON", 2, 6, 0.9)], "PERSON"),
        (
            [("ACCOUNT_NUMBER", 0, 5, 0.9), ("EMAIL_ADDRESS", 4, 9, 0.8), ("PERSON", 8, 12, 0.7)],
            "ACCOUNT_NUMBER",
        ),
        ([("PERSON", 0, 12, 0.9), ("PERSON", 0, 12, 0.9)], "PERSON"),
        ([("ACCOUNT_NUMBER", 0, 12, 0.9), ("PERSON", 2, 8, 0.9)], "ACCOUNT_NUMBER"),
    ],
    ids=["type-tie", "containment", "chained-overlap", "duplicate", "length-tie"],
)
@pytest.mark.parametrize("transcript", [False, True])
@pytest.mark.parametrize("boundary", ["input", "result"])
def test_conflict_replacement_is_order_independent_and_keeps_release_boundary(
    spans, kind, transcript, boundary, caplog
):
    policy = TrustPolicy(
        version=1,
        data_policies={
            kind: {
                "external_llm": "tokenize",
                "destinations": {"read_value": "allow", "write_value": "allow"},
            }
        },
    )
    for order in permutations(spans):
        entities = tuple(
            SensitiveEntity(entity_type=entity_type, start=start, end=end, score=score)
            for entity_type, start, end, score in order
        )
        with TrustSession(
            detector=Detector(entities), policy=policy, transcript=transcript
        ) as session:
            raw = {"items": [RAW_VALUE, {"again": RAW_VALUE}]}
            original = deepcopy(raw)
            if boundary == "input":
                token = session.sanitize(RAW_VALUE)
            else:
                safe = session.sanitize_tool_result(raw)
                token = safe["items"][0]
                assert safe["items"][1]["again"] == token
                assert raw == original
            assert re.fullmatch(rf"\[{kind}_[1-9][0-9]*\]", token)
            assert session.sanitize(RAW_VALUE) == token
            before = session.transcript
            for destination in ("read_value", "write_value"):
                call = ToolCall(name=destination, arguments={"value": token})
                assert session.rehydrate_for_tool(call) == {"value": RAW_VALUE}
                assert call.arguments == {"value": token}
            with pytest.raises(DataReleaseDenied):
                session.rehydrate_for_tool(ToolCall(name="unlisted", arguments={"value": token}))
            with TrustSession(policy=policy, transcript=transcript) as other:
                with pytest.raises(CrossSessionTokenError):
                    other.rehydrate_for_tool(
                        ToolCall(name="read_value", arguments={"value": token})
                    )
                assert other.transcript == ()
            assert session.transcript == before
            assert_no_raw_sensitive_values(
                (token, session.transcript, session._audit_sink.events, caplog.text), RAW_VALUE
            )


@pytest.mark.parametrize("transcript", [False, True])
@pytest.mark.parametrize("value", ["", None, [], {}, {"nested": [[], {}, "", None]}])
def test_empty_results_do_not_create_vault_or_resolution_state(value, transcript):
    with TrustSession(detector=Detector(), transcript=transcript) as session:
        assert session.sanitize("") == ""
        assert session.sanitize_tool_result(value) == value
        assert session._vault._entries_by_token == {}
        assert session._entity_resolver._mention_states == []
        assert all(event.tokens == event.resolutions == () for event in session._audit_sink.events)
        assert len(session.transcript) == (2 if transcript else 0)


def test_shared_container_is_copied_without_being_mistaken_for_cycle():
    entity = SensitiveEntity(entity_type="ACCOUNT_NUMBER", start=0, end=12, score=1)
    shared = [RAW_VALUE]
    result = {"left": shared, "right": shared}
    with TrustSession(detector=Detector((entity,)), transcript=True) as session:
        safe = session.sanitize_tool_result(result)
        assert safe["left"] == safe["right"]
        assert safe["left"] is not safe["right"]
        assert result["left"] is result["right"] is shared
        assert shared == [RAW_VALUE]
        assert_no_raw_sensitive_values(
            (safe, session.transcript, session._audit_sink.events), RAW_VALUE
        )
