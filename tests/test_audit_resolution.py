"""Safe per-occurrence resolution evidence at the audit boundary."""

from copy import deepcopy

import pytest
from security_assertions import assert_no_raw_sensitive_values

from trustgate import (
    AuditEvent,
    AuditEventType,
    AuditResolution,
    DataReleaseDenied,
    DetectionUnavailableError,
    InMemoryAuditSink,
    ModelValidationError,
    SensitiveEntity,
    ToolCall,
    ToolResultSanitizationError,
    TrustPolicy,
    TrustSession,
)
from trustgate import (
    EntityResolutionReason as Reason,
)
from trustgate import (
    EntityResolutionState as State,
)
from trustgate.audit import audit_identifier

NAMES = (
    "Elizabeth Taylor",
    "Beth Taylor",
    "Elizabeth",
    "Mr Taylor",
    "Joseph Taylor",
    "Joanna Taylor",
    "Jo Taylor",
    "Nobody",
)


class PersonDetector:
    def detect(self, text: str) -> tuple[SensitiveEntity, ...]:
        if text == "Elizabeth Taylor met Elizabeth":
            return tuple(
                SensitiveEntity(entity_type="PERSON", start=start, end=end, score=1)
                for start, end in ((21, 30), (0, 16))
            )
        if text in NAMES:
            return (SensitiveEntity(entity_type="PERSON", start=0, end=len(text), score=1),)
        if text == "12345678":
            return (SensitiveEntity(entity_type="ACCOUNT_NUMBER", start=0, end=len(text), score=1),)
        return ()


def _session() -> TrustSession:
    return TrustSession(
        detector=PersonDetector(),
        aliases={"Beth": ["Elizabeth"]},
        policy=TrustPolicy(
            version=1,
            data_policies={
                "PERSON": {
                    "external_llm": "tokenize",
                    "destinations": {"lookup_person": "allow", "update_person": "allow"},
                }
            },
        ),
    )


def _assert_safe(value: object) -> None:
    assert_no_raw_sensitive_values(
        value, *NAMES, *(name.casefold() for name in NAMES), "Beth", "beth", "12345678"
    )


@pytest.mark.parametrize(
    ("known", "mention", "state", "reason"),
    [
        ([], "Elizabeth Taylor", State.EXACT, Reason.EXACT_NORMALIZED_FULL_NAME),
        (["Elizabeth Taylor"], "Elizabeth Taylor", State.EXACT, Reason.EXACT_NORMALIZED_FULL_NAME),
        (["Elizabeth Taylor"], "Elizabeth", State.UNIQUE_PARTIAL, Reason.FIRST_NAME_MATCH),
        (["Elizabeth Taylor"], "Mr Taylor", State.UNIQUE_PARTIAL, Reason.LAST_NAME_MATCH),
        (["Elizabeth Taylor"], "Beth Taylor", State.UNIQUE_ALIAS, Reason.UNIQUE_ALIAS_MATCH),
        ([], "Nobody", State.UNRESOLVED, Reason.NO_CANDIDATES),
        (
            ["Joanna Taylor", "Joseph Taylor"],
            "Jo Taylor",
            State.AMBIGUOUS,
            Reason.AMBIGUOUS_CANDIDATES,
        ),
    ],
)
def test_sanitization_audits_safe_resolution_evidence(known, mention, state, reason, caplog):
    with _session() as session:
        for name in known:
            session.sanitize(name)
        token = session.sanitize(mention)
        event = session._audit_sink.events[-1]
        assert event.event_type is AuditEventType.VALUE_SANITIZED
        assert event.resolutions == (
            AuditResolution(token=audit_identifier(token), state=state, reason=reason),
        )
        assert event.resolutions[0].token in event.tokens
    _assert_safe((token, session._audit_sink.events, caplog.text))
    restored = AuditEvent.model_validate_json(event.model_dump_json())
    assert restored == event
    assert set(restored.resolutions[0].model_dump()) == {"token", "state", "reason"}


def test_same_text_keeps_occurrence_order_and_multiple_reasons_for_one_token():
    with _session() as session:
        safe = session.sanitize("Elizabeth Taylor met Elizabeth")
        event = session._audit_sink.events[-1]
        assert [item.state for item in event.resolutions] == [State.EXACT, State.UNIQUE_PARTIAL]
        assert [item.reason for item in event.resolutions] == [
            Reason.EXACT_NORMALIZED_FULL_NAME,
            Reason.FIRST_NAME_MATCH,
        ]
        assert len(event.tokens) == 1
        assert all(item.token == event.tokens[0] for item in event.resolutions)
        first, second = safe.split(" met ")
        assert first == second
    _assert_safe((safe, session._audit_sink.events))


def test_nested_result_audits_each_occurrence_without_history_or_input_mutation():
    with _session() as session:
        token = session.sanitize("Elizabeth Taylor")
        previous = session._audit_sink.events[-1]
        result = {"Mr Taylor": ["Beth Taylor", {"owner": "Elizabeth Taylor"}]}
        original = deepcopy(result)
        safe = session.sanitize_tool_result(result)
        assert result == original
        assert safe == {token: [token, {"owner": token}]}
        event = session._audit_sink.events[-1]
        assert [item.state for item in event.resolutions] == [
            State.UNIQUE_PARTIAL,
            State.UNIQUE_ALIAS,
            State.EXACT,
        ]
        assert all(item.token == audit_identifier(token) for item in event.resolutions)
        assert len(event.tokens) == 1
        assert previous.resolutions[0].state is State.EXACT
        session.sanitize_tool_result({"empty": ["", None, {}, []]})
        assert session._audit_sink.events[-1].resolutions == ()
    _assert_safe((safe, session._audit_sink.events))


def test_non_person_and_lifecycle_events_have_no_resolution_evidence():
    with _session() as session:
        session.sanitize("12345678")
        session.sanitize("plain text")
    assert all(event.resolutions == () for event in session._audit_sink.events)
    _assert_safe(session._audit_sink.events)


@pytest.mark.parametrize("destination", ["lookup_person", "update_person"])
def test_audit_metadata_preserves_canonical_release_and_default_deny(destination, caplog):
    with _session() as session:
        canonical = session.sanitize("Elizabeth Taylor")
        alias = session.sanitize("Beth Taylor")
        assert alias == canonical
        call = ToolCall(name=destination, arguments={"owner": alias})
        original = call.model_dump()
        assert session.rehydrate_for_tool(call) == {"owner": "Elizabeth Taylor"}
        assert call.model_dump() == original
        allowed = session._audit_sink.events[-1]
        assert allowed.event_type is AuditEventType.TOOL_RELEASE_ALLOWED
        assert allowed.resolutions == ()
        with pytest.raises(DataReleaseDenied) as error:
            session.rehydrate_for_tool(ToolCall(name="unlisted", arguments={"owner": alias}))
        assert session._audit_sink.events[-1].event_type is AuditEventType.TOOL_RELEASE_DENIED
    _assert_safe((session._audit_sink.events, caplog.text, error.value))


def test_uncertain_resolution_audit_is_not_retroactively_promoted_or_shared():
    sink = InMemoryAuditSink()
    with (
        TrustSession(detector=PersonDetector(), audit_sink=sink) as first,
        TrustSession(detector=PersonDetector(), audit_sink=sink) as second,
    ):
        uncertain = first.sanitize("Elizabeth")
        original = sink.events[-1]
        canonical = first.sanitize("Elizabeth Taylor")
        assert first.sanitize("Elizabeth") == uncertain != canonical
        assert sink.events[-1].resolutions == original.resolutions
        assert original.resolutions[0].state is State.UNRESOLVED
        second_token = second.sanitize("Elizabeth")
        assert second_token != uncertain
        assert sink.events[-1].resolutions[0].token == audit_identifier(second_token)
        assert sink.events[-1].session_id == second.session_id
    _assert_safe(sink.events)


@pytest.mark.parametrize("failure", ["collision", "detector"])
def test_failed_result_records_only_safe_processed_evidence(failure, caplog):
    class FailingDetector(PersonDetector):
        def detect(self, text):
            if text == "RAW_FAILURE_DO_NOT_LEAK":
                raise RuntimeError(text)
            return super().detect(text)

    with _session() as session:
        token = session.sanitize("Elizabeth Taylor")
        session._detector = FailingDetector()
        if failure == "collision":
            result = {"Elizabeth Taylor": "first", "Beth Taylor": "second"}
            expected = ToolResultSanitizationError
            expected_states = [State.EXACT, State.UNIQUE_ALIAS]
        else:
            result = ["Beth Taylor", "RAW_FAILURE_DO_NOT_LEAK"]
            expected = DetectionUnavailableError
            expected_states = [State.UNIQUE_ALIAS]
        original = deepcopy(result)
        with pytest.raises(expected) as error:
            session.sanitize_tool_result(result)
        assert result == original
        event = session._audit_sink.events[-1]
        assert event.event_type is AuditEventType.TOOL_RESULT_SANITIZATION_FAILED
        assert [item.state for item in event.resolutions] == expected_states
        assert all(item.token == audit_identifier(token) for item in event.resolutions)
        assert error.value.__context__ is error.value.__cause__ is None
    _assert_safe((session._audit_sink.events, error.value, caplog.text))
    assert_no_raw_sensitive_values(
        (session._audit_sink.events, error.value, caplog.text), "RAW_FAILURE_DO_NOT_LEAK"
    )


@pytest.mark.parametrize(
    "update",
    [
        {"token": "RAW_INVALID_DO_NOT_LEAK"},
        {"state": "RAW_INVALID_DO_NOT_LEAK"},
        {"reason": "RAW_INVALID_DO_NOT_LEAK"},
        {"state": "ambiguous"},
        {"surface_form": "RAW_INVALID_DO_NOT_LEAK"},
    ],
)
@pytest.mark.parametrize("entry", ["constructor", "json", "construct", "copy", "event"])
def test_resolution_model_rejects_unsafe_or_inconsistent_metadata(update, entry):
    import json

    valid = {
        "token": audit_identifier("[PERSON_1]"),
        "state": "exact",
        "reason": "exact_normalized_full_name",
    }
    invalid = valid | update
    with pytest.raises(ModelValidationError) as error:
        if entry == "constructor":
            AuditResolution(**invalid)
        elif entry == "json":
            AuditResolution.model_validate_json(json.dumps(invalid))
        elif entry == "construct":
            AuditResolution.model_construct(**invalid)
        elif entry == "copy":
            AuditResolution(**valid).model_copy(update=update)
        else:
            AuditEvent(
                event_type=AuditEventType.VALUE_SANITIZED,
                session_id="safe-session",
                resolutions=[invalid],
            )
    assert error.value.__cause__ is error.value.__context__ is None
    assert_no_raw_sensitive_values(error.value, "RAW_INVALID_DO_NOT_LEAK")
