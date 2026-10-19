"""Adversarial failures must not expose values or escape session cleanup."""

import re
import traceback
from copy import deepcopy

import pytest
from security_assertions import assert_no_raw_sensitive_values

from trustgate import (
    AuditEventType,
    DetectionUnavailableError,
    SensitiveEntity,
    SessionClosedError,
    ToolCall,
    ToolResultSanitizationError,
    TrustGateError,
    TrustSession,
)

NAMES = ("Prior Person", "Alice Waters", "Rowan Vega")
RAW_ERROR = "RAW_RESOLVER_DETAIL_DO_NOT_LEAK"


class Detector:
    def detect(self, text: str) -> tuple[SensitiveEntity, ...]:
        return tuple(
            SensitiveEntity(entity_type="PERSON", start=match.start(), end=match.end(), score=1)
            for match in re.finditer("|".join(re.escape(name) for name in NAMES), text)
        )


def _session(transcript: bool) -> TrustSession:
    return TrustSession(detector=Detector(), transcript=transcript, aliases={"Rory": ["Rowan"]})


def _assert_safe(value: object) -> None:
    assert_no_raw_sensitive_values(
        value, *NAMES, *(name.casefold() for name in NAMES), RAW_ERROR, "Rory", "rory"
    )


def _assert_cleared(session: TrustSession, tokens: tuple[str, ...]) -> None:
    assert session.is_closed
    vault = session._vault
    assert vault._entries_by_token == vault._tokens_by_value == vault._tokens_by_identity == {}
    assert all(vault._registry.owner_for(token) is None for token in tokens)
    resolver = session._entity_resolver
    assert resolver._entities_by_id == resolver._identities_by_id == {}
    assert resolver._unconfirmed_by_surface_form == {}
    assert resolver._mention_states == []
    assert resolver._alias_resolver._aliases == frozenset()


@pytest.mark.parametrize("transcript", [False, True])
@pytest.mark.parametrize("stage", ["before_registration", "after_registration"])
@pytest.mark.parametrize("boundary", ["input", "nested_value", "nested_key"])
@pytest.mark.parametrize("processed", [False, True])
def test_resolver_error_drops_raw_chains_and_cleans_partial_state(
    transcript, stage, boundary, processed, monkeypatch, caplog
):
    session = _session(transcript)
    original = session._entity_resolver.resolve_person
    issued = []

    def failing_resolver(**kwargs):
        if kwargs["surface_form"] == "Rowan Vega":
            if stage == "after_registration":
                original(**kwargs)
            issued.extend(session._vault._entries_by_token)
            try:
                raise ValueError(RAW_ERROR)
            except ValueError as cause:
                raise RuntimeError(kwargs["surface_form"]) from cause
        return original(**kwargs)

    monkeypatch.setattr(session._entity_resolver, "resolve_person", failing_resolver)
    if boundary == "input":
        payload = "Alice Waters then Rowan Vega" if processed else "Rowan Vega"
    elif boundary == "nested_value":
        payload = (
            {"items": ["Alice Waters", {"owner": "Rowan Vega"}]}
            if processed
            else [{"owner": "Rowan Vega"}]
        )
    else:
        payload = (
            {"Alice Waters": "first", "nested": {"Rowan Vega": "last"}}
            if processed
            else {"nested": {"Rowan Vega": "last"}}
        )
    unchanged = deepcopy(payload)
    returned = []
    with pytest.raises(TrustGateError) as error:
        with session:
            session.sanitize("Prior Person")
            before = session.transcript
            if boundary == "input":
                returned.append(session.sanitize(payload))
            else:
                returned.append(session.sanitize_tool_result(payload))
    assert type(error.value).__name__ == "EntityResolutionError"
    assert returned == []
    assert payload == unchanged
    assert error.value.__cause__ is error.value.__context__ is None
    assert session.transcript == before
    _assert_cleared(session, tuple(issued))
    assert bool(issued)
    if processed:
        assert len(issued) == 2  # Previous operation plus earlier item of the failed operation.
    if boundary != "input":
        failed = session._audit_sink.events[-2]
        assert failed.event_type is AuditEventType.TOOL_RESULT_SANITIZATION_FAILED
        assert failed.failure_reason.value == "entity_resolution_unavailable"
    assert session._audit_sink.events[-1].event_type is AuditEventType.SESSION_CLOSED
    _assert_safe(
        (
            error.value,
            "".join(traceback.format_exception(error.value)),
            session.transcript,
            session._audit_sink.events,
            caplog.text,
        )
    )


def test_explicit_session_failure_retains_lifecycle_until_caller_closes(monkeypatch):
    session = _session(True)
    token = session.sanitize("Prior Person")
    before = session.transcript

    def fail(**kwargs):
        raise RuntimeError(RAW_ERROR)

    monkeypatch.setattr(session._entity_resolver, "resolve_person", fail)
    with pytest.raises(TrustGateError) as error:
        session.sanitize("Rowan Vega")
    assert not session.is_closed
    assert session.transcript == before
    session.close()
    _assert_cleared(session, (token,))
    with pytest.raises(SessionClosedError):
        session.rehydrate_for_tool(ToolCall(name="lookup", arguments={"person": token}))
    _assert_safe((error.value, session.transcript, session._audit_sink.events))


@pytest.mark.parametrize("kind", ["list", "dict", "cycle"])
@pytest.mark.parametrize("transcript", [False, True])
def test_unexpected_structure_errors_are_static_without_partial_outputs(kind, transcript, caplog):
    class FailingList(list):
        def __iter__(self):
            yield "Alice Waters"
            raise RuntimeError(RAW_ERROR)

    class FailingDict(dict):
        def items(self):
            yield "Alice Waters", "first"
            raise RuntimeError(RAW_ERROR)

    if kind == "list":
        payload = FailingList(["Alice Waters"])
    elif kind == "dict":
        payload = FailingDict({"Alice Waters": "first"})
    else:
        payload = ["Alice Waters"]
        payload.append(payload)
    session = _session(transcript)
    with pytest.raises(ToolResultSanitizationError) as error:
        with session:
            before = session.transcript
            session.sanitize_tool_result(payload)
    assert error.value.__cause__ is error.value.__context__ is None
    assert session.transcript == before
    assert len(payload) == (2 if kind == "cycle" else 1)
    if kind == "cycle":
        assert payload[1] is payload
    _assert_cleared(session, ())
    failed = session._audit_sink.events[-2]
    assert failed.event_type is AuditEventType.TOOL_RESULT_SANITIZATION_FAILED
    assert failed.failure_reason.value == "unsafe_result_structure"
    _assert_safe((error.value, session._audit_sink.events, session.transcript, caplog.text))


@pytest.mark.parametrize("boundary", ["input", "result"])
@pytest.mark.parametrize("bad_result", [None, ("RAW_RESOLVER_DETAIL_DO_NOT_LEAK",)])
def test_malformed_detector_output_fails_safely(boundary, bad_result):
    class BadDetector:
        def detect(self, text):
            return bad_result

    session = TrustSession(detector=BadDetector(), transcript=True)
    with pytest.raises(DetectionUnavailableError) as error:
        with session:
            if boundary == "input":
                session.sanitize(RAW_ERROR)
            else:
                session.sanitize_tool_result({"owner": RAW_ERROR})
    assert error.value.__cause__ is error.value.__context__ is None
    assert session.transcript == ()
    _assert_cleared(session, ())
    _assert_safe((error.value, session._audit_sink.events))
