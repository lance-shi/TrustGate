"""Fault injection at diagnostic and mutable JSON boundaries."""

import traceback
from collections.abc import Iterator
from contextlib import contextmanager

import pytest
from security_assertions import assert_no_raw_sensitive_values

from trustgate import (
    AuditEvent,
    AuditEventType,
    DataReleaseRequest,
    FeatureUnavailableError,
    InMemoryAuditSink,
    ModelValidationError,
    PolicyValidationError,
    SensitiveEntity,
    ToolCall,
    ToolResultSanitizationError,
    TrustGate,
    TrustGateError,
    TrustPolicy,
    TrustSession,
    UnknownTokenError,
)

RAW = "DIAGNOSTIC_SECRET_Adversarial_Fixture"
PERSON = "Elizabeth Fixture"


class Detector:
    def detect(self, text: str) -> tuple[SensitiveEntity, ...]:
        if text not in (RAW, PERSON):
            return ()
        return (
            SensitiveEntity(
                entity_type="PERSON" if text == PERSON else "ACCOUNT_NUMBER",
                start=0,
                end=len(text),
                score=1,
            ),
        )


class RaisingSink(InMemoryAuditSink):
    def __init__(self) -> None:
        super().__init__()
        self.fail_on: set[AuditEventType] = set()

    def record(self, event: AuditEvent) -> None:
        super().record(event)
        if event.event_type in self.fail_on:
            try:
                raise ValueError(RAW)
            except ValueError as cause:
                raise RuntimeError(PERSON) from cause


def _policy(destination: str = "lookup") -> TrustPolicy:
    return TrustPolicy(
        version=1,
        data_policies={
            kind: {
                "external_llm": "tokenize",
                "destinations": {destination: "allow", "update": "allow"},
            }
            for kind in ("PERSON", "ACCOUNT_NUMBER")
        },
    )


@contextmanager
def _session(transcript: bool = True) -> Iterator[tuple[TrustSession, RaisingSink]]:
    sink = RaisingSink()
    session = TrustSession(
        detector=Detector(),
        policy=_policy(),
        audit_sink=sink,
        aliases={"Beth": ["Elizabeth"]},
        transcript=transcript,
    )
    try:
        yield session, sink
    finally:
        # A test may leave close-event injection enabled after asserting its failure.
        sink.fail_on.clear()
        session.close()


def _safe(error, session, sink, caplog, capsys):
    captured = capsys.readouterr()
    assert error.__cause__ is error.__context__ is None
    assert_no_raw_sensitive_values(
        (
            error,
            "".join(traceback.format_exception(error)),
            [event.model_dump_json() for event in sink.events],
            session.transcript,
            caplog.text,
            captured.out,
            captured.err,
        ),
        RAW,
        PERSON,
        PERSON.casefold(),
        "Beth",
        "beth",
        "Elizabeth",
        "elizabeth",
    )


def _cleared(session, tokens=()):
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
@pytest.mark.parametrize(
    ("operation", "event_type"),
    [
        ("input", AuditEventType.VALUE_SANITIZED),
        ("result", AuditEventType.TOOL_RESULT_SANITIZED),
        ("allow", AuditEventType.TOOL_RELEASE_ALLOWED),
        ("deny", AuditEventType.TOOL_RELEASE_DENIED),
        ("unknown", AuditEventType.TOOL_RELEASE_DENIED),
        ("result_failure", AuditEventType.TOOL_RESULT_SANITIZATION_FAILED),
        ("close", AuditEventType.SESSION_CLOSED),
    ],
)
def test_raising_sink_has_static_failure_without_partial_return_or_transcript(
    transcript, operation, event_type, caplog, capsys
):
    with _session(transcript) as (session, sink):
        token = session.sanitize(PERSON)
        before = session.transcript
        sink.fail_on.add(event_type)
        returned = []
        with pytest.raises(TrustGateError) as error:
            if operation == "input":
                returned.append(session.sanitize(RAW))
            elif operation == "result":
                returned.append(session.sanitize_tool_result({"people": [PERSON, RAW]}))
            elif operation in ("allow", "deny", "unknown"):
                call = ToolCall(
                    name="blocked" if operation == "deny" else "lookup",
                    arguments={
                        "person": "[PERSON_" + "9" * 100 + "]" if operation == "unknown" else token
                    },
                )
                returned.append(session.rehydrate_for_tool(call))
            elif operation == "result_failure":
                returned.append(session.sanitize_tool_result([RAW, object()]))
            else:
                returned.append(session.close())
        assert type(error.value).__name__ == "AuditRecordingError"
        assert returned == []
        assert session.transcript == before
        assert sink.events[-1].event_type is event_type
        if operation == "close":
            _cleared(session, (token,))
            session.close()  # No second audit attempt for an already closed session.
        else:
            assert not session.is_closed  # Explicit lifecycle, not transaction rollback.
        _safe(error.value, session, sink, caplog, capsys)


@pytest.mark.parametrize("entry", ["session", "gate"])
@pytest.mark.parametrize("transcript", [False, True])
def test_failed_session_open_cleans_retained_private_state(
    entry, transcript, monkeypatch, caplog, capsys
):
    instances = []

    class CapturingSession(TrustSession):
        def __init__(self, **kwargs):
            instances.append(self)
            super().__init__(**kwargs)

    sink = RaisingSink()
    sink.fail_on.add(AuditEventType.SESSION_OPENED)
    aliases = {"Beth": ["Elizabeth"]}
    with pytest.raises(TrustGateError) as error:
        if entry == "session":
            CapturingSession(audit_sink=sink, aliases=aliases, transcript=transcript)
        else:
            monkeypatch.setattr("trustgate.gate.TrustSession", CapturingSession)
            TrustGate(audit_sink=sink).session(aliases=aliases, transcript=transcript)
    session = instances[0]
    assert type(error.value).__name__ == "AuditRecordingError"
    _cleared(session)
    assert len(sink.events) == 1
    _safe(error.value, session, sink, caplog, capsys)


@pytest.mark.parametrize("transcript", [False, True])
def test_close_audit_failure_does_not_chain_an_unsafe_context_body_error(
    transcript, caplog, capsys
):
    with _session(transcript) as (session, sink):
        token = session.sanitize(PERSON)
        before = session.transcript
        sink.fail_on.add(AuditEventType.SESSION_CLOSED)
        with pytest.raises(TrustGateError) as error:
            with session:
                raise RuntimeError(RAW)
        assert type(error.value).__name__ == "AuditRecordingError"
        _cleared(session, (token,))
        assert session.transcript == before
        _safe(error.value, session, sink, caplog, capsys)


class UnsafeObject:
    def __repr__(self):
        return RAW


class UnsafeString(str):
    def __repr__(self):
        return RAW


class UnsafeInt(int):
    def __repr__(self):
        return RAW


class UnsafeFloat(float):
    def __repr__(self):
        return RAW


class FailingList(list):
    def __iter__(self):
        yield PERSON
        raise RuntimeError(RAW)


class FailingDict(dict):
    def items(self):
        yield "first", PERSON
        raise RuntimeError(RAW)


def _attack(kind, root):
    if kind == "cycle":
        return root
    if kind == "deep":
        value = PERSON
        for _ in range(1500):
            value = [value]
        return value
    return {
        "object": UnsafeObject,
        "string_subclass": lambda: UnsafeString("ordinary"),
        "int_subclass": lambda: UnsafeInt(1),
        "float_subclass": lambda: UnsafeFloat(1),
        "list_error": FailingList,
        "dict_error": FailingDict,
        "bad_key": lambda: {UnsafeObject(): "value"},
    }[kind]()


@pytest.mark.parametrize("transcript", [False, True])
@pytest.mark.parametrize("destination", ["lookup", "update"])
@pytest.mark.parametrize(
    "attack",
    [
        "cycle",
        "deep",
        "object",
        "string_subclass",
        "int_subclass",
        "float_subclass",
        "list_error",
        "dict_error",
        "bad_key",
    ],
)
def test_mutated_argument_tree_fails_safely_after_an_allowed_token(
    transcript, destination, attack, caplog, capsys
):
    with _session(transcript) as (session, sink):
        token = session.sanitize(PERSON)
        call = ToolCall(name=destination, arguments={"first_allowed": token})
        bad = _attack(attack, call.arguments)
        call.arguments["bad"] = bad
        root = call.arguments
        before = session.transcript
        returned = []
        with pytest.raises(TrustGateError) as error:
            returned.append(session.rehydrate_for_tool(call))
        assert type(error.value).__name__ == "ToolArgumentRehydrationError"
        assert returned == []
        assert call.arguments is root and call.arguments["bad"] is bad
        assert call.arguments["first_allowed"] == token
        assert session.transcript == before
        assert sink.events[-1].event_type is AuditEventType.TOOL_RELEASE_DENIED
        assert sink.events[-1].failure_reason.value == "unsafe_argument_structure"
        _safe(error.value, session, sink, caplog, capsys)


@pytest.mark.parametrize("transcript", [False, True])
@pytest.mark.parametrize("scalar", [UnsafeString, UnsafeInt, UnsafeFloat])
def test_scalar_subclasses_never_escape_as_sanitized_python_objects(
    transcript, scalar, caplog, capsys
):
    value = scalar("ordinary" if scalar is UnsafeString else 1)
    with _session(transcript) as (session, sink):
        before = session.transcript
        with pytest.raises(ToolResultSanitizationError) as error:
            session.sanitize_tool_result({"people": [PERSON, value]})
        assert session.transcript == before
        _safe(error.value, session, sink, caplog, capsys)


def test_public_sanitize_rejects_custom_string_object_without_unsafe_repr(caplog, capsys):
    with _session() as (session, sink):
        with pytest.raises(ModelValidationError) as error:
            session.sanitize(UnsafeString("ordinary"))
        assert session.transcript == ()
        _safe(error.value, session, sink, caplog, capsys)


@pytest.mark.parametrize("entry", ["policy", "call", "request"])
def test_surrogate_metadata_is_rejected_before_audit_encoding(entry, caplog, capsys):
    destination = RAW + "\ud800"
    with _session() as (session, sink):
        history = session.transcript
        events = sink.events
        expected = PolicyValidationError if entry == "policy" else ModelValidationError
        with pytest.raises(expected) as error:
            if entry == "policy":
                _policy(destination)
            elif entry == "call":
                session.rehydrate_for_tool(ToolCall(name=destination))
            else:
                session.decide_data_release(
                    DataReleaseRequest(entity_type="PERSON", destination=destination)
                )
        assert session.transcript == history
        assert sink.events == events
        _safe(error.value, session, sink, caplog, capsys)


def test_mutated_but_valid_json_and_shared_containers_remain_supported():
    with _session() as (session, sink):
        token = session.sanitize(PERSON)
        call = ToolCall(name="update")
        shared = {"person": token, "primitive": [None, False, 0, 1.25, ""]}
        call.arguments.update({"left": shared, "right": shared})
        history = session.transcript
        result = session.rehydrate_for_tool(call)
        expected = {"person": PERSON, "primitive": [None, False, 0, 1.25, ""]}
        assert result == {"left": expected, "right": expected}
        assert result["left"] is not result["right"]
        assert result["left"] is not shared
        assert call.arguments["left"] is call.arguments["right"] is shared
        assert shared["person"] == token
        assert session.transcript == history
        assert_no_raw_sensitive_values(sink.events, PERSON)


def test_open_session_user_rehydration_is_unavailable_and_leak_free(caplog, capsys):
    with _session() as (session, sink):
        token = session.sanitize(PERSON)
        before = session.transcript
        with pytest.raises(FeatureUnavailableError) as error:
            session.rehydrate_for_user(token + RAW)
        assert session.transcript == before
        _safe(error.value, session, sink, caplog, capsys)


@pytest.mark.parametrize("subclass", [False, True])
def test_caller_iterator_cannot_smuggle_an_unsafe_token_exception(subclass, caplog, capsys):
    class CallerError(UnknownTokenError):
        default_message = RAW

    class ErrorDict(dict):
        def items(self):
            error = CallerError() if subclass else UnknownTokenError()
            error.args = (RAW,)
            raise error

    with _session() as (session, sink):
        token = session.sanitize(PERSON)
        call = ToolCall(name="lookup", arguments={"first": token})
        call.arguments["bad"] = ErrorDict()
        with pytest.raises(TrustGateError) as error:
            session.rehydrate_for_tool(call)
        expected = "ToolArgumentRehydrationError" if subclass else "UnknownTokenError"
        assert type(error.value).__name__ == expected
        _safe(error.value, session, sink, caplog, capsys)


@pytest.mark.parametrize("transcript", [False, True])
def test_sink_serialization_failure_is_safe_and_never_appends_transcript(
    transcript, monkeypatch, caplog, capsys
):
    class SerializingSink(InMemoryAuditSink):
        def record(self, event):
            super().record(event)
            event.model_dump_json()

    sink = SerializingSink()
    with TrustSession(detector=Detector(), audit_sink=sink, transcript=transcript) as session:
        token = session.sanitize(PERSON)
        before = session.transcript

        def fail_serializer(self, **kwargs):
            raise RuntimeError(RAW)

        # Restore the injected failure before inspecting stored event JSON.
        with monkeypatch.context() as injection:
            injection.setattr(AuditEvent, "model_dump_json", fail_serializer)
            with pytest.raises(TrustGateError) as error:
                session.sanitize_tool_result([PERSON, RAW])
        assert type(error.value).__name__ == "AuditRecordingError"
        assert session.transcript == before
        assert not session.is_closed
        _safe(error.value, session, sink, caplog, capsys)
    _cleared(session, (token,))
