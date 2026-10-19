"""Transcript collection occurs only after complete sanitization boundaries."""

from copy import deepcopy

import pytest
from security_assertions import assert_no_raw_sensitive_values

from trustgate import (
    CrossSessionTokenError,
    DataReleaseDenied,
    DetectionUnavailableError,
    EntityResolutionError,
    InMemoryAuditSink,
    ModelValidationError,
    SensitiveEntity,
    SessionClosedError,
    TokenResolutionError,
    ToolCall,
    ToolResultSanitizationError,
    TranscriptEntry,
    TranscriptEntryType,
    TrustGate,
    TrustPolicy,
    TrustSession,
)

NAMES = ("Elizabeth Taylor", "Beth Taylor", "Joanna Taylor", "Joseph Taylor", "Jo Taylor", "Beth")
RAW_FAILURE = "RAW_TRANSCRIPT_FAILURE_DO_NOT_LEAK"
RAW_ACCOUNT = "12345678"


class Detector:
    def detect(self, text: str) -> tuple[SensitiveEntity, ...]:
        if text == RAW_FAILURE:
            raise RuntimeError(text)
        kind = "PERSON" if text in NAMES else "ACCOUNT_NUMBER" if text == RAW_ACCOUNT else None
        if kind is None:
            return ()
        return (SensitiveEntity(entity_type=kind, start=0, end=len(text), score=1),)


def _gate() -> TrustGate:
    return TrustGate(
        policy=TrustPolicy(
            version=1,
            data_policies={
                "PERSON": {
                    "external_llm": "tokenize",
                    "destinations": {"lookup_person": "allow", "update_person": "allow"},
                }
            },
        )
    )


def _session(enabled: bool = True) -> TrustSession:
    session = _gate().session(transcript=enabled, aliases={"Beth": ["Elizabeth"]})
    session._detector = Detector()
    return session


def _assert_safe(value: object) -> None:
    assert_no_raw_sensitive_values(
        value,
        *NAMES,
        *(name.casefold() for name in NAMES),
        "Beth",
        "beth",
        RAW_ACCOUNT,
        RAW_FAILURE,
    )


@pytest.mark.parametrize("entry", ["gate", "session"])
@pytest.mark.parametrize("explicit", [True, False])
def test_transcript_is_disabled_by_default_and_when_explicitly_false(entry, explicit):
    factory = _gate().session if entry == "gate" else TrustSession
    options = {"transcript": False} if explicit else {}
    with factory(**options) as session:
        session._detector = Detector()
        assert session._transcript is None
        session.sanitize(NAMES[0])
        session.sanitize_tool_result({"owner": NAMES[0]})
        assert session.transcript == ()
    assert session.transcript == ()


@pytest.mark.parametrize("entry", ["gate", "session"])
def test_explicit_opt_in_collects_ordered_outputs_and_serializes_after_close(entry, caplog, capsys):
    factory = _gate().session if entry == "gate" else TrustSession
    with factory(transcript=True) as session:
        session._detector = Detector()
        token = session.sanitize(NAMES[0])
        result = session.sanitize_tool_result({NAMES[0]: [RAW_ACCOUNT, NAMES[0]]})
        entries = session.transcript
        assert [item.kind for item in entries] == [
            TranscriptEntryType.INPUT_SANITIZED,
            TranscriptEntryType.TOOL_RESULT_SANITIZED,
        ]
        assert entries[0].content == token
        assert entries[1].content == result
        assert result[token][1] == token
        for item in entries:
            assert TranscriptEntry.model_validate_json(item.model_dump_json()) == item
            assert set(item.model_dump()) == {"kind", "content"}
    assert session.transcript == entries
    assert session._vault._entries_by_token == {}
    output = capsys.readouterr()
    assert output.out == output.err == ""
    _assert_safe((session.transcript, session._audit_sink.events, caplog.text))


def test_snapshots_and_returned_results_do_not_share_nested_mutable_content():
    with _session() as session:
        token = session.sanitize(NAMES[0])
        raw = {NAMES[0]: [{"owner": "Beth Taylor"}]}
        original = deepcopy(raw)
        result = session.sanitize_tool_result(raw)
        snapshot = session.transcript
        snapshot[1].content[token][0]["owner"] = RAW_FAILURE
        assert result == {token: [{"owner": token}]}
        assert session.transcript[1].content == result
        result[token].append(RAW_FAILURE)
        raw[NAMES[0]].append(RAW_FAILURE)
        assert session.transcript[1].content == {token: [{"owner": token}]}
        assert original == {NAMES[0]: [{"owner": "Beth Taylor"}]}
        before = session.transcript
        session.sanitize("next message")
        assert len(before) == 2 and len(session.transcript) == 3
        _assert_safe(session.transcript)


@pytest.mark.parametrize("destination", ["lookup_person", "update_person"])
def test_release_arguments_and_call_metadata_never_enter_transcript(destination, caplog):
    with _session() as session:
        token = session.sanitize(NAMES[0])
        assert session.sanitize("Beth Taylor") == token
        before = session.transcript
        call = ToolCall(name=destination, arguments={"owner": token})
        assert session.rehydrate_for_tool(call) == {"owner": NAMES[0]}
        # Even a caller supplying raw arguments/names is not trusted for logging.
        assert session.rehydrate_for_tool(
            ToolCall(name=RAW_FAILURE, arguments={RAW_FAILURE: RAW_FAILURE})
        ) == {RAW_FAILURE: RAW_FAILURE}
        with pytest.raises(DataReleaseDenied):
            session.rehydrate_for_tool(ToolCall(name="unlisted", arguments={"owner": token}))
        assert session.transcript == before
    _assert_safe((session.transcript, session._audit_sink.events, caplog.text))


@pytest.mark.parametrize("token", ["[PERSON_999999999]", "[PERSON_broken]", "[PERSON_1"])
def test_invalid_tool_references_do_not_append_transcript(token):
    with _session() as session:
        before = session.transcript
        with pytest.raises(TokenResolutionError):
            session.rehydrate_for_tool(ToolCall(name="lookup_person", arguments={"owner": token}))
        assert session.transcript == before


def test_sessions_keep_independent_histories_tokens_and_aliases():
    gate = _gate()
    with (
        gate.session(transcript=True, aliases={"Beth": ["Elizabeth"]}) as first,
        gate.session(transcript=True) as second,
        gate.session() as disabled,
    ):
        first._detector = second._detector = disabled._detector = Detector()
        token = first.sanitize(NAMES[0])
        assert first.sanitize("Beth Taylor") == token
        assert second.transcript == disabled.transcript == ()
        other_token = second.sanitize("Beth Taylor")
        assert other_token != token
        with pytest.raises(CrossSessionTokenError):
            second.rehydrate_for_tool(ToolCall(name="lookup_person", arguments={"owner": token}))
        assert len(second.transcript) == 1
        assert len(first.transcript) == 2
        disabled.sanitize(NAMES[0])
        assert disabled.transcript == ()
    _assert_safe((first.transcript, second.transcript))


def test_ambiguity_and_stable_uncertain_identity_are_preserved():
    with _session() as session:
        uncertain = session.sanitize("Beth")
        canonical = session.sanitize("Elizabeth Taylor")
        assert session.sanitize("Beth") == uncertain != canonical
        first = session.sanitize("Joanna Taylor")
        second = session.sanitize("Joseph Taylor")
        ambiguous = session.sanitize("Jo Taylor")
        assert session.sanitize("Jo Taylor") == ambiguous
        assert len({uncertain, canonical, first, second, ambiguous}) == 5
        assert [entry.content for entry in session.transcript] == [
            uncertain,
            canonical,
            uncertain,
            first,
            second,
            ambiguous,
            ambiguous,
        ]
        assert session.rehydrate_for_tool(
            ToolCall(name="lookup_person", arguments={"owner": ambiguous})
        ) == {"owner": "Jo Taylor"}
    _assert_safe(session.transcript)


@pytest.mark.parametrize("failure", ["input", "result", "collision", "unsupported", "resolver"])
def test_failure_never_records_partial_content_and_context_exit_clears_mappings(failure, caplog):
    session = _session()
    with pytest.raises(
        (DetectionUnavailableError, ToolResultSanitizationError, EntityResolutionError)
    ):
        with session:
            session.sanitize("previous safe message")
            before = session.transcript
            if failure == "input":
                session.sanitize(RAW_FAILURE)
            elif failure == "result":
                session.sanitize_tool_result([NAMES[0], RAW_FAILURE])
            elif failure == "collision":
                session.sanitize_tool_result({NAMES[0]: "one", "Beth Taylor": "two"})
            elif failure == "unsupported":
                session.sanitize_tool_result([NAMES[0], object()])
            else:

                def fail_resolver(**kwargs):
                    raise ValueError("Resolver unavailable.")

                session._entity_resolver.resolve_person = fail_resolver
                session.sanitize_tool_result(["processed safe item", NAMES[0]])
    assert session.is_closed
    assert session.transcript == before
    assert session._vault._entries_by_token == {}
    assert session._entity_resolver._entities_by_id == {}
    assert session._entity_resolver._mention_states == []
    assert session._entity_resolver._alias_resolver._aliases == frozenset()
    _assert_safe((session.transcript, session._audit_sink.events, caplog.text))


@pytest.mark.parametrize("operation", ["input", "result", "release"])
def test_closed_session_rejects_new_operations_and_preserves_safe_history(operation):
    session = _session()
    token = session.sanitize(NAMES[0])
    before = session.transcript
    session.close()
    session.close()
    with pytest.raises(SessionClosedError):
        if operation == "input":
            session.sanitize(RAW_FAILURE)
        elif operation == "result":
            session.sanitize_tool_result({"owner": RAW_FAILURE})
        else:
            session.rehydrate_for_tool(ToolCall(name="lookup_person", arguments={"owner": token}))
    assert session.transcript == before
    _assert_safe(session.transcript)


@pytest.mark.parametrize("content", ["", None, {}, [], {"empty": ["", {}, [], None]}, True, 42])
def test_empty_and_primitive_results_are_recorded_without_changing_output(content):
    with _session() as session:
        assert session.sanitize("") == ""
        assert session.sanitize_tool_result(content) == content
        assert session.transcript[0].content == ""
        assert session.transcript[1].content == content


@pytest.mark.parametrize("entry", ["gate", "session"])
@pytest.mark.parametrize("invalid", [None, 0, 1, "false", RAW_FAILURE, [], {}])
def test_non_boolean_opt_in_fails_safely_before_session_creation(entry, invalid):
    sink = InMemoryAuditSink()
    factory = (
        TrustGate(audit_sink=sink).session
        if entry == "gate"
        else (lambda **options: TrustSession(audit_sink=sink, **options))
    )
    with pytest.raises(ModelValidationError) as error:
        factory(transcript=invalid)
    assert sink.events == ()
    assert error.value.__cause__ is error.value.__context__ is None
    _assert_safe(error.value)


def test_transcript_with_real_local_detection():
    with TrustSession(transcript=True) as session:
        text = "Ada Lovelace has account 12345678."
        safe = session.sanitize(text)
        result = session.sanitize_tool_result({"owner": "Ada Lovelace", "account": RAW_ACCOUNT})
        assert session.transcript[0].content == safe
        assert session.transcript[1].content == result
    assert_no_raw_sensitive_values(session.transcript, "Ada", "Lovelace", RAW_ACCOUNT)
