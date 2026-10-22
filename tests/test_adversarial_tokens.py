"""Attack cases for token release at every JSON argument position."""

from collections.abc import Iterator
from copy import deepcopy

import pytest
from security_assertions import assert_no_raw_sensitive_values

from trustgate import (
    AuditEventType,
    CrossSessionTokenError,
    DataReleaseDenied,
    InMemoryAuditSink,
    MalformedTokenError,
    SensitiveEntity,
    TokenResolutionError,
    ToolCall,
    TrustPolicy,
    TrustSession,
    UnknownTokenError,
)
from trustgate.models import JsonValue

RAW_ACCOUNT = "ACCOUNT_SECRET_78654321"
RAW_SECOND_ACCOUNT = "ACCOUNT_SECRET_2"
RAW_PERSON = "PERSON_SECRET_Adversarial_Fixture"


class FixtureDetector:
    def detect(self, text: str) -> tuple[SensitiveEntity, ...]:
        if text not in (RAW_ACCOUNT, RAW_SECOND_ACCOUNT, RAW_PERSON):
            return ()
        return (
            SensitiveEntity(
                entity_type="PERSON" if text == RAW_PERSON else "ACCOUNT_NUMBER",
                start=0,
                end=len(text),
                score=1,
            ),
        )


@pytest.fixture
def session() -> Iterator[TrustSession]:
    policy = TrustPolicy(
        version=1,
        data_policies={
            "ACCOUNT_NUMBER": {
                "external_llm": "tokenize",
                "destinations": {"get_account": "allow", "update_account": "allow"},
            },
            "PERSON": {
                "external_llm": "tokenize",
                "destinations": {"get_account": "deny", "update_account": "deny"},
            },
        },
    )
    with TrustSession(
        policy=policy, detector=FixtureDetector(), audit_sink=InMemoryAuditSink(), transcript=True
    ) as current:
        yield current


def _arguments(text: str, position: str) -> dict[str, JsonValue]:
    if position == "key":
        return {text: "value"}
    if position == "nested_key":
        return {"filters": [{text: "value"}]}
    return {"filters": [{"account": text}]}


def _assert_safe(session: TrustSession, error: BaseException, caplog, capsys) -> None:
    captured = capsys.readouterr()
    assert error.__cause__ is None
    assert error.__context__ is None
    assert_no_raw_sensitive_values(
        (
            error,
            [event.model_dump_json() for event in session._audit_sink.events],
            session.transcript,
            caplog.text,
            captured.out,
            captured.err,
        ),
        RAW_ACCOUNT,
        RAW_SECOND_ACCOUNT,
        RAW_PERSON,
    )
    assert session._audit_sink.events[-1].event_type is AuditEventType.TOOL_RELEASE_DENIED


@pytest.mark.parametrize("destination", ["get_account", "update_account"])
@pytest.mark.parametrize("position", ["key", "nested_key", "value"])
def test_allowed_tokens_in_all_argument_positions_use_policy_and_copy(
    session, destination, position, caplog, capsys
):
    token = session.sanitize(RAW_ACCOUNT)
    call = ToolCall(name=destination, arguments=_arguments(f"prefix={token}{token}", position))
    before = deepcopy(call.arguments)
    history = session.transcript

    result = session.rehydrate_for_tool(call)

    assert result == _arguments(f"prefix={RAW_ACCOUNT}{RAW_ACCOUNT}", position)
    assert call.arguments == before
    assert session.transcript == history
    assert session._audit_sink.events[-1].event_type is AuditEventType.TOOL_RELEASE_ALLOWED
    captured = capsys.readouterr()
    assert_no_raw_sensitive_values(
        (session._audit_sink.events, session.transcript, caplog.text, captured.out, captured.err),
        RAW_ACCOUNT,
    )


@pytest.mark.parametrize("destination", ["get_account", "update_account"])
@pytest.mark.parametrize("position", ["key", "nested_key", "value"])
@pytest.mark.parametrize("attack", ["denied", "unknown", "foreign", "closed_owner", "malformed"])
def test_invalid_reference_after_allowed_value_never_returns_partial_arguments(
    session, destination, position, attack, caplog, capsys
):
    allowed = session.sanitize(RAW_ACCOUNT)
    if attack == "denied":
        bad, error_type = session.sanitize(RAW_PERSON), DataReleaseDenied
    elif attack in ("foreign", "closed_owner"):
        with TrustSession(detector=FixtureDetector()) as owner:
            bad = owner.sanitize(RAW_ACCOUNT)
            if attack == "closed_owner":
                owner.close()
            error_type = UnknownTokenError if attack == "closed_owner" else CrossSessionTokenError
            if attack == "foreign":
                _check_rejected(
                    session, destination, position, allowed, bad, error_type, caplog, capsys
                )
                return
    elif attack == "unknown":
        bad, error_type = "[ACCOUNT_NUMBER_" + "9" * 1000 + "]", UnknownTokenError
    else:
        bad, error_type = "[ACCOUNT_NUMBER_01]", MalformedTokenError
    _check_rejected(session, destination, position, allowed, bad, error_type, caplog, capsys)


def _check_rejected(session, destination, position, allowed, bad, error_type, caplog, capsys):
    arguments = {"first_allowed": allowed, **_arguments(bad, position)}
    call = ToolCall(name=destination, arguments=arguments)
    before = deepcopy(call.arguments)
    history = session.transcript
    with pytest.raises(error_type) as error:
        session.rehydrate_for_tool(call)
    assert call.arguments == before
    assert session.transcript == history
    _assert_safe(session, error.value, caplog, capsys)


@pytest.mark.parametrize(
    "attack",
    [
        "[",
        "]",
        "[]",
        "[[ACCOUNT_NUMBER_1]]",
        "[ACCOUNT_NUMBER_0]",
        "[ACCOUNT_NUMBER_01]",
        "[account_number_1]",
        "[ACCOUNT_NUMBER_-1]",
        "[ACCOUNT_NUMBER_1.0]",
        "[ACCOUNT_NUMBER_١]",
        "[ACCOUNT_NUMBER_1\n]",
        "[ACCOUNT_NUMBER_1]tail]",
        "[ACCOUNT_NUMBER_1][",
        "[ACCOUNT_NUMBER_1][[]]",
    ],
)
def test_malformed_brackets_fail_safely_even_after_a_valid_token(session, attack, caplog, capsys):
    token = session.sanitize(RAW_ACCOUNT)
    call = ToolCall(name="get_account", arguments={"account": token + attack})
    with pytest.raises(MalformedTokenError) as error:
        session.rehydrate_for_tool(call)
    _assert_safe(session, error.value, caplog, capsys)


@pytest.mark.parametrize("position", ["key", "nested_key"])
@pytest.mark.parametrize("reverse", [False, True])
def test_rehydrated_key_collision_rejects_without_overwrite_or_leak(
    session, position, reverse, caplog, capsys
):
    token = session.sanitize(RAW_ACCOUNT)
    pairs = [(token, "token_value"), (RAW_ACCOUNT, "literal_value")]
    collision = dict(reversed(pairs) if reverse else pairs)
    arguments = collision if position == "key" else {"filters": [collision]}
    call = ToolCall(name="get_account", arguments=arguments)
    before = deepcopy(call.arguments)
    history = session.transcript
    with pytest.raises(TokenResolutionError) as error:
        session.rehydrate_for_tool(call)
    assert call.arguments == before
    assert session.transcript == history
    _assert_safe(session, error.value, caplog, capsys)


@pytest.mark.parametrize(
    "destination",
    [
        "GET_ACCOUNT",
        "get_account ",
        " get_account",
        "get_account\n",
        "get_account.*",
        "get_account/",
        "get_аccount",
        "get_account\u200b",
    ],
)
def test_destination_matching_does_not_normalize_or_expand_permissions(
    session, destination, caplog, capsys
):
    token = session.sanitize(RAW_ACCOUNT)
    with pytest.raises(DataReleaseDenied) as error:
        session.rehydrate_for_tool(ToolCall(name=destination, arguments={"account": token}))
    _assert_safe(session, error.value, caplog, capsys)


def test_adjacent_tokens_with_different_raw_lengths_replace_right_to_left(session):
    first = session.sanitize(RAW_ACCOUNT)
    second = session.sanitize(RAW_SECOND_ACCOUNT)
    assert second != first
    assert session.rehydrate_for_tool(
        ToolCall(name="update_account", arguments={"value": first + "|" + second + first})
    ) == {"value": RAW_ACCOUNT + "|" + RAW_SECOND_ACCOUNT + RAW_ACCOUNT}


@pytest.mark.parametrize("destination", ["get_account", "update_account"])
@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("attack", ["denied", "unknown", "foreign"])
def test_every_token_in_one_string_requires_its_own_allowance(
    session, destination, reverse, attack, caplog, capsys
):
    allowed = session.sanitize(RAW_ACCOUNT)
    with TrustSession(detector=FixtureDetector()) as owner:
        if attack == "denied":
            bad, error_type = session.sanitize(RAW_PERSON), DataReleaseDenied
        elif attack == "unknown":
            bad, error_type = "[ACCOUNT_NUMBER_" + "9" * 1000 + "]", UnknownTokenError
        else:
            bad, error_type = owner.sanitize(RAW_ACCOUNT), CrossSessionTokenError
        text = bad + allowed if reverse else allowed + bad
        call = ToolCall(name=destination, arguments={"text": text})
        before = deepcopy(call.arguments)
        history = session.transcript
        with pytest.raises(error_type) as error:
            session.rehydrate_for_tool(call)
        assert call.arguments == before
        assert session.transcript == history
        _assert_safe(session, error.value, caplog, capsys)


@pytest.mark.parametrize("position", ["key", "nested_key", "value"])
def test_missing_policy_never_releases_tokens_in_any_position(position, caplog, capsys):
    with TrustSession(detector=FixtureDetector(), transcript=True) as current:
        token = current.sanitize(RAW_ACCOUNT)
        with pytest.raises(DataReleaseDenied) as error:
            current.rehydrate_for_tool(
                ToolCall(name="update_account", arguments=_arguments(token, position))
            )
        _assert_safe(current, error.value, caplog, capsys)
