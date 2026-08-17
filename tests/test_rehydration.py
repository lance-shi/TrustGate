"""Tests for policy-controlled, atomic tool argument rehydration."""

import pytest
from security_assertions import assert_no_raw_sensitive_values

from trustgate import (
    CrossSessionTokenError,
    DataReleaseDenied,
    MalformedTokenError,
    ToolCall,
    TrustGate,
    TrustPolicy,
    UnknownTokenError,
)

RAW_ACCOUNT = "RAW_ACCOUNT_DO_NOT_LEAK_12345678"
RAW_PERSON = "RAW_PERSON_DO_NOT_LEAK_JANE_SMITH"


def _gate() -> TrustGate:
    return TrustGate(
        policy=TrustPolicy(
            version=1,
            data_policies={
                "ACCOUNT_NUMBER": {
                    "external_llm": "tokenize",
                    "destinations": {"get_account": "allow", "update_account": "allow"},
                },
                "PERSON": {
                    "external_llm": "tokenize",
                    "destinations": {"get_account": "deny"},
                },
            },
        )
    )


def test_rehydrate_releases_an_allowed_current_session_token() -> None:
    session = _gate().session()
    token = session._vault.store(value=RAW_ACCOUNT, entity_type="ACCOUNT_NUMBER")

    arguments = session.rehydrate_for_tool(
        ToolCall(name="get_account", arguments={"account": token.value})
    )

    assert arguments == {"account": RAW_ACCOUNT}


def test_rehydrate_denies_a_disallowed_destination_without_leaking_raw_value() -> None:
    session = _gate().session()
    token = session._vault.store(value=RAW_PERSON, entity_type="PERSON")

    with pytest.raises(DataReleaseDenied) as error:
        session.rehydrate_for_tool(ToolCall(name="get_account", arguments={"person": token.value}))

    assert_no_raw_sensitive_values(error.value, RAW_PERSON)


@pytest.mark.parametrize(
    ("token", "error_type"),
    [
        ("[account_number_1]", MalformedTokenError),
        ("[ACCOUNT_NUMBER_99]", UnknownTokenError),
    ],
)
def test_rehydrate_rejects_invalid_tokens_without_disclosure(
    token: str, error_type: type[Exception]
) -> None:
    session = _gate().session()

    with pytest.raises(error_type) as error:
        session.rehydrate_for_tool(ToolCall(name="get_account", arguments={"account": token}))

    assert_no_raw_sensitive_values(error.value, RAW_ACCOUNT, RAW_PERSON)


def test_rehydrate_rejects_a_cross_session_token_without_disclosure() -> None:
    gate = _gate()
    current_session = gate.session()
    other_session = gate.session()
    token = other_session._vault.store(value=RAW_ACCOUNT, entity_type="ACCOUNT_NUMBER")

    with pytest.raises(CrossSessionTokenError) as error:
        current_session.rehydrate_for_tool(
            ToolCall(name="get_account", arguments={"account": token.value})
        )

    assert_no_raw_sensitive_values(error.value, RAW_ACCOUNT)


def test_rehydrate_is_atomic_when_one_of_multiple_tokens_is_denied() -> None:
    session = _gate().session()
    account = session._vault.store(value=RAW_ACCOUNT, entity_type="ACCOUNT_NUMBER")
    person = session._vault.store(value=RAW_PERSON, entity_type="PERSON")

    with pytest.raises(DataReleaseDenied) as error:
        session.rehydrate_for_tool(
            ToolCall(
                name="get_account",
                arguments={"account": account.value, "person": person.value},
            )
        )

    assert_no_raw_sensitive_values(error.value, RAW_ACCOUNT, RAW_PERSON)


def test_rehydrate_handles_nested_arguments_without_mutating_the_tool_call() -> None:
    session = _gate().session()
    first = session._vault.store(value=RAW_ACCOUNT, entity_type="ACCOUNT_NUMBER")
    second = session._vault.store(
        value="RAW_ACCOUNT_DO_NOT_LEAK_87654321",
        entity_type="ACCOUNT_NUMBER",
    )
    tool_call = ToolCall(
        name="get_account",
        arguments={
            "filters": {"accounts": [first.value, f"secondary={second.value}"]},
            "limit": 2,
        },
    )
    before = tool_call.model_dump()

    arguments = session.rehydrate_for_tool(tool_call)

    assert arguments == {
        "filters": {
            "accounts": [RAW_ACCOUNT, "secondary=RAW_ACCOUNT_DO_NOT_LEAK_87654321"]
        },
        "limit": 2,
    }
    assert tool_call.model_dump() == before


def test_rehydrate_allows_explicitly_allowed_write_style_destination() -> None:
    session = _gate().session()
    token = session._vault.store(value=RAW_ACCOUNT, entity_type="ACCOUNT_NUMBER")

    arguments = session.rehydrate_for_tool(
        ToolCall(name="update_account", arguments={"account": token.value})
    )

    assert arguments == {"account": RAW_ACCOUNT}
