"""Day 1 safety constraints for failure paths."""

import pytest
from security_assertions import assert_no_raw_sensitive_values

from trustgate import (
    CrossSessionTokenError,
    DataReleaseDenied,
    EntityResolutionError,
    MalformedTokenError,
    ModelValidationError,
    PolicyError,
    PolicyValidationError,
    SessionClosedError,
    ToolCall,
    TrustGate,
    TrustGateError,
    UnknownTokenError,
)

RAW_SENTINEL = "RAW_SECRET_DO_NOT_LEAK_12345678"


def assert_does_not_disclose_raw_value(value: object) -> None:
    assert RAW_SENTINEL not in str(value)


def test_sanitization_does_not_return_detected_raw_input() -> None:
    session = TrustGate().session()
    sensitive_value = "12345678"

    sanitized = session.sanitize(f"Check account {sensitive_value}.")

    assert sensitive_value not in sanitized


def test_tool_rehydration_is_denied_by_default_without_disclosing_input() -> None:
    session = TrustGate().session()
    token = session._vault.store(value=RAW_SENTINEL, entity_type="ACCOUNT_NUMBER")
    call = ToolCall(name="get_account", arguments={"account": token.value})

    with pytest.raises(DataReleaseDenied) as error:
        session.rehydrate_for_tool(call)

    assert_does_not_disclose_raw_value(error.value)


def test_closed_session_fails_without_disclosing_input() -> None:
    session = TrustGate().session()
    session.close()

    with pytest.raises(SessionClosedError) as error:
        session.sanitize(RAW_SENTINEL)

    assert_does_not_disclose_raw_value(error.value)


def test_token_release_is_denied_without_a_policy() -> None:
    session = TrustGate().session()
    token = session._vault.store(value=RAW_SENTINEL, entity_type="ACCOUNT_NUMBER")
    tool_call = ToolCall(name="get_account", arguments={"account": token.value})

    with pytest.raises(DataReleaseDenied) as error:
        session.rehydrate_for_tool(tool_call)

    assert_no_raw_sensitive_values(error.value, RAW_SENTINEL)


def test_context_manager_closes_the_session_after_a_failed_operation() -> None:
    session = TrustGate().session()

    with session:
        assert "12345678" not in session.sanitize("Check account 12345678.")

    assert session.is_closed
    with pytest.raises(SessionClosedError) as error:
        session.sanitize_tool_result({"account": RAW_SENTINEL})
    assert_no_raw_sensitive_values(error.value, RAW_SENTINEL)


def test_closed_session_rejects_all_sensitive_boundary_operations() -> None:
    session = TrustGate().session()
    session.close()

    operations = [
        lambda: session.sanitize(RAW_SENTINEL),
        lambda: session.rehydrate_for_tool(ToolCall(name="get_account")),
        lambda: session.sanitize_tool_result({"account": RAW_SENTINEL}),
        lambda: session.rehydrate_for_user(RAW_SENTINEL),
    ]

    for operation in operations:
        with pytest.raises(SessionClosedError) as error:
            operation()
        assert_no_raw_sensitive_values(error.value, RAW_SENTINEL)


def test_policy_loading_failure_is_safe_for_a_sensitive_path() -> None:
    with pytest.raises(PolicyValidationError) as error:
        TrustGate.from_yaml(f"{RAW_SENTINEL}.yaml")

    assert_no_raw_sensitive_values(error.value, RAW_SENTINEL)


@pytest.mark.parametrize(
    "error_type",
    [
        TrustGateError,
        ModelValidationError,
        PolicyError,
        PolicyValidationError,
        DataReleaseDenied,
        EntityResolutionError,
        UnknownTokenError,
        CrossSessionTokenError,
        MalformedTokenError,
        SessionClosedError,
    ],
)
def test_public_trustgate_exceptions_are_static_and_safe(
    error_type: type[TrustGateError],
) -> None:
    error = error_type()

    assert str(error)
    assert_does_not_disclose_raw_value(error)
