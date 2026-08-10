"""Tests that protect the shared no-raw-value testing contract itself."""

import pytest
from security_assertions import assert_no_raw_sensitive_values

from trustgate import AuditEvent, AuditEventType, ModelValidationError, SensitiveToken

RAW_ACCOUNT = "RAW_ACCOUNT_DO_NOT_LEAK_12345678"
RAW_PERSON = "RAW_PERSON_DO_NOT_LEAK_JANE_SMITH"


def test_no_raw_value_assertion_accepts_safe_nested_values() -> None:
    value = {
        "result": ["[ACCOUNT_NUMBER_1]", {"owner": "[PERSON_1]"}],
        "metadata": {"count": 2},
    }

    assert_no_raw_sensitive_values(value, RAW_ACCOUNT, RAW_PERSON)


def test_no_raw_value_assertion_rejects_nested_disclosure_without_echoing_it() -> None:
    with pytest.raises(AssertionError, match="raw sensitive test value") as error:
        assert_no_raw_sensitive_values({"nested": [RAW_ACCOUNT]}, RAW_ACCOUNT)

    assert RAW_ACCOUNT not in str(error.value)


def test_no_raw_value_assertion_inspects_exception_context() -> None:
    try:
        raise ValueError(RAW_PERSON)
    except ValueError:
        try:
            raise ModelValidationError
        except ModelValidationError as error:
            with pytest.raises(AssertionError, match="raw sensitive test value"):
                assert_no_raw_sensitive_values(error, RAW_PERSON)


def test_public_model_validation_error_has_no_hidden_raw_exception_context() -> None:
    with pytest.raises(ModelValidationError) as error:
        SensitiveToken(value=RAW_ACCOUNT, entity_type="ACCOUNT_NUMBER")

    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert_no_raw_sensitive_values(error.value, RAW_ACCOUNT)


def test_audit_event_serialization_has_no_raw_sensitive_values() -> None:
    event = AuditEvent(
        event_type=AuditEventType.VALUE_SANITIZED,
        session_id="84b4c05e5fca4e68909a5b6df2ce8194",
        entity_types=("ACCOUNT_NUMBER", "PERSON"),
        tokens=("[ACCOUNT_NUMBER_1]", "[PERSON_1]"),
    )

    assert_no_raw_sensitive_values(event, RAW_ACCOUNT, RAW_PERSON)
