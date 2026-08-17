"""Validation tests for LLM-safe public models."""

import pytest

from trustgate import (
    AuditEvent,
    AuditEventType,
    DataReleaseDecision,
    DataReleaseResult,
    ModelValidationError,
    SensitiveEntity,
    SensitiveToken,
    ToolCall,
)

AUDIT_IDENTIFIER = "audit_" + "0" * 64


def test_core_models_accept_valid_non_sensitive_metadata() -> None:
    SensitiveEntity(entity_type="ACCOUNT_NUMBER", start=2, end=10, score=0.95)
    token = SensitiveToken(value="[ACCOUNT_NUMBER_1]", entity_type="ACCOUNT_NUMBER")
    tool_call = ToolCall(name="get_account", arguments={"account": token.value})
    result = DataReleaseResult(
        entity_type="ACCOUNT_NUMBER",
        destination=tool_call.name,
        decision=DataReleaseDecision.ALLOW,
    )
    event = AuditEvent(
        event_type=AuditEventType.TOOL_RELEASE_ALLOWED,
        session_id="session-opaque-id",
        entity_types=(AUDIT_IDENTIFIER,),
        destination=AUDIT_IDENTIFIER,
        decision=result.decision,
        tokens=(AUDIT_IDENTIFIER,),
    )

    assert event.model_dump(mode="json")["tokens"] == [AUDIT_IDENTIFIER]


@pytest.mark.parametrize(
    ("model", "values"),
    [
        (SensitiveEntity, {"entity_type": "account number", "start": 0, "end": 1, "score": 1}),
        (SensitiveEntity, {"entity_type": "PERSON", "start": 3, "end": 3, "score": 1}),
        (SensitiveToken, {"value": "ACCOUNT_NUMBER_1", "entity_type": "ACCOUNT_NUMBER"}),
        (ToolCall, {"name": "", "arguments": {}}),
    ],
)
def test_core_models_reject_invalid_values(model: type[object], values: dict[str, object]) -> None:
    with pytest.raises(ModelValidationError):
        model(**values)  # type: ignore[operator]


def test_model_validation_error_text_hides_invalid_raw_input() -> None:
    raw_value = "RAW_SECRET_DO_NOT_LEAK_12345678"

    with pytest.raises(ModelValidationError) as error:
        SensitiveToken(value=raw_value, entity_type="ACCOUNT_NUMBER")

    assert raw_value not in str(error.value)


def test_model_validation_error_hides_raw_input_in_all_public_views() -> None:
    raw_value = "RAW_SECRET_DO_NOT_LEAK_12345678"

    with pytest.raises(ModelValidationError) as error:
        SensitiveToken.model_validate({"value": raw_value, "entity_type": "ACCOUNT_NUMBER"})

    assert raw_value not in str(error.value)
    assert raw_value not in repr(error.value)


@pytest.mark.parametrize(
    "operation",
    [
        lambda raw_value: SensitiveToken.model_validate_json(
            f'{{"value": "{raw_value}", "entity_type": "ACCOUNT_NUMBER"}}'
        ),
        lambda raw_value: SensitiveToken.model_validate_strings(
            {"value": raw_value, "entity_type": "ACCOUNT_NUMBER"}
        ),
    ],
)
def test_alternate_pydantic_validation_paths_hide_raw_input(operation: object) -> None:
    raw_value = "RAW_SECRET_DO_NOT_LEAK_12345678"

    with pytest.raises(ModelValidationError) as error:
        operation(raw_value)  # type: ignore[operator]

    assert raw_value not in str(error.value)
    assert raw_value not in repr(error.value)


@pytest.mark.parametrize(
    "operation",
    [
        lambda raw_value: SensitiveToken.model_construct(
            value=raw_value,
            entity_type="ACCOUNT_NUMBER",
        ),
        lambda raw_value: SensitiveToken(
            value="[ACCOUNT_NUMBER_1]",
            entity_type="ACCOUNT_NUMBER",
        ).model_copy(update={"value": raw_value}),
    ],
)
def test_pydantic_trusted_construction_paths_still_validate_sensitive_tokens(
    operation: object,
) -> None:
    raw_value = "RAW_SECRET_DO_NOT_LEAK_12345678"

    with pytest.raises(ModelValidationError) as error:
        operation(raw_value)  # type: ignore[operator]

    assert raw_value not in str(error.value)
    assert raw_value not in repr(error.value)
