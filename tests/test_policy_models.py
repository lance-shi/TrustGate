"""Validation tests for the v0.1 default-deny policy schema."""

import pytest
from security_assertions import assert_no_raw_sensitive_values

from trustgate import (
    DataReleaseDecision,
    ExternalLLMHandling,
    PolicyValidationError,
    TrustPolicy,
)


def test_policy_model_accepts_the_documented_schema() -> None:
    policy = TrustPolicy(
        version=1,
        data_policies={
            "ACCOUNT_NUMBER": {
                "external_llm": "tokenize",
                "destinations": {"get_account": "allow", "send_email": "deny"},
            }
        },
    )

    account_policy = policy.data_policies["ACCOUNT_NUMBER"]
    assert account_policy.external_llm is ExternalLLMHandling.TOKENIZE
    assert account_policy.destinations["get_account"] is DataReleaseDecision.ALLOW
    assert account_policy.destinations["send_email"] is DataReleaseDecision.DENY


def test_policy_mapping_cannot_be_mutated_after_validation() -> None:
    policy = TrustPolicy(
        version=1,
        data_policies={
            "ACCOUNT_NUMBER": {
                "external_llm": "tokenize",
                "destinations": {"get_account": "allow"},
            }
        },
    )

    with pytest.raises(TypeError):
        policy.data_policies["PERSON"] = policy.data_policies["ACCOUNT_NUMBER"]  # type: ignore[index]
    with pytest.raises(TypeError):
        policy.data_policies["ACCOUNT_NUMBER"].destinations["send_email"] = (  # type: ignore[index]
            DataReleaseDecision.ALLOW
        )


@pytest.mark.parametrize(
    "policy",
    [
        {"version": 2, "data_policies": {}},
        {
            "version": 1,
            "data_policies": {
                "account_number": {"external_llm": "tokenize", "destinations": {}}
            },
        },
        {
            "version": 1,
            "data_policies": {
                "ACCOUNT_NUMBER": {"external_llm": "reveal", "destinations": {}}
            },
        },
        {
            "version": 1,
            "data_policies": {
                "ACCOUNT_NUMBER": {
                    "external_llm": "tokenize",
                    "destinations": {"get_account": "conditional"},
                }
            },
        },
    ],
)
def test_policy_model_rejects_invalid_allowed_values(policy: dict[str, object]) -> None:
    with pytest.raises(PolicyValidationError):
        TrustPolicy.model_validate(policy)


def test_policy_model_rejects_unknown_fields_without_disclosing_input() -> None:
    raw_value = "RAW_POLICY_VALUE_DO_NOT_LEAK_12345678"
    policy = {
        "version": 1,
        "data_policies": {},
        "unexpected": raw_value,
    }

    with pytest.raises(PolicyValidationError) as error:
        TrustPolicy.model_validate(policy)

    assert_no_raw_sensitive_values(error.value, raw_value)
