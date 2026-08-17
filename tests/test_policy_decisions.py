"""Tests for pure, destination-aware default-deny policy evaluation."""

from trustgate import (
    DataReleaseDecision,
    DataReleaseRequest,
    TrustPolicy,
    decide_data_release,
)


def _policy() -> TrustPolicy:
    return TrustPolicy(
        version=1,
        data_policies={
            "ACCOUNT_NUMBER": {
                "external_llm": "tokenize",
                "destinations": {
                    "get_account": "allow",
                    "update_account": "allow",
                    "send_email": "deny",
                },
            }
        },
    )


def test_explicit_allow_is_returned_without_mutating_the_policy() -> None:
    policy = _policy()
    before = policy.model_dump()

    result = decide_data_release(
        policy,
        DataReleaseRequest(entity_type="ACCOUNT_NUMBER", destination="get_account"),
    )

    assert result.decision is DataReleaseDecision.ALLOW
    assert policy.model_dump() == before


def test_explicit_deny_is_returned() -> None:
    result = decide_data_release(
        _policy(),
        DataReleaseRequest(entity_type="ACCOUNT_NUMBER", destination="send_email"),
    )

    assert result.decision is DataReleaseDecision.DENY


def test_unknown_entity_type_is_denied() -> None:
    result = decide_data_release(
        _policy(),
        DataReleaseRequest(entity_type="PERSON", destination="get_account"),
    )

    assert result.decision is DataReleaseDecision.DENY


def test_unknown_destination_is_denied() -> None:
    result = decide_data_release(
        _policy(),
        DataReleaseRequest(entity_type="ACCOUNT_NUMBER", destination="delete_account"),
    )

    assert result.decision is DataReleaseDecision.DENY


def test_missing_policy_is_denied() -> None:
    result = decide_data_release(
        None,
        DataReleaseRequest(entity_type="ACCOUNT_NUMBER", destination="get_account"),
    )

    assert result.decision is DataReleaseDecision.DENY


def test_explicitly_allowed_write_style_destination_is_allowed() -> None:
    result = decide_data_release(
        _policy(),
        DataReleaseRequest(entity_type="ACCOUNT_NUMBER", destination="update_account"),
    )

    assert result.decision is DataReleaseDecision.ALLOW
