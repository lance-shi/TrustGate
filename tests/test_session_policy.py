"""Tests for policy injection into explicit TrustGate sessions."""

import pytest

from trustgate import (
    DataReleaseDecision,
    DataReleaseRequest,
    SessionClosedError,
    TrustGate,
    TrustPolicy,
)


def _policy() -> TrustPolicy:
    return TrustPolicy(
        version=1,
        data_policies={
            "ACCOUNT_NUMBER": {
                "external_llm": "tokenize",
                "destinations": {"get_account": "allow"},
            }
        },
    )


def test_sessions_from_a_configured_gate_use_its_policy_but_have_distinct_vaults() -> None:
    gate = TrustGate(policy=_policy())
    first = gate.session()
    second = gate.session()
    request = DataReleaseRequest(entity_type="ACCOUNT_NUMBER", destination="get_account")

    assert first.decide_data_release(request).decision is DataReleaseDecision.ALLOW
    assert second.decide_data_release(request).decision is DataReleaseDecision.ALLOW
    assert first._vault is not second._vault


def test_session_from_an_unconfigured_gate_denies_by_default() -> None:
    session = TrustGate().session()

    result = session.decide_data_release(
        DataReleaseRequest(entity_type="ACCOUNT_NUMBER", destination="get_account")
    )

    assert result.decision is DataReleaseDecision.DENY


def test_session_from_a_yaml_configured_gate_uses_the_loaded_policy(tmp_path: object) -> None:
    path = tmp_path / "policy.yaml"  # type: ignore[operator]
    path.write_text(
        """\
version: 1
data_policies:
  EMAIL_ADDRESS:
    external_llm: tokenize
    destinations:
      send_email: allow
""",
        encoding="utf-8",
    )

    session = TrustGate.from_yaml(path).session()
    result = session.decide_data_release(
        DataReleaseRequest(entity_type="EMAIL_ADDRESS", destination="send_email")
    )

    assert result.decision is DataReleaseDecision.ALLOW


def test_closed_session_cannot_evaluate_a_policy() -> None:
    session = TrustGate(policy=_policy()).session()
    session.close()

    with pytest.raises(SessionClosedError):
        session.decide_data_release(
            DataReleaseRequest(entity_type="ACCOUNT_NUMBER", destination="get_account")
        )
