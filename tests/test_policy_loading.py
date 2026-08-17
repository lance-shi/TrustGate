"""Tests for fail-closed YAML policy loading."""

import pytest
from security_assertions import assert_no_raw_sensitive_values

from trustgate import DataReleaseDecision, PolicyValidationError, TrustGate


def test_from_yaml_loads_a_valid_policy(tmp_path: object) -> None:
    path = tmp_path / "policy.yaml"  # type: ignore[operator]
    path.write_text(
        """\
version: 1
data_policies:
  ACCOUNT_NUMBER:
    external_llm: tokenize
    destinations:
      get_account: allow
""",
        encoding="utf-8",
    )

    gate = TrustGate.from_yaml(path)

    assert gate.policy is not None
    assert gate.policy.data_policies["ACCOUNT_NUMBER"].destinations[
        "get_account"
    ] is DataReleaseDecision.ALLOW


@pytest.mark.parametrize(
    "document",
    [
        "version: [\ndata_policies: {}\n",
        "",
        "- not\n- a policy mapping\n",
        "version: 1\ndata_policies:\n  ACCOUNT_NUMBER: unexpected\n",
    ],
)
def test_from_yaml_rejects_malformed_or_invalid_documents(
    tmp_path: object, document: str
) -> None:
    path = tmp_path / "invalid.yaml"  # type: ignore[operator]
    path.write_text(document, encoding="utf-8")

    with pytest.raises(PolicyValidationError):
        TrustGate.from_yaml(path)


def test_from_yaml_hides_sensitive_path_and_document_content(tmp_path: object) -> None:
    raw_value = "RAW_POLICY_VALUE_DO_NOT_LEAK_12345678"
    path = tmp_path / f"{raw_value}.yaml"  # type: ignore[operator]
    path.write_text(f"unexpected: {raw_value}\n", encoding="utf-8")

    with pytest.raises(PolicyValidationError) as error:
        TrustGate.from_yaml(path)

    assert_no_raw_sensitive_values(error.value, raw_value)


def test_from_yaml_hides_a_missing_sensitive_path() -> None:
    raw_value = "RAW_POLICY_PATH_DO_NOT_LEAK_12345678"

    with pytest.raises(PolicyValidationError) as error:
        TrustGate.from_yaml(f"{raw_value}.yaml")

    assert_no_raw_sensitive_values(error.value, raw_value)
