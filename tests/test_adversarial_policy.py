"""Hostile policy inputs must fail closed without diagnostic disclosure."""

import json
from pathlib import Path

import pytest
from security_assertions import assert_no_raw_sensitive_values

from trustgate import (
    DataReleaseDecision,
    DataReleaseRequest,
    PolicyValidationError,
    TrustGate,
    TrustPolicy,
    decide_data_release,
)

RAW = "POLICY_SECRET_Adversarial_Fixture"
VALID = """version: 1
data_policies:
  ACCOUNT_NUMBER:
    external_llm: tokenize
    destinations:
      get_account: allow
"""


@pytest.mark.parametrize(
    "document",
    [
        VALID + "version: 1\n",
        VALID.replace("  ACCOUNT_NUMBER:", "  ACCOUNT_NUMBER: {}\n  ACCOUNT_NUMBER:"),
        VALID.replace("    destinations:", "    destinations: {}\n    destinations:"),
        VALID.replace(
            "      get_account: allow", "      get_account: deny\n      get_account: allow"
        ),
        VALID + "---\n" + VALID,
        "version: 1\ndata_policies: &loop {ACCOUNT_NUMBER: *loop}\n",
        "&loop {version: 1, data_policies: *loop}\n",
        "version: 1\ndata_policies: { ? [" + RAW + "] : {} }\n",
        "version: 1\ndata_policies: { ? {" + RAW + ": value} : {} }\n",
        "version: 1\ndata_policies: {42: {}}\n",
        VALID.replace("get_account: allow", "42: allow"),
        VALID.replace("get_account: allow", "get_account: yes"),
        VALID.replace("get_account: allow", "get_account: ALLOW"),
        VALID.replace("    destinations:", "    <<: {external_llm: tokenize}\n    destinations:"),
        "!!python/object/apply:builtins.str [" + RAW + "]\n",
        "version: 1\ndata_policies: " + "[" * 1500 + RAW + "]" * 1500,
        VALID.replace("version: 1", "version: true"),
        VALID.replace("version: 1", "version: 1.0"),
    ],
    ids=[
        "duplicate-version",
        "duplicate-type",
        "duplicate-destinations",
        "duplicate-destination",
        "multiple-documents",
        "recursive-type",
        "recursive-root",
        "sequence-key",
        "mapping-key",
        "numeric-type",
        "numeric-destination",
        "yaml-boolean-decision",
        "uppercase-decision",
        "merge-key",
        "python-tag",
        "excessive-nesting",
        "boolean-version",
        "float-version",
    ],
)
def test_hostile_yaml_has_only_safe_policy_error(tmp_path: Path, document, caplog, capsys):
    path = tmp_path / (RAW + ".yaml")
    path.write_text(document + "\n# " + RAW, encoding="utf-8")
    with pytest.raises(PolicyValidationError) as error:
        TrustGate.from_yaml(path)
    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    captured = capsys.readouterr()
    assert_no_raw_sensitive_values((error.value, caplog.text, captured.out, captured.err), RAW)


def test_invalid_utf8_policy_hides_path_and_document(tmp_path: Path, caplog, capsys):
    path = tmp_path / (RAW + ".yaml")
    path.write_bytes(VALID.encode() + RAW.encode() + b"\xff")
    with pytest.raises(PolicyValidationError) as error:
        TrustGate.from_yaml(path)
    assert error.value.__context__ is None
    captured = capsys.readouterr()
    assert_no_raw_sensitive_values((error.value, caplog.text, captured.out, captured.err), RAW)


@pytest.mark.parametrize("version", [True, 1.0])
@pytest.mark.parametrize("entry", ["init", "validate", "json", "construct", "copy"])
def test_policy_version_requires_integer_one_through_all_construction_paths(version, entry):
    data = {"version": version, "data_policies": {}}
    with pytest.raises(PolicyValidationError) as error:
        if entry == "init":
            TrustPolicy(**data)
        elif entry == "validate":
            TrustPolicy.model_validate(data)
        elif entry == "json":
            TrustPolicy.model_validate_json(json.dumps(data))
        elif entry == "construct":
            TrustPolicy.model_construct(**data)
        else:
            TrustPolicy(version=1, data_policies={}).model_copy(update={"version": version})
    assert error.value.__cause__ is None
    assert error.value.__context__ is None


@pytest.mark.parametrize("entry", ["init", "validate", "json", "construct", "copy"])
def test_invalid_release_rule_cannot_bypass_policy_validation(entry):
    invalid = {
        "version": 1,
        "data_policies": {
            "ACCOUNT_NUMBER": {"external_llm": "tokenize", "destinations": {"get_account": RAW}}
        },
    }
    with pytest.raises(PolicyValidationError) as error:
        if entry == "init":
            TrustPolicy(**invalid)
        elif entry == "validate":
            TrustPolicy.model_validate(invalid)
        elif entry == "json":
            TrustPolicy.model_validate_json(json.dumps(invalid))
        elif entry == "construct":
            TrustPolicy.model_construct(**invalid)
        else:
            TrustPolicy(version=1, data_policies={}).model_copy(update=invalid)
    assert error.value.__context__ is None
    assert_no_raw_sensitive_values(error.value, RAW)


def test_nonrecursive_yaml_aliases_keep_explicit_rules_without_expansion(tmp_path: Path):
    path = tmp_path / "aliases.yaml"
    path.write_text(
        "version: 1\ndata_policies:\n"
        "  ACCOUNT_NUMBER: &rules\n    external_llm: tokenize\n"
        "    destinations: {get_account: allow}\n  PERSON: *rules\n",
        encoding="utf-8",
    )
    gate = TrustGate.from_yaml(path)
    assert gate.policy is not None
    for entity_type in ("ACCOUNT_NUMBER", "PERSON"):
        for destination, expected in (
            ("get_account", DataReleaseDecision.ALLOW),
            ("update_account", DataReleaseDecision.DENY),
        ):
            assert (
                decide_data_release(
                    gate.policy,
                    DataReleaseRequest(entity_type=entity_type, destination=destination),
                ).decision
                is expected
            )


def test_caller_policy_mutation_cannot_add_a_release_permission():
    data = {
        "version": 1,
        "data_policies": {
            "ACCOUNT_NUMBER": {"external_llm": "tokenize", "destinations": {"get_account": "deny"}}
        },
    }
    policy = TrustPolicy.model_validate(data)
    data["data_policies"]["ACCOUNT_NUMBER"]["destinations"]["get_account"] = "allow"
    data["data_policies"]["ACCOUNT_NUMBER"]["destinations"]["update_account"] = "allow"
    for destination in ("get_account", "update_account"):
        assert (
            decide_data_release(
                policy, DataReleaseRequest(entity_type="ACCOUNT_NUMBER", destination=destination)
            ).decision
            is DataReleaseDecision.DENY
        )
