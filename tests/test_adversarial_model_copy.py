"""Model-copy failures must not serialize or log caller-owned secret objects."""

import warnings
from collections.abc import Mapping

import pytest
from security_assertions import assert_no_raw_sensitive_values

from trustgate import (
    ModelValidationError,
    PolicyValidationError,
    SensitiveToken,
    ToolCall,
    TrustPolicy,
)

RAW = "MODEL_COPY_SECRET_Adversarial_Fixture"


class FailingUpdate(Mapping):
    def __iter__(self):
        raise RuntimeError(RAW)

    def __len__(self):
        return 1

    def __getitem__(self, key):
        raise RuntimeError(RAW)


class SecretObject:
    def __repr__(self):
        return RAW


@pytest.mark.parametrize("kind", ["token", "call", "policy"])
def test_copy_update_iterator_errors_have_only_safe_model_errors(kind, caplog, capsys):
    model = {
        "token": lambda: SensitiveToken(value="[PERSON_1]", entity_type="PERSON"),
        "call": lambda: ToolCall(name="lookup"),
        "policy": lambda: TrustPolicy(version=1, data_policies={}),
    }[kind]()
    expected = PolicyValidationError if kind == "policy" else ModelValidationError
    with pytest.raises(expected) as error:
        model.model_copy(update=FailingUpdate())
    assert error.value.__cause__ is error.value.__context__ is None
    captured = capsys.readouterr()
    assert_no_raw_sensitive_values((error.value, caplog.text, captured.out, captured.err), RAW)


def test_copy_of_mutated_call_does_not_emit_serializer_warning_with_raw_repr(caplog, capsys):
    call = ToolCall(name="lookup")
    value = SecretObject()
    call.arguments["bad"] = value
    with warnings.catch_warnings(record=True) as emitted:
        warnings.simplefilter("always")
        with pytest.raises(ModelValidationError) as error:
            call.model_copy()
    assert call.arguments["bad"] is value
    assert error.value.__cause__ is error.value.__context__ is None
    captured = capsys.readouterr()
    assert_no_raw_sensitive_values(
        (error.value, [str(w.message) for w in emitted], caplog.text, captured.out, captured.err),
        RAW,
    )
    assert emitted == []


@pytest.mark.parametrize("deep", [False, True])
def test_valid_model_copy_preserves_validation_and_independent_argument_containers(deep):
    call = ToolCall(name="lookup", arguments={"nested": [{"value": "[PERSON_1]"}]})
    copied = call.model_copy(deep=deep)
    assert copied == call
    assert copied.arguments is not call.arguments
    copied.arguments["nested"][0]["value"] = "ordinary"
    assert call.arguments["nested"][0]["value"] == "[PERSON_1]"
