"""Whole-flow regressions through the public API and the real local detector."""

import re
from copy import deepcopy
from pathlib import Path

import pytest
from security_assertions import assert_no_raw_sensitive_values

from trustgate import (
    AuditEventType,
    CrossSessionTokenError,
    DataReleaseDenied,
    DetectionUnavailableError,
    SensitiveEntity,
    SessionClosedError,
    ToolCall,
    ToolResultSanitizationError,
    TrustGate,
    TrustSession,
)

POLICY_PATH = Path(__file__).resolve().parents[1] / "examples" / "sample-policy.yaml"


def _mock_llm(safe_input: str, destination: str) -> ToolCall:
    """The LLM side receives only sanitized text and returns token references."""
    assert_no_raw_sensitive_values(safe_input, "Ada", "Lovelace", "12345678")
    person = re.search(r"\[PERSON_[1-9][0-9]*\]", safe_input)
    account = re.search(r"\[ACCOUNT_NUMBER_[1-9][0-9]*\]", safe_input)
    assert person is not None and account is not None
    return ToolCall(
        name=destination,
        arguments={"request": {"owners": [person.group()], "account": account.group()}},
    )


@pytest.mark.parametrize("destination", ["get_account", "update_account"])
def test_real_detector_input_tool_result_followup_and_session_close(
    destination: str, caplog
) -> None:
    gate = TrustGate.from_yaml(POLICY_PATH)
    transcript = []
    with gate.session() as session:
        safe_input = session.sanitize("Ada Lovelace has account 12345678.")
        transcript.append(safe_input)
        call = _mock_llm(safe_input, destination)
        original_call = call.model_dump()
        arguments = session.rehydrate_for_tool(call)
        assert arguments == {"request": {"owners": ["Ada Lovelace"], "account": "12345678"}}
        assert call.model_dump() == original_call
        person_token = call.arguments["request"]["owners"][0]
        account_token = call.arguments["request"]["account"]

        # Trusted tool runtime sees approved raw arguments. Its raw return is
        # never added to the LLM transcript.
        raw_result = {
            "owners": [{"name": "Ada Lovelace", "account": "12345678"}],
            "Mr Lovelace": ["Ada", "12345678"],
            "empty": ["", {}, [], None],
        }
        original_result = deepcopy(raw_result)
        safe_result = session.sanitize_tool_result(raw_result)
        assert raw_result == original_result
        assert safe_result == {
            "owners": [{"name": person_token, "account": account_token}],
            person_token: [person_token, account_token],
            "empty": ["", {}, [], None],
        }
        transcript.append(safe_result)
        followup = session.sanitize("Mr Lovelace")
        assert followup == person_token
        transcript.append(followup)
        with pytest.raises(DataReleaseDenied) as denied:
            session.rehydrate_for_tool(ToolCall(name="send_email", arguments={"person": followup}))
        assert_no_raw_sensitive_values(denied.value, "Ada", "Lovelace", "12345678")
        other = gate.session()
        with other, pytest.raises(CrossSessionTokenError):
            other.rehydrate_for_tool(call)

    assert session.is_closed
    with pytest.raises(SessionClosedError):
        session.rehydrate_for_tool(call)
    assert_no_raw_sensitive_values(
        (transcript, gate.audit_sink.events, caplog.text), "Ada", "Lovelace", "12345678"
    )
    assert any(
        event.event_type is AuditEventType.TOOL_RELEASE_DENIED for event in gate.audit_sink.events
    )


def test_real_detector_custom_alias_and_builtin_alias_ambiguity(caplog) -> None:
    gate = TrustGate.from_yaml(POLICY_PATH)
    transcript = []
    with gate.session(aliases={"Liz": ["Elizabeth"]}) as session:
        canonical = session.sanitize("Elizabeth Taylor")
        assert session.sanitize("Liz Taylor") == canonical
        safe_input = session.sanitize("Joanna Taylor met Joseph Taylor. Ask Jo Taylor.")
        tokens = re.findall(r"\[PERSON_[1-9][0-9]*\]", safe_input)
        assert len(tokens) == len(set(tokens)) == 3
        assert session.sanitize("Jo Taylor") == tokens[-1]
        call = ToolCall(name="get_account", arguments={"person": canonical})
        assert session.rehydrate_for_tool(call) == {"person": "Elizabeth Taylor"}
        result = session.sanitize_tool_result({"owner": "Liz Taylor", "uncertain": "Jo Taylor"})
        assert result == {"owner": canonical, "uncertain": tokens[-1]}
        transcript.extend([canonical, safe_input, result])
    assert_no_raw_sensitive_values(
        (transcript, gate.audit_sink.events, caplog.text),
        "Elizabeth",
        "Liz",
        "Joanna",
        "Joseph",
        "Jo Taylor",
        "Taylor",
    )


def test_real_detector_does_not_promote_an_earlier_unresolved_name() -> None:
    with TrustGate.from_yaml(POLICY_PATH).session() as session:
        earlier = session.sanitize("Ada")
        canonical = session.sanitize("Ada Lovelace")
        assert session.sanitize("Ada") == earlier != canonical
        result = session.sanitize_tool_result({"name": "Ada", "full": "Ada Lovelace"})
        assert result == {"name": earlier, "full": canonical}


def test_alias_key_collision_fails_without_modifying_result_or_exposing_values() -> None:
    gate = TrustGate.from_yaml(POLICY_PATH)
    with gate.session(aliases={"Liz": ["Elizabeth"]}) as session:
        session.sanitize("Elizabeth Taylor")
        result = {"Elizabeth Taylor": "first", "Liz Taylor": "second"}
        original = deepcopy(result)
        with pytest.raises(ToolResultSanitizationError) as error:
            session.sanitize_tool_result(result)
        assert result == original
        assert_no_raw_sensitive_values(
            (error.value, gate.audit_sink.events), "Elizabeth", "Liz", "Taylor"
        )


@pytest.mark.parametrize("tool_result", [True, False])
def test_detector_failure_closes_session_and_cannot_expose_exception_context(
    tool_result: bool,
) -> None:
    class FailingDetector:
        def detect(self, text: str) -> tuple[SensitiveEntity, ...]:
            raise RuntimeError(text)

    session = TrustSession(detector=FailingDetector(), aliases={"Liz": ["Elizabeth"]})
    with pytest.raises(DetectionUnavailableError) as error:
        with session:
            if tool_result:
                session.sanitize_tool_result({"person": "RAW_PERSON_DO_NOT_LEAK"})
            else:
                session.sanitize("RAW_PERSON_DO_NOT_LEAK")
    assert error.value.__cause__ is error.value.__context__ is None
    assert session.is_closed
    assert session._vault._entries_by_token == {}
    assert session._entity_resolver._alias_resolver._aliases == frozenset()
    assert_no_raw_sensitive_values(error.value, "RAW_PERSON_DO_NOT_LEAK")
