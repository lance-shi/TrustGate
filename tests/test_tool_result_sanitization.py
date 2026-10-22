"""Tests for recursive tool-result sanitization and safe auditing."""

from dataclasses import dataclass

import pytest
from security_assertions import assert_no_raw_sensitive_values

from trustgate import (
    AuditEventType,
    AuditFailureReason,
    DetectionUnavailableError,
    InMemoryAuditSink,
    SensitiveEntity,
    ToolResultSanitizationError,
    TrustSession,
)

RAW_ACCOUNT = "RAW_ACCOUNT_DO_NOT_LEAK_12345678"
RAW_PERSON = "RAW_PERSON_DO_NOT_LEAK_JANE_SMITH"


@dataclass(frozen=True)
class MappingDetector:
    entities_by_text: dict[str, tuple[SensitiveEntity, ...]]

    def detect(self, text: str) -> tuple[SensitiveEntity, ...]:
        return self.entities_by_text.get(text, ())


def _entity(entity_type: str, text: str) -> SensitiveEntity:
    return SensitiveEntity(entity_type=entity_type, start=0, end=len(text), score=0.9)


def _session(audit_sink: InMemoryAuditSink) -> TrustSession:
    detector = MappingDetector(
        {
            RAW_ACCOUNT: (_entity("ACCOUNT_NUMBER", RAW_ACCOUNT),),
            RAW_PERSON: (_entity("PERSON", RAW_PERSON),),
        }
    )
    return TrustSession(detector=detector, audit_sink=audit_sink)


def test_sanitize_tool_result_recursively_sanitizes_values_and_keys_without_mutation() -> None:
    audit_sink = InMemoryAuditSink()
    session = _session(audit_sink)
    result = {
        "owner": RAW_PERSON,
        "nested": {"account": RAW_ACCOUNT},
        "items": [RAW_PERSON, 2],
        RAW_PERSON: "sensitive key",
    }
    original = {
        "owner": RAW_PERSON,
        "nested": {"account": RAW_ACCOUNT},
        "items": [RAW_PERSON, 2],
        RAW_PERSON: "sensitive key",
    }

    sanitized = session.sanitize_tool_result(result)

    assert sanitized is not result
    assert result == original
    assert_no_raw_sensitive_values(sanitized, RAW_ACCOUNT, RAW_PERSON)
    assert sanitized["owner"] == sanitized["items"][0]
    assert any(key.startswith("[PERSON_") for key in sanitized)


def test_tool_result_sanitization_audit_contains_only_safe_metadata() -> None:
    audit_sink = InMemoryAuditSink()
    session = _session(audit_sink)

    session.sanitize_tool_result({"account": RAW_ACCOUNT, "person": RAW_PERSON})
    session.close()

    events = audit_sink.events
    assert [event.event_type for event in events] == [
        AuditEventType.SESSION_OPENED,
        AuditEventType.TOOL_RESULT_SANITIZED,
        AuditEventType.SESSION_CLOSED,
    ]
    assert all(identifier.startswith("audit_") for identifier in events[1].entity_types)
    assert_no_raw_sensitive_values(events, RAW_ACCOUNT, RAW_PERSON)


def test_tool_result_key_collision_fails_closed_without_disclosing_raw_values() -> None:
    audit_sink = InMemoryAuditSink()
    session = _session(audit_sink)
    token = session.sanitize(RAW_PERSON)

    with pytest.raises(ToolResultSanitizationError) as error:
        session.sanitize_tool_result({RAW_PERSON: "first", token: "second"})

    assert_no_raw_sensitive_values(error.value, RAW_PERSON)
    assert audit_sink.events[-1].event_type is AuditEventType.TOOL_RESULT_SANITIZATION_FAILED
    assert audit_sink.events[-1].failure_reason is AuditFailureReason.UNSAFE_RESULT_STRUCTURE


def test_non_json_tool_result_fails_closed_without_rendering_its_value() -> None:
    raw_value = "RAW_TOOL_RESULT_DO_NOT_LEAK_12345678"

    class UnsupportedResult:
        def __repr__(self) -> str:
            return raw_value

    audit_sink = InMemoryAuditSink()
    session = _session(audit_sink)

    with pytest.raises(ToolResultSanitizationError) as error:
        session.sanitize_tool_result(UnsupportedResult())  # type: ignore[arg-type]

    assert_no_raw_sensitive_values(error.value, raw_value)
    assert audit_sink.events[-1].event_type is AuditEventType.TOOL_RESULT_SANITIZATION_FAILED
    assert audit_sink.events[-1].failure_reason is AuditFailureReason.UNSAFE_RESULT_STRUCTURE


def test_tool_result_detection_failure_is_audited_without_raw_text() -> None:
    raw_value = "RAW_TOOL_RESULT_DO_NOT_LEAK_12345678"

    class FailingDetector:
        def detect(self, text: str) -> tuple[SensitiveEntity, ...]:
            raise RuntimeError(text)

    audit_sink = InMemoryAuditSink()
    session = TrustSession(detector=FailingDetector(), audit_sink=audit_sink)

    with pytest.raises(DetectionUnavailableError) as error:
        session.sanitize_tool_result({"value": raw_value})

    assert_no_raw_sensitive_values(error.value, raw_value)
    event = audit_sink.events[-1]
    assert event.event_type is AuditEventType.TOOL_RESULT_SANITIZATION_FAILED
    assert event.failure_reason is AuditFailureReason.DETECTION_UNAVAILABLE
    assert_no_raw_sensitive_values(event, raw_value)


@pytest.mark.parametrize("invalid_key", [42, (RAW_ACCOUNT,)], ids=["integer", "tuple"])
def test_non_string_result_key_fails_after_prior_sanitization_without_leak_or_mutation(
    invalid_key, caplog
) -> None:
    sink = InMemoryAuditSink()
    result = {"processed": RAW_PERSON, invalid_key: RAW_ACCOUNT}
    original = result.copy()
    with _session(sink) as session:
        with pytest.raises(ToolResultSanitizationError) as error:
            session.sanitize_tool_result(result)  # type: ignore[arg-type]
        assert result == original
        assert error.value.__cause__ is error.value.__context__ is None
        assert sink.events[-1].failure_reason is AuditFailureReason.UNSAFE_RESULT_STRUCTURE
        assert_no_raw_sensitive_values(
            (error.value, [event.model_dump_json() for event in sink.events], caplog.text),
            RAW_PERSON,
            RAW_ACCOUNT,
        )
    assert session._vault._entries_by_token == {}
