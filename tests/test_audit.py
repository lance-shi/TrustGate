"""Tests for in-memory audit events around sensitive-data boundaries."""

from security_assertions import assert_no_raw_sensitive_values

from trustgate import (
    AuditEvent,
    AuditEventType,
    InMemoryAuditSink,
    ToolCall,
    TrustGate,
    TrustPolicy,
)
from trustgate.audit import audit_identifier

RAW_ACCOUNT = "RAW_ACCOUNT_DO_NOT_LEAK_12345678"
RAW_DESTINATION = "RAW_DESTINATION_DO_NOT_LEAK_JANE_SMITH"


class FalsyAuditSink:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def __bool__(self) -> bool:
        return False

    def record(self, event: AuditEvent) -> None:
        self.events.append(event)


def test_rehydration_audit_records_only_token_metadata() -> None:
    audit_sink = InMemoryAuditSink()
    gate = TrustGate(
        audit_sink=audit_sink,
        policy=TrustPolicy(
            version=1,
            data_policies={
                "ACCOUNT_NUMBER": {
                    "external_llm": "tokenize",
                    "destinations": {"get_account": "allow"},
                }
            },
        ),
    )
    session = gate.session()
    token = session._vault.store(value=RAW_ACCOUNT, entity_type="ACCOUNT_NUMBER")

    session.rehydrate_for_tool(ToolCall(name="get_account", arguments={"account": token.value}))

    event = audit_sink.events[-1]
    assert event.event_type is AuditEventType.TOOL_RELEASE_ALLOWED
    assert event.tokens == (audit_identifier(token.value),)
    assert_no_raw_sensitive_values(audit_sink.events, RAW_ACCOUNT)


def test_audit_never_records_a_raw_destination() -> None:
    audit_sink = InMemoryAuditSink()
    gate = TrustGate(
        audit_sink=audit_sink,
        policy=TrustPolicy(
            version=1,
            data_policies={
                "ACCOUNT_NUMBER": {
                    "external_llm": "tokenize",
                    "destinations": {RAW_DESTINATION: "allow"},
                }
            },
        ),
    )
    session = gate.session()
    token = session._vault.store(value=RAW_ACCOUNT, entity_type="ACCOUNT_NUMBER")

    session.rehydrate_for_tool(ToolCall(name=RAW_DESTINATION, arguments={"account": token.value}))

    event = audit_sink.events[-1]
    assert event.destination == audit_identifier(RAW_DESTINATION)
    assert_no_raw_sensitive_values(audit_sink.events, RAW_ACCOUNT, RAW_DESTINATION)


def test_no_token_tool_call_does_not_emit_a_release_audit_event() -> None:
    audit_sink = InMemoryAuditSink()
    session = TrustGate(audit_sink=audit_sink).session()

    assert session.rehydrate_for_tool(ToolCall(name="get_account", arguments={"limit": 2})) == {
        "limit": 2
    }

    assert [event.event_type for event in audit_sink.events] == [AuditEventType.SESSION_OPENED]


def test_falsy_audit_sink_is_retained() -> None:
    audit_sink = FalsyAuditSink()

    TrustGate(audit_sink=audit_sink).session()

    assert [event.event_type for event in audit_sink.events] == [AuditEventType.SESSION_OPENED]
