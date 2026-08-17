"""Tests for in-memory audit events around sensitive-data boundaries."""

from security_assertions import assert_no_raw_sensitive_values

from trustgate import (
    AuditEventType,
    InMemoryAuditSink,
    ToolCall,
    TrustGate,
    TrustPolicy,
)

RAW_ACCOUNT = "RAW_ACCOUNT_DO_NOT_LEAK_12345678"


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
    assert event.tokens == (token.value,)
    assert_no_raw_sensitive_values(audit_sink.events, RAW_ACCOUNT)
