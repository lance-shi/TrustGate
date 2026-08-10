"""Tests fixing the intended Day 1 public library surface."""

import trustgate


def test_public_api_exports_the_core_types() -> None:
    expected = {
        "TrustGate",
        "TrustSession",
        "SensitiveEntity",
        "SensitiveToken",
        "ToolCall",
        "DataReleaseDecision",
        "AuditEvent",
        "TrustGateError",
        "DataReleaseDenied",
        "SessionClosedError",
    }

    assert expected <= set(trustgate.__all__)
    for name in expected:
        assert getattr(trustgate, name) is not None


def test_gate_creates_an_explicit_session_with_an_opaque_identifier() -> None:
    gate = trustgate.TrustGate()

    with gate.session(principal="user-123") as session:
        assert len(session.session_id) == 32
        assert not session.is_closed

    assert session.is_closed


def test_gate_creates_distinct_sessions() -> None:
    gate = trustgate.TrustGate()

    first = gate.session()
    second = gate.session()

    assert first is not second
    assert first.session_id != second.session_id
    assert not first.is_closed
    assert not second.is_closed
