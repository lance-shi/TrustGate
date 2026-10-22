"""Tests fixing the intended Day 1 public library surface."""

import trustgate
from trustgate.entity import EntityResolver
from trustgate.transcript import _SanitizedTranscript
from trustgate.vault import TokenRegistry, TokenVault, VaultEntry


def test_public_api_exports_the_core_types() -> None:
    expected = {
        "TrustGate",
        "TrustSession",
        "SensitiveEntity",
        "SensitiveToken",
        "ToolCall",
        "DataReleaseDecision",
        "AuditEvent",
        "AuditResolution",
        "TranscriptEntry",
        "TranscriptEntryType",
        "EntityResolutionState",
        "EntityResolutionReason",
        "EntityResolutionError",
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


def test_public_exports_and_session_surface_have_no_direct_vault_capability() -> None:
    private_types = (TokenVault, TokenRegistry, VaultEntry, EntityResolver, _SanitizedTranscript)
    for name in trustgate.__all__:
        value = getattr(trustgate, name)
        assert value not in private_types
        assert not isinstance(value, private_types)
    for private_type in private_types:
        assert private_type.__name__ not in trustgate.__all__
        assert not hasattr(trustgate, private_type.__name__)
    public_members = {name for name in vars(trustgate.TrustSession) if not name.startswith("_")}
    assert public_members == {
        "transcript",
        "session_id",
        "is_closed",
        "decide_data_release",
        "close",
        "sanitize",
        "rehydrate_for_tool",
        "sanitize_tool_result",
        "rehydrate_for_user",
    }
    assert not hasattr(trustgate.TrustSession, "vault")
    assert not hasattr(trustgate.TrustSession, "resolve")
    assert not hasattr(trustgate.TrustSession, "store")
    assert not hasattr(trustgate.TrustSession, "append")


def test_new_failure_types_are_public_static_errors() -> None:
    for name in ("AuditRecordingError", "ToolArgumentRehydrationError"):
        error_type = getattr(trustgate, name)
        assert name in trustgate.__all__
        assert issubclass(error_type, trustgate.TrustGateError)
        error = error_type()
        assert error.args == (error_type.default_message,)
        assert error.__cause__ is error.__context__ is None
