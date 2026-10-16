"""Session integration for unique partials and immutable uncertain identities."""

import json
from dataclasses import asdict, dataclass

import pytest
from security_assertions import assert_no_raw_sensitive_values

from trustgate import (
    CrossSessionTokenError,
    DataReleaseDenied,
    InMemoryAuditSink,
    SensitiveEntity,
    SessionClosedError,
    ToolCall,
    TrustPolicy,
    TrustSession,
)
from trustgate.entity import EntityResolutionState as State


@dataclass(frozen=True)
class NameDetector:
    names: tuple[str, ...]

    def detect(self, text: str) -> tuple[SensitiveEntity, ...]:
        if text not in self.names:
            return ()
        return (SensitiveEntity(entity_type="PERSON", start=0, end=len(text), score=0.9),)


def _session(*names: str, decision: str = "allow") -> TrustSession:
    return TrustSession(
        detector=NameDetector(names),
        policy=TrustPolicy(
            version=1,
            data_policies={
                "PERSON": {
                    "external_llm": "tokenize",
                    "destinations": {"lookup_person": decision, "update_person": decision},
                }
            },
        ),
        audit_sink=InMemoryAuditSink(),
    )


def _rehydrate(session: TrustSession, token: str, destination: str = "lookup_person") -> str:
    result = session.rehydrate_for_tool(ToolCall(name=destination, arguments={"person": token}))
    assert isinstance(result["person"], str)
    return result["person"]


@pytest.mark.parametrize(
    ("full_name", "partial"),
    [
        ("John Smith", "John"),
        ("John Smith", "Mr Smith"),
        ("John Paul Smith", "JOHN"),
        ("John Smith", "Ｍｒ．　Ｓｍｉｔｈ"),
        ("Jos\u00e9 Smith", "Jose\u0301"),
    ],
)
@pytest.mark.parametrize("destination", ["lookup_person", "update_person"])
def test_unique_partial_reuses_canonical_token(full_name, partial, destination) -> None:
    session = _session(full_name, partial)
    canonical_token = session.sanitize(full_name)
    assert session.sanitize(partial) == canonical_token
    assert _rehydrate(session, canonical_token, destination) == full_name
    states = session._entity_resolver._mention_states
    assert [item.state for item in states] == [State.EXACT, State.UNIQUE_PARTIAL]
    assert states[0].token_entity_id == states[1].token_entity_id
    assert_no_raw_sensitive_values(canonical_token, full_name, partial)


@pytest.mark.parametrize(
    ("first", "second", "partial"),
    [("John Smith", "Larry Smith", "Mr Smith"), ("John Smith", "John Taylor", "John")],
)
def test_multiple_candidates_get_an_independent_stable_token(first, second, partial) -> None:
    session = _session(first, second, partial)
    first_token, second_token = session.sanitize(first), session.sanitize(second)
    token = session.sanitize(partial)
    assert token not in (first_token, second_token)
    assert session.sanitize(partial) == token
    assert _rehydrate(session, token) == partial
    assert [item.state for item in session._entity_resolver._mention_states][-2:] == [
        State.AMBIGUOUS,
        State.AMBIGUOUS,
    ]


@pytest.mark.parametrize("partial", ["John", "Mr Smith"])
def test_earlier_unresolved_surface_never_merges_after_a_full_name(partial: str) -> None:
    session = _session(partial, "John Smith")
    earlier = session.sanitize(partial)
    snapshot = tuple(session._entity_resolver._mention_states)
    full = session.sanitize("John Smith")
    assert session.sanitize(partial) == earlier != full
    assert _rehydrate(session, earlier) == partial
    assert _rehydrate(session, full) == "John Smith"
    states = session._entity_resolver._mention_states
    assert tuple(states[:1]) == snapshot
    assert states[0].state is states[-1].state is State.UNRESOLVED
    assert len(session._entity_resolver._identities_by_id) == 1


def test_unconfirmed_names_are_not_candidates_for_other_mentions() -> None:
    session = _session("John", "Mr John")
    first = session.sanitize("John")
    second = session.sanitize("Mr John")
    assert first != second
    assert all(item.state is State.UNRESOLVED for item in session._entity_resolver._mention_states)
    assert session._entity_resolver._identities_by_id == {}


def test_later_competitor_does_not_change_earlier_confirmed_identity() -> None:
    session = _session("John Smith", "Mr Smith", "Larry Smith")
    full = session.sanitize("John Smith")
    assert session.sanitize("Mr Smith") == full
    confirmed = session._entity_resolver._mention_states[-1]
    session.sanitize("Larry Smith")
    ambiguous = session.sanitize("Mr Smith")
    assert ambiguous != full
    assert session.sanitize("Mr Smith") == ambiguous
    assert confirmed.state is State.UNIQUE_PARTIAL
    assert session._entity_resolver._mention_states[1] is confirmed
    assert _rehydrate(session, full) == "John Smith"
    assert _rehydrate(session, ambiguous) == "Mr Smith"


def test_nested_tool_results_share_resolution_without_mutating_the_result() -> None:
    session = _session("John Smith", "John", "Mr Smith")
    token = session.sanitize("John Smith")
    result = {"owners": [{"name": "John"}], "Mr Smith": "John Smith"}
    safe = session.sanitize_tool_result(result)
    assert safe == {"owners": [{"name": token}], token: token}
    assert result == {"owners": [{"name": "John"}], "Mr Smith": "John Smith"}
    assert_no_raw_sensitive_values(safe, "John", "Mr Smith", "John Smith")


def test_tool_result_cannot_retroactively_resolve_an_uncertain_input() -> None:
    session = _session("John", "John Smith")
    earlier = session.sanitize("John")
    safe = session.sanitize_tool_result({"person": "John Smith", "short": "John"})
    assert safe["short"] == earlier
    assert safe["person"] != earlier
    assert _rehydrate(session, earlier) == "John"


def test_same_text_is_processed_in_observation_order() -> None:
    text = "John met John Smith and John"

    class OrderedDetector:
        def detect(self, text: str) -> tuple[SensitiveEntity, ...]:
            return tuple(
                SensitiveEntity(entity_type="PERSON", start=start, end=end, score=0.9)
                for start, end in ((24, 28), (9, 19), (0, 4))
            )

    session = _session()
    session._detector = OrderedDetector()
    safe = session.sanitize(text)
    states = session._entity_resolver._mention_states
    assert [item.state for item in states] == [State.UNRESOLVED, State.EXACT, State.UNRESOLVED]
    assert states[0].token_entity_id == states[2].token_entity_id != states[1].token_entity_id
    assert_no_raw_sensitive_values(safe, "John", "Smith")


@pytest.mark.parametrize("decision", ["deny", "missing"])
def test_partial_tokens_cannot_bypass_release_policy(decision: str) -> None:
    session = _session("John Smith", "John", decision="deny" if decision == "deny" else "allow")
    if decision == "missing":
        session._policy = None
    session.sanitize("John Smith")
    token = session.sanitize("John")
    with pytest.raises(DataReleaseDenied) as error:
        _rehydrate(session, token)
    assert_no_raw_sensitive_values(error.value, "John Smith", "John")


@pytest.mark.parametrize("partial_first", [True, False])
def test_partial_tokens_cannot_cross_sessions_and_close_clears_all_state(partial_first) -> None:
    session = _session("John Smith", "John")
    if not partial_first:
        session.sanitize("John Smith")
    token = session.sanitize("John")
    other = _session("John Smith", "John")
    other.sanitize("John Smith")
    with pytest.raises(CrossSessionTokenError):
        _rehydrate(other, token)
    session.close()
    resolver = session._entity_resolver
    assert resolver._mention_states == []
    assert resolver._unconfirmed_by_surface_form == {}
    assert resolver._entities_by_id == resolver._identities_by_id == {}
    assert session._vault._tokens_by_identity == {}
    with pytest.raises(SessionClosedError):
        _rehydrate(session, token)


def test_audit_logs_and_mention_metadata_never_disclose_name_values(caplog) -> None:
    session = _session("John Smith", "Larry Smith", "John", "Mr Smith")
    safe_values = [
        session.sanitize(name) for name in ("John Smith", "John", "Larry Smith", "Mr Smith")
    ]
    _rehydrate(session, safe_values[1])
    _rehydrate(session, safe_values[-1])
    metadata = json.dumps([asdict(item) for item in session._entity_resolver._mention_states])
    assert_no_raw_sensitive_values(
        (safe_values, metadata, session._audit_sink.events, caplog.text),
        "John Smith",
        "Larry Smith",
        "John",
        "Mr Smith",
        "john",
        "smith",
    )
