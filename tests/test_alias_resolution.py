"""Alias decisions use complete session-local candidate sets and safe tokens."""

from dataclasses import dataclass
from itertools import permutations

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
from trustgate.entity import AliasResolver, ExactNameResolver, PartialNameResolver
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
        audit_sink=InMemoryAuditSink(),
        policy=TrustPolicy(
            version=1,
            data_policies={
                "PERSON": {
                    "external_llm": "tokenize",
                    "destinations": {"lookup_person": decision, "update_person": decision},
                }
            },
        ),
    )


def _rehydrate(session: TrustSession, token: str, destination: str = "lookup_person") -> str:
    result = session.rehydrate_for_tool(ToolCall(name=destination, arguments={"person": token}))
    assert isinstance(result["person"], str)
    return result["person"]


@pytest.mark.parametrize(
    ("canonical", "alias"),
    [
        ("Joanna Taylor", "Jo Taylor"),
        ("Joanna Taylor", "Jo"),
        ("Joseph Taylor", "Joe Taylor"),
        ("Joanne Anne Taylor", "Dr. JO Anne Taylor"),
    ],
)
@pytest.mark.parametrize("destination", ["lookup_person", "update_person"])
def test_unique_alias_reuses_token_and_canonical_tool_value(canonical, alias, destination) -> None:
    session = _session(canonical, alias)
    token = session.sanitize(canonical)
    assert session.sanitize(alias) == token
    assert _rehydrate(session, token, destination) == canonical
    assert session._entity_resolver._mention_states[-1].state is State.UNIQUE_ALIAS
    assert len(session._entity_resolver._identities_by_id) == 1
    assert_no_raw_sensitive_values(token, canonical, alias)


@pytest.mark.parametrize("alias", ["Jo Taylor", "Jo"])
def test_alias_collisions_remain_distinct_stable_and_ambiguous(alias: str) -> None:
    session = _session("Joanna Taylor", "Joseph Taylor", alias)
    first = session.sanitize("Joanna Taylor")
    second = session.sanitize("Joseph Taylor")
    token = session.sanitize(alias)
    assert len({first, second, token}) == 3
    assert session.sanitize(alias) == token
    assert _rehydrate(session, token) == alias
    assert all(
        item.state is State.AMBIGUOUS for item in session._entity_resolver._mention_states[-2:]
    )
    assert len(session._entity_resolver._identities_by_id) == 2


def test_surname_can_narrow_alias_candidates_without_narrowing_bare_alias() -> None:
    session = _session("Joanna Taylor", "Joseph Jones", "Jo Taylor", "Jo")
    first = session.sanitize("Joanna Taylor")
    second = session.sanitize("Joseph Jones")
    assert session.sanitize("Jo Taylor") == first
    bare = session.sanitize("Jo")
    assert bare not in (first, second)
    assert session._entity_resolver._mention_states[-1].state is State.AMBIGUOUS


@pytest.mark.parametrize("conflict", ["exact", "partial"])
def test_alias_conflicts_cannot_be_resolved_by_producer_order(conflict: str) -> None:
    producers = (ExactNameResolver(), PartialNameResolver(), AliasResolver())
    for ordered in permutations(producers):
        session = _session("Jo Taylor", "Jo Smith", "Joanna Taylor", "Jo")
        first = session.sanitize("Jo Taylor" if conflict == "exact" else "Jo Smith")
        second = session.sanitize("Joanna Taylor")
        session._entity_resolver._candidate_producers = ordered
        token = session.sanitize("Jo Taylor" if conflict == "exact" else "Jo")
        assert token not in (first, second)
        assert session._entity_resolver._mention_states[-1].state is State.AMBIGUOUS


def test_unresolved_alias_is_not_promoted_by_later_full_names_or_tool_results() -> None:
    session = _session("Jo", "Joanna Taylor", "Joseph Taylor")
    token = session.sanitize("Jo")
    earlier = session._entity_resolver._mention_states[0]
    session.sanitize("Joanna Taylor")
    assert session.sanitize("Jo") == token
    result = session.sanitize_tool_result({"person": "Joseph Taylor", "alias": "Jo"})
    assert result["alias"] == token
    assert _rehydrate(session, token) == "Jo"
    assert earlier.state is State.UNRESOLVED
    assert session._entity_resolver._mention_states[-1].state is State.UNRESOLVED


def test_later_alias_conflict_does_not_change_previous_confirmed_token() -> None:
    session = _session("Joanna Taylor", "Joseph Taylor", "Jo Taylor")
    first = session.sanitize("Joanna Taylor")
    assert session.sanitize("Jo Taylor") == first
    earlier = session._entity_resolver._mention_states[-1]
    second = session.sanitize("Joseph Taylor")
    ambiguous = session.sanitize("Jo Taylor")
    assert ambiguous not in (first, second)
    assert earlier.state is State.UNIQUE_ALIAS
    assert session.sanitize("Jo Taylor") == ambiguous
    assert _rehydrate(session, first) == "Joanna Taylor"
    assert _rehydrate(session, ambiguous) == "Jo Taylor"


def test_alias_tool_results_are_copied_and_diagnostics_remain_safe(caplog) -> None:
    session = _session("Joanna Taylor", "Jo Taylor")
    token = session.sanitize("Joanna Taylor")
    result = {"owners": [{"name": "Jo Taylor"}], "Jo Taylor": "Joanna Taylor"}
    safe = session.sanitize_tool_result(result)
    assert safe == {"owners": [{"name": token}], token: token}
    assert result == {"owners": [{"name": "Jo Taylor"}], "Jo Taylor": "Joanna Taylor"}
    _rehydrate(session, token)
    assert_no_raw_sensitive_values(
        (
            safe,
            session._audit_sink.events,
            repr(session._entity_resolver._mention_states),
            caplog.text,
        ),
        "Jo Taylor",
        "Joanna Taylor",
        "joanna",
        "taylor",
    )


@pytest.mark.parametrize("decision", ["deny", "missing"])
def test_alias_resolution_does_not_bypass_policy(decision: str) -> None:
    session = _session("Joanna Taylor", "Jo Taylor", decision="deny")
    if decision == "missing":
        session._policy = None
    session.sanitize("Joanna Taylor")
    token = session.sanitize("Jo Taylor")
    with pytest.raises(DataReleaseDenied) as error:
        _rehydrate(session, token)
    assert_no_raw_sensitive_values(error.value, "Joanna Taylor", "Jo Taylor")


def test_alias_resolution_and_tokens_stay_session_local() -> None:
    owner = _session("Joanna Taylor", "Jo Taylor")
    other = _session("Joanna Taylor", "Jo Taylor")
    token = owner.sanitize("Joanna Taylor")
    assert owner.sanitize("Jo Taylor") == token
    other_token = other.sanitize("Jo Taylor")
    assert other_token != token
    assert _rehydrate(other, other_token) == "Jo Taylor"
    with pytest.raises(CrossSessionTokenError):
        _rehydrate(other, token)
    owner.close()
    assert owner._entity_resolver._identities_by_id == {}
    assert owner._entity_resolver._mention_states == []
    with pytest.raises(SessionClosedError):
        _rehydrate(owner, token)


@pytest.mark.parametrize("ambiguous", [True, False])
def test_uncertain_alias_diagnostics_do_not_disclose_names(ambiguous: bool, caplog) -> None:
    session = _session("Joanna Taylor", "Joseph Taylor", "Jo")
    if ambiguous:
        session.sanitize("Joanna Taylor")
        session.sanitize("Joseph Taylor")
    token = session.sanitize("Jo")
    expected = State.AMBIGUOUS if ambiguous else State.UNRESOLVED
    assert session._entity_resolver._mention_states[-1].state is expected
    assert_no_raw_sensitive_values(
        (
            token,
            session._audit_sink.events,
            repr(session._entity_resolver._mention_states),
            caplog.text,
        ),
        "Joanna Taylor",
        "Joseph Taylor",
        "Jo",
        "joanna",
        "joseph",
        "taylor",
    )
