"""Candidate generation is read-only; identity decisions are session-local."""

import json
from dataclasses import asdict, fields
from itertools import permutations

import pytest

from trustgate.entity import (
    EntityCandidate,
    EntityResolver,
    ExactNameResolver,
    PersonIdentity,
    PersonName,
)
from trustgate.entity import (
    EntityResolutionReason as Reason,
)
from trustgate.entity import (
    EntityResolutionState as State,
)


def _register(resolver: EntityResolver, value: str) -> str:
    result = resolver.resolve_exact_full_name(surface_form=value, start=0, end=len(value))
    assert result.entity is not None
    return result.entity.entity_id


@pytest.mark.parametrize(
    ("value", "components", "title"),
    [
        ("John", ("john",), None),
        ("Mr. Smith", ("smith",), "mr"),
        ("Ｍｒ．　Ｊｏｈｎ　Ｓｍｉｔｈ", ("john", "smith"), "mr"),
        (" Dr. John Paul O'Connor ", ("john", "paul", "o'connor"), "dr"),
        ("John-Smith", ("john-smith",), None),
        ("", (), None),
        ("Mr.", (), "mr"),
    ],
)
def test_structured_name_preserves_title_and_order(value, components, title) -> None:
    name = PersonName.parse(value)
    assert name.components == components
    assert name.title == title
    assert repr(name) == "PersonName()"


def test_exact_producer_returns_only_ids_and_reasons_without_mutating_sources() -> None:
    identity = PersonIdentity(entity_id="a" * 32, name=PersonName.parse("John Smith"))
    other = PersonIdentity(entity_id="b" * 32, name=PersonName.parse("Larry Smith"))
    identities = (identity, other)
    before = tuple(asdict(item) for item in identities)

    candidates = ExactNameResolver().candidates(
        name=PersonName.parse("MR. JOHN SMITH"), identities=identities
    )

    assert candidates == (EntityCandidate(identity.entity_id, Reason.EXACT_NORMALIZED_FULL_NAME),)
    assert tuple(asdict(item) for item in identities) == before
    assert {item.name for item in fields(EntityCandidate)} == {"entity_id", "reason"}
    diagnostics = repr(candidates) + json.dumps([asdict(item) for item in candidates])
    for sensitive in ("John Smith", "john smith", "Larry Smith", "larry smith"):
        assert sensitive not in diagnostics
        assert sensitive not in repr(identities)


@pytest.mark.parametrize("value", ["John", "Mr Smith", "John-Smith", "John Jones"])
def test_exact_producer_does_not_infer_partial_or_alias_matches(value: str) -> None:
    identity = PersonIdentity(entity_id="a" * 32, name=PersonName.parse("John Smith"))
    assert (
        ExactNameResolver().candidates(name=PersonName.parse(value), identities=(identity,)) == ()
    )


def test_duplicate_evidence_for_one_identity_is_not_ambiguous() -> None:
    resolver = EntityResolver()
    entity_id = _register(resolver, "John Smith")
    evidence = tuple(
        EntityCandidate(entity_id, reason)
        for reason in (
            Reason.EXACT_NORMALIZED_FULL_NAME,
            Reason.UNIQUE_PARTIAL_NAME,
            Reason.UNIQUE_ALIAS_MATCH,
        )
    )
    for ordered in permutations(evidence):
        result = resolver._resolve_candidates(ordered + ordered)
        assert result.state is State.EXACT
        assert result.entity is not None
        assert result.entity.entity_id == entity_id
        assert result.entity.canonical_value == "John Smith"


@pytest.mark.parametrize("reason", [Reason.UNIQUE_PARTIAL_NAME, Reason.UNIQUE_ALIAS_MATCH])
def test_conflicting_candidates_stay_ambiguous_even_with_exact_evidence(reason: Reason) -> None:
    resolver = EntityResolver()
    first = _register(resolver, "John Smith")
    second = _register(resolver, "Larry Smith")
    evidence = (
        EntityCandidate(first, Reason.EXACT_NORMALIZED_FULL_NAME),
        EntityCandidate(second, reason),
    )
    for ordered in permutations(evidence):
        result = resolver._resolve_candidates(ordered)
        assert result.state is State.AMBIGUOUS
        assert result.entity is None


def test_no_candidates_does_not_create_an_identity() -> None:
    resolver = EntityResolver()
    result = resolver._resolve_candidates(())
    assert result.state is State.UNRESOLVED
    assert result.reason is Reason.NO_CANDIDATES
    assert resolver._entities_by_id == {}


@pytest.mark.parametrize(
    ("reason", "state"),
    [
        (Reason.UNIQUE_PARTIAL_NAME, State.UNIQUE_PARTIAL),
        (Reason.UNIQUE_ALIAS_MATCH, State.UNIQUE_ALIAS),
    ],
)
def test_one_eligible_identity_can_be_confirmed_by_each_evidence_type(reason, state) -> None:
    resolver = EntityResolver()
    entity_id = _register(resolver, "John Smith")
    result = resolver._resolve_candidates((EntityCandidate(entity_id, reason),))
    assert result.state is state
    assert result.entity is not None
    assert result.entity.entity_id == entity_id


def test_resolver_collects_all_producers_before_deciding() -> None:
    resolver = EntityResolver()
    _register(resolver, "John Smith")
    second_id = _register(resolver, "Larry Smith")

    class ConflictingProducer:
        def candidates(self, *, name, identities):
            return (EntityCandidate(second_id, Reason.UNIQUE_ALIAS_MATCH),)

    resolver._candidate_producers = (ExactNameResolver(), ConflictingProducer())
    result = resolver.resolve_person(surface_form="John Smith", start=0, end=10).resolution
    assert result.state is State.AMBIGUOUS
    assert result.entity is None
    assert len(resolver._entities_by_id) == 2


def test_cross_resolver_and_cleared_candidates_are_rejected() -> None:
    owner = EntityResolver()
    candidate = EntityCandidate(_register(owner, "John Smith"), Reason.EXACT_NORMALIZED_FULL_NAME)
    other = EntityResolver()
    _register(other, "John Smith")
    for resolver in (other, owner):
        if resolver is owner:
            resolver.clear()
            assert resolver._identities_by_id == {}
            assert resolver._entities_by_id == {}
        with pytest.raises(ValueError) as error:
            resolver._resolve_candidates((candidate,))
        assert "John Smith" not in str(error.value)
        assert "john smith" not in repr(error.value)


@pytest.mark.parametrize(
    ("entity_id", "reason"),
    [
        ("RAW_PERSON_John Smith", Reason.UNIQUE_ALIAS_MATCH),
        ("a" * 32, "RAW_ALIAS_Joanna"),
        ("a" * 32, Reason.AMBIGUOUS_CANDIDATES),
    ],
)
def test_candidate_validation_does_not_disclose_invalid_input(entity_id, reason) -> None:
    with pytest.raises(ValueError) as error:
        EntityCandidate(entity_id=entity_id, reason=reason)
    assert str(error.value) == "Invalid private entity candidate."
