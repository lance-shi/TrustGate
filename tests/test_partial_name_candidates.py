"""Conservative partial matching produces evidence without changing identity."""

import json
from dataclasses import asdict
from itertools import permutations

import pytest
from security_assertions import assert_no_raw_sensitive_values

from trustgate.entity import (
    EntityResolutionReason,
    EntityResolutionState,
    EntityResolver,
    PartialNameResolver,
    PersonIdentity,
    PersonName,
)


def _identities(*names: str) -> tuple[PersonIdentity, ...]:
    return tuple(
        PersonIdentity(entity_id=f"{index:032x}", name=PersonName.parse(name))
        for index, name in enumerate(names, start=1)
    )


@pytest.mark.parametrize(
    ("mention", "full_name", "reason"),
    [
        ("John", "John Smith", EntityResolutionReason.FIRST_NAME_MATCH),
        (" JOHN ", "John Paul Smith", EntityResolutionReason.FIRST_NAME_MATCH),
        ("Ｍｒ．　Ｓｍｉｔｈ", "John Smith", EntityResolutionReason.LAST_NAME_MATCH),
        ("Mr Smith", "John Smith", EntityResolutionReason.LAST_NAME_MATCH),
        ("Mrs. Smith", "Jane Smith", EntityResolutionReason.LAST_NAME_MATCH),
        ("Ms Smith", "Jane Smith", EntityResolutionReason.LAST_NAME_MATCH),
        ("Dr. Smith", "Dr. John Smith", EntityResolutionReason.LAST_NAME_MATCH),
        ("Jose\u0301", "Jos\u00e9 Smith", EntityResolutionReason.FIRST_NAME_MATCH),
        ("Mr O'Connor", "John O'Connor", EntityResolutionReason.LAST_NAME_MATCH),
        ("Mary-Jane", "Mary-Jane Smith", EntityResolutionReason.FIRST_NAME_MATCH),
    ],
)
def test_single_component_matches_the_correct_name_position(
    mention: str, full_name: str, reason: EntityResolutionReason
) -> None:
    identities = _identities(full_name)
    candidates = PartialNameResolver().candidates(
        name=PersonName.parse(mention), identities=identities
    )
    assert len(candidates) == 1
    assert candidates[0].entity_id == identities[0].entity_id
    assert candidates[0].reason is reason


@pytest.mark.parametrize(
    "mention",
    [
        "",
        "Mr.",
        "Smith",
        "Mr John",
        "Paul",
        "J",
        "J.",
        "Joh",
        "Johnny",
        "John Smith",
        "Mr John Smith",
        "Mr. OConnor",
        "Mary",
    ],
)
def test_insufficient_or_incompatible_mentions_do_not_generate_candidates(mention: str) -> None:
    assert (
        PartialNameResolver().candidates(
            name=PersonName.parse(mention),
            identities=_identities("John Paul Smith", "Jane O'Connor", "Mary-Jane Jones"),
        )
        == ()
    )


@pytest.mark.parametrize("mention", ["John", "Mr Smith"])
def test_single_component_sources_are_not_eligible_full_identities(mention: str) -> None:
    assert (
        PartialNameResolver().candidates(
            name=PersonName.parse(mention), identities=_identities("John", "Mr Smith", "")
        )
        == ()
    )


@pytest.mark.parametrize(
    ("mention", "names"),
    [("Mr Smith", ("John Smith", "Larry Smith")), ("John", ("John Smith", "John Taylor"))],
)
def test_ambiguous_mentions_return_all_candidates_without_choosing_one(
    mention: str, names: tuple[str, ...]
) -> None:
    identities = _identities(*names)
    for ordered in permutations(identities):
        candidates = PartialNameResolver().candidates(
            name=PersonName.parse(mention), identities=ordered
        )
        assert {item.entity_id for item in candidates} == {
            identity.entity_id for identity in identities
        }


def test_candidates_are_read_only_and_diagnostics_do_not_disclose_names(
    caplog: pytest.LogCaptureFixture,
) -> None:
    identities = _identities("John Smith", "Larry Smith")
    mention = PersonName.parse("Mr Smith")
    before = tuple(asdict(identity) for identity in identities)
    candidates = PartialNameResolver().candidates(name=mention, identities=identities)

    assert tuple(asdict(identity) for identity in identities) == before
    assert mention == PersonName.parse("Mr Smith")
    assert_no_raw_sensitive_values(
        (
            repr(identities),
            repr(mention),
            repr(candidates),
            json.dumps([asdict(candidate) for candidate in candidates]),
            caplog.text,
        ),
        "John Smith",
        "Larry Smith",
        "john",
        "larry",
        "smith",
    )


def test_producer_retains_no_candidates_between_session_views() -> None:
    producer = PartialNameResolver()
    name = PersonName.parse("John")
    owner = EntityResolver()
    other = EntityResolver()
    owner.resolve_exact_full_name(surface_form="John Smith", start=0, end=10)
    owner_view = tuple(owner._identities_by_id.values())
    assert len(producer.candidates(name=name, identities=owner_view)) == 1
    assert producer.candidates(name=name, identities=tuple(other._identities_by_id.values())) == ()
    owner.clear()
    assert producer.candidates(name=name, identities=tuple(owner._identities_by_id.values())) == ()


def test_generated_candidates_can_be_decided_by_the_central_resolver() -> None:
    resolver = EntityResolver()
    resolver.resolve_exact_full_name(surface_form="John Smith", start=0, end=10)
    producer = PartialNameResolver()
    name = PersonName.parse("Mr Smith")
    candidates = producer.candidates(
        name=name, identities=tuple(resolver._identities_by_id.values())
    )
    result = resolver._resolve_candidates(candidates)
    assert result.state is EntityResolutionState.UNIQUE_PARTIAL
    assert result.reason is EntityResolutionReason.LAST_NAME_MATCH
    assert result.entity is not None
    assert result.entity.canonical_value == "John Smith"

    resolver.resolve_exact_full_name(surface_form="Larry Smith", start=0, end=11)
    candidates = producer.candidates(
        name=name, identities=tuple(resolver._identities_by_id.values())
    )
    result = resolver._resolve_candidates(candidates)
    assert result.state is EntityResolutionState.AMBIGUOUS
    assert result.entity is None


def test_partial_matching_is_not_enabled_in_the_session_resolution_path_yet() -> None:
    resolver = EntityResolver()
    resolver.resolve_exact_full_name(surface_form="John Smith", start=0, end=10)
    result = resolver.resolve_exact_full_name(surface_form="John", start=0, end=4)
    assert result.state is EntityResolutionState.UNRESOLVED
    assert result.entity is None
