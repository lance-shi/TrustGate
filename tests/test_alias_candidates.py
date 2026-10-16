"""Direct alias expansion generates all candidates without asserting identity."""

import json
from dataclasses import asdict
from itertools import permutations

import pytest
from security_assertions import assert_no_raw_sensitive_values

from trustgate.entity import (
    AliasResolver,
    EntityResolutionReason,
    PersonIdentity,
    PersonName,
)


def _identities(*names: str) -> tuple[PersonIdentity, ...]:
    return tuple(
        PersonIdentity(entity_id=f"{index:032x}", name=PersonName.parse(name))
        for index, name in enumerate(names, 1)
    )


@pytest.mark.parametrize("mention", ["Jo", "Jo Taylor", "Mr. JO TAYLOR", "Ｊｏ　Ｔａｙｌｏｒ"])
def test_alias_returns_every_compatible_candidate(mention: str) -> None:
    identities = _identities("Joanna Taylor", "Joseph Taylor", "Joanne Taylor")
    for ordered in permutations(identities):
        candidates = AliasResolver().candidates(name=PersonName.parse(mention), identities=ordered)
        assert {item.entity_id for item in candidates} == {item.entity_id for item in identities}
        assert all(item.reason is EntityResolutionReason.UNIQUE_ALIAS_MATCH for item in candidates)


@pytest.mark.parametrize("mention", ["Jo", "Joe", "Jo Taylor", "Joe Taylor"])
def test_multiple_aliases_can_generate_the_same_given_name(mention: str) -> None:
    identities = _identities("Joseph Taylor")
    candidates = AliasResolver().candidates(name=PersonName.parse(mention), identities=identities)
    assert len(candidates) == 1
    assert candidates[0].entity_id == identities[0].entity_id


@pytest.mark.parametrize(
    ("mention", "expected"),
    [
        ("Jo Taylor", {0}),
        ("Jo Jones", {1}),
        ("Jo Anne Taylor", {2}),
        ("Jo", {0, 1, 2}),
        ("Jo Ann Taylor", set()),
        ("Jo OConnor", set()),
    ],
)
def test_all_available_name_components_must_match(mention: str, expected: set[int]) -> None:
    identities = _identities("Joanna Taylor", "Joseph Jones", "Joanne Anne Taylor")
    candidates = AliasResolver().candidates(name=PersonName.parse(mention), identities=identities)
    assert {item.entity_id for item in candidates} == {
        identities[index].entity_id for index in expected
    }


@pytest.mark.parametrize("mention", ["", "Mr.", "Mr Jo", "Dr Joe", "J", "J.", "Joan", "Jo-Ann"])
def test_alias_does_not_match_surnames_initials_or_substrings(mention: str) -> None:
    assert (
        AliasResolver().candidates(
            name=PersonName.parse(mention), identities=_identities("Joanna Taylor", "Joseph Taylor")
        )
        == ()
    )


@pytest.mark.parametrize(
    ("mention", "known"),
    [
        ("Joanna Taylor", "Jo Taylor"),
        ("Joseph Taylor", "Joanna Taylor"),
        ("Joe Taylor", "Joanna Taylor"),
        ("Joanna Taylor", "Joanna Taylor"),
    ],
)
def test_aliases_do_not_form_symmetric_or_transitive_equivalence_classes(
    mention: str, known: str
) -> None:
    # Joanna and Joseph share Jo, but must not be related to one another.
    # Joe -> Joseph also must not imply Joe -> Joanna or Joe -> Jo.
    assert (
        AliasResolver().candidates(name=PersonName.parse(mention), identities=_identities(known))
        == ()
    )


def test_alias_does_not_use_single_component_identities() -> None:
    assert (
        AliasResolver().candidates(
            name=PersonName.parse("Jo"), identities=_identities("Joanna", "Joseph", "Mr Joanne")
        )
        == ()
    )


def test_alias_generation_is_read_only_stateless_and_raw_value_free(caplog) -> None:
    identities = _identities("Joanna Taylor", "Joseph Taylor")
    before = tuple(asdict(item) for item in identities)
    producer = AliasResolver()
    candidates = producer.candidates(name=PersonName.parse("Jo Taylor"), identities=identities)
    assert tuple(asdict(item) for item in identities) == before
    assert producer.candidates(name=PersonName.parse("Jo Taylor"), identities=()) == ()
    assert_no_raw_sensitive_values(
        (
            repr(producer),
            repr(identities),
            repr(candidates),
            json.dumps([asdict(item) for item in candidates]),
            caplog.text,
        ),
        "Jo Taylor",
        "Joanna Taylor",
        "Joseph Taylor",
        "joanna",
        "joseph",
        "taylor",
    )
