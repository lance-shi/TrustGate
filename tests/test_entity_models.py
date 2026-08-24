"""Tests for private, session-local entity-resolution records."""

import pytest

from trustgate.entity import (
    EntityMention,
    EntityRecord,
    EntityResolution,
    EntityResolutionReason,
    EntityResolutionState,
    EntityResolver,
    normalize_person_name,
)


def test_entity_record_keeps_a_canonical_value_behind_an_opaque_identifier() -> None:
    raw_name = "RAW_PERSON_DO_NOT_LEAK_John Smith"

    entity = EntityRecord.create(entity_type="PERSON", canonical_value=raw_name)

    assert len(entity.entity_id) == 32
    assert entity.entity_type == "PERSON"
    assert entity.canonical_value == raw_name
    assert raw_name not in repr(entity)


def test_mention_can_reference_one_entity_without_exposing_surface_form_in_repr() -> None:
    raw_name = "RAW_PERSON_DO_NOT_LEAK_John Smith"
    entity = EntityRecord.create(entity_type="PERSON", canonical_value=raw_name)

    mention = EntityMention(
        entity_type="PERSON",
        start=4,
        end=14,
        surface_form=raw_name,
        resolution_state=EntityResolutionState.EXACT,
        resolution_reason=EntityResolutionReason.EXACT_NORMALIZED_FULL_NAME,
        entity_id=entity.entity_id,
    )

    assert mention.entity_id == entity.entity_id
    assert raw_name not in repr(mention)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("JOHN SMITH", "john smith"),
        ("  John   Smith  ", "john smith"),
        ("Mr John Smith", "john smith"),
        ("Mr. John Smith", "john smith"),
        ("Dr., John-Smith", "john smith"),
        ("John O'Connor", "john o connor"),
        ("Ｊｏｈｎ　Ｓｍｉｔｈ", "john smith"),
    ],
)
def test_normalize_person_name_returns_a_deterministic_private_key(
    value: str,
    expected: str,
) -> None:
    assert normalize_person_name(value) == expected


def test_normalize_person_name_normalizes_equivalent_unicode_composition() -> None:
    composed = "Jos\N{LATIN SMALL LETTER E WITH ACUTE} Smith"
    decomposed = "Jose\N{COMBINING ACUTE ACCENT} Smith"

    assert normalize_person_name(composed) == "jos\N{LATIN SMALL LETTER E WITH ACUTE} smith"
    assert normalize_person_name(decomposed) == normalize_person_name(composed)


def test_exact_and_unresolved_results_retain_safe_state_and_reason_metadata() -> None:
    raw_full_name = "John Smith"
    raw_single_name = "John"
    resolver = EntityResolver()

    exact = resolver.resolve_exact_full_name(
        surface_form=raw_full_name,
        start=0,
        end=len(raw_full_name),
    )
    unresolved = resolver.resolve_exact_full_name(
        surface_form=raw_single_name,
        start=0,
        end=len(raw_single_name),
    )

    assert exact.state is EntityResolutionState.EXACT
    assert exact.reason is EntityResolutionReason.EXACT_NORMALIZED_FULL_NAME
    assert exact.is_confirmed
    assert unresolved.state is EntityResolutionState.UNRESOLVED
    assert unresolved.reason is EntityResolutionReason.INSUFFICIENT_NAME_COMPONENTS
    assert not unresolved.is_confirmed
    assert unresolved.entity is None
    assert raw_full_name not in repr(exact)
    assert raw_single_name not in repr(unresolved)


@pytest.mark.parametrize(
    "resolution",
    [
        lambda: EntityResolution(
            state=EntityResolutionState.EXACT,
            reason=EntityResolutionReason.EXACT_NORMALIZED_FULL_NAME,
            entity=None,
        ),
        lambda: EntityResolution(
            state=EntityResolutionState.UNRESOLVED,
            reason=EntityResolutionReason.AMBIGUOUS_CANDIDATES,
            entity=None,
        ),
    ],
)
def test_resolution_model_rejects_inconsistent_state_without_disclosure(
    resolution: object,
) -> None:
    raw_name = "RAW_PERSON_DO_NOT_LEAK_John Smith"

    with pytest.raises(ValueError) as error:
        resolution()  # type: ignore[operator]

    assert raw_name not in str(error.value)
    assert raw_name not in repr(error.value)


@pytest.mark.parametrize(
    "factory",
    [
        lambda raw_name: EntityRecord(entity_id="", entity_type="PERSON", canonical_value=raw_name),
        lambda raw_name: EntityRecord(entity_id="entity", entity_type="", canonical_value=raw_name),
        lambda raw_name: EntityMention(
            entity_type="PERSON",
            start=1,
            end=1,
            surface_form=raw_name,
            resolution_state=EntityResolutionState.UNRESOLVED,
            resolution_reason=EntityResolutionReason.INSUFFICIENT_NAME_COMPONENTS,
        ),
        lambda raw_name: EntityMention(
            entity_type="PERSON",
            start=0,
            end=4,
            surface_form="",
            resolution_state=EntityResolutionState.EXACT,
            resolution_reason=EntityResolutionReason.EXACT_NORMALIZED_FULL_NAME,
            entity_id="",
        ),
    ],
)
def test_private_entity_models_reject_invalid_state_without_disclosing_values(
    factory: object,
) -> None:
    raw_name = "RAW_PERSON_DO_NOT_LEAK_John Smith"

    with pytest.raises(ValueError) as error:
        factory(raw_name)  # type: ignore[operator]

    assert raw_name not in str(error.value)
    assert raw_name not in repr(error.value)
