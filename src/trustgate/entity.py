"""Private, session-local records used for person-entity resolution.

These records deliberately remain outside the public package API.  They may
contain raw or normalized sensitive values and must never be sent to an audit
sink, log, exception, or LLM-facing return value.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from unicodedata import category, normalize
from uuid import uuid4

_SUPPORTED_PERSON_TITLES = frozenset({"dr", "mr", "mrs", "ms"})


def normalize_person_name(value: str) -> str:
    """Return a private, deterministic comparison key for an English person name.

    This function is deliberately not exported from the public package API.
    Its result may be sensitive and must remain in session-local resolver
    state; it is not safe audit, log, exception, or LLM-visible data.
    """
    normalized = normalize("NFKC", value).casefold()
    without_punctuation = "".join(
        " " if category(character).startswith("P") else character for character in normalized
    )
    components = without_punctuation.split()
    if components and components[0] in _SUPPORTED_PERSON_TITLES:
        components = components[1:]
    return " ".join(components)


@dataclass(frozen=True, slots=True)
class EntityRecord:
    """One session-local sensitive entity and its canonical tool value."""

    entity_id: str
    entity_type: str
    canonical_value: str = field(repr=False)

    @classmethod
    def create(cls, *, entity_type: str, canonical_value: str) -> EntityRecord:
        """Create an entity with an opaque identifier local to its session."""
        return cls(
            entity_id=uuid4().hex,
            entity_type=entity_type,
            canonical_value=canonical_value,
        )

    def __post_init__(self) -> None:
        if not self.entity_id or not self.entity_type or not self.canonical_value:
            raise ValueError("Invalid private entity record.")


@dataclass(frozen=True, slots=True)
class EntityMention:
    """A detected surface form and its optional resolved session-local entity."""

    entity_type: str
    start: int
    end: int
    surface_form: str = field(repr=False)
    entity_id: str | None = None

    def __post_init__(self) -> None:
        if (
            not self.entity_type
            or self.start < 0
            or self.end <= self.start
            or not self.surface_form
            or (self.entity_id is not None and not self.entity_id)
        ):
            raise ValueError("Invalid private entity mention.")


class EntityResolver:
    """Resolve only exact normalized full-person-name matches within one session."""

    def __init__(self) -> None:
        self._entities_by_normalized_full_name: dict[str, EntityRecord] = {}
        self._mentions: list[EntityMention] = []

    def resolve_exact_full_name(
        self,
        *,
        surface_form: str,
        start: int,
        end: int,
    ) -> EntityRecord | None:
        """Return a stable entity for an exact normalized full name, if eligible.

        A single-component or otherwise insufficient name is intentionally not
        resolved here. It continues through the existing vault behavior until
        the conservative partial and alias rules are implemented.
        """
        normalized_name = normalize_person_name(surface_form)
        if len(normalized_name.split()) < 2:
            return None

        entity = self._entities_by_normalized_full_name.get(normalized_name)
        if entity is None:
            entity = EntityRecord.create(entity_type="PERSON", canonical_value=surface_form)
            self._entities_by_normalized_full_name[normalized_name] = entity
        self._mentions.append(
            EntityMention(
                entity_type="PERSON",
                start=start,
                end=end,
                surface_form=surface_form,
                entity_id=entity.entity_id,
            )
        )
        return entity

    def clear(self) -> None:
        """Discard all private entity values when the owning session closes."""
        self._entities_by_normalized_full_name.clear()
        self._mentions.clear()
