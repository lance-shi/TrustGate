"""Private, session-local records used for person-entity resolution.

These records deliberately remain outside the public package API.  They may
contain raw or normalized sensitive values and must never be sent to an audit
sink, log, exception, or LLM-facing return value.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from unicodedata import category, normalize
from uuid import uuid4

_SUPPORTED_PERSON_TITLES = frozenset({"dr", "mr", "mrs", "ms"})


class EntityResolutionState(StrEnum):
    """Safe resolution states retained for a session-local person mention."""

    EXACT = "exact"
    UNIQUE_PARTIAL = "unique_partial"
    UNIQUE_ALIAS = "unique_alias"
    UNRESOLVED = "unresolved"
    AMBIGUOUS = "ambiguous"


class EntityResolutionReason(StrEnum):
    """Safe, raw-value-free explanations for one resolution state."""

    EXACT_NORMALIZED_FULL_NAME = "exact_normalized_full_name"
    INSUFFICIENT_NAME_COMPONENTS = "insufficient_name_components"
    UNIQUE_PARTIAL_NAME = "unique_partial_name"
    UNIQUE_ALIAS_MATCH = "unique_alias_match"
    AMBIGUOUS_CANDIDATES = "ambiguous_candidates"


_CONFIRMED_RESOLUTION_STATES = frozenset(
    {
        EntityResolutionState.EXACT,
        EntityResolutionState.UNIQUE_PARTIAL,
        EntityResolutionState.UNIQUE_ALIAS,
    }
)
_REASONS_BY_RESOLUTION_STATE = {
    EntityResolutionState.EXACT: frozenset(
        {EntityResolutionReason.EXACT_NORMALIZED_FULL_NAME}
    ),
    EntityResolutionState.UNIQUE_PARTIAL: frozenset(
        {EntityResolutionReason.UNIQUE_PARTIAL_NAME}
    ),
    EntityResolutionState.UNIQUE_ALIAS: frozenset({EntityResolutionReason.UNIQUE_ALIAS_MATCH}),
    EntityResolutionState.UNRESOLVED: frozenset(
        {EntityResolutionReason.INSUFFICIENT_NAME_COMPONENTS}
    ),
    EntityResolutionState.AMBIGUOUS: frozenset({EntityResolutionReason.AMBIGUOUS_CANDIDATES}),
}


def _is_confirmed_resolution_state(state: EntityResolutionState) -> bool:
    return state in _CONFIRMED_RESOLUTION_STATES


def _is_valid_resolution_reason(
    *,
    state: EntityResolutionState,
    reason: EntityResolutionReason,
) -> bool:
    return reason in _REASONS_BY_RESOLUTION_STATE[state]


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
class EntityResolution:
    """One private resolver result with safe state and reason metadata."""

    state: EntityResolutionState
    reason: EntityResolutionReason
    entity: EntityRecord | None = field(repr=False)

    @property
    def is_confirmed(self) -> bool:
        """Return whether this result may reuse an existing entity token."""
        return _is_confirmed_resolution_state(self.state)

    def __post_init__(self) -> None:
        if (
            not _is_valid_resolution_reason(state=self.state, reason=self.reason)
            or self.is_confirmed != (self.entity is not None)
        ):
            raise ValueError("Invalid private entity resolution.")


@dataclass(frozen=True, slots=True)
class EntityMention:
    """A detected surface form and its optional resolved session-local entity."""

    entity_type: str
    start: int
    end: int
    surface_form: str = field(repr=False)
    resolution_state: EntityResolutionState
    resolution_reason: EntityResolutionReason
    entity_id: str | None = None

    def __post_init__(self) -> None:
        if (
            not self.entity_type
            or self.start < 0
            or self.end <= self.start
            or not self.surface_form
            or (self.entity_id is not None and not self.entity_id)
            or not _is_valid_resolution_reason(
                state=self.resolution_state,
                reason=self.resolution_reason,
            )
            or (
                _is_confirmed_resolution_state(self.resolution_state)
                != (self.entity_id is not None)
            )
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
    ) -> EntityResolution:
        """Return the safe result of exact normalized full-name resolution.

        A single-component or otherwise insufficient name is intentionally not
        resolved here. It continues through the existing vault behavior until
        the conservative partial and alias rules are implemented.
        """
        normalized_name = normalize_person_name(surface_form)
        if len(normalized_name.split()) < 2:
            resolution = EntityResolution(
                state=EntityResolutionState.UNRESOLVED,
                reason=EntityResolutionReason.INSUFFICIENT_NAME_COMPONENTS,
                entity=None,
            )
            self._mentions.append(
                EntityMention(
                    entity_type="PERSON",
                    start=start,
                    end=end,
                    surface_form=surface_form,
                    resolution_state=resolution.state,
                    resolution_reason=resolution.reason,
                )
            )
            return resolution

        entity = self._entities_by_normalized_full_name.get(normalized_name)
        if entity is None:
            entity = EntityRecord.create(entity_type="PERSON", canonical_value=surface_form)
            self._entities_by_normalized_full_name[normalized_name] = entity
        resolution = EntityResolution(
            state=EntityResolutionState.EXACT,
            reason=EntityResolutionReason.EXACT_NORMALIZED_FULL_NAME,
            entity=entity,
        )
        self._mentions.append(
            EntityMention(
                entity_type="PERSON",
                start=start,
                end=end,
                surface_form=surface_form,
                resolution_state=resolution.state,
                resolution_reason=resolution.reason,
                entity_id=entity.entity_id,
            )
        )
        return resolution

    def clear(self) -> None:
        """Discard all private entity values when the owning session closes."""
        self._entities_by_normalized_full_name.clear()
        self._mentions.clear()
