"""Private, session-local records used for person-entity resolution.

These records deliberately remain outside the public package API.  They may
contain raw or normalized sensitive values and must never be sent to an audit
sink, log, exception, or LLM-facing return value.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol
from unicodedata import normalize
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
    FIRST_NAME_MATCH = "first_name_match"
    LAST_NAME_MATCH = "last_name_match"
    UNIQUE_ALIAS_MATCH = "unique_alias_match"
    AMBIGUOUS_CANDIDATES = "ambiguous_candidates"
    NO_CANDIDATES = "no_candidates"


_CONFIRMED_RESOLUTION_STATES = frozenset(
    {
        EntityResolutionState.EXACT,
        EntityResolutionState.UNIQUE_PARTIAL,
        EntityResolutionState.UNIQUE_ALIAS,
    }
)
_REASONS_BY_RESOLUTION_STATE = {
    EntityResolutionState.EXACT: frozenset({EntityResolutionReason.EXACT_NORMALIZED_FULL_NAME}),
    EntityResolutionState.UNIQUE_PARTIAL: frozenset(
        {
            EntityResolutionReason.UNIQUE_PARTIAL_NAME,
            EntityResolutionReason.FIRST_NAME_MATCH,
            EntityResolutionReason.LAST_NAME_MATCH,
        }
    ),
    EntityResolutionState.UNIQUE_ALIAS: frozenset({EntityResolutionReason.UNIQUE_ALIAS_MATCH}),
    EntityResolutionState.UNRESOLVED: frozenset(
        {EntityResolutionReason.INSUFFICIENT_NAME_COMPONENTS, EntityResolutionReason.NO_CANDIDATES}
    ),
    EntityResolutionState.AMBIGUOUS: frozenset({EntityResolutionReason.AMBIGUOUS_CANDIDATES}),
}


def _is_confirmed_resolution_state(state: EntityResolutionState) -> bool:
    return isinstance(state, EntityResolutionState) and state in _CONFIRMED_RESOLUTION_STATES


def _is_valid_resolution_reason(
    *,
    state: object,
    reason: object,
) -> bool:
    if not isinstance(state, EntityResolutionState) or not isinstance(
        reason, EntityResolutionReason
    ):
        return False
    return reason in _REASONS_BY_RESOLUTION_STATE[state]


def normalize_person_name(value: str) -> str:
    """Return a private, deterministic comparison key for an English person name.

    This function is deliberately not exported from the public package API.
    Its result may be sensitive and must remain in session-local resolver
    state; it is not safe audit, log, exception, or LLM-visible data.
    """
    return " ".join(PersonName.parse(value).components)


def _is_supported_person_title(component: str) -> bool:
    """Return whether one leading component is an explicitly supported title."""
    return component in _SUPPORTED_PERSON_TITLES or (
        component.endswith(".") and component[:-1] in _SUPPORTED_PERSON_TITLES
    )


@dataclass(frozen=True, slots=True)
class PersonName:
    """Private normalized components; a titled singleton is a surname mention.

    Components remain ordered, including middle names and internal punctuation.
    No surname/given-name inference is made for other single-component names.
    """

    components: tuple[str, ...] = field(repr=False)
    title: str | None = field(default=None, repr=False)

    @classmethod
    def parse(cls, value: str) -> PersonName:
        components = normalize("NFKC", value).casefold().split()
        title = None
        if components and _is_supported_person_title(components[0]):
            title = components.pop(0).removesuffix(".")
        return cls(components=tuple(components), title=title)


@dataclass(frozen=True, slots=True)
class PersonIdentity:
    """Immutable candidate-source view, without a canonical raw value."""

    entity_id: str
    name: PersonName = field(repr=False)


_CANDIDATE_STATES = {
    EntityResolutionReason.EXACT_NORMALIZED_FULL_NAME: EntityResolutionState.EXACT,
    EntityResolutionReason.UNIQUE_PARTIAL_NAME: EntityResolutionState.UNIQUE_PARTIAL,
    EntityResolutionReason.FIRST_NAME_MATCH: EntityResolutionState.UNIQUE_PARTIAL,
    EntityResolutionReason.LAST_NAME_MATCH: EntityResolutionState.UNIQUE_PARTIAL,
    EntityResolutionReason.UNIQUE_ALIAS_MATCH: EntityResolutionState.UNIQUE_ALIAS,
}


@dataclass(frozen=True, slots=True)
class EntityCandidate:
    """Candidate evidence only; it neither holds raw values nor confirms identity."""

    entity_id: str
    reason: EntityResolutionReason

    def __post_init__(self) -> None:
        if (
            not isinstance(self.entity_id, str)
            or len(self.entity_id) != 32
            or any(char not in "0123456789abcdef" for char in self.entity_id)
            or not isinstance(self.reason, EntityResolutionReason)
            or self.reason not in _CANDIDATE_STATES
        ):
            raise ValueError("Invalid private entity candidate.")


class NameCandidateProducer(Protocol):
    """Shared boundary for exact, partial, and alias candidate generation.

    Producers receive immutable session-local views and must not register or
    merge entities. Only EntityResolver makes the final identity decision.
    """

    def candidates(
        self, *, name: PersonName, identities: tuple[PersonIdentity, ...]
    ) -> tuple[EntityCandidate, ...]:
        """Return all matching entity IDs and safe reasons, without raw values."""
        ...


class ExactNameResolver:
    """Produce candidates for equivalent complete normalized names only."""

    def candidates(
        self, *, name: PersonName, identities: tuple[PersonIdentity, ...]
    ) -> tuple[EntityCandidate, ...]:
        if len(name.components) < 2:
            return ()
        return tuple(
            EntityCandidate(
                entity_id=identity.entity_id,
                reason=EntityResolutionReason.EXACT_NORMALIZED_FULL_NAME,
            )
            for identity in identities
            if identity.name.components == name.components
        )


class PartialNameResolver:
    """Produce every compatible candidate for a single-component mention.

    For the supported English name order, an untitled singleton matches the
    first component of a confirmed full name; a titled singleton matches the
    last. Titles select the name position, without inferring gender or identity.
    Middle names, initials, substrings, and aliases are not partial matches.

    The caller supplies only previously confirmed session-local identities.
    This producer is stateless and never decides uniqueness or registers an
    entity. It is deliberately not enabled in the session pipeline yet.
    """

    def candidates(
        self, *, name: PersonName, identities: tuple[PersonIdentity, ...]
    ) -> tuple[EntityCandidate, ...]:
        if len(name.components) != 1:
            return ()
        index = -1 if name.title is not None else 0
        reason = (
            EntityResolutionReason.LAST_NAME_MATCH
            if name.title is not None
            else EntityResolutionReason.FIRST_NAME_MATCH
        )
        return tuple(
            EntityCandidate(entity_id=identity.entity_id, reason=reason)
            for identity in identities
            if len(identity.name.components) >= 2
            and identity.name.components[index] == name.components[0]
        )


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
        if not _is_valid_resolution_reason(
            state=self.state, reason=self.reason
        ) or self.is_confirmed != (self.entity is not None):
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
        self._entities_by_id: dict[str, EntityRecord] = {}
        self._identities_by_id: dict[str, PersonIdentity] = {}
        self._candidate_producers: tuple[NameCandidateProducer, ...] = (ExactNameResolver(),)

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
        name = PersonName.parse(surface_form)
        if len(name.components) < 2:
            return EntityResolution(
                state=EntityResolutionState.UNRESOLVED,
                reason=EntityResolutionReason.INSUFFICIENT_NAME_COMPONENTS,
                entity=None,
            )

        identities = tuple(self._identities_by_id.values())
        candidates = tuple(
            candidate
            for producer in self._candidate_producers
            for candidate in producer.candidates(name=name, identities=identities)
        )
        resolution = self._resolve_candidates(candidates)
        if resolution.state is not EntityResolutionState.UNRESOLVED:
            return resolution

        entity = EntityRecord.create(entity_type="PERSON", canonical_value=surface_form)
        self._entities_by_id[entity.entity_id] = entity
        self._identities_by_id[entity.entity_id] = PersonIdentity(
            entity_id=entity.entity_id, name=name
        )
        return EntityResolution(
            state=EntityResolutionState.EXACT,
            reason=EntityResolutionReason.EXACT_NORMALIZED_FULL_NAME,
            entity=entity,
        )

    def _resolve_candidates(self, candidates: tuple[EntityCandidate, ...]) -> EntityResolution:
        """Decide over the complete candidate set, deduplicated by entity ID.

        Evidence priority only selects a reason for the same entity. It never
        breaks a tie between different identities or depends on producer order.
        """
        if any(candidate.entity_id not in self._entities_by_id for candidate in candidates):
            raise ValueError("Candidate does not belong to this resolver.")
        entity_ids = {candidate.entity_id for candidate in candidates}
        if not entity_ids:
            return EntityResolution(
                state=EntityResolutionState.UNRESOLVED,
                reason=EntityResolutionReason.NO_CANDIDATES,
                entity=None,
            )
        if len(entity_ids) > 1:
            return EntityResolution(
                state=EntityResolutionState.AMBIGUOUS,
                reason=EntityResolutionReason.AMBIGUOUS_CANDIDATES,
                entity=None,
            )
        reason = next(
            reason
            for reason in _CANDIDATE_STATES
            if any(candidate.reason is reason for candidate in candidates)
        )
        return EntityResolution(
            state=_CANDIDATE_STATES[reason],
            reason=reason,
            entity=self._entities_by_id[next(iter(entity_ids))],
        )

    def clear(self) -> None:
        """Discard all private entity values when the owning session closes."""
        self._entities_by_id.clear()
        self._identities_by_id.clear()
