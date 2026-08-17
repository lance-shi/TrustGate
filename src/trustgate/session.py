"""Explicit session lifecycle and private token-vault ownership."""

from __future__ import annotations

from threading import RLock
from types import TracebackType
from typing import Protocol
from uuid import uuid4

from .detection import PresidioDetector
from .exceptions import (
    DataReleaseDenied,
    DetectionUnavailableError,
    FeatureUnavailableError,
    SessionClosedError,
)
from .models import (
    DataReleaseRequest,
    DataReleaseResult,
    JsonValue,
    SensitiveEntity,
    ToolCall,
    TrustPolicy,
)
from .policy import decide_data_release
from .vault import TokenRegistry, TokenVault

_PROCESS_TOKEN_REGISTRY = TokenRegistry()


class EntityDetector(Protocol):
    """The minimal local detector interface used by a TrustSession."""

    def detect(self, text: str) -> tuple[SensitiveEntity, ...]:
        """Return metadata for sensitive spans found in text."""


class TrustSession:
    """An explicit TrustGate session with a private session-local token vault."""

    def __init__(
        self,
        *,
        detector: EntityDetector | None = None,
        policy: TrustPolicy | None = None,
    ) -> None:
        self._session_id = uuid4().hex
        self._closed = False
        self._lock = RLock()
        self._vault = TokenVault(session_id=self._session_id, registry=_PROCESS_TOKEN_REGISTRY)
        self._detector = detector
        self._policy = policy

    @property
    def session_id(self) -> str:
        """Return an opaque identifier suitable for safe audit correlation."""
        return self._session_id

    @property
    def is_closed(self) -> bool:
        """Return whether the session has been closed."""
        with self._lock:
            return self._closed

    def decide_data_release(self, request: DataReleaseRequest) -> DataReleaseResult:
        """Evaluate this session's policy without releasing a token-vault value."""
        with self._lock:
            self._ensure_open()
            return decide_data_release(self._policy, request)

    def __enter__(self) -> TrustSession:
        with self._lock:
            self._ensure_open()
            return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        """Close the session and discard every private raw token mapping."""
        with self._lock:
            if self._closed:
                return
            self._vault.clear()
            self._closed = True

    def sanitize(self, text: str) -> str:
        """Replace detected sensitive spans with stable session-local tokens."""
        with self._lock:
            self._ensure_open()
            entities = self._detect(text)
            _validate_entity_ranges(entities, text_length=len(text))
            sanitized = text
            for entity in reversed(_merge_overlapping_entities(entities)):
                raw_value = text[entity.start : entity.end]
                token = self._vault.store(value=raw_value, entity_type=entity.entity_type)
                sanitized = f"{sanitized[:entity.start]}{token.value}{sanitized[entity.end:]}"
            return sanitized

    def rehydrate_for_tool(self, tool_call: ToolCall) -> dict[str, JsonValue]:
        """Release approved token values to a tool; default denial is already active."""
        with self._lock:
            self._ensure_open()
            raise DataReleaseDenied

    def sanitize_tool_result(self, result: JsonValue) -> JsonValue:
        """Return an LLM-safe copy of a tool result once sanitization is implemented."""
        with self._lock:
            self._ensure_open()
            raise FeatureUnavailableError

    def rehydrate_for_user(self, text: str) -> str:
        """Restore a tokenized response for its user after vault support is implemented."""
        with self._lock:
            self._ensure_open()
            raise FeatureUnavailableError

    def _ensure_open(self) -> None:
        if self._closed:
            raise SessionClosedError

    def _detect(self, text: str) -> tuple[SensitiveEntity, ...]:
        detector = self._detector
        if detector is None:
            detector = PresidioDetector()
            self._detector = detector
        try:
            return detector.detect(text)
        except DetectionUnavailableError:
            raise
        except Exception:
            raise DetectionUnavailableError from None


def _merge_overlapping_entities(
    entities: tuple[SensitiveEntity, ...],
) -> tuple[SensitiveEntity, ...]:
    """Merge intersecting spans so conflict handling cannot leave raw text behind."""
    if not entities:
        return ()

    ordered = sorted(entities, key=lambda entity: (entity.start, entity.end, entity.entity_type))
    merged: list[SensitiveEntity] = []
    cluster: list[SensitiveEntity] = [ordered[0]]
    cluster_end = ordered[0].end

    for entity in ordered[1:]:
        if entity.start < cluster_end:
            cluster.append(entity)
            cluster_end = max(cluster_end, entity.end)
            continue
        merged.append(_merge_cluster(cluster))
        cluster = [entity]
        cluster_end = entity.end
    merged.append(_merge_cluster(cluster))
    return tuple(merged)


def _validate_entity_ranges(entities: tuple[SensitiveEntity, ...], *, text_length: int) -> None:
    """Fail closed when a detector returns a span outside its input text."""
    if any(entity.end > text_length for entity in entities):
        raise DetectionUnavailableError


def _merge_cluster(cluster: list[SensitiveEntity]) -> SensitiveEntity:
    """Choose a deterministic entity type while preserving a cluster's full range."""
    representative = max(
        cluster,
        key=lambda entity: (entity.score, entity.end - entity.start, entity.entity_type),
    )
    return SensitiveEntity(
        entity_type=representative.entity_type,
        start=min(entity.start for entity in cluster),
        end=max(entity.end for entity in cluster),
        score=representative.score,
    )
