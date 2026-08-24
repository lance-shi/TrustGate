"""Explicit session lifecycle and private token-vault ownership."""

from __future__ import annotations

from re import Match, Pattern, compile
from threading import RLock
from types import TracebackType
from typing import Protocol
from uuid import uuid4

from .audit import AuditSink, InMemoryAuditSink, audit_identifier
from .detection import PresidioDetector
from .entity import EntityResolver
from .exceptions import (
    DataReleaseDenied,
    DetectionUnavailableError,
    FeatureUnavailableError,
    MalformedTokenError,
    SessionClosedError,
    TokenResolutionError,
    ToolResultSanitizationError,
)
from .models import (
    AuditEvent,
    AuditEventType,
    AuditFailureReason,
    DataReleaseDecision,
    DataReleaseRequest,
    DataReleaseResult,
    JsonValue,
    SensitiveEntity,
    SensitiveToken,
    ToolCall,
    TrustPolicy,
)
from .policy import decide_data_release
from .vault import TokenRegistry, TokenVault

_PROCESS_TOKEN_REGISTRY = TokenRegistry()
_BRACKETED_VALUE_PATTERN: Pattern[str] = compile(r"\[[^\[\]]*\]")


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
        audit_sink: AuditSink | None = None,
    ) -> None:
        self._session_id = uuid4().hex
        self._closed = False
        self._lock = RLock()
        self._vault = TokenVault(session_id=self._session_id, registry=_PROCESS_TOKEN_REGISTRY)
        self._entity_resolver = EntityResolver()
        self._detector = detector
        self._policy = policy
        self._audit_sink = audit_sink if audit_sink is not None else InMemoryAuditSink()
        self._record_audit(AuditEventType.SESSION_OPENED)

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
            self._entity_resolver.clear()
            self._closed = True
            self._record_audit(AuditEventType.SESSION_CLOSED)

    def sanitize(self, text: str) -> str:
        """Replace detected sensitive spans with stable session-local tokens."""
        with self._lock:
            self._ensure_open()
            sanitized, tokens = self._sanitize_text(text)
            self._record_audit(AuditEventType.VALUE_SANITIZED, tokens=tokens)
            return sanitized

    def rehydrate_for_tool(self, tool_call: ToolCall) -> dict[str, JsonValue]:
        """Return a copied tool argument tree with approved tokens rehydrated.

        Token references are validated before any argument tree is returned, so
        one denied or invalid reference cannot produce a partially rehydrated
        tool call. Values without token references are non-sensitive to this
        boundary and are copied unchanged.
        """
        with self._lock:
            self._ensure_open()
            tokens: list[SensitiveToken] = []
            try:
                arguments = {
                    name: self._rehydrate_value(
                        value=value,
                        destination=tool_call.name,
                        tokens=tokens,
                    )
                    for name, value in tool_call.arguments.items()
                }
            except (DataReleaseDenied, TokenResolutionError):
                self._record_audit(
                    AuditEventType.TOOL_RELEASE_DENIED,
                    destination=tool_call.name,
                    decision=DataReleaseDecision.DENY,
                    tokens=tuple(tokens),
                )
                raise
            if tokens:
                self._record_audit(
                    AuditEventType.TOOL_RELEASE_ALLOWED,
                    destination=tool_call.name,
                    decision=DataReleaseDecision.ALLOW,
                    tokens=tuple(tokens),
                )
            return arguments

    def sanitize_tool_result(self, result: JsonValue) -> JsonValue:
        """Recursively return an LLM-safe copy of one tool result."""
        with self._lock:
            self._ensure_open()
            tokens: list[SensitiveToken] = []
            try:
                sanitized = self._sanitize_result_value(value=result, tokens=tokens)
            except DetectionUnavailableError:
                self._record_audit(
                    AuditEventType.TOOL_RESULT_SANITIZATION_FAILED,
                    failure_reason=AuditFailureReason.DETECTION_UNAVAILABLE,
                    tokens=tuple(tokens),
                )
                raise
            except ToolResultSanitizationError:
                self._record_audit(
                    AuditEventType.TOOL_RESULT_SANITIZATION_FAILED,
                    failure_reason=AuditFailureReason.UNSAFE_RESULT_STRUCTURE,
                    tokens=tuple(tokens),
                )
                raise
            self._record_audit(AuditEventType.TOOL_RESULT_SANITIZED, tokens=tuple(tokens))
            return sanitized

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

    def _sanitize_text(self, text: str) -> tuple[str, tuple[SensitiveToken, ...]]:
        entities = self._detect(text)
        _validate_entity_ranges(entities, text_length=len(text))
        tokens: list[SensitiveToken] = []
        replacements: list[tuple[SensitiveEntity, SensitiveToken]] = []
        for entity in _merge_overlapping_entities(entities):
            raw_value = text[entity.start : entity.end]
            token = self._tokenize_entity(
                entity=entity,
                raw_value=raw_value,
            )
            tokens.append(token)
            replacements.append((entity, token))

        sanitized = text
        for entity, token in reversed(replacements):
            sanitized = f"{sanitized[:entity.start]}{token.value}{sanitized[entity.end:]}"
        return sanitized, tuple(tokens)

    def _tokenize_entity(
        self,
        *,
        entity: SensitiveEntity,
        raw_value: str,
    ) -> SensitiveToken:
        if entity.entity_type == "PERSON":
            resolution = self._entity_resolver.resolve_exact_full_name(
                surface_form=raw_value,
                start=entity.start,
                end=entity.end,
            )
            if resolution.is_confirmed:
                resolved_entity = resolution.entity
                assert resolved_entity is not None
                return self._vault.store(
                    value=resolved_entity.canonical_value,
                    entity_type=resolved_entity.entity_type,
                )
        return self._vault.store(value=raw_value, entity_type=entity.entity_type)

    def _sanitize_result_value(
        self,
        *,
        value: object,
        tokens: list[SensitiveToken],
    ) -> JsonValue:
        if isinstance(value, str):
            sanitized, detected_tokens = self._sanitize_text(value)
            tokens.extend(detected_tokens)
            return sanitized
        if value is None or isinstance(value, bool | int | float):
            return value
        if isinstance(value, list):
            return [self._sanitize_result_value(value=item, tokens=tokens) for item in value]
        if isinstance(value, dict):
            sanitized: dict[str, JsonValue] = {}
            for key, item in value.items():
                if not isinstance(key, str):
                    raise ToolResultSanitizationError
                sanitized_key, key_tokens = self._sanitize_text(key)
                tokens.extend(key_tokens)
                if sanitized_key in sanitized:
                    raise ToolResultSanitizationError
                sanitized[sanitized_key] = self._sanitize_result_value(value=item, tokens=tokens)
            return sanitized
        raise ToolResultSanitizationError

    def _rehydrate_value(
        self,
        *,
        value: JsonValue,
        destination: str,
        tokens: list[SensitiveToken],
    ) -> JsonValue:
        if isinstance(value, str):
            return self._rehydrate_text(text=value, destination=destination, tokens=tokens)
        if isinstance(value, list):
            return [
                self._rehydrate_value(value=item, destination=destination, tokens=tokens)
                for item in value
            ]
        if isinstance(value, dict):
            return {
                name: self._rehydrate_value(value=item, destination=destination, tokens=tokens)
                for name, item in value.items()
            }
        return value

    def _rehydrate_text(
        self,
        *,
        text: str,
        destination: str,
        tokens: list[SensitiveToken],
    ) -> str:
        matches = tuple(_BRACKETED_VALUE_PATTERN.finditer(text))
        unmatched_brackets = _BRACKETED_VALUE_PATTERN.sub("", text)
        if not matches:
            if "[" in text or "]" in text:
                raise MalformedTokenError
            return text
        if "[" in unmatched_brackets or "]" in unmatched_brackets:
            raise MalformedTokenError

        replacements: list[tuple[Match[str], str]] = []
        for match in matches:
            entry = self._vault.resolve(match.group())
            tokens.append(SensitiveToken(value=match.group(), entity_type=entry.entity_type))
            result = self.decide_data_release(
                DataReleaseRequest(entity_type=entry.entity_type, destination=destination)
            )
            if result.decision is not DataReleaseDecision.ALLOW:
                raise DataReleaseDenied
            replacements.append((match, entry.value))

        rehydrated = text
        for match, raw_value in reversed(replacements):
            rehydrated = f"{rehydrated[:match.start()]}{raw_value}{rehydrated[match.end():]}"
        return rehydrated

    def _record_audit(
        self,
        event_type: AuditEventType,
        *,
        destination: str | None = None,
        decision: DataReleaseDecision | None = None,
        tokens: tuple[SensitiveToken, ...] = (),
        failure_reason: AuditFailureReason | None = None,
    ) -> None:
        unique_tokens = tuple(dict.fromkeys(audit_identifier(token.value) for token in tokens))
        entity_types = tuple(dict.fromkeys(audit_identifier(token.entity_type) for token in tokens))
        self._audit_sink.record(
            AuditEvent(
                event_type=event_type,
                session_id=self._session_id,
                entity_types=entity_types,
                destination=audit_identifier(destination) if destination is not None else None,
                decision=decision,
                tokens=unique_tokens,
                failure_reason=failure_reason,
            )
        )


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
