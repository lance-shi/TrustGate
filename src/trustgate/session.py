"""Explicit session lifecycle and private token-vault ownership."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from re import Match, Pattern, compile
from threading import RLock
from types import TracebackType
from typing import Protocol
from uuid import uuid4

from .audit import AuditSink, InMemoryAuditSink, audit_identifier
from .detection import PresidioDetector
from .entity import EntityResolver
from .exceptions import (
    AuditRecordingError,
    CrossSessionTokenError,
    DataReleaseDenied,
    DetectionUnavailableError,
    EntityResolutionError,
    FeatureUnavailableError,
    MalformedTokenError,
    ModelValidationError,
    SessionClosedError,
    TokenResolutionError,
    ToolArgumentRehydrationError,
    ToolResultSanitizationError,
    TrustGateError,
    UnknownTokenError,
)
from .models import (
    AuditEvent,
    AuditEventType,
    AuditFailureReason,
    AuditResolution,
    DataReleaseDecision,
    DataReleaseRequest,
    DataReleaseResult,
    JsonValue,
    SensitiveEntity,
    SensitiveToken,
    ToolCall,
    TranscriptEntry,
    TranscriptEntryType,
    TrustPolicy,
)
from .policy import decide_data_release
from .transcript import _SanitizedTranscript
from .vault import TokenRegistry, TokenVault

_PROCESS_TOKEN_REGISTRY = TokenRegistry()
_BRACKETED_VALUE_PATTERN: Pattern[str] = compile(r"\[[^\[\]]*\]")


class EntityDetector(Protocol):
    """The minimal local detector interface used by a TrustSession."""

    def detect(self, text: str) -> tuple[SensitiveEntity, ...]:
        """Return metadata for sensitive spans found in text."""


class TrustSession:
    """An explicit TrustGate session with private ephemeral token and alias state.

    ``aliases`` optionally adds direct given-name relations, copied at creation
    and cleared on close. Invalid configuration raises AliasValidationError
    before a session-opened audit event is emitted.

    ``transcript=True`` opts into in-memory copies of completed sanitization
    outputs. Collection is disabled by default; safe snapshots survive close.
    Audit failures raise AuditRecordingError; failed opening clears private state.
    """

    def __init__(
        self,
        *,
        detector: EntityDetector | None = None,
        policy: TrustPolicy | None = None,
        audit_sink: AuditSink | None = None,
        aliases: Mapping[str, Sequence[str]] | None = None,
        transcript: bool = False,
    ) -> None:
        if not isinstance(transcript, bool):
            raise ModelValidationError
        entity_resolver = EntityResolver(aliases=aliases)
        self._session_id = uuid4().hex
        self._closed = False
        self._lock = RLock()
        self._vault = TokenVault(session_id=self._session_id, registry=_PROCESS_TOKEN_REGISTRY)
        self._entity_resolver = entity_resolver
        self._detector = detector
        self._policy = policy
        self._audit_sink = audit_sink if audit_sink is not None else InMemoryAuditSink()
        self._transcript = _SanitizedTranscript() if transcript else None
        try:
            self._record_audit(AuditEventType.SESSION_OPENED)
        except AuditRecordingError:
            # A constructor failure must not leave live mappings or aliases
            # even if a trusted caller retains the partially created instance.
            self._vault.clear()
            self._entity_resolver.clear()
            self._closed = True
            raise

    @property
    def transcript(self) -> tuple[TranscriptEntry, ...]:
        """Return an isolated safe-output snapshot, including after close.

        Collection is disabled by default. This never reads private mappings;
        nested content in the returned snapshot can be edited independently.
        """
        with self._lock:
            return self._transcript._snapshot() if self._transcript is not None else ()

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
        """Discard private state before auditing; audit failure leaves it closed."""
        with self._lock:
            if self._closed:
                return
            self._vault.clear()
            self._entity_resolver.clear()
            self._closed = True
            self._record_audit(AuditEventType.SESSION_CLOSED)

    def sanitize(self, text: str) -> str:
        """Tokenize detected spans in a built-in str; reject custom scalar objects."""
        with self._lock:
            self._ensure_open()
            resolutions: list[AuditResolution] = []
            sanitized, tokens = self._sanitize_text(text, resolutions=resolutions)
            self._record_audit(
                AuditEventType.VALUE_SANITIZED, tokens=tokens, resolutions=tuple(resolutions)
            )
            if self._transcript is not None:
                self._transcript._record(TranscriptEntryType.INPUT_SANITIZED, sanitized)
            return sanitized

    def rehydrate_for_tool(self, tool_call: ToolCall) -> dict[str, JsonValue]:
        """Return a copied tool argument tree with approved tokens rehydrated.

        Token references are validated before any argument tree is returned, so
        one denied or invalid reference cannot produce a partially rehydrated
        tool call. Dictionary keys and values use the same release checks;
        rehydrated key collisions fail closed. Strings without token references
        are copied unchanged. Cycles and unsupported structures fail safely;
        shared containers are copied independently.
        """
        with self._lock:
            self._ensure_open()
            tokens: list[SensitiveToken] = []
            failure: TrustGateError | None = None
            try:
                arguments = self._rehydrate_value(
                    value=tool_call.arguments,
                    destination=tool_call.name,
                    tokens=tokens,
                    active_containers=set(),
                )
                if not isinstance(arguments, dict):
                    raise ToolArgumentRehydrationError
            except (DataReleaseDenied, TokenResolutionError) as error:
                # A caller-defined iterator could raise or alter these exceptions.
                # Reconstruct only our exact known static types, never its payload.
                safe_types = (
                    DataReleaseDenied,
                    TokenResolutionError,
                    MalformedTokenError,
                    UnknownTokenError,
                    CrossSessionTokenError,
                )
                failure = (
                    type(error)() if type(error) in safe_types else ToolArgumentRehydrationError()
                )
            except Exception:
                failure = ToolArgumentRehydrationError()
            if failure is not None:
                self._record_audit(
                    AuditEventType.TOOL_RELEASE_DENIED,
                    destination=tool_call.name,
                    decision=DataReleaseDecision.DENY,
                    tokens=tuple(tokens),
                    failure_reason=(
                        AuditFailureReason.UNSAFE_ARGUMENT_STRUCTURE
                        if isinstance(failure, ToolArgumentRehydrationError)
                        else None
                    ),
                )
                raise failure
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
            resolutions: list[AuditResolution] = []
            failure: TrustGateError | None = None
            failure_reason = AuditFailureReason.UNSAFE_RESULT_STRUCTURE
            try:
                sanitized = self._sanitize_result_value(
                    value=result, tokens=tokens, resolutions=resolutions, active_containers=set()
                )
            except DetectionUnavailableError:
                failure = DetectionUnavailableError()
                failure_reason = AuditFailureReason.DETECTION_UNAVAILABLE
            except EntityResolutionError:
                failure = EntityResolutionError()
                failure_reason = AuditFailureReason.ENTITY_RESOLUTION_UNAVAILABLE
            except Exception:
                # Includes malformed/cyclic structures and caller-defined container
                # iteration errors. Never propagate their messages or chains.
                failure = ToolResultSanitizationError()
            if failure is not None:
                self._record_audit(
                    AuditEventType.TOOL_RESULT_SANITIZATION_FAILED,
                    failure_reason=failure_reason,
                    tokens=tuple(tokens),
                    resolutions=tuple(resolutions),
                )
                # Outside the handler so even __context__ cannot disclose input.
                raise failure
            self._record_audit(
                AuditEventType.TOOL_RESULT_SANITIZED,
                tokens=tuple(tokens),
                resolutions=tuple(resolutions),
            )
            if self._transcript is not None:
                self._transcript._record(TranscriptEntryType.TOOL_RESULT_SANITIZED, sanitized)
            return sanitized

    def rehydrate_for_user(self, text: str) -> str:
        """Raise FeatureUnavailableError; user-response rehydration is not implemented."""
        with self._lock:
            self._ensure_open()
            raise FeatureUnavailableError

    def _ensure_open(self) -> None:
        if self._closed:
            raise SessionClosedError

    def _detect(self, text: str) -> tuple[SensitiveEntity, ...]:
        try:
            detector = self._detector
            if detector is None:
                detector = PresidioDetector()
                self._detector = detector
            entities = detector.detect(text)
            _validate_entity_ranges(entities, text_length=len(text))
            return entities
        except Exception:
            pass
        # A suppressed context is still reachable via __context__. Raise only
        # after leaving the handler so detector exceptions cannot expose text.
        raise DetectionUnavailableError

    def _sanitize_text(
        self, text: str, *, resolutions: list[AuditResolution]
    ) -> tuple[str, tuple[SensitiveToken, ...]]:
        if type(text) is not str:
            raise ModelValidationError
        entities = self._detect(text)
        tokens: list[SensitiveToken] = []
        replacements: list[tuple[SensitiveEntity, SensitiveToken]] = []
        for entity in _merge_overlapping_entities(entities):
            raw_value = text[entity.start : entity.end]
            token = self._tokenize_entity(
                entity=entity,
                raw_value=raw_value,
                resolutions=resolutions,
            )
            tokens.append(token)
            replacements.append((entity, token))

        sanitized = text
        for entity, token in reversed(replacements):
            sanitized = f"{sanitized[: entity.start]}{token.value}{sanitized[entity.end :]}"
        return sanitized, tuple(tokens)

    def _tokenize_entity(
        self,
        *,
        entity: SensitiveEntity,
        raw_value: str,
        resolutions: list[AuditResolution],
    ) -> SensitiveToken:
        if entity.entity_type == "PERSON":
            try:
                result = self._entity_resolver.resolve_person(
                    surface_form=raw_value,
                    start=entity.start,
                    end=entity.end,
                )
            except Exception:
                result = None
            if result is None:
                # A suppressed exception would still retain its raw context.
                raise EntityResolutionError
            resolved_entity = result.token_entity
            token = self._vault.store(
                value=resolved_entity.canonical_value,
                entity_type=resolved_entity.entity_type,
                identity_id=resolved_entity.entity_id,
            )
            resolutions.append(
                AuditResolution(
                    token=audit_identifier(token.value),
                    state=result.resolution.state,
                    reason=result.resolution.reason,
                )
            )
            return token
        return self._vault.store(value=raw_value, entity_type=entity.entity_type)

    def _sanitize_result_value(
        self,
        *,
        value: object,
        tokens: list[SensitiveToken],
        resolutions: list[AuditResolution],
        active_containers: set[int],
    ) -> JsonValue:
        if type(value) is str:
            sanitized, detected_tokens = self._sanitize_text(value, resolutions=resolutions)
            tokens.extend(detected_tokens)
            return sanitized
        if value is None or type(value) in (bool, int, float):
            return value
        if not isinstance(value, list | dict):
            raise ToolResultSanitizationError
        container_id = id(value)
        if container_id in active_containers:
            raise ToolResultSanitizationError
        active_containers.add(container_id)
        try:
            if isinstance(value, list):
                return [
                    self._sanitize_result_value(
                        value=item,
                        tokens=tokens,
                        resolutions=resolutions,
                        active_containers=active_containers,
                    )
                    for item in value
                ]
            sanitized: dict[str, JsonValue] = {}
            for key, item in value.items():
                if not isinstance(key, str):
                    raise ToolResultSanitizationError
                sanitized_key, key_tokens = self._sanitize_text(key, resolutions=resolutions)
                tokens.extend(key_tokens)
                if sanitized_key in sanitized:
                    raise ToolResultSanitizationError
                sanitized[sanitized_key] = self._sanitize_result_value(
                    value=item,
                    tokens=tokens,
                    resolutions=resolutions,
                    active_containers=active_containers,
                )
            return sanitized
        finally:
            active_containers.remove(container_id)

    def _rehydrate_value(
        self,
        *,
        value: JsonValue,
        destination: str,
        tokens: list[SensitiveToken],
        active_containers: set[int],
    ) -> JsonValue:
        if type(value) is str:
            return self._rehydrate_text(text=value, destination=destination, tokens=tokens)
        if value is None or type(value) in (bool, int, float):
            return value
        if not isinstance(value, list | dict):
            raise ToolArgumentRehydrationError
        container_id = id(value)
        if container_id in active_containers:
            raise ToolArgumentRehydrationError
        active_containers.add(container_id)
        try:
            if isinstance(value, list):
                return [
                    self._rehydrate_value(
                        value=item,
                        destination=destination,
                        tokens=tokens,
                        active_containers=active_containers,
                    )
                    for item in value
                ]
            return self._rehydrate_mapping(
                value=value,
                destination=destination,
                tokens=tokens,
                active_containers=active_containers,
            )
        finally:
            active_containers.remove(container_id)

    def _rehydrate_mapping(
        self,
        *,
        value: dict[str, JsonValue],
        destination: str,
        tokens: list[SensitiveToken],
        active_containers: set[int],
    ) -> dict[str, JsonValue]:
        rehydrated: dict[str, JsonValue] = {}
        for name, item in value.items():
            if type(name) is not str:
                raise ToolArgumentRehydrationError
            key = self._rehydrate_text(text=name, destination=destination, tokens=tokens)
            if key in rehydrated:
                # Resolving distinct references must never overwrite an argument.
                raise TokenResolutionError
            rehydrated[key] = self._rehydrate_value(
                value=item,
                destination=destination,
                tokens=tokens,
                active_containers=active_containers,
            )
        return rehydrated

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
            rehydrated = f"{rehydrated[: match.start()]}{raw_value}{rehydrated[match.end() :]}"
        return rehydrated

    def _record_audit(
        self,
        event_type: AuditEventType,
        *,
        destination: str | None = None,
        decision: DataReleaseDecision | None = None,
        tokens: tuple[SensitiveToken, ...] = (),
        failure_reason: AuditFailureReason | None = None,
        resolutions: tuple[AuditResolution, ...] = (),
    ) -> None:
        try:
            unique_tokens = tuple(dict.fromkeys(audit_identifier(token.value) for token in tokens))
            entity_types = tuple(
                dict.fromkeys(audit_identifier(token.entity_type) for token in tokens)
            )
            self._audit_sink.record(
                AuditEvent(
                    event_type=event_type,
                    session_id=self._session_id,
                    entity_types=entity_types,
                    destination=audit_identifier(destination) if destination is not None else None,
                    decision=decision,
                    tokens=unique_tokens,
                    failure_reason=failure_reason,
                    resolutions=resolutions,
                )
            )
        except Exception:
            pass
        else:
            return
        # Raising outside the handler drops the sink's error. During __exit__,
        # Python can still attach the caller's active (possibly raw) body error.
        # Clear that context on the new static exception, then use a bare re-raise
        # so Python does not attach it again.
        try:
            raise AuditRecordingError
        except AuditRecordingError as failure:
            failure.__context__ = None
            raise


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
    if not isinstance(entities, tuple) or any(
        not isinstance(entity, SensitiveEntity) or entity.end > text_length for entity in entities
    ):
        raise DetectionUnavailableError


def _merge_cluster(cluster: list[SensitiveEntity]) -> SensitiveEntity:
    """Merge one type only; never discard another type's release restrictions."""
    if len({entity.entity_type for entity in cluster}) != 1:
        raise DetectionUnavailableError
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
