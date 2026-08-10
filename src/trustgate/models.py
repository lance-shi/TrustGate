"""Typed, LLM-safe public models for TrustGate."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Annotated, Self

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from typing_extensions import TypeAliasType

from .exceptions import ModelValidationError

JsonValue = TypeAliasType(
    "JsonValue",
    str | int | float | bool | None | list["JsonValue"] | dict[str, "JsonValue"]
)

EntityType = Annotated[str, Field(pattern=r"^[A-Z][A-Z0-9_]*$", min_length=1)]
TokenValue = Annotated[
    str,
    Field(pattern=r"^\[[A-Z][A-Z0-9_]*_[1-9][0-9]*\]$", min_length=5),
]
Destination = Annotated[str, Field(min_length=1, max_length=256)]
SAFE_MODEL_CONFIG = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)


class SafePublicModel(BaseModel):
    """A public model that never exposes invalid caller input through errors."""

    model_config = SAFE_MODEL_CONFIG

    def __init__(self, /, **data: object) -> None:
        try:
            super().__init__(**data)
        except ValidationError:
            pass
        else:
            return
        raise ModelValidationError

    @classmethod
    def model_validate(cls, *args: object, **kwargs: object) -> Self:
        try:
            return super().model_validate(*args, **kwargs)
        except ValidationError:
            pass
        raise ModelValidationError


class DataReleaseDecision(StrEnum):
    """A destination-aware decision to release a sensitive value to a tool."""

    ALLOW = "allow"
    DENY = "deny"


class AuditEventType(StrEnum):
    """Safe event categories emitted by the audit boundary."""

    SESSION_OPENED = "session_opened"
    SESSION_CLOSED = "session_closed"
    VALUE_SANITIZED = "value_sanitized"
    TOOL_RELEASE_ALLOWED = "tool_release_allowed"
    TOOL_RELEASE_DENIED = "tool_release_denied"
    TOOL_RESULT_SANITIZED = "tool_result_sanitized"


class SensitiveEntity(SafePublicModel):
    """A detected sensitive span without its original value."""

    entity_type: EntityType
    start: int = Field(ge=0)
    end: int = Field(gt=0)
    score: float = Field(ge=0, le=1)

    def model_post_init(self, __context: object) -> None:
        if self.end <= self.start:
            raise ValueError("Sensitive entity end must be greater than start.")


class SensitiveToken(SafePublicModel):
    """An LLM-visible token referencing a session-local sensitive value."""

    value: TokenValue
    entity_type: EntityType


class DataReleaseRequest(SafePublicModel):
    """The non-sensitive context used to decide a tool data release."""

    entity_type: EntityType
    destination: Destination


class DataReleaseResult(DataReleaseRequest):
    """The policy decision for a tool data-release request."""

    decision: DataReleaseDecision


class ToolCall(SafePublicModel):
    """A tool call proposed by the LLM; arguments must be LLM-visible values."""

    name: Destination
    arguments: dict[str, JsonValue] = Field(default_factory=dict)


class AuditEvent(SafePublicModel):
    """A serializable audit record that intentionally has no raw-value field."""

    event_type: AuditEventType
    session_id: str = Field(min_length=1)
    entity_types: tuple[EntityType, ...] = ()
    destination: Destination | None = None
    decision: DataReleaseDecision | None = None
    tokens: tuple[TokenValue, ...] = ()
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
