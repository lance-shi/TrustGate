"""The Day 1 public session scaffold.

Sensitive transformations are implemented in later milestones. Until then,
operations that could disclose a value fail safely rather than returning input.
"""

from __future__ import annotations

from types import TracebackType
from uuid import uuid4

from .exceptions import DataReleaseDenied, FeatureUnavailableError, SessionClosedError
from .models import JsonValue, ToolCall


class TrustSession:
    """An explicit TrustGate session with a future session-local token vault."""

    def __init__(self) -> None:
        self._session_id = uuid4().hex
        self._closed = False

    @property
    def session_id(self) -> str:
        """Return an opaque identifier suitable for safe audit correlation."""
        return self._session_id

    @property
    def is_closed(self) -> bool:
        """Return whether the session has been closed."""
        return self._closed

    def __enter__(self) -> TrustSession:
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
        """Close the session. Vault cleanup is added with the vault implementation."""
        self._closed = True

    def sanitize(self, text: str) -> str:
        """Return LLM-safe text once detection and tokenization are implemented."""
        self._ensure_open()
        raise FeatureUnavailableError

    def rehydrate_for_tool(self, tool_call: ToolCall) -> dict[str, JsonValue]:
        """Release approved token values to a tool; default denial is already active."""
        self._ensure_open()
        raise DataReleaseDenied

    def sanitize_tool_result(self, result: JsonValue) -> JsonValue:
        """Return an LLM-safe copy of a tool result once sanitization is implemented."""
        self._ensure_open()
        raise FeatureUnavailableError

    def rehydrate_for_user(self, text: str) -> str:
        """Restore a tokenized response for its user after vault support is implemented."""
        self._ensure_open()
        raise FeatureUnavailableError

    def _ensure_open(self) -> None:
        if self._closed:
            raise SessionClosedError
