"""Private, process-local storage for one session's sensitive token mappings."""

from __future__ import annotations

from dataclasses import dataclass
from re import Pattern, compile
from threading import Lock, RLock
from uuid import uuid4

from .exceptions import CrossSessionTokenError, MalformedTokenError, UnknownTokenError
from .models import SensitiveToken

TOKEN_PATTERN: Pattern[str] = compile(r"^\[[A-Z][A-Z0-9_]*_[1-9][0-9]*\]$")


@dataclass(frozen=True, slots=True)
class VaultEntry:
    """A raw mapping kept exclusively inside an active process-local vault."""

    value: str
    entity_type: str


class TokenRegistry:
    """Process-local token ownership metadata without raw sensitive values."""

    def __init__(self) -> None:
        self._owners_by_token: dict[str, str] = {}
        self._next_sequence_by_entity_type: dict[str, int] = {}
        self._lock = Lock()

    def issue(self, *, entity_type: str, session_id: str) -> str:
        """Allocate a process-unique token and record its owning session."""
        with self._lock:
            sequence = self._next_sequence_by_entity_type.get(entity_type, 0) + 1
            token = f"[{entity_type}_{sequence}]"
            self._next_sequence_by_entity_type[entity_type] = sequence
            self._owners_by_token[token] = session_id
        return token

    def owner_for(self, token: str) -> str | None:
        """Return an active token's owner without exposing sensitive data."""
        with self._lock:
            return self._owners_by_token.get(token)

    def revoke(self, tokens: tuple[str, ...]) -> None:
        """Discard ownership metadata for tokens belonging to a closed vault."""
        with self._lock:
            for token in tokens:
                self._owners_by_token.pop(token, None)


class TokenVault:
    """In-memory token mappings for exactly one TrustSession.

    This type intentionally offers no serialization or persistence interface.
    Callers must clear it when its owning session closes.
    """

    def __init__(
        self,
        *,
        session_id: str | None = None,
        registry: TokenRegistry | None = None,
    ) -> None:
        self._session_id = session_id or uuid4().hex
        self._registry = registry or TokenRegistry()
        self._entries_by_token: dict[str, VaultEntry] = {}
        self._tokens_by_value: dict[tuple[str, str], SensitiveToken] = {}
        self._lock = RLock()

    def store(self, *, value: str, entity_type: str) -> SensitiveToken:
        """Store a raw value and return its stable token for this vault."""
        with self._lock:
            mapping_key = (entity_type, value)
            existing_token = self._tokens_by_value.get(mapping_key)
            if existing_token is not None:
                return existing_token

            token = SensitiveToken(
                value=self._registry.issue(entity_type=entity_type, session_id=self._session_id),
                entity_type=entity_type,
            )
            self._entries_by_token[token.value] = VaultEntry(value=value, entity_type=entity_type)
            self._tokens_by_value[mapping_key] = token
            return token

    def resolve(self, token: str) -> VaultEntry:
        """Return an internal mapping or fail closed for an unknown token."""
        with self._lock:
            if not TOKEN_PATTERN.fullmatch(token):
                raise MalformedTokenError

            entry = self._entries_by_token.get(token)
            if entry is not None:
                return entry
            owner_session_id = self._registry.owner_for(token)
            if owner_session_id is not None and owner_session_id != self._session_id:
                raise CrossSessionTokenError
            raise UnknownTokenError

    def clear(self) -> None:
        """Irreversibly discard all mappings held by this process-local vault."""
        with self._lock:
            self._registry.revoke(tuple(self._entries_by_token))
            self._entries_by_token.clear()
            self._tokens_by_value.clear()
