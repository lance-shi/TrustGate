"""In-memory, raw-value-free audit event collection."""

from __future__ import annotations

from hashlib import sha256
from threading import RLock
from typing import Protocol

from .models import AuditEvent


def audit_identifier(value: str) -> str:
    """Return a fixed-format identifier without retaining the source text."""
    digest = sha256(value.encode("utf-8")).hexdigest()
    return f"audit_{digest}"


class AuditSink(Protocol):
    """A destination for already-safe TrustGate audit events."""

    def record(self, event: AuditEvent) -> None:
        """Record one audit event that contains no raw sensitive values."""


class InMemoryAuditSink:
    """A process-local audit sink intended for tests and v0.1 integrations."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []
        self._lock = RLock()

    @property
    def events(self) -> tuple[AuditEvent, ...]:
        """Return a snapshot of the safe, serialized-event inputs."""
        with self._lock:
            return tuple(self._events)

    def record(self, event: AuditEvent) -> None:
        with self._lock:
            self._events.append(event)
