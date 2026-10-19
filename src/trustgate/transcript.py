"""Private in-memory collection of completed sanitization outputs only."""

from __future__ import annotations

from copy import deepcopy

from .models import JsonValue, TranscriptEntry, TranscriptEntryType


class _SanitizedTranscript:
    """Owned by one session; no public append or external logging sink."""

    def __init__(self) -> None:
        self._entries: list[TranscriptEntry] = []

    def _record(self, kind: TranscriptEntryType, content: JsonValue) -> None:
        # Only TrustSession calls this, after a complete sanitization succeeds.
        self._entries.append(TranscriptEntry(kind=kind, content=deepcopy(content)))

    def _snapshot(self) -> tuple[TranscriptEntry, ...]:
        # Frozen models alone do not protect nested JSON lists and dictionaries.
        return tuple(deepcopy(entry) for entry in self._entries)
