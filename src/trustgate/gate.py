"""The provider-independent TrustGate entry point."""

from __future__ import annotations

from pathlib import Path

from .exceptions import FeatureUnavailableError
from .session import TrustSession


class TrustGate:
    """Create explicit sessions around an application's LLM and tool boundaries."""

    @classmethod
    def from_yaml(cls, path: str | Path) -> TrustGate:
        """Create a gate from YAML policy once policy loading is implemented on Day 3."""
        raise FeatureUnavailableError

    def session(self, *, principal: str | None = None) -> TrustSession:
        """Create a new explicit session.

        ``principal`` is accepted for the planned public API but is deliberately
        not retained by the Day 1 scaffold.
        """
        return TrustSession()
