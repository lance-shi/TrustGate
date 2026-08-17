"""The provider-independent TrustGate entry point."""

from __future__ import annotations

from pathlib import Path

import yaml

from .audit import AuditSink, InMemoryAuditSink
from .exceptions import PolicyValidationError
from .models import TrustPolicy
from .session import TrustSession


class TrustGate:
    """Create explicit sessions around an application's LLM and tool boundaries."""

    def __init__(
        self,
        *,
        policy: TrustPolicy | None = None,
        audit_sink: AuditSink | None = None,
    ) -> None:
        self._policy = policy
        self._audit_sink = audit_sink or InMemoryAuditSink()

    @property
    def policy(self) -> TrustPolicy | None:
        """Return the validated release policy, if this gate was configured with one."""
        return self._policy

    @property
    def audit_sink(self) -> AuditSink:
        """Return the safe audit sink shared by this gate's sessions."""
        return self._audit_sink

    @classmethod
    def from_yaml(cls, path: str | Path) -> TrustGate:
        """Create a gate from one validated UTF-8 YAML policy document.

        Any unreadable, malformed, or structurally invalid document fails closed
        with a static exception that does not expose the path or document content.
        """
        try:
            document = Path(path).read_text(encoding="utf-8")
            parsed = yaml.safe_load(document)
            policy = TrustPolicy.model_validate(parsed)
        except (OSError, TypeError, UnicodeError, yaml.YAMLError, PolicyValidationError):
            policy = None
        if policy is None:
            raise PolicyValidationError
        return cls(policy=policy)

    def session(self, *, principal: str | None = None) -> TrustSession:
        """Create a new explicit session.

        ``principal`` is accepted for the planned public API but is deliberately
        not retained by the Day 1 scaffold.
        """
        return TrustSession(policy=self._policy, audit_sink=self._audit_sink)
