"""TrustGate: a policy-controlled privacy boundary for LLM applications."""

from .exceptions import (
    CrossSessionTokenError,
    DataReleaseDenied,
    DetectionUnavailableError,
    FeatureUnavailableError,
    MalformedTokenError,
    ModelValidationError,
    PolicyError,
    PolicyValidationError,
    SessionClosedError,
    TokenResolutionError,
    TrustGateError,
    UnknownTokenError,
)
from .gate import TrustGate
from .models import (
    AuditEvent,
    AuditEventType,
    DataReleaseDecision,
    DataReleaseRequest,
    DataReleaseResult,
    SensitiveEntity,
    SensitiveToken,
    ToolCall,
)
from .session import TrustSession

__all__ = [
    "AuditEvent",
    "AuditEventType",
    "CrossSessionTokenError",
    "DataReleaseDecision",
    "DataReleaseDenied",
    "DetectionUnavailableError",
    "DataReleaseRequest",
    "DataReleaseResult",
    "FeatureUnavailableError",
    "MalformedTokenError",
    "ModelValidationError",
    "PolicyError",
    "PolicyValidationError",
    "SensitiveEntity",
    "SensitiveToken",
    "SessionClosedError",
    "TokenResolutionError",
    "ToolCall",
    "TrustGate",
    "TrustGateError",
    "TrustSession",
    "UnknownTokenError",
]
