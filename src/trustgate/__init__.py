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
    DataPolicy,
    DataReleaseDecision,
    DataReleaseRequest,
    DataReleaseResult,
    ExternalLLMHandling,
    SensitiveEntity,
    SensitiveToken,
    ToolCall,
    TrustPolicy,
)
from .policy import decide_data_release
from .session import TrustSession

__all__ = [
    "AuditEvent",
    "AuditEventType",
    "CrossSessionTokenError",
    "DataPolicy",
    "DataReleaseDecision",
    "DataReleaseDenied",
    "DetectionUnavailableError",
    "ExternalLLMHandling",
    "DataReleaseRequest",
    "DataReleaseResult",
    "decide_data_release",
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
    "TrustPolicy",
    "TrustSession",
    "UnknownTokenError",
]
