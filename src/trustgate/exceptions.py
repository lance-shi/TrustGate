"""Exceptions with deliberately non-sensitive messages."""


class TrustGateError(Exception):
    """Base exception for TrustGate failures."""

    default_message = "TrustGate operation failed."

    def __init__(self) -> None:
        super().__init__(self.default_message)


class FeatureUnavailableError(TrustGateError):
    """Raised when a planned capability has not yet been implemented."""

    default_message = "This TrustGate capability is not available yet."


class PolicyError(TrustGateError):
    """Base exception for invalid or unavailable data-release policy."""

    default_message = "The data-release policy cannot be used."


class ModelValidationError(TrustGateError):
    """Raised when a public TrustGate model receives invalid input."""

    default_message = "TrustGate model input is invalid."


class PolicyValidationError(PolicyError):
    """Raised when a policy cannot be parsed or validated."""

    default_message = "The data-release policy is invalid."


class DataReleaseDenied(TrustGateError):
    """Raised when a policy does not explicitly allow data release."""

    default_message = "Sensitive data release is denied."


class TokenResolutionError(TrustGateError):
    """Base exception for invalid token resolution attempts."""

    default_message = "The sensitive token cannot be resolved."


class UnknownTokenError(TokenResolutionError):
    """Raised when a token is unknown to the active session."""

    default_message = "The sensitive token is unknown to this session."


class CrossSessionTokenError(TokenResolutionError):
    """Raised when a token belongs to another session."""

    default_message = "The sensitive token belongs to a different session."


class MalformedTokenError(TokenResolutionError):
    """Raised when a token has an invalid TrustGate format."""

    default_message = "The sensitive token has an invalid format."


class SessionClosedError(TrustGateError):
    """Raised when an operation requires an active session."""

    default_message = "The TrustGate session is closed."
