"""Exception hierarchy for BDOS."""

from __future__ import annotations


class BDOSError(Exception):
    """Base class for every BDOS error."""


class ConfigError(BDOSError):
    """Malformed or inconsistent configuration."""


class PolicyViolation(BDOSError):
    """An action was denied by a policy engine."""


class AttestationError(BDOSError):
    """A safety-notice capability token failed validation."""


class ReplayError(AttestationError):
    """A token nonce was already seen (replay attempt)."""


class ExpiredError(AttestationError):
    """A token is outside its validity window."""


class RevokedError(AttestationError):
    """A token (or its key) has been revoked."""


class SealedEnclaveError(PolicyViolation):
    """A mutating operation was attempted against a sealed black-domain enclave."""
