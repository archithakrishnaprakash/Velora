"""Typed exception hierarchy for Velora."""
from __future__ import annotations


class VeloraError(Exception):
    """Base class for all framework errors."""


class ConfigError(VeloraError):
    """Raised when configuration is invalid or missing."""


class ScopeViolation(VeloraError):
    """Raised when an action would target a resource outside the authorized scope.

    This is a security control: it must never be swallowed silently. Callers may
    catch it to log and skip, but must not proceed with the blocked request.
    """

    def __init__(self, url: str, reason: str) -> None:
        self.url = url
        self.reason = reason
        super().__init__(f"OUT_OF_SCOPE: {url} ({reason})")


class AuthorizationError(VeloraError):
    """Raised when a scan is attempted without an authorization acknowledgement."""


class RateLimitExceeded(VeloraError):
    """Raised when the configured request budget for a scan is exhausted."""


class IntegrationError(VeloraError):
    """Raised when an external tool adapter fails or is unavailable."""


class AIProviderError(VeloraError):
    """Raised when an AI provider cannot produce a valid, schema-conformant response."""
