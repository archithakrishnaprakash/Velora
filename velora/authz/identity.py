"""Identity resolution.

An ``Identity`` record stores only a reference to a secret (an environment variable
name), never the secret itself. ``IdentityResolver`` reads the value at request time and
converts it into request headers. Resolved values are held only for the duration of a
request and are never written to the database, logs, evidence, or reports.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from ..models.domain import Identity
from ..models.enums import IdentityRole
from ..utils.logging import get_logger

log = get_logger("authz.identity")

# Auth schemes we know how to apply.
SUPPORTED_SCHEMES = frozenset({"bearer", "header", "cookie", "none"})


class MissingCredentialError(RuntimeError):
    """Raised when an identity's secret reference is not set in the environment."""


@dataclass
class ResolvedIdentity:
    """An identity with its request headers materialized for a single run.

    ``headers`` may contain a credential, so this object must never be persisted,
    logged, or embedded in evidence. Use :meth:`safe_summary` for anything recorded.
    """

    identity: Identity
    headers: dict[str, str] = field(default_factory=dict)
    resolved: bool = False
    reason: str = ""

    @property
    def role(self) -> IdentityRole:
        return self.identity.role

    @property
    def name(self) -> str:
        return self.identity.name

    @property
    def is_anonymous(self) -> bool:
        return self.identity.role == IdentityRole.ANONYMOUS or not self.headers

    def safe_summary(self) -> dict[str, object]:
        """A record-safe description: names and flags only, never values."""
        return {
            "identity_id": self.identity.id,
            "name": self.identity.name,
            "role": self.identity.role.value,
            "authenticated": bool(self.headers),
            "auth_scheme": self.identity.auth_scheme,
            "header_names": sorted(self.headers.keys()),
            "secret_ref": self.identity.secret_ref or "(none)",
            "resolved": self.resolved,
            "reason": self.reason,
        }


class IdentityResolver:
    """Turns stored ``Identity`` records into request headers using the environment."""

    def __init__(self, env: dict[str, str] | None = None) -> None:
        # Injectable for tests; defaults to the real process environment.
        self._env = env if env is not None else os.environ

    def available(self, identity: Identity) -> bool:
        """True when the identity can be used (anonymous, or its secret is present)."""
        if identity.role == IdentityRole.ANONYMOUS or identity.auth_scheme == "none":
            return True
        return bool(identity.secret_ref) and bool(self._env.get(identity.secret_ref))

    def resolve(self, identity: Identity, *, strict: bool = False) -> ResolvedIdentity:
        """Materialize request headers for ``identity``.

        With ``strict=True`` a missing credential raises instead of degrading to an
        unauthenticated identity — important so a misconfigured run is not silently
        interpreted as "anonymous could read everything".
        """
        scheme = (identity.auth_scheme or "none").lower()
        if scheme not in SUPPORTED_SCHEMES:
            raise ValueError(f"unsupported auth_scheme: {identity.auth_scheme}")

        if identity.role == IdentityRole.ANONYMOUS or scheme == "none":
            return ResolvedIdentity(identity=identity, headers={}, resolved=True,
                                    reason="anonymous identity (no credential required)")

        if not identity.secret_ref:
            msg = f"identity '{identity.name}' has no secret_ref configured"
            if strict:
                raise MissingCredentialError(msg)
            log.warning("%s; treating as unauthenticated", msg)
            return ResolvedIdentity(identity=identity, headers={}, resolved=False, reason=msg)

        secret = self._env.get(identity.secret_ref)
        if not secret:
            msg = (f"environment variable '{identity.secret_ref}' is not set for identity "
                   f"'{identity.name}'")
            if strict:
                raise MissingCredentialError(msg)
            # Never log the variable's value — only its name.
            log.warning("%s; treating as unauthenticated", msg)
            return ResolvedIdentity(identity=identity, headers={}, resolved=False, reason=msg)

        headers = self._build_headers(identity, secret)
        return ResolvedIdentity(identity=identity, headers=headers, resolved=True,
                                reason=f"credential loaded from {identity.secret_ref}")

    @staticmethod
    def _build_headers(identity: Identity, secret: str) -> dict[str, str]:
        scheme = (identity.auth_scheme or "bearer").lower()
        header_name = identity.auth_header_name or "Authorization"
        if scheme == "bearer":
            return {header_name: f"Bearer {secret}"}
        if scheme == "header":
            return {header_name: secret}
        if scheme == "cookie":
            return {"Cookie": secret}
        return {}

    def resolve_all(
        self, identities: list[Identity], *, strict: bool = False
    ) -> dict[str, ResolvedIdentity]:
        return {i.id: self.resolve(i, strict=strict) for i in identities}
