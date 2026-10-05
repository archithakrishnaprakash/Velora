"""Authorization test-matrix construction.

A matrix pairs every configured identity against every declared resource and records
what the operator expects to happen. Expectations are the ground truth against which
observed behaviour is judged, so they are derived conservatively and can always be
overridden explicitly in the plan.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..models.domain import Identity
from ..models.enums import AccessExpectation, IdentityRole


@dataclass
class ResourceSpec:
    """A resource under test, and who legitimately owns/may reach it."""

    url: str
    method: str = "GET"
    name: str = ""
    # Identity name that owns this resource (for horizontal tests).
    owner: str | None = None
    # Minimum role required to reach it (for vertical tests).
    requires_role: IdentityRole | None = None
    # Explicit per-identity overrides: {identity_name: "ALLOW"|"DENY"|"UNKNOWN"}
    expectations: dict[str, str] = field(default_factory=dict)

    @property
    def label(self) -> str:
        return self.name or f"{self.method} {self.url}"


@dataclass
class AuthzCase:
    """One cell of the matrix."""

    identity: Identity
    resource: ResourceSpec
    expected: AccessExpectation
    rationale: str = ""

    @property
    def key(self) -> str:
        return f"{self.identity.name}:{self.resource.method}:{self.resource.url}"


@dataclass
class AuthzMatrix:
    cases: list[AuthzCase] = field(default_factory=list)
    skipped: list[dict[str, str]] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.cases)

    def for_resource(self, url: str) -> list[AuthzCase]:
        return [c for c in self.cases if c.resource.url == url]


def expectation_for(identity: Identity, resource: ResourceSpec) -> tuple[AccessExpectation, str]:
    """Derive the expected access decision for one identity/resource pair.

    Order of precedence:
      1. An explicit per-identity expectation in the resource spec.
      2. Ownership: the owner is allowed; a same-or-lower-privilege non-owner is denied.
      3. Required role: identities below the required rank are denied.
      4. Otherwise UNKNOWN — the matrix will not judge what the operator did not declare.
    """
    override = resource.expectations.get(identity.name)
    if override:
        try:
            return AccessExpectation(override.upper()), "explicit expectation from plan"
        except ValueError:
            pass

    if resource.owner:
        if identity.name == resource.owner:
            return AccessExpectation.ALLOW, "identity owns this resource"
        if identity.role == IdentityRole.ANONYMOUS:
            return AccessExpectation.DENY, "anonymous access to an owned resource"
        # An administrator may legitimately read other users' resources; do not assume.
        if identity.role.privilege_rank > IdentityRole.USER_A.privilege_rank:
            return (AccessExpectation.UNKNOWN,
                    "higher-privilege identity may legitimately access this resource; "
                    "declare an explicit expectation to test it")
        return AccessExpectation.DENY, "cross-account access by a same-privilege identity"

    if resource.requires_role:
        if identity.role.privilege_rank >= resource.requires_role.privilege_rank:
            return AccessExpectation.ALLOW, "identity meets the required role"
        return AccessExpectation.DENY, (
            f"identity rank below required role '{resource.requires_role.value}'"
        )

    return AccessExpectation.UNKNOWN, "no ownership or required role declared"


def build_matrix(identities: list[Identity], resources: list[ResourceSpec]) -> AuthzMatrix:
    """Construct the full identity × resource matrix."""
    matrix = AuthzMatrix()
    for resource in resources:
        for identity in identities:
            expected, rationale = expectation_for(identity, resource)
            matrix.cases.append(
                AuthzCase(identity=identity, resource=resource,
                          expected=expected, rationale=rationale)
            )
    return matrix
