"""Authorization matrix execution.

Executes each matrix cell as an ordinary scope-gated request and decides what was
observed. Where an owner baseline exists, the differential engine is used to strengthen
the signal: a non-owner response that is *structurally identical* to the owner's is far
stronger evidence than a bare 200.

Nothing here escalates privileges or exploits anything — it issues configured requests
and records what came back.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..core.http import HttpResponse, SafeHTTPClient
from ..differential.engine import DifferentialEngine, DifferentialResult
from ..models.enums import AccessExpectation, AccessObservation, AuthzOutcome, IdentityRole
from ..utils.errors import RateLimitExceeded, ScopeViolation
from ..utils.logging import get_logger
from .identity import IdentityResolver, ResolvedIdentity
from .matrix import AuthzCase, AuthzMatrix

log = get_logger("authz.runner")

# Markers suggesting the response is a sign-in / denial surface rather than the resource.
_DENIAL_MARKERS = (
    re.compile(r"(?i)<form[^>]*(login|signin|sign-in)"),
    re.compile(r"(?i)\b(please\s+log\s?in|sign\s?in\s+to\s+continue|access\s+denied|"
               r"not\s+authori[sz]ed|permission\s+denied|forbidden)\b"),
    re.compile(r"(?i)\"error\"\s*:\s*\"(unauthorized|forbidden|access denied)\""),
)

_LOGIN_PATH = re.compile(r"(?i)/(login|signin|sign-in|auth|account/login)\b")


@dataclass
class AuthzTestResult:
    """The outcome of executing one matrix cell."""

    case: AuthzCase
    observed: AccessObservation
    outcome: AuthzOutcome
    status_code: int | None = None
    response_size: int = 0
    reason: str = ""
    differential: DifferentialResult | None = None
    identity_summary: dict[str, object] = field(default_factory=dict)
    error: str | None = None

    @property
    def is_weakness(self) -> bool:
        return self.outcome.is_weakness


def classify_observation(resp: HttpResponse) -> tuple[AccessObservation, str]:
    """Decide whether a response represents granted or denied access."""
    if resp.error:
        return AccessObservation.ERROR, f"transport error: {resp.error}"
    status = resp.status_code
    if status in (401, 403):
        return AccessObservation.DENIED, f"explicit deny status {status}"
    if status in (404, 410):
        # Could be a genuine 404 or a deliberate "hide it" response. Not a grant.
        return AccessObservation.INCONCLUSIVE, f"status {status} (absent or hidden)"
    if 500 <= status < 600:
        return AccessObservation.INCONCLUSIVE, f"server error {status}"
    if 300 <= status < 400:
        location = resp.header("location") or ""
        if _LOGIN_PATH.search(location):
            return AccessObservation.DENIED, f"redirected to a sign-in surface ({location[:80]})"
        return AccessObservation.INCONCLUSIVE, f"redirect to {location[:80] or 'unknown'}"
    if 200 <= status < 300:
        body = resp.body or ""
        for marker in _DENIAL_MARKERS:
            if marker.search(body):
                return (AccessObservation.DENIED,
                        "status 200 but the body is a sign-in/denial surface")
        return AccessObservation.GRANTED, f"status {status} with resource-like content"
    return AccessObservation.INCONCLUSIVE, f"unhandled status {status}"


def classify_outcome(case: AuthzCase, observed: AccessObservation) -> tuple[AuthzOutcome, str]:
    """Compare expectation with observation and name the weakness class, if any."""
    expected = case.expected
    identity = case.identity
    resource = case.resource

    if expected == AccessExpectation.UNKNOWN:
        return (AuthzOutcome.INCONCLUSIVE,
                "no expectation was declared for this pair, so no judgement is made")

    if observed in (AccessObservation.ERROR, AccessObservation.INCONCLUSIVE):
        return AuthzOutcome.INCONCLUSIVE, "observation was not decisive"

    if expected == AccessExpectation.ALLOW:
        if observed == AccessObservation.GRANTED:
            return AuthzOutcome.AS_EXPECTED, "allowed as expected"
        # Denied where allowed is a functional/credential problem, not a security weakness.
        return (AuthzOutcome.INCONCLUSIVE,
                "expected ALLOW but access was denied — check the identity's credential "
                "or the expectation; this is not treated as a security weakness")

    # expected == DENY
    if observed == AccessObservation.DENIED:
        return AuthzOutcome.AS_EXPECTED, "denied as expected"

    # Denied was expected but access was granted -> classify the boundary that was crossed.
    if identity.role == IdentityRole.ANONYMOUS:
        return (AuthzOutcome.UNAUTHENTICATED_ACCESS,
                "an unauthenticated identity reached a resource expected to be protected")
    if resource.owner and identity.name != resource.owner:
        return (AuthzOutcome.HORIZONTAL_AUTHORIZATION_WEAKNESS,
                f"identity '{identity.name}' reached a resource owned by '{resource.owner}'")
    if resource.requires_role and identity.role.privilege_rank < resource.requires_role.privilege_rank:
        return (AuthzOutcome.VERTICAL_AUTHORIZATION_WEAKNESS,
                f"identity role '{identity.role.value}' reached a resource requiring "
                f"'{resource.requires_role.value}'")
    return (AuthzOutcome.PRIVILEGE_BOUNDARY_WEAKNESS,
            "access was granted where the plan expected it to be denied")


class AuthzRunner:
    """Executes an authorization matrix through the scope-gated HTTP client."""

    def __init__(
        self,
        client: SafeHTTPClient,
        resolver: IdentityResolver | None = None,
        engine: DifferentialEngine | None = None,
    ) -> None:
        self.client = client
        self.resolver = resolver or IdentityResolver()
        self.engine = engine or DifferentialEngine(ignore_timing=True)

    async def _fetch(self, url: str, method: str, resolved: ResolvedIdentity) -> HttpResponse | None:
        try:
            return await self.client.request(method, url, headers=resolved.headers or None)
        except ScopeViolation as exc:
            log.security("AUTHZ_REQUEST_BLOCKED url=%s identity=%s reason=%s",
                         url, resolved.name, exc.reason)
            return None
        except RateLimitExceeded:
            log.warning("authorization run stopped: request budget exhausted")
            return None

    async def run(self, matrix: AuthzMatrix, *, strict_credentials: bool = False) -> list[AuthzTestResult]:
        """Execute every cell, returning one result per case."""
        results: list[AuthzTestResult] = []
        # Resolve each identity once.
        resolved_cache: dict[str, ResolvedIdentity] = {}
        # Owner baselines, keyed by resource url, used for differential strengthening.
        owner_baselines: dict[str, HttpResponse] = {}

        # First pass: capture owner baselines so cross-account comparisons are possible.
        for case in matrix.cases:
            owner = case.resource.owner
            if not owner or case.identity.name != owner:
                continue
            resolved = resolved_cache.setdefault(
                case.identity.id, self.resolver.resolve(case.identity, strict=strict_credentials))
            resp = await self._fetch(case.resource.url, case.resource.method, resolved)
            if resp is not None and not resp.error:
                owner_baselines[case.resource.url] = resp

        # Second pass: execute every cell.
        for case in matrix.cases:
            resolved = resolved_cache.setdefault(
                case.identity.id, self.resolver.resolve(case.identity, strict=strict_credentials))
            resp = await self._fetch(case.resource.url, case.resource.method, resolved)
            if resp is None:
                results.append(AuthzTestResult(
                    case=case, observed=AccessObservation.ERROR,
                    outcome=AuthzOutcome.INCONCLUSIVE,
                    reason="request blocked by scope policy or request budget",
                    identity_summary=resolved.safe_summary(), error="blocked"))
                continue

            observed, obs_reason = classify_observation(resp)
            differential = None
            baseline = owner_baselines.get(case.resource.url)
            if (baseline is not None and case.identity.name != case.resource.owner
                    and observed == AccessObservation.GRANTED):
                differential = self.engine.compare_responses(baseline, resp)
                if not differential.changed:
                    obs_reason += ("; response is structurally identical to the owner's "
                                   "response (strong cross-account signal)")

            outcome, out_reason = classify_outcome(case, observed)
            results.append(AuthzTestResult(
                case=case,
                observed=observed,
                outcome=outcome,
                status_code=resp.status_code,
                response_size=resp.response_size,
                reason=f"{obs_reason}; {out_reason}",
                differential=differential,
                identity_summary=resolved.safe_summary(),
            ))
        return results
