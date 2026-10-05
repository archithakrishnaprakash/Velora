"""Persistence for authorization testing.

Converts runner results into ``AuthorizationTest`` records, evidence, and — for genuine
weaknesses — ``Potential`` findings. Findings are never auto-confirmed; a human must
validate them. Credentials never reach any persisted structure: only the identity's
safe summary (names, flags, the secret *reference*) is stored.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..database.repository import Repository
from ..differential.service import DifferentialService, ExchangeSpec
from ..evidence.store import EvidenceStore
from ..models.domain import AuditLog, AuthorizationTest, Finding, Scan
from ..models.enums import (
    AccessObservation,
    AuthzOutcome,
    Confidence,
    FindingStatus,
    Severity,
    ValidationState,
)
from ..findings import fingerprint as fp
from ..risk.scoring import PriorityInputs, compute_priority
from ..scanners.base import EvidenceItem
from ..utils.logging import get_logger
from .runner import AuthzTestResult

log = get_logger("authz.service")

# Weakness class -> (severity, CWE, OWASP category, title template, remediation)
_OUTCOME_PROFILE: dict[AuthzOutcome, tuple[Severity, str, str, str, str]] = {
    AuthzOutcome.UNAUTHENTICATED_ACCESS: (
        Severity.HIGH, "CWE-306", "A01:2021-Broken Access Control",
        "Unauthenticated access to a protected resource",
        "Require authentication on this endpoint and verify the session server-side.",
    ),
    AuthzOutcome.HORIZONTAL_AUTHORIZATION_WEAKNESS: (
        Severity.HIGH, "CWE-639", "A01:2021-Broken Access Control",
        "Cross-account access to another user's resource",
        "Enforce an ownership check that binds the resource to the authenticated "
        "principal on every request; do not trust identifiers supplied by the client.",
    ),
    AuthzOutcome.VERTICAL_AUTHORIZATION_WEAKNESS: (
        Severity.HIGH, "CWE-269", "A01:2021-Broken Access Control",
        "Privileged functionality reachable by a lower-privileged identity",
        "Enforce role checks server-side on every privileged operation.",
    ),
    AuthzOutcome.PRIVILEGE_BOUNDARY_WEAKNESS: (
        Severity.MEDIUM, "CWE-285", "A01:2021-Broken Access Control",
        "Access granted where the assessment plan expected denial",
        "Review the access-control rule for this endpoint and enforce it server-side.",
    ),
}


@dataclass
class AuthzRunSummary:
    total: int = 0
    weaknesses: int = 0
    as_expected: int = 0
    inconclusive: int = 0
    findings: list[Finding] = field(default_factory=list)
    tests: list[AuthorizationTest] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "total": self.total,
            "weaknesses": self.weaknesses,
            "as_expected": self.as_expected,
            "inconclusive": self.inconclusive,
            "findings": [f.id for f in self.findings],
        }


class AuthorizationTestingService:
    def __init__(self, repo: Repository) -> None:
        self.repo = repo
        self.evidence = EvidenceStore(repo)
        self.differential = DifferentialService(repo)

    def _confidence_for(self, result: AuthzTestResult) -> Confidence:
        """Confidence that the observation is reliable, not that it is exploitable."""
        if result.observed != AccessObservation.GRANTED:
            return Confidence.TENTATIVE
        # A structurally identical response to the owner's is the strongest signal.
        if result.differential is not None and not result.differential.changed:
            return Confidence.FIRM
        if result.status_code and 200 <= result.status_code < 300:
            return Confidence.FIRM
        return Confidence.TENTATIVE

    def record(
        self,
        results: list[AuthzTestResult],
        *,
        scan: Scan | None = None,
        engagement_id: str | None = None,
        plan_id: str | None = None,
        create_findings: bool = True,
    ) -> AuthzRunSummary:
        summary = AuthzRunSummary(total=len(results))
        scan_id = scan.id if scan else None

        for result in results:
            case = result.case
            evidence_ids: list[str] = []
            if scan_id:
                item = EvidenceItem(
                    test_name="authz.matrix",
                    request={
                        "url": case.resource.url,
                        "method": case.resource.method,
                        # Identity summary only — never headers or credentials.
                        "identity": result.identity_summary,
                    },
                    response={"status_code": result.status_code,
                              "response_size": result.response_size},
                    status_code=result.status_code,
                    response_size=result.response_size,
                    excerpt=(f"expected={case.expected.value} observed={result.observed.value} "
                             f"outcome={result.outcome.value}: {result.reason}"),
                    confidence=self._confidence_for(result).score,
                )
                record = self.evidence.persist(scan_id, item)
                evidence_ids.append(record.id)

            # Persist the owner-baseline comparison so the evidence matrix can credit
            # it. Without this the differential exists only as prose in `notes`, and
            # the "owner-baseline comparison performed" signal is unreachable.
            differential_id: str | None = None
            if result.differential is not None and scan_id:
                observation = self.differential.persist(
                    result.differential,
                    ExchangeSpec(url=case.resource.url, method=case.resource.method,
                                 label=f"owner:{case.resource.owner or 'unknown'}"),
                    ExchangeSpec(url=case.resource.url, method=case.resource.method,
                                 label=f"identity:{case.identity.name}"),
                    scan_id=scan_id, engagement_id=engagement_id,
                    label=f"owner baseline vs {case.identity.name}")
                differential_id = observation.id

            owner_identity = (self.repo.get_identity_by_name(case.resource.owner)
                              if case.resource.owner else None)
            test = AuthorizationTest(
                scan_id=scan_id,
                engagement_id=engagement_id,
                plan_id=plan_id,
                identity_id=case.identity.id,
                identity_role=case.identity.role,
                # Store an Identity id when the owner is a known identity; fall back to
                # the plan's owner label otherwise, so the field is never silently empty.
                resource_owner_identity_id=(owner_identity.id if owner_identity
                                            else case.resource.owner),
                differential_id=differential_id,
                url=case.resource.url,
                method=case.resource.method,
                expected=case.expected,
                observed=result.observed,
                outcome=result.outcome,
                status_code=result.status_code,
                response_size=result.response_size,
                evidence_ids=evidence_ids,
                notes=result.reason,
            )
            self.repo.add_authz_test(test)
            summary.tests.append(test)

            if result.outcome == AuthzOutcome.AS_EXPECTED:
                summary.as_expected += 1
            elif result.outcome.is_weakness:
                summary.weaknesses += 1
                if create_findings and scan is not None:
                    finding = self._create_finding(scan, result, test, engagement_id)
                    summary.findings.append(finding)
            else:
                summary.inconclusive += 1

        self.repo.audit(AuditLog(
            action="authz_test_executed",
            actor=scan.operator if scan else "",
            target_ref=scan_id or "",
            detail=summary.to_dict(),
        ))
        log.info("AUTHZ_TEST_EXECUTED total=%d weaknesses=%d inconclusive=%d",
                 summary.total, summary.weaknesses, summary.inconclusive)
        return summary

    def _create_finding(
        self,
        scan: Scan,
        result: AuthzTestResult,
        test: AuthorizationTest,
        engagement_id: str | None,
    ) -> Finding:
        severity, cwe, owasp, title, remediation = _OUTCOME_PROFILE[result.outcome]
        confidence = self._confidence_for(result)
        case = result.case

        description = (
            f"Identity '{case.identity.name}' (role {case.identity.role.value}) issued "
            f"{case.resource.method} {case.resource.url}. The assessment plan expected "
            f"{case.expected.value} ({case.rationale}); the observed result was "
            f"{result.observed.value}. {result.reason}. "
            "This is an evidence-backed INDICATOR of an access-control gap and requires "
            "human validation before it is treated as confirmed."
        )

        finding = Finding(
            scan_id=scan.id,
            engagement_id=engagement_id,
            identity_id=case.identity.id,
            title=f"{title}: {case.resource.label}",
            description=description,
            category="authorization",
            severity=severity,
            confidence=confidence,
            status=FindingStatus.POTENTIAL,
            endpoint=case.resource.url,
            method=case.resource.method,
            evidence_ids=list(test.evidence_ids),
            impact=("An actor could reach data or functionality that the access-control "
                    "model is meant to prevent."),
            remediation=remediation,
            references=["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"],
            scanner="authz.matrix",
            cwe_id=cwe,
            owasp_category=owasp,
            validation_state=ValidationState.OBSERVED,
            first_seen_scan_id=scan.id,
        )
        priority = compute_priority(PriorityInputs(
            severity=severity,
            confidence=confidence,
            exposure=0.7,
            asset_importance=0.6,
            evidence_quality=confidence.score,
            unauthenticated=(result.outcome == AuthzOutcome.UNAUTHENTICATED_ACCESS),
        ))
        finding.priority_score = priority.score
        fp.ensure(finding)
        self.repo.add_finding(finding)
        # Link the test row back to the finding via its evidence.
        self.repo.audit(AuditLog(
            action="finding_created", actor=scan.operator, target_ref=finding.id,
            detail={"source": "authz.matrix", "outcome": result.outcome.value,
                    "severity": severity.value, "priority": priority.score},
        ))
        return finding
