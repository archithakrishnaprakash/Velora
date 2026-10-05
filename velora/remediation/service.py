"""Remediation lifecycle and retest verification.

    Finding -> Remediation -> Retest -> Comparison -> Verification

The verification rule is deliberately conservative: a retest that no longer detects the
issue yields ``FIX_VERIFIED`` only when the retest actually *covered* the endpoint. If
the retest never reached the endpoint, the result is inconclusive and the remediation
stays ``READY_FOR_RETEST`` — absence of detection is not evidence of a fix.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ..database.repository import Repository
from ..findings import fingerprint as fp
from ..models.domain import AuditLog, Finding, RemediationAction, RetestRun, Scan
from ..models.enums import FindingStatus, RemediationStatus
from ..utils.logging import get_logger

log = get_logger("remediation")

# Transitions the operator may drive directly.
_OPERATOR_TRANSITIONS = {
    RemediationStatus.OPEN,
    RemediationStatus.REMEDIATION_IN_PROGRESS,
    RemediationStatus.READY_FOR_RETEST,
}


@dataclass
class VerificationResult:
    finding_id: str
    verdict: RemediationStatus
    still_present: bool | None
    covered: bool
    detail: str
    retest: RetestRun | None = None
    evidence_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "verdict": self.verdict.value,
            "still_present": self.still_present,
            "endpoint_covered_by_retest": self.covered,
            "detail": self.detail,
            "retest_id": self.retest.id if self.retest else None,
        }


class RemediationService:
    def __init__(self, repo: Repository) -> None:
        self.repo = repo

    # ---- lifecycle -------------------------------------------------------
    def get_or_open(self, finding: Finding, owner: str = "") -> RemediationAction:
        existing = self.repo.get_remediation_for_finding(finding.id)
        if existing is not None:
            return existing
        action = RemediationAction(
            finding_id=finding.id, engagement_id=finding.engagement_id,
            status=RemediationStatus.OPEN, owner=owner)
        self.repo.add_remediation(action)
        self._sync_finding(finding, RemediationStatus.OPEN)
        self.repo.audit(AuditLog(action="remediation_opened", actor=owner,
                                 target_ref=finding.id, detail={"remediation_id": action.id}))
        return action

    def set_status(self, finding_id: str, status: RemediationStatus, *,
                   owner: str = "", note: str = "") -> RemediationAction | None:
        finding = self.repo.get_finding(finding_id)
        if finding is None:
            return None
        action = self.get_or_open(finding, owner)
        if status not in _OPERATOR_TRANSITIONS:
            raise ValueError(
                f"{status.value} is set by a retest, not directly; use `remediation retest`")
        action.status = status
        action.owner = owner or action.owner
        action.note = note or action.note
        action.updated_at = datetime.now(timezone.utc)
        self.repo.update_remediation(action)
        self._sync_finding(finding, status)
        self.repo.audit(AuditLog(action="remediation_status_changed", actor=owner,
                                 target_ref=finding_id,
                                 detail={"status": status.value, "note": note}))
        log.info("remediation %s -> %s", finding_id, status.value)
        return action

    def start(self, finding_id: str, owner: str = "", note: str = "") -> RemediationAction | None:
        return self.set_status(finding_id, RemediationStatus.REMEDIATION_IN_PROGRESS,
                               owner=owner, note=note)

    def ready_for_retest(self, finding_id: str, owner: str = "",
                         note: str = "") -> RemediationAction | None:
        return self.set_status(finding_id, RemediationStatus.READY_FOR_RETEST,
                               owner=owner, note=note)

    def _sync_finding(self, finding: Finding, status: RemediationStatus) -> None:
        finding.remediation_status = status
        fp.ensure(finding)
        if status == RemediationStatus.FIX_VERIFIED:
            finding.status = FindingStatus.REMEDIATED
        self.repo.update_finding(finding)

    # ---- verification ----------------------------------------------------
    def verify_against_scan(self, finding_id: str, retest_scan: Scan, *,
                            operator: str = "") -> VerificationResult:
        """Compare a finding against a later scan and decide the verification verdict."""
        finding = self.repo.get_finding(finding_id)
        if finding is None:
            raise ValueError(f"finding not found: {finding_id}")
        action = self.get_or_open(finding, operator)
        signature = fp.ensure(finding)

        retest_findings = self.repo.list_findings(retest_scan.id)
        index = fp.index_by_fingerprint(retest_findings)
        still_present = signature in index

        # Did the retest actually cover this endpoint? Without coverage the retest
        # proves nothing.
        target_endpoint = fp.normalize_endpoint(finding.endpoint)
        covered_endpoints = {fp.normalize_endpoint(e.url)
                             for e in self.repo.list_endpoints(retest_scan.id)}
        covered_endpoints |= {fp.normalize_endpoint(f.endpoint) for f in retest_findings}
        covered = target_endpoint in covered_endpoints or still_present

        if still_present:
            verdict = RemediationStatus.FIX_FAILED
            detail = (f"the issue was detected again in scan {retest_scan.id} "
                      f"(fingerprint {signature})")
        elif not covered:
            verdict = RemediationStatus.READY_FOR_RETEST
            detail = (f"scan {retest_scan.id} did not cover {finding.endpoint}; the retest is "
                      "inconclusive. Absence of detection is not evidence of a fix.")
        else:
            verdict = RemediationStatus.FIX_VERIFIED
            detail = (f"the endpoint was re-examined in scan {retest_scan.id} and the issue "
                      "was no longer detected")

        evidence_ids: list[str] = []
        if still_present:
            evidence_ids = list(index[signature].evidence_ids)

        retest = RetestRun(
            finding_id=finding.id, remediation_id=action.id,
            original_scan_id=finding.scan_id, retest_scan_id=retest_scan.id,
            still_present=still_present, verdict=verdict, detail=detail,
            evidence_ids=evidence_ids)
        self.repo.add_retest(retest)

        action.status = verdict
        action.last_retest_id = retest.id
        action.updated_at = datetime.now(timezone.utc)
        if verdict == RemediationStatus.FIX_VERIFIED:
            action.verified_at = datetime.now(timezone.utc)
        self.repo.update_remediation(action)
        self._sync_finding(finding, verdict)

        self.repo.audit(AuditLog(
            action="retest_completed", actor=operator, target_ref=finding.id,
            detail={"verdict": verdict.value, "retest_scan": retest_scan.id,
                    "still_present": still_present, "covered": covered}))
        log.info("RETEST_COMPLETED finding=%s verdict=%s", finding.id, verdict.value)

        return VerificationResult(
            finding_id=finding.id, verdict=verdict, still_present=still_present,
            covered=covered, detail=detail, retest=retest, evidence_ids=evidence_ids)

    def verify_scan(self, original_scan_id: str, retest_scan: Scan, *,
                    operator: str = "") -> list[VerificationResult]:
        """Verify every finding of an original scan against a retest scan."""
        results: list[VerificationResult] = []
        for finding in self.repo.list_findings(original_scan_id):
            results.append(self.verify_against_scan(finding.id, retest_scan, operator=operator))
        return results

    # ---- reporting -------------------------------------------------------
    def status_table(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for action in self.repo.list_remediations():
            finding = self.repo.get_finding(action.finding_id)
            rows.append({
                "remediation_id": action.id,
                "finding_id": action.finding_id,
                "title": finding.title if finding else "(finding missing)",
                "severity": finding.severity.value if finding else "",
                "status": action.status.value,
                "owner": action.owner,
                "verified_at": action.verified_at.isoformat() if action.verified_at else None,
                "last_retest_id": action.last_retest_id,
            })
        return rows
