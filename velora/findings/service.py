"""FindingService — turns deterministic check outputs into managed findings.

Key invariant: findings created by scanners start as ``Potential``. Only a human operator
can move a finding to ``Confirmed`` (via ``validate``). Neither the scanner nor the AI
layer may set ``Confirmed``.
"""
from __future__ import annotations

from datetime import datetime, timezone

from ..database.repository import Repository
from ..evidence.store import EvidenceStore
from ..models.domain import AuditLog, Finding, Scan, Target
from ..models.enums import FindingStatus, ValidationState
from ..risk.scoring import PriorityInputs, compute_priority
from ..scanners.base import CheckOutput
from . import fingerprint as fp
from ..utils.logging import get_logger

log = get_logger("findings")

# Categories that imply the issue is reachable without authentication in a typical crawl.
_UNAUTH_CATEGORIES = {"authorization", "authentication", "information_disclosure", "configuration"}


class FindingService:
    def __init__(self, repo: Repository) -> None:
        self.repo = repo
        self.evidence = EvidenceStore(repo)

    # ---- creation -------------------------------------------------------
    def record(self, scan: Scan, output: CheckOutput, target: Target | None = None) -> Finding:
        finding = Finding(
            scan_id=scan.id,
            title=output.title,
            description=output.description,
            category=output.category,
            severity=output.severity,
            confidence=output.confidence,
            status=FindingStatus.POTENTIAL,
            endpoint=output.endpoint,
            method=output.method,
            impact=output.impact,
            remediation=output.remediation,
            references=list(output.references),
            scanner=output.evidence[0].test_name if output.evidence else output.category,
            cvss_version=output.cvss_version,
            cvss_vector=output.cvss_vector,
            cvss_base_score=output.cvss_base_score,
            cvss_severity=None,
        )
        # Persist evidence and link ids.
        evidence_ids: list[str] = []
        max_ev_conf = 0.0
        for item in output.evidence:
            record = self.evidence.persist(scan.id, item, finding_id=finding.id)
            evidence_ids.append(record.id)
            max_ev_conf = max(max_ev_conf, item.confidence)
        finding.evidence_ids = evidence_ids

        # Priority score.
        exposure = 0.4 if _is_lab(target) else 0.7
        priority = compute_priority(
            PriorityInputs(
                severity=output.severity,
                confidence=output.confidence,
                exposure=exposure,
                asset_importance=0.5,
                evidence_quality=max_ev_conf or output.confidence.score,
                unauthenticated=output.category in _UNAUTH_CATEGORIES,
            )
        )
        finding.priority_score = priority.score
        # Stable cross-scan identity, used by regression analysis and retest verification.
        fp.ensure(finding)
        if not finding.first_seen_scan_id:
            finding.first_seen_scan_id = scan.id

        self.repo.add_finding(finding)
        self.repo.audit(
            AuditLog(action="finding_created", actor=scan.operator, target_ref=finding.id,
                     detail={"title": finding.title, "severity": finding.severity.value,
                             "priority": priority.score})
        )
        return finding

    # ---- validation workflow -------------------------------------------
    #: The epistemic state a lifecycle status implies. Confirming a finding is the one
    #: action in Velora that can move something to VALIDATED, so the status change and
    #: the validation state have to move together — otherwise the field never records
    #: what its own definition says it records.
    _STATE_FOR_STATUS = {
        FindingStatus.CONFIRMED: ValidationState.VALIDATED,
        FindingStatus.REJECTED: ValidationState.UNKNOWN,
    }

    def _transition(self, finding_id: str, status: FindingStatus, operator: str,
                    note: str, action: str) -> Finding | None:
        finding = self.repo.get_finding(finding_id)
        if finding is None:
            return None
        finding.status = status
        new_state = self._STATE_FOR_STATUS.get(status)
        if new_state is not None:
            finding.validation_state = new_state
        finding.validated_by = operator
        finding.validation_note = note
        finding.updated_at = datetime.now(timezone.utc)
        self.repo.update_finding(finding)
        self.repo.audit(
            AuditLog(action=action, actor=operator, target_ref=finding_id,
                     detail={"status": status.value, "note": note})
        )
        log.info("%s finding=%s by=%s", action, finding_id, operator or "-")
        return finding

    def validate(self, finding_id: str, operator: str, note: str = "") -> Finding | None:
        """Mark a finding Confirmed. Human-only action."""
        return self._transition(finding_id, FindingStatus.CONFIRMED, operator, note,
                                "finding_validated")

    def reject(self, finding_id: str, operator: str, note: str = "") -> Finding | None:
        return self._transition(finding_id, FindingStatus.REJECTED, operator, note,
                                "finding_rejected")

    def mark_remediated(self, finding_id: str, operator: str, note: str = "") -> Finding | None:
        return self._transition(finding_id, FindingStatus.REMEDIATED, operator, note,
                                "finding_remediated")

    def mark_needs_review(self, finding_id: str, operator: str = "") -> Finding | None:
        return self._transition(finding_id, FindingStatus.NEEDS_REVIEW, operator, "",
                                "finding_needs_review")


def _is_lab(target: Target | None) -> bool:
    if target is None:
        return False
    from ..models.enums import AuthorizationStatus
    return target.authorization_status == AuthorizationStatus.LAB_ONLY
