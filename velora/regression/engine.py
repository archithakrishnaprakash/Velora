"""Security regression engine.

Compares two scans of the same target and classifies what changed. Findings are matched
by their stable fingerprint (see ``velora.findings.fingerprint``), not by id, so the same
issue detected in two runs is recognised as one issue.

``REINTRODUCED_FINDING`` requires history: an issue counts as reintroduced only if it was
present in an earlier scan, absent in the previous one, and is present again now — or if
a remediation for it was previously verified. Without that evidence it is simply new.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ..database.repository import Repository
from ..findings import fingerprint as fp
from ..models.domain import AuditLog, Finding, RegressionResult, Scan
from ..models.enums import RegressionChange, RemediationStatus, Severity
from ..utils.logging import get_logger


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


log = get_logger("regression")


@dataclass
class RegressionSummary:
    previous_scan_id: str = ""
    current_scan_id: str = ""
    results: list[RegressionResult] = field(default_factory=list)

    def by_change(self, change: RegressionChange) -> list[RegressionResult]:
        return [r for r in self.results if r.change == change]

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for r in self.results:
            out[r.change.value] = out.get(r.change.value, 0) + 1
        return out

    def severity_breakdown(self, change: RegressionChange) -> dict[str, int]:
        out: dict[str, int] = {}
        for r in self.by_change(change):
            if r.severity:
                out[r.severity] = out.get(r.severity, 0) + 1
        return out

    @property
    def has_regression(self) -> bool:
        return bool(self.by_change(RegressionChange.REINTRODUCED_FINDING))

    @property
    def new_findings(self) -> list[RegressionResult]:
        return self.by_change(RegressionChange.NEW_FINDING)

    def to_dict(self) -> dict[str, Any]:
        return {
            "previous_scan_id": self.previous_scan_id,
            "current_scan_id": self.current_scan_id,
            "counts": self.counts(),
            "fixed_by_severity": self.severity_breakdown(RegressionChange.FIXED_FINDING),
            "new_by_severity": self.severity_breakdown(RegressionChange.NEW_FINDING),
            "persisting_by_severity":
                self.severity_breakdown(RegressionChange.PERSISTING_FINDING),
            "regression_detected": self.has_regression,
            "changes": [
                {"change": r.change.value, "subject": r.subject,
                 "severity": r.severity, "detail": r.detail}
                for r in self.results
            ],
        }


class RegressionEngine:
    def __init__(self, repo: Repository) -> None:
        self.repo = repo

    # ---- history ---------------------------------------------------------
    def _mark_regressed(self, signature: str, finding: Finding) -> None:
        """Move the remediation behind a reintroduced finding to REGRESSION_DETECTED."""
        for action in self.repo.list_remediations():
            original = self.repo.get_finding(action.finding_id)
            if original is None or fp.ensure(original) != signature:
                continue
            if action.status != RemediationStatus.FIX_VERIFIED:
                continue
            action.status = RemediationStatus.REGRESSION_DETECTED
            action.note = (f"{action.note} | regression: detected again as {finding.id}"
                           ).strip(" |")
            action.updated_at = _utcnow()
            self.repo.update_remediation(action)
            self.repo.audit(AuditLog(
                action="REGRESSION_DETECTED", target_ref=action.finding_id,
                detail={"remediation_id": action.id, "current_finding_id": finding.id}))

    def _historical_fingerprints(self, target_id: str, exclude: set[str]) -> set[str]:
        """Fingerprints seen in any earlier scan of this target."""
        seen: set[str] = set()
        for scan in self.repo.list_scans(target_id):
            if scan.id in exclude:
                continue
            for finding in self.repo.list_findings(scan.id):
                seen.add(fp.ensure(finding))
        return seen

    def _verified_fixed(self, fingerprints: set[str]) -> set[str]:
        """Fingerprints whose remediation was previously marked FIX_VERIFIED."""
        out: set[str] = set()
        for action in self.repo.list_remediations():
            if action.status != RemediationStatus.FIX_VERIFIED:
                continue
            finding = self.repo.get_finding(action.finding_id)
            if finding is not None:
                candidate = fp.ensure(finding)
                if candidate in fingerprints:
                    out.add(candidate)
        return out

    # ---- comparison ------------------------------------------------------
    def compare(self, previous: Scan, current: Scan, *, persist: bool = True
                ) -> RegressionSummary:
        summary = RegressionSummary(previous_scan_id=previous.id, current_scan_id=current.id)

        prev_findings = self.repo.list_findings(previous.id)
        curr_findings = self.repo.list_findings(current.id)
        prev_index = fp.index_by_fingerprint(prev_findings)
        curr_index = fp.index_by_fingerprint(curr_findings)

        history = self._historical_fingerprints(
            current.target_id, exclude={previous.id, current.id})
        verified_fixed = self._verified_fixed(set(curr_index))

        # --- findings ---
        for signature, finding in curr_index.items():
            if signature in prev_index:
                summary.results.append(self._result(
                    previous, current, RegressionChange.PERSISTING_FINDING, finding,
                    {"previous_finding_id": prev_index[signature].id,
                     "current_finding_id": finding.id,
                     "severity_changed":
                         prev_index[signature].severity.value != finding.severity.value}))
            elif signature in history or signature in verified_fixed:
                summary.results.append(self._result(
                    previous, current, RegressionChange.REINTRODUCED_FINDING, finding,
                    {"current_finding_id": finding.id,
                     "reason": ("previously remediated and verified"
                                if signature in verified_fixed
                                else "seen in an earlier scan, absent in the previous scan")}))
                # A fix that was verified and has come back is a regression against that
                # remediation, so the remediation's own status has to say so. Leaving it
                # at FIX_VERIFIED would show a closed issue that is demonstrably open.
                if signature in verified_fixed and persist:
                    self._mark_regressed(signature, finding)
            else:
                summary.results.append(self._result(
                    previous, current, RegressionChange.NEW_FINDING, finding,
                    {"current_finding_id": finding.id}))

        for signature, finding in prev_index.items():
            if signature not in curr_index:
                summary.results.append(self._result(
                    previous, current, RegressionChange.FIXED_FINDING, finding,
                    {"previous_finding_id": finding.id,
                     "note": ("no longer detected; absence of detection is not proof of a "
                              "fix — verify with a targeted retest")}))

        # --- endpoints ---
        prev_eps = {fp.normalize_endpoint(e.url) for e in self.repo.list_endpoints(previous.id)}
        curr_eps = {fp.normalize_endpoint(e.url) for e in self.repo.list_endpoints(current.id)}
        for url in sorted(curr_eps - prev_eps):
            summary.results.append(self._raw(previous, current,
                                             RegressionChange.NEW_ENDPOINT, url, ""))
        for url in sorted(prev_eps - curr_eps):
            summary.results.append(self._raw(previous, current,
                                             RegressionChange.REMOVED_ENDPOINT, url, ""))

        # --- technologies ---
        prev_tech = {f"{t.name}:{t.version or '?'}"
                     for t in self.repo.list_technologies(previous.id)}
        curr_tech = {f"{t.name}:{t.version or '?'}"
                     for t in self.repo.list_technologies(current.id)}
        for tech in sorted(curr_tech ^ prev_tech):
            summary.results.append(self._raw(
                previous, current, RegressionChange.CHANGED_TECHNOLOGY, tech,
                "", {"added": tech in curr_tech - prev_tech}))

        # --- security controls (header presence is the observable control surface) ---
        for change in self._control_changes(previous, current, prev_index, curr_index):
            summary.results.append(change)

        if persist:
            for result in summary.results:
                self.repo.add_regression(result)
            self.repo.audit(AuditLog(
                action=("regression_detected" if summary.has_regression
                        else "regression_compared"),
                target_ref=current.id,
                detail={"previous": previous.id, **summary.counts()}))
            if summary.has_regression:
                log.security("REGRESSION_DETECTED previous=%s current=%s count=%d",
                             previous.id, current.id,
                             len(summary.by_change(RegressionChange.REINTRODUCED_FINDING)))
        log.info("regression compare previous=%s current=%s counts=%s",
                 previous.id, current.id, summary.counts())
        return summary

    def _control_changes(self, previous: Scan, current: Scan,
                         prev_index: dict[str, Finding],
                         curr_index: dict[str, Finding]) -> list[RegressionResult]:
        """A configuration finding appearing/disappearing means a control changed."""
        out: list[RegressionResult] = []
        control_categories = {"configuration", "session", "tls"}

        def controls(index: dict[str, Finding]) -> set[str]:
            return {f.title for f in index.values() if f.category in control_categories}

        prev_controls, curr_controls = controls(prev_index), controls(curr_index)
        for title in sorted(prev_controls - curr_controls):
            out.append(self._raw(previous, current, RegressionChange.CHANGED_SECURITY_CONTROL,
                                 title, "", {"direction": "control now present / issue gone"}))
        for title in sorted(curr_controls - prev_controls):
            out.append(self._raw(previous, current, RegressionChange.CHANGED_SECURITY_CONTROL,
                                 title, "", {"direction": "control weakened / issue appeared"}))
        return out

    # ---- helpers ---------------------------------------------------------
    def _result(self, previous: Scan, current: Scan, change: RegressionChange,
                finding: Finding, detail: dict[str, Any]) -> RegressionResult:
        return RegressionResult(
            engagement_id=current.engagement_id,
            previous_scan_id=previous.id, current_scan_id=current.id,
            change=change, subject=fp.ensure(finding), severity=finding.severity.value,
            detail={"title": finding.title, "endpoint": finding.endpoint, **detail})

    def _raw(self, previous: Scan, current: Scan, change: RegressionChange,
             subject: str, severity: str, detail: dict[str, Any] | None = None
             ) -> RegressionResult:
        return RegressionResult(
            engagement_id=current.engagement_id,
            previous_scan_id=previous.id, current_scan_id=current.id,
            change=change, subject=subject, severity=severity, detail=detail or {})


def severity_delta(previous: list[Finding], current: list[Finding]) -> dict[str, dict[str, int]]:
    """Per-severity counts for the two scans, for the report header."""
    def counts(items: list[Finding]) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in items:
            out[f.severity.value] += 1
        return out

    return {"previous": counts(previous), "current": counts(current)}
