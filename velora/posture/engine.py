"""Velora Security Posture Score.

**This is not CVSS.** CVSS scores a single vulnerability's technical severity. The
Velora Security Posture Score is an aggregate, Velora-specific 0–100 indicator of how a
target looks *across* its assessed attack surface at a point in time. It exists for trend
lines and executive summaries, not for risk acceptance decisions.

Methodology (version 1.0), fully documented in ``docs/POSTURE.md``:

1. Each assessed **category** starts at 100.
2. Every finding in that category deducts ``severity_penalty × confidence_weight``.
3. A category with no coverage is reported as ``None`` (not 100) — an unassessed control
   is unknown, never "good".
4. ``overall`` is the category-weighted mean of the assessed category scores.
5. Adjustments: verified remediations add back a bounded credit; reintroduced findings
   (regressions) apply a bounded penalty.
6. The result always lists its major contributors so a number can be traced to findings.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..database.repository import Repository
from ..models.domain import Finding, SecurityPostureSnapshot
from ..models.enums import RegressionChange, RemediationStatus, Severity

METHODOLOGY_VERSION = "1.0"

# Finding category -> posture category.
CATEGORY_MAP: dict[str, str] = {
    "authentication": "Authentication",
    "authorization": "Authorization",
    "session": "Session Management",
    "tls": "Transport Security",
    "configuration": "Configuration",
    "information_disclosure": "Information Exposure",
    "input_validation": "Input Handling",
}

CATEGORIES = tuple(dict.fromkeys(CATEGORY_MAP.values()))

# Relative importance when averaging category scores.
CATEGORY_WEIGHTS: dict[str, float] = {
    "Authentication": 1.2,
    "Authorization": 1.3,
    "Session Management": 1.0,
    "Transport Security": 1.1,
    "Configuration": 0.9,
    "Information Exposure": 1.0,
    "Input Handling": 1.0,
}

SEVERITY_PENALTY: dict[Severity, float] = {
    Severity.CRITICAL: 40.0,
    Severity.HIGH: 24.0,
    Severity.MEDIUM: 11.0,
    Severity.LOW: 4.0,
    Severity.INFO: 1.0,
}

# Bounded adjustments so no single factor can dominate the score.
MAX_REMEDIATION_CREDIT = 8.0
MAX_REGRESSION_PENALTY = 12.0


#: Band thresholds for the Velora Security Posture Score. This is the ONE definition;
#: the CLI, the dashboard and the report all call it. Duplicating these numbers is how
#: a score of 87 ends up "Adequate" in one surface and "Strong" in another.
BAND_THRESHOLDS: tuple[tuple[float, str], ...] = (
    (90.0, "Strong"),
    (75.0, "Adequate"),
    (55.0, "Weak"),
)


def band_for(overall: float | None) -> str:
    """Return the band label for a posture score, or "Not Assessed" for None."""
    if overall is None:
        return "Not Assessed"
    for threshold, label in BAND_THRESHOLDS:
        if overall >= threshold:
            return label
    return "Poor"


@dataclass
class PostureResult:
    overall: float = 0.0
    categories: dict[str, float | None] = field(default_factory=dict)
    contributors: list[dict[str, Any]] = field(default_factory=list)
    explanation: str = ""
    coverage: dict[str, int] = field(default_factory=dict)
    adjustments: dict[str, float] = field(default_factory=dict)
    methodology_version: str = METHODOLOGY_VERSION

    @property
    def band(self) -> str:
        return band_for(self.overall)

    def to_dict(self) -> dict[str, Any]:
        return {
            "metric": "Velora Security Posture Score",
            "not_cvss": True,
            "methodology_version": self.methodology_version,
            "overall": round(self.overall, 1),
            "band": self.band,
            "categories": {k: (round(v, 1) if v is not None else None)
                           for k, v in self.categories.items()},
            "coverage": self.coverage,
            "adjustments": {k: round(v, 2) for k, v in self.adjustments.items()},
            "contributors": self.contributors,
            "explanation": self.explanation,
        }


class PostureEngine:
    def __init__(self, repo: Repository) -> None:
        self.repo = repo

    def _confidence_weight(self, finding: Finding) -> float:
        """A tentative detection should not dent the score as hard as a certain one."""
        return 0.55 + 0.45 * finding.confidence.score

    def compute(self, scan_id: str, *, include_adjustments: bool = True) -> PostureResult:
        findings = self.repo.list_findings(scan_id)
        result = PostureResult()

        # Which categories did this scan actually exercise? A check that ran and found
        # nothing still counts as coverage.
        exercised = self._exercised_categories(scan_id, findings)

        penalties: dict[str, float] = {c: 0.0 for c in CATEGORIES}
        counts: dict[str, int] = {c: 0 for c in CATEGORIES}
        contributors: list[dict[str, Any]] = []

        for finding in findings:
            category = CATEGORY_MAP.get(finding.category)
            if category is None:
                continue
            if finding.status.value in {"Rejected", "Remediated"}:
                continue  # a rejected or fixed issue must not keep depressing the score
            penalty = SEVERITY_PENALTY[finding.severity] * self._confidence_weight(finding)
            penalties[category] += penalty
            counts[category] += 1
            contributors.append({
                "finding_id": finding.id,
                "title": finding.title,
                "category": category,
                "severity": finding.severity.value,
                "confidence": finding.confidence.value,
                "penalty": round(penalty, 2),
            })

        for category in CATEGORIES:
            if category not in exercised:
                result.categories[category] = None   # unassessed != healthy
            else:
                result.categories[category] = max(0.0, 100.0 - penalties[category])
        result.coverage = {c: counts[c] for c in CATEGORIES}

        assessed = {c: s for c, s in result.categories.items() if s is not None}
        if assessed:
            total_weight = sum(CATEGORY_WEIGHTS[c] for c in assessed)
            result.overall = sum(
                s * CATEGORY_WEIGHTS[c] for c, s in assessed.items()) / total_weight
        else:
            result.overall = 0.0

        if include_adjustments:
            credit = self._remediation_credit(scan_id)
            penalty = self._regression_penalty(scan_id)
            result.adjustments = {"remediation_credit": credit, "regression_penalty": -penalty}
            result.overall = max(0.0, min(100.0, result.overall + credit - penalty))

        contributors.sort(key=lambda c: -c["penalty"])
        result.contributors = contributors[:10]
        result.explanation = self._explain(result, assessed, len(findings))
        return result

    def _exercised_categories(self, scan_id: str, findings: list[Finding]) -> set[str]:
        """Categories covered by this scan — from events if available, else findings."""
        exercised = {CATEGORY_MAP[f.category] for f in findings if f.category in CATEGORY_MAP}
        # A completed scan runs the full safe check set, so treat those categories as
        # exercised even when they produced nothing.
        scan = self.repo.get_scan(scan_id)
        if scan is not None and scan.status.value == "completed":
            checks_run = scan.stats.get("checks_run")
            if isinstance(checks_run, int) and checks_run > 0:
                from ..scanners import registry

                for check in registry.for_profile(scan.profile.value):
                    mapped = CATEGORY_MAP.get(check.category)
                    if mapped:
                        exercised.add(mapped)
        return exercised

    def _remediation_credit(self, scan_id: str) -> float:
        """Credit for fixes verified against *this* scan's findings.

        Scoping matters: counted globally, a backlog of old verified fixes from other
        targets would inflate the posture of a scan that fixed nothing.
        """
        finding_ids = {f.id for f in self.repo.list_findings(scan_id)}
        if not finding_ids:
            return 0.0
        actions = [a for a in self.repo.list_remediations() if a.finding_id in finding_ids]
        if not actions:
            return 0.0
        verified = sum(1 for a in actions if a.status == RemediationStatus.FIX_VERIFIED)
        ratio = verified / len(actions)
        return round(MAX_REMEDIATION_CREDIT * ratio, 2)

    def _regression_penalty(self, scan_id: str) -> float:
        results = self.repo.list_regressions(scan_id)
        reintroduced = [r for r in results
                        if r.change == RegressionChange.REINTRODUCED_FINDING]
        if not reintroduced:
            return 0.0
        return round(min(MAX_REGRESSION_PENALTY, 4.0 * len(reintroduced)), 2)

    def _explain(self, result: PostureResult, assessed: dict[str, float],
                 total_findings: int) -> str:
        if not assessed:
            return ("No posture categories were assessed in this scan, so no score can be "
                    "computed. This is not a statement that the target is secure.")
        weakest = min(assessed.items(), key=lambda kv: kv[1])
        strongest = max(assessed.items(), key=lambda kv: kv[1])
        unassessed = [c for c, s in result.categories.items() if s is None]
        parts = [
            f"Velora Security Posture Score {result.overall:.1f}/100 ({result.band}), "
            f"derived from {len(assessed)} assessed category/categories and "
            f"{total_findings} finding(s).",
            f"Weakest area: {weakest[0]} at {weakest[1]:.0f}. "
            f"Strongest assessed area: {strongest[0]} at {strongest[1]:.0f}.",
        ]
        if result.contributors:
            top = result.contributors[0]
            parts.append(f"Largest single contributor: '{top['title']}' "
                         f"({top['severity']}, -{top['penalty']:.1f}).")
        if unassessed:
            parts.append(f"Not assessed (reported as unknown, not as healthy): "
                         f"{', '.join(unassessed)}.")
        adj = result.adjustments
        if adj.get("remediation_credit"):
            parts.append(f"Verified remediations added {adj['remediation_credit']:.1f}.")
        if adj.get("regression_penalty"):
            parts.append(f"Reintroduced findings deducted "
                         f"{abs(adj['regression_penalty']):.1f}.")
        parts.append("This aggregate is a Velora-specific trend metric and is not a CVSS "
                     "score, nor a statement that unfound issues do not exist.")
        return " ".join(parts)

    # ---- persistence -----------------------------------------------------
    def snapshot(self, scan_id: str, *, target_id: str | None = None,
                 engagement_id: str | None = None) -> SecurityPostureSnapshot:
        result = self.compute(scan_id)
        scan = self.repo.get_scan(scan_id)
        snap = SecurityPostureSnapshot(
            engagement_id=engagement_id or (scan.engagement_id if scan else None),
            target_id=target_id or (scan.target_id if scan else None),
            scan_id=scan_id,
            overall=result.overall,
            # Unassessed categories are persisted as None, not filtered out: a stored
            # snapshot that silently omits them cannot be told apart from one where
            # every category scored, which is exactly the confusion this metric exists
            # to avoid.
            categories=dict(result.categories),
            contributors=result.contributors,
            explanation=result.explanation,
            methodology_version=METHODOLOGY_VERSION,
        )
        self.repo.add_posture(snap)
        return snap

    def trend(self, target_id: str) -> list[dict[str, Any]]:
        """Posture over time for a target, oldest first."""
        snapshots = self.repo.list_postures(target_id)
        return [{"scan_id": s.scan_id, "overall": round(s.overall, 1),
                 "categories": s.categories, "at": s.created_at.isoformat()}
                for s in snapshots]
