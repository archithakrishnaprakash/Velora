"""Benchmark execution and metric computation.

Runs a real scan against a benchmark target and scores the detections against ground
truth. Every number reported here is measured; none is assumed or hard-coded.

Two honesty rules govern the metrics:

1. **Uncovered detections are not false positives.** A finding that no benchmark case
   describes is reported separately as an *uncovered detection*. Counting it as a false
   positive would punish Velora for finding something the suite simply does not know
   about; counting it as a true positive would be self-congratulation. It is neither.
2. **True negatives come only from explicit negative cases.** TN is not "everything the
   scanner didn't say", which would be unbounded and meaningless.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .. import __version__
from ..database.repository import Repository
from ..findings.fingerprint import normalize_endpoint
from ..models.domain import BenchmarkCase, BenchmarkRun, Finding
from ..models.enums import BenchmarkOutcome
from ..utils.logging import get_logger
from .suite import Suite

log = get_logger("benchmark")


@dataclass
class CaseResult:
    case: BenchmarkCase
    outcome: BenchmarkOutcome
    detected: bool
    matched_finding_id: str | None = None
    evidence_satisfied: bool = False
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "case": self.case.name,
            "check": self.case.expected_check_id,
            "endpoint": self.case.endpoint_path,
            "expected_detection": self.case.expected_detection,
            "detected": self.detected,
            "outcome": self.outcome.value,
            "matched_finding_id": self.matched_finding_id,
            "evidence_satisfied": self.evidence_satisfied,
            "detail": self.detail,
        }


@dataclass
class Metrics:
    true_positives: int = 0
    true_negatives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    uncovered_detections: int = 0

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return round(self.true_positives / denom, 4) if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return round(self.true_positives / denom, 4) if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return round(2 * p * r / (p + r), 4) if (p + r) else 0.0

    @property
    def false_positive_rate(self) -> float:
        denom = self.false_positives + self.true_negatives
        return round(self.false_positives / denom, 4) if denom else 0.0

    @property
    def false_negative_rate(self) -> float:
        denom = self.false_negatives + self.true_positives
        return round(self.false_negatives / denom, 4) if denom else 0.0

    #: Total detections Velora produced in the benchmark scan, covered or not. Set by
    #: the runner; used to express how much of the output the suite can speak to.
    total_detections: int = 0

    @property
    def detection_coverage(self) -> float:
        """Fraction of Velora's detections that the suite has ground truth for.

        This is deliberately NOT recall. Recall asks "of the issues the suite knows
        about, how many did Velora find". Coverage asks the opposite and more humbling
        question: "of what Velora reported, how much can this suite judge at all".
        A high recall with low coverage means the suite is scoring a small slice of the
        output and the headline metrics should be read accordingly.
        """
        if not self.total_detections:
            return 0.0
        covered = self.total_detections - self.uncovered_detections
        return round(max(0, covered) / self.total_detections, 4)

    def to_dict(self) -> dict[str, Any]:
        return {
            "true_positives": self.true_positives,
            "true_negatives": self.true_negatives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "uncovered_detections": self.uncovered_detections,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "false_positive_rate": self.false_positive_rate,
            "false_negative_rate": self.false_negative_rate,
            "total_detections": self.total_detections,
            "detection_coverage": self.detection_coverage,
        }


@dataclass
class BenchmarkReport:
    suite: str
    target_url: str
    scan_id: str
    metrics: Metrics = field(default_factory=Metrics)
    case_results: list[CaseResult] = field(default_factory=list)
    evidence_completeness: float = 0.0
    ai_agreement: float | None = None
    human_validation_rate: float | None = None
    uncovered: list[dict[str, str]] = field(default_factory=list)
    velora_version: str = __version__

    def to_dict(self) -> dict[str, Any]:
        return {
            "suite": self.suite,
            "target_url": self.target_url,
            "scan_id": self.scan_id,
            "velora_version": self.velora_version,
            "total_cases": len(self.case_results),
            "metrics": self.metrics.to_dict(),
            "evidence_completeness": round(self.evidence_completeness, 4),
            "ai_agreement": self.ai_agreement,
            "human_validation_rate": self.human_validation_rate,
            "cases": [c.to_dict() for c in self.case_results],
            "uncovered_detections": self.uncovered,
            "notes": [
                "Uncovered detections are findings no benchmark case describes. They are "
                "counted as neither true nor false positives.",
                "True negatives come only from explicit negative ground-truth cases.",
                "These figures describe Velora's behaviour on this suite only and do not "
                "generalize to other applications.",
            ],
        }


class BenchmarkRunner:
    """Scores a completed scan against a ground-truth suite."""

    def __init__(self, repo: Repository) -> None:
        self.repo = repo

    # ---- matching --------------------------------------------------------
    def _matches(self, case: BenchmarkCase, finding: Finding) -> bool:
        if finding.scanner != case.expected_check_id:
            return False
        if case.endpoint_path in ("", "*"):
            return True
        expected = case.endpoint_path.rstrip("/") or "/"
        actual = normalize_endpoint(finding.endpoint)
        actual_path = "/" + actual.split("/", 1)[1] if "/" in actual else "/"
        # No `or expected == "/"` escape hatch: that made every root-path case match a
        # finding on ANY endpoint, silently disabling the endpoint constraint for most
        # of the suite and inflating true positives. A case that should match anywhere
        # says so explicitly with endpoint_path "*".
        return (actual_path.rstrip("/") or "/") == (expected.rstrip("/") or "/")

    def _evidence_satisfied(self, case: BenchmarkCase, finding: Finding) -> bool:
        if not case.evidence_requirements:
            return bool(finding.evidence_ids)
        rows = self.repo.list_evidence_for_finding(finding.id)
        if not rows:
            return False
        haystack = " ".join(
            f"{r.test_name} {r.sanitized_excerpt} {' '.join(r.headers.keys())}".lower()
            for r in rows)
        # A requirement is satisfied when its salient words appear in the evidence.
        for requirement in case.evidence_requirements:
            words = [w for w in requirement.lower().split() if len(w) > 3]
            if not any(w in haystack for w in words):
                # Header/body capture is also satisfied structurally.
                if "header" in requirement.lower() and any(r.headers for r in rows):
                    continue
                if "body" in requirement.lower() and any(r.sanitized_excerpt for r in rows):
                    continue
                return False
        return True

    # ---- scoring ---------------------------------------------------------
    def score(self, suite: Suite, scan_id: str, target_url: str) -> BenchmarkReport:
        findings = self.repo.list_findings(scan_id)
        report = BenchmarkReport(suite=suite.name, target_url=target_url, scan_id=scan_id)
        matched_finding_ids: set[str] = set()
        satisfied = 0
        positive_detected = 0

        for case in suite.cases:
            match = next((f for f in findings if self._matches(case, f)), None)
            detected = match is not None
            if match is not None:
                matched_finding_ids.add(match.id)

            evidence_ok = self._evidence_satisfied(case, match) if match else False
            if case.expected_detection:
                if detected:
                    outcome = BenchmarkOutcome.TRUE_POSITIVE
                    report.metrics.true_positives += 1
                    positive_detected += 1
                    if evidence_ok:
                        satisfied += 1
                    detail = f"detected by {match.scanner} as '{match.title}'"
                else:
                    outcome = BenchmarkOutcome.FALSE_NEGATIVE
                    report.metrics.false_negatives += 1
                    detail = f"expected {case.expected_check_id} to fire, but it did not"
            else:
                if detected:
                    outcome = BenchmarkOutcome.FALSE_POSITIVE
                    report.metrics.false_positives += 1
                    detail = (f"{case.expected_check_id} reported '{match.title}' where "
                              "ground truth says there is nothing to report")
                else:
                    outcome = BenchmarkOutcome.TRUE_NEGATIVE
                    report.metrics.true_negatives += 1
                    detail = "correctly stayed silent"

            report.case_results.append(CaseResult(
                case=case, outcome=outcome, detected=detected,
                matched_finding_id=match.id if match else None,
                evidence_satisfied=evidence_ok, detail=detail))

        # Detections no case describes — reported, never scored.
        for finding in findings:
            if finding.id not in matched_finding_ids:
                report.metrics.uncovered_detections += 1
                report.uncovered.append({
                    "finding_id": finding.id, "check": finding.scanner,
                    "title": finding.title, "severity": finding.severity.value})

        report.metrics.total_detections = len(findings)
        report.evidence_completeness = (satisfied / positive_detected) if positive_detected else 0.0
        report.ai_agreement = self._ai_agreement(scan_id, findings)
        report.human_validation_rate = self._human_validation_rate(findings)
        return report

    def _ai_agreement(self, scan_id: str, findings: list[Finding]) -> float | None:
        """Fraction of AI-analysed findings whose classification matches the category.

        ``None`` when no AI analysis has been run — reporting 0.0 would be misleading.
        """
        analysed = [f for f in findings if f.ai_analysis_id]
        if not analysed:
            return None
        agree = 0
        for finding in analysed:
            analysis = self.repo.get_ai_analysis(finding.ai_analysis_id or "")
            if analysis is None:
                continue
            stem = finding.category.split("_")[0].lower()
            if stem and stem in analysis.classification.lower():
                agree += 1
        return round(agree / len(analysed), 4)

    def _human_validation_rate(self, findings: list[Finding]) -> float | None:
        if not findings:
            return None
        validated = sum(1 for f in findings
                        if f.status.value in {"Confirmed", "Rejected", "Remediated"})
        return round(validated / len(findings), 4)

    # ---- persistence -----------------------------------------------------
    def persist(self, report: BenchmarkReport) -> BenchmarkRun:
        m = report.metrics
        run = BenchmarkRun(
            suite=report.suite, scan_id=report.scan_id, target_url=report.target_url,
            total_cases=len(report.case_results),
            true_positives=m.true_positives, true_negatives=m.true_negatives,
            false_positives=m.false_positives, false_negatives=m.false_negatives,
            precision=m.precision, recall=m.recall, f1=m.f1,
            false_positive_rate=m.false_positive_rate,
            false_negative_rate=m.false_negative_rate,
            detection_coverage=m.detection_coverage,
            evidence_completeness=report.evidence_completeness,
            uncovered_detections=m.uncovered_detections,
            uncovered=list(report.uncovered),
            ai_agreement=report.ai_agreement,
            human_validation_rate=report.human_validation_rate,
            per_case=[c.to_dict() for c in report.case_results],
            velora_version=report.velora_version)
        self.repo.add_benchmark_run(run)
        log.info("benchmark suite=%s TP=%d FP=%d FN=%d TN=%d precision=%.3f recall=%.3f",
                 report.suite, m.true_positives, m.false_positives,
                 m.false_negatives, m.true_negatives, m.precision, m.recall)
        return run
