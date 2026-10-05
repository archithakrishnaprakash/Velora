"""CI/CD security gate.

Evaluates a scan against a declarative policy and returns a decision whose exit code the
CLI propagates:

    0 = PASS   — no policy violation
    1 = FAIL   — at least one policy violation
    2 = ERROR  — the gate could not be evaluated (bad config, missing scan)

Design notes:

* A gate that silently passes when it cannot evaluate is worse than no gate. Any
  configuration or data problem is ``ERROR`` (exit 2), never ``PASS``.
* ``Rejected`` findings are excluded: a human has already dismissed them.
* Unvalidated ``Potential`` findings **do** count by default, because a CI gate exists to
  stop regressions before a human has triaged them. ``ignore_unvalidated`` makes that
  explicit and opt-in rather than a hidden default.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..database.repository import Repository
from ..models.domain import AuditLog, Finding, SecurityGateResult
from ..models.enums import GateDecision, RegressionChange, Severity
from ..utils.errors import ConfigError
from ..utils.logging import get_logger

log = get_logger("gate")

_SEVERITY_BY_NAME = {s.value.lower(): s for s in Severity}


@dataclass
class GatePolicy:
    """Declarative gate policy."""

    #: Severities that cause failure if present at all.
    fail_on: list[Severity] = field(default_factory=list)
    #: Maximum permitted CVSS base score among findings that have one.
    max_cvss: float | None = None
    #: Maximum permitted Velora Priority Score.
    max_priority_score: float | None = None
    #: Maximum number of NEW findings relative to a baseline scan.
    max_new_findings: int | None = None
    #: Fail when the regression engine reports a reintroduced finding.
    fail_on_regression: bool = True
    #: Exclude findings a human has not validated.
    ignore_unvalidated: bool = False

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "GatePolicy":
        if not isinstance(data, dict):
            raise ConfigError("gate policy must be a mapping")
        raw = data.get("gate", data)
        fail_on: list[Severity] = []
        for name in raw.get("fail_on", []) or []:
            key = str(name).strip().lower()
            if key not in _SEVERITY_BY_NAME:
                raise ConfigError(
                    f"unknown severity '{name}' in fail_on; valid values: "
                    f"{sorted(_SEVERITY_BY_NAME)}")
            fail_on.append(_SEVERITY_BY_NAME[key])

        def _number(key: str) -> float | None:
            value = raw.get(key)
            if value is None:
                return None
            try:
                return float(value)
            except (TypeError, ValueError) as exc:
                raise ConfigError(f"{key} must be a number, got {value!r}") from exc

        max_new = raw.get("max_new_findings")
        if max_new is not None:
            try:
                max_new = int(max_new)
            except (TypeError, ValueError) as exc:
                raise ConfigError("max_new_findings must be an integer") from exc
            if max_new < 0:
                raise ConfigError("max_new_findings must be >= 0")

        policy = cls(
            fail_on=fail_on,
            max_cvss=_number("max_cvss"),
            max_priority_score=_number("max_priority_score"),
            max_new_findings=max_new,
            fail_on_regression=bool(raw.get("fail_on_regression", True)),
            ignore_unvalidated=bool(raw.get("ignore_unvalidated", False)),
        )
        if not policy.has_any_rule:
            raise ConfigError(
                "gate policy defines no rules; set at least one of fail_on, max_cvss, "
                "max_priority_score, max_new_findings, or fail_on_regression")
        return policy

    @classmethod
    def from_file(cls, path: str | Path) -> "GatePolicy":
        file_path = Path(path)
        if not file_path.exists():
            raise ConfigError(f"gate policy not found: {file_path}")
        try:
            data = yaml.safe_load(file_path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"invalid YAML in {file_path}: {exc}") from exc
        return cls.from_dict(data)

    @property
    def has_any_rule(self) -> bool:
        return bool(self.fail_on) or self.max_cvss is not None \
            or self.max_priority_score is not None \
            or self.max_new_findings is not None or self.fail_on_regression

    def to_dict(self) -> dict[str, Any]:
        return {
            "fail_on": [s.value for s in self.fail_on],
            "max_cvss": self.max_cvss,
            "max_priority_score": self.max_priority_score,
            "max_new_findings": self.max_new_findings,
            "fail_on_regression": self.fail_on_regression,
            "ignore_unvalidated": self.ignore_unvalidated,
        }


DEFAULT_POLICY_YAML = """\
# Velora CI/CD security gate policy.
gate:
  # Fail the build if any finding at these severities is present.
  fail_on: [critical, high]

  # Optional numeric thresholds. Omit to disable.
  # max_cvss: 7.0
  # max_priority_score: 70
  # max_new_findings: 0        # relative to --baseline

  # Fail if a previously-absent finding reappears.
  fail_on_regression: true

  # Count only findings a human has validated (off by default: a gate should stop
  # regressions before triage, not after).
  ignore_unvalidated: false
"""


@dataclass
class Violation:
    rule: str
    detail: str
    finding_id: str | None = None
    severity: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"rule": self.rule, "detail": self.detail,
                "finding_id": self.finding_id, "severity": self.severity}


@dataclass
class GateEvaluation:
    decision: GateDecision
    policy: GatePolicy
    violations: list[Violation] = field(default_factory=list)
    summary: str = ""
    considered: int = 0

    @property
    def exit_code(self) -> int:
        return self.decision.exit_code

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "exit_code": self.exit_code,
            "policy": self.policy.to_dict(),
            "findings_considered": self.considered,
            "violations": [v.to_dict() for v in self.violations],
            "summary": self.summary,
        }


class SecurityGate:
    def __init__(self, repo: Repository) -> None:
        self.repo = repo

    def _considered(self, findings: list[Finding], policy: GatePolicy) -> list[Finding]:
        out = [f for f in findings if f.status.value not in {"Rejected", "Remediated"}]
        if policy.ignore_unvalidated:
            out = [f for f in out if f.status.value == "Confirmed"]
        return out

    def _error(self, scan_id: str, policy: "GatePolicy", summary: str, *,
               persist: bool, engagement_id: str | None = None) -> "GateEvaluation":
        """Record and return an ERROR outcome.

        An ERROR is the outcome a pipeline most needs to be able to look up later: it
        means the gate could not judge the scan at all. Returning it without persisting
        it made `velora gate history` unable to ever show one.
        """
        evaluation = GateEvaluation(decision=GateDecision.ERROR, policy=policy,
                                    summary=summary)
        log.error("SECURITY_GATE_ERROR scan=%s reason=%s", scan_id, summary)
        if persist:
            self.repo.add_gate_result(SecurityGateResult(
                scan_id=scan_id, engagement_id=engagement_id,
                decision=GateDecision.ERROR, policy=policy.to_dict(),
                violations=[], summary=summary))
            self.repo.audit(AuditLog(
                action="security_gate_error", target_ref=scan_id,
                detail={"reason": summary, "policy": policy.to_dict()}))
        return evaluation

    def evaluate(self, scan_id: str, policy: GatePolicy, *,
                 baseline_scan_id: str | None = None,
                 persist: bool = True) -> GateEvaluation:
        scan = self.repo.get_scan(scan_id)
        if scan is None:
            return self._error(scan_id, policy, f"scan not found: {scan_id}",
                               persist=persist)
        if scan.status.value != "completed":
            return self._error(
                scan_id, policy,
                f"scan {scan_id} is '{scan.status.value}', not 'completed'; refusing to "
                "pass a gate on an incomplete scan",
                persist=persist, engagement_id=scan.engagement_id)

        findings = self._considered(self.repo.list_findings(scan_id), policy)
        violations: list[Violation] = []

        # Rule: severity presence.
        if policy.fail_on:
            names = {s for s in policy.fail_on}
            for finding in findings:
                if finding.severity in names:
                    violations.append(Violation(
                        "fail_on",
                        f"{finding.severity.value} finding present: {finding.title}",
                        finding.id, finding.severity.value))

        # Rule: CVSS ceiling (only findings that actually have a score).
        if policy.max_cvss is not None:
            for finding in findings:
                if finding.cvss_base_score is not None \
                        and finding.cvss_base_score > policy.max_cvss:
                    violations.append(Violation(
                        "max_cvss",
                        f"CVSS {finding.cvss_base_score} exceeds {policy.max_cvss}: "
                        f"{finding.title}", finding.id, finding.severity.value))

        # Rule: Velora Priority Score ceiling.
        if policy.max_priority_score is not None:
            for finding in findings:
                if (finding.priority_score or 0) > policy.max_priority_score:
                    violations.append(Violation(
                        "max_priority_score",
                        f"priority {finding.priority_score:.1f} exceeds "
                        f"{policy.max_priority_score}: {finding.title}",
                        finding.id, finding.severity.value))

        # Rules needing a baseline.
        if policy.max_new_findings is not None or policy.fail_on_regression:
            baseline_id = baseline_scan_id or scan.baseline_scan_id
            regressions = self.repo.list_regressions(scan_id)
            if not regressions and baseline_id:
                baseline = self.repo.get_scan(baseline_id)
                if baseline is None:
                    return self._error(
                        scan_id, policy, f"baseline scan not found: {baseline_id}",
                        persist=persist, engagement_id=scan.engagement_id)
                from ..regression import RegressionEngine
                regressions = RegressionEngine(self.repo).compare(
                    baseline, scan, persist=False).results

            if regressions:
                new_count = sum(1 for r in regressions
                                if r.change == RegressionChange.NEW_FINDING)
                if policy.max_new_findings is not None \
                        and new_count > policy.max_new_findings:
                    violations.append(Violation(
                        "max_new_findings",
                        f"{new_count} new finding(s) exceed the limit of "
                        f"{policy.max_new_findings}"))
                if policy.fail_on_regression:
                    for r in regressions:
                        if r.change == RegressionChange.REINTRODUCED_FINDING:
                            violations.append(Violation(
                                "fail_on_regression",
                                f"previously-absent finding reappeared: "
                                f"{r.detail.get('title', r.subject)}",
                                severity=r.severity))
            elif policy.max_new_findings is not None and not baseline_id:
                return self._error(
                    scan_id, policy,
                    "max_new_findings requires a baseline scan; pass --baseline or "
                    "record one on the scan",
                    persist=persist, engagement_id=scan.engagement_id)

        decision = GateDecision.FAIL if violations else GateDecision.PASS
        summary = (f"{len(violations)} policy violation(s) across {len(findings)} "
                   f"considered finding(s)" if violations
                   else f"no policy violations across {len(findings)} considered finding(s)")
        evaluation = GateEvaluation(decision=decision, policy=policy,
                                    violations=violations, summary=summary,
                                    considered=len(findings))

        if persist:
            self.repo.add_gate_result(SecurityGateResult(
                scan_id=scan_id, engagement_id=scan.engagement_id,
                decision=decision, policy=policy.to_dict(),
                violations=[v.to_dict() for v in violations], summary=summary))
            self.repo.audit(AuditLog(
                action=("security_gate_failed" if decision == GateDecision.FAIL
                        else "security_gate_passed"),
                target_ref=scan_id,
                detail={"violations": len(violations), "policy": policy.to_dict()}))
        if decision == GateDecision.FAIL:
            log.security("SECURITY_GATE_FAILED scan=%s violations=%d", scan_id, len(violations))
        else:
            log.info("SECURITY_GATE_PASSED scan=%s", scan_id)
        return evaluation
