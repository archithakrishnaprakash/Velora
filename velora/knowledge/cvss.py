"""CVSS v3.1 base-score computation.

Velora never invents a CVSS score. A score exists only when a **valid vector string** is
supplied — either by a check that can justify every metric, or manually by an operator.
Otherwise the finding reports ``Not Assessed``.

The arithmetic follows the CVSS v3.1 specification (section 7.1) exactly, including the
specified ``Roundup`` function, which must be implemented with integer arithmetic to
avoid floating-point drift.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any

NOT_ASSESSED = "Not Assessed"

# Metric -> code -> numeric weight (CVSS v3.1 Table 14-18).
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.00}
_SCOPE = {"U", "C"}

_REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
_VECTOR_RE = re.compile(r"^CVSS:3\.[01]/(?:[A-Z]+:[A-Z]+/)*[A-Z]+:[A-Z]+$")


class InvalidVectorError(ValueError):
    """Raised when a CVSS vector string is malformed or incomplete."""


def _roundup(value: float) -> float:
    """CVSS v3.1 Roundup: smallest number to one decimal place that is >= value."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def parse_vector(vector: str) -> dict[str, str]:
    """Parse and validate a CVSS v3.x base vector into its metric codes."""
    if not vector or not isinstance(vector, str):
        raise InvalidVectorError("vector must be a non-empty string")
    vector = vector.strip()
    if not _VECTOR_RE.match(vector):
        raise InvalidVectorError(f"malformed CVSS vector: {vector!r}")

    parts = vector.split("/")
    prefix, metric_parts = parts[0], parts[1:]
    if not prefix.startswith("CVSS:3."):
        raise InvalidVectorError("only CVSS v3.0/3.1 vectors are supported")

    metrics: dict[str, str] = {}
    for part in metric_parts:
        key, _, value = part.partition(":")
        if key in metrics:
            raise InvalidVectorError(f"duplicate metric {key}")
        metrics[key] = value

    missing = [m for m in _REQUIRED if m not in metrics]
    if missing:
        raise InvalidVectorError(f"missing base metric(s): {', '.join(missing)}")

    validators = {"AV": _AV, "AC": _AC, "UI": _UI, "C": _CIA, "I": _CIA, "A": _CIA}
    for key, table in validators.items():
        if metrics[key] not in table:
            raise InvalidVectorError(f"invalid value for {key}: {metrics[key]}")
    if metrics["S"] not in _SCOPE:
        raise InvalidVectorError(f"invalid value for S: {metrics['S']}")
    if metrics["PR"] not in _PR_UNCHANGED:
        raise InvalidVectorError(f"invalid value for PR: {metrics['PR']}")
    return metrics


def base_score(vector: str) -> float:
    """Compute the CVSS v3.1 base score for a validated vector."""
    m = parse_vector(vector)
    scope_changed = m["S"] == "C"

    iss = 1 - ((1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]]))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss

    pr_table = _PR_CHANGED if scope_changed else _PR_UNCHANGED
    exploitability = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr_table[m["PR"]] * _UI[m["UI"]]

    if impact <= 0:
        return 0.0
    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10))
    return _roundup(min(impact + exploitability, 10))


def severity_for(score: float) -> str:
    """CVSS v3.1 qualitative severity rating scale."""
    if score == 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


@dataclass
class CVSSAssessment:
    """A CVSS result, or an explicit statement that none was assessed."""

    vector: str | None = None
    version: str | None = None
    base_score: float | None = None
    severity: str = NOT_ASSESSED
    assessed: bool = False
    source: str = "none"     # "check" | "manual" | "none"
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        if not self.assessed:
            return {"status": NOT_ASSESSED,
                    **({"error": self.error} if self.error else {})}
        return {
            "status": "Assessed",
            "version": self.version,
            "vector": self.vector,
            "base_score": self.base_score,
            "severity": self.severity,
            "source": self.source,
        }


def assess(vector: str | None, *, source: str = "manual") -> CVSSAssessment:
    """Assess a vector, returning ``Not Assessed`` rather than guessing on failure."""
    if not vector:
        return CVSSAssessment()
    try:
        metrics = parse_vector(vector)
    except InvalidVectorError as exc:
        return CVSSAssessment(error=str(exc))
    score = base_score(vector)
    version = vector.split("/")[0].replace("CVSS:", "")
    return CVSSAssessment(
        vector=vector, version=version, base_score=score,
        severity=severity_for(score), assessed=True, source=source,
    )
