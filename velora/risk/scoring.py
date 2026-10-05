"""Velora Priority Score.

A custom, transparent triage metric. It is deliberately NOT presented as CVSS: CVSS
(when available) is stored separately on the finding. Severity is the anchor; contextual
factors modulate it within a bounded range so an operator can triage a long finding list.

Formula (each factor in [0, 1]):

    context = 0.5 + 0.5 * (0.30 * confidence
                          + 0.30 * exposure
                          + 0.20 * evidence_quality
                          + 0.20 * asset_importance)      # -> [0.5, 1.0]

    priority = clamp(100 * severity_weight * context * auth_multiplier, 0, 100)

``auth_multiplier`` is 1.15 when the issue is reachable without authentication. Because
severity anchors the product, an Informational finding can never be scored as a
high-priority item, while contextual factors still differentiate items of equal severity.
Weights are documented and adjustable in code.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..models.enums import Confidence, Severity

_SEVERITY_WEIGHT: dict[Severity, float] = {
    Severity.INFO: 0.10,
    Severity.LOW: 0.30,
    Severity.MEDIUM: 0.60,
    Severity.HIGH: 0.85,
    Severity.CRITICAL: 1.00,
}

_CONTEXT_WEIGHTS = {
    "confidence": 0.30,
    "exposure": 0.30,
    "evidence_quality": 0.20,
    "asset_importance": 0.20,
}


@dataclass
class PriorityInputs:
    severity: Severity
    confidence: Confidence
    exposure: float = 0.6          # 0=internal/hard-to-reach, 1=internet-facing
    asset_importance: float = 0.5  # 0=throwaway, 1=crown-jewel
    evidence_quality: float = 0.7  # 0=weak, 1=strong/direct
    unauthenticated: bool = True   # reachable without credentials?


@dataclass
class PriorityResult:
    score: float
    band: str
    factors: dict[str, float]

    @property
    def label(self) -> str:
        return f"{self.score:.1f} ({self.band})"


def _clamp01(x: float) -> float:
    return max(0.0, min(1.0, x))


def _band(score: float) -> str:
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 40:
        return "Medium"
    if score >= 20:
        return "Low"
    return "Informational"


def compute_priority(inp: PriorityInputs) -> PriorityResult:
    sev = _SEVERITY_WEIGHT[inp.severity]
    conf = inp.confidence.score
    exposure = _clamp01(inp.exposure)
    evidence = _clamp01(inp.evidence_quality)
    asset = _clamp01(inp.asset_importance)

    context = 0.5 + 0.5 * (
        _CONTEXT_WEIGHTS["confidence"] * conf
        + _CONTEXT_WEIGHTS["exposure"] * exposure
        + _CONTEXT_WEIGHTS["evidence_quality"] * evidence
        + _CONTEXT_WEIGHTS["asset_importance"] * asset
    )
    auth_multiplier = 1.15 if inp.unauthenticated else 1.0
    score = min(100.0, 100.0 * sev * context * auth_multiplier)
    factors = {
        "severity": round(sev, 3),
        "confidence": round(conf, 3),
        "exposure": round(exposure, 3),
        "evidence_quality": round(evidence, 3),
        "asset_importance": round(asset, 3),
        "context": round(context, 3),
        "auth_multiplier": auth_multiplier,
    }
    return PriorityResult(score=round(score, 1), band=_band(score), factors=factors)
