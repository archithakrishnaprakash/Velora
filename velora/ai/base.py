"""AI provider interface and the strict result contract.

Velora 2.0 extends the contract with an explicit evidence model. The 1.x fields are all
preserved with their original names and defaults, so existing providers and stored rows
keep working.
"""
from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any

from ..models.enums import ValidationState
from .envelope import PromptEnvelope


@dataclass
class AnalysisInput:
    """Structured, evidence-first input handed to a provider (never free-form).

    Everything here is produced by Velora. Content captured from the assessed system is
    carried separately in ``untrusted_content`` and is sanitized and fenced by the
    :class:`~velora.ai.envelope.PromptEnvelope` before it reaches a model.
    """

    # --- 1.x fields (unchanged) ---
    target: str
    endpoint: str
    method: str
    finding_title: str
    category: str
    severity: str
    scanner_confidence: str
    description: str
    evidence_excerpts: list[str] = field(default_factory=list)
    status_code: int | None = None
    headers: dict[str, str] = field(default_factory=dict)

    # --- 2.0 evidence-reasoning fields ---
    finding_id: str = ""
    evidence_matrix: dict[str, Any] = field(default_factory=dict)
    differential_observations: list[dict[str, Any]] = field(default_factory=list)
    authorization_tests: list[dict[str, Any]] = field(default_factory=list)
    technologies: list[dict[str, Any]] = field(default_factory=list)
    related_findings: list[dict[str, Any]] = field(default_factory=list)
    attack_graph_context: dict[str, Any] = field(default_factory=dict)
    scope_metadata: dict[str, Any] = field(default_factory=dict)
    validation_history: list[dict[str, Any]] = field(default_factory=list)
    #: Target-derived text. Treated as hostile; sanitized and fenced before use.
    untrusted_content: list[tuple[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Trusted evidence only — never includes untrusted target content."""
        return {
            "target": self.target,
            "endpoint": self.endpoint,
            "method": self.method,
            "finding": self.finding_title,
            "finding_id": self.finding_id,
            "category": self.category,
            "severity": self.severity,
            "scanner_confidence": self.scanner_confidence,
            "description": self.description,
            "evidence": self.evidence_excerpts,
            "status_code": self.status_code,
            "headers": self.headers,
            "evidence_matrix": self.evidence_matrix,
            "differential_observations": self.differential_observations,
            "authorization_tests": self.authorization_tests,
            "technologies": self.technologies,
            "related_findings": self.related_findings,
            "attack_graph_context": self.attack_graph_context,
            "scope_metadata": self.scope_metadata,
            "validation_history": self.validation_history,
        }

    def build_envelope(self) -> PromptEnvelope:
        """Build the trust-boundary envelope for this input."""
        envelope = PromptEnvelope(evidence=self.to_dict())
        for label, content in self.untrusted_content:
            envelope.add_untrusted(label, content)
        return envelope


@dataclass
class AnalysisResult:
    """Normalized provider output. ``human_validation_required`` is always True."""

    # --- 1.x fields (unchanged) ---
    classification: str
    confidence: float
    reasoning_summary: str
    impact: str
    remediation: str
    related_findings: list[str] = field(default_factory=list)
    human_validation_required: bool = True
    ai_generated: bool = True
    provider: str = ""
    model: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    # --- 2.0 evidence-reasoning fields ---
    supporting_evidence: list[str] = field(default_factory=list)
    contradicting_evidence: list[str] = field(default_factory=list)
    missing_evidence: list[str] = field(default_factory=list)
    recommended_validation: str = ""
    validation_state: ValidationState = ValidationState.HYPOTHESIZED
    evidence_matrix: dict[str, Any] = field(default_factory=dict)
    prompt_sanitized: bool = True
    injection_detected: bool = False

    #: Terminology that would overstate what an automated assistant can establish.
    BANNED_TERMS = ("confirmed", "exploited", "proven", "verified vulnerable",
                    "definitely vulnerable", "guaranteed")

    def enforce_safety(self, max_confidence: float | None = None) -> "AnalysisResult":
        """Clamp fields so an AI result can never over-claim.

        ``max_confidence`` lets the deterministic evidence matrix cap the model: a
        provider cannot be more certain than the evidence coverage allows.
        """
        self.human_validation_required = True
        self.ai_generated = True
        try:
            self.confidence = max(0.0, min(1.0, float(self.confidence)))
        except (TypeError, ValueError):
            self.confidence = 0.0
        if max_confidence is not None:
            self.confidence = min(self.confidence, max(0.0, min(1.0, max_confidence)))

        low = (self.classification or "").lower()
        if any(term in low for term in self.BANNED_TERMS):
            self.classification = "potential-" + self.classification

        # An AI result may never assert the VALIDATED state; only a human sets that.
        if self.validation_state == ValidationState.VALIDATED:
            self.validation_state = ValidationState.HYPOTHESIZED
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "classification": self.classification,
            "confidence": round(self.confidence, 3),
            "supporting_evidence": self.supporting_evidence,
            "contradicting_evidence": self.contradicting_evidence,
            "missing_evidence": self.missing_evidence,
            "reasoning_summary": self.reasoning_summary,
            "impact": self.impact,
            "remediation": self.remediation,
            "recommended_validation": self.recommended_validation,
            "related_findings": self.related_findings,
            "validation_state": self.validation_state.value,
            "human_validation_required": True,
            "ai_generated": True,
            "prompt_sanitized": self.prompt_sanitized,
            "injection_detected": self.injection_detected,
            "provider": self.provider,
            "model": self.model,
        }


class AIProvider(abc.ABC):
    """Abstract provider. Implementations must be side-effect-free w.r.t. the target."""

    name: str = "base"

    @abc.abstractmethod
    def analyze(self, data: AnalysisInput) -> AnalysisResult:
        raise NotImplementedError

    def summarize(self, findings_summary: dict[str, Any]) -> str:
        """Default scan summary; providers may override with a richer version."""
        counts = findings_summary.get("by_severity", {})
        total = findings_summary.get("total", 0)
        return (
            f"{total} finding(s) identified: "
            + ", ".join(f"{k}={v}" for k, v in counts.items())
            + ". All findings are evidence-backed and require human validation."
        )
