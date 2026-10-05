"""NullProvider — returns a minimal deterministic result with no analysis.

Used when the operator wants to disable AI analysis entirely while keeping the pipeline
interface intact.
"""
from __future__ import annotations

from ..models.enums import ValidationState
from .base import AIProvider, AnalysisInput, AnalysisResult


class NullProvider(AIProvider):
    name = "null"

    def analyze(self, data: AnalysisInput) -> AnalysisResult:
        return AnalysisResult(
            classification="not-analyzed",
            confidence=0.0,
            reasoning_summary="AI analysis is disabled (null provider).",
            impact="",
            remediation="",
            recommended_validation="Enable an AI provider or validate this finding manually.",
            validation_state=ValidationState.UNKNOWN,
            evidence_matrix=data.evidence_matrix,
            provider=self.name,
            model="none",
        ).enforce_safety()
