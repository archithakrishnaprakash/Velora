"""AI abstraction layer.

Design rules (enforced, not advisory):
  * The AI is an *analysis assistant*. It explains evidence produced by deterministic
    scanners; it never decides that a vulnerability exists.
  * The AI can never set a finding to Confirmed. Every AI result carries
    ``human_validation_required=True`` and ``ai_generated=True``.
  * Only concise security reasoning summaries are stored — never hidden chain-of-thought.
  * No provider is hard-coded; providers are pluggable behind ``AIProvider``.
"""
from .base import AIProvider, AnalysisInput, AnalysisResult
from .envelope import PromptEnvelope, SanitizationReport, sanitize_untrusted
from .evidence_matrix import EvidenceMatrix, EvidenceMatrixBuilder
from .heuristic import HeuristicProvider
from .null import NullProvider
from .service import AIService, build_provider

__all__ = [
    "AIProvider",
    "PromptEnvelope",
    "SanitizationReport",
    "sanitize_untrusted",
    "EvidenceMatrix",
    "EvidenceMatrixBuilder",
    "AnalysisInput",
    "AnalysisResult",
    "HeuristicProvider",
    "NullProvider",
    "AIService",
    "build_provider",
]
