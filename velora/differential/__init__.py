"""Differential request analysis.

Compares a *baseline* exchange against a *candidate* exchange produced by a controlled
variation (a different identity, a changed parameter, a removed cookie) and reports the
structural differences between them.

Design rule: **a difference is not a vulnerability.** The engine reports classified,
evidence-backed observations with a confidence score and an explicit
``validation_required`` flag. Interpretation is deliberately conservative, and nothing
here ever creates a Confirmed finding.
"""
from .fingerprint import ResponseFingerprint, fingerprint_response
from .engine import DifferentialEngine, DifferentialResult

__all__ = [
    "ResponseFingerprint",
    "fingerprint_response",
    "DifferentialEngine",
    "DifferentialResult",
]
