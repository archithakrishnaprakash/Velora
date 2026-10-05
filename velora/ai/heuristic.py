"""HeuristicProvider — a deterministic, offline evidence-reasoning assistant.

This provider produces evidence-grounded explanations without any external LLM call. It
is the safe default: no network, no key, no over-claiming, and every result requires
human validation.

In 2.0 it reads the deterministic :class:`~velora.ai.evidence_matrix.EvidenceMatrix`
that Velora computed before any model was consulted, so its supporting/contradicting/
missing lists and its confidence come from measured test coverage rather than prose.
"""
from __future__ import annotations

from ..models.enums import ValidationState
from .base import AIProvider, AnalysisInput, AnalysisResult

# category -> (classification, impact, remediation)
_KNOWLEDGE: dict[str, tuple[str, str, str]] = {
    "configuration": (
        "security-misconfiguration",
        "Missing hardening controls weaken defence-in-depth and make other attacks easier.",
        "Apply the recommended header/method/configuration change and re-test.",
    ),
    "session": (
        "session-management-weakness",
        "Session cookies without protective attributes can be stolen or replayed, enabling "
        "session hijacking.",
        "Set HttpOnly, Secure (HTTPS), and SameSite on session cookies.",
    ),
    "authentication": (
        "authentication-weakness",
        "Weak authentication handling can expose credentials or enable account compromise.",
        "Enforce HTTPS for all auth flows and add anti-CSRF protection to state-changing forms.",
    ),
    "authorization": (
        "possible-access-control-gap",
        "If access control is missing, unauthorized users may reach privileged functionality "
        "or other users' data.",
        "Enforce an ownership/role check server-side on every request; do not trust "
        "identifiers supplied by the client.",
    ),
    "information_disclosure": (
        "information-disclosure",
        "Disclosed data (versions, errors, secrets) aids an attacker in targeting the system.",
        "Suppress verbose output and remove secrets from responses; rotate any exposed secret.",
    ),
    "tls": (
        "transport-security-weakness",
        "Weak TLS undermines the confidentiality and integrity of data in transit.",
        "Require TLS 1.2+/1.3 with strong ciphers and valid certificates.",
    ),
    "input_validation": (
        "possible-input-validation-issue",
        "Reflected input can become XSS if not correctly encoded; impact depends on context.",
        "Contextually output-encode reflected input and apply a strong CSP; validate manually.",
    ),
}

_DEFAULT = (
    "potential-issue",
    "Impact depends on context; review the evidence.",
    "Review the evidence and apply appropriate hardening.",
)


class HeuristicProvider(AIProvider):
    name = "heuristic"

    def analyze(self, data: AnalysisInput) -> AnalysisResult:
        classification, impact, remediation = _KNOWLEDGE.get(data.category, _DEFAULT)
        matrix = data.evidence_matrix or {}

        supporting = [i.get("statement", "") for i in matrix.get("supporting", [])]
        contradicting = [i.get("statement", "") for i in matrix.get("contradicting", [])]
        missing = list(matrix.get("missing", []))
        recommended = matrix.get("recommended_validation", [])
        recommended_text = " ".join(recommended) if isinstance(recommended, list) else str(recommended)

        # Confidence comes from the deterministic matrix when available; otherwise it is
        # derived from the scanner's own confidence and deliberately capped.
        if "confidence" in matrix:
            confidence = float(matrix["confidence"])
        else:
            confidence = {"Certain": 0.8, "Firm": 0.65, "Tentative": 0.45}.get(
                data.scanner_confidence, 0.5)

        try:
            state = ValidationState(matrix.get("validation_state", "HYPOTHESIZED"))
        except ValueError:
            state = ValidationState.HYPOTHESIZED

        # Build the envelope so untrusted content is sanitized and injection is detected,
        # even though this provider makes no network call.
        envelope = data.build_envelope()
        injection = envelope.injection_detected

        reasoning = self._reasoning(data, classification, supporting, contradicting,
                                   missing, injection)

        return AnalysisResult(
            classification=classification,
            confidence=confidence,
            reasoning_summary=reasoning,
            impact=impact,
            remediation=remediation,
            related_findings=[f.get("id", "") for f in data.related_findings if f.get("id")],
            supporting_evidence=supporting,
            contradicting_evidence=contradicting,
            missing_evidence=missing,
            recommended_validation=recommended_text,
            validation_state=state,
            evidence_matrix=matrix,
            prompt_sanitized=True,
            injection_detected=injection,
            provider=self.name,
            model="heuristic-v2",
            raw={"category": data.category, "severity": data.severity,
                 "sanitization": envelope.sanitization_summary()},
        ).enforce_safety(max_confidence=matrix.get("confidence"))

    @staticmethod
    def _reasoning(data: AnalysisInput, classification: str, supporting: list[str],
                   contradicting: list[str], missing: list[str], injection: bool) -> str:
        parts = [
            f"The scanner observed '{data.finding_title}' at {data.method} {data.endpoint}, "
            f"which maps to {classification}.",
        ]
        if supporting:
            parts.append(f"OBSERVED: {'; '.join(supporting[:3])}.")
        else:
            parts.append("OBSERVED: no direct evidence rows were recorded for this finding.")
        if contradicting:
            parts.append(f"CONTRADICTING: {'; '.join(contradicting[:2])}.")
        if missing:
            parts.append(f"UNKNOWN (missing evidence): {'; '.join(missing[:3])}.")
        if injection:
            parts.append(
                "NOTE: instruction-like text was detected in content captured from the "
                "target and was neutralized; it was treated as data, not instructions.")
        parts.append(
            "This explanation is AI-assisted and evidence-based. It is HYPOTHESIZED, not "
            "confirmed: a human must validate it.")
        return " ".join(parts)
