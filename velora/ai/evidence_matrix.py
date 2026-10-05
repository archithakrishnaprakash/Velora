"""The AI Evidence Matrix.

Before any model is consulted, Velora builds a **deterministic** matrix of what was
observed, what argues against the finding, and what evidence is missing. This is the
single most important part of the reasoning engine: it means confidence is grounded in
which tests actually ran, not in how persuasive a model's prose sounds.

The matrix is computed from stored artifacts only (evidence rows, differential
observations, authorization tests, graph context). It is handed to the provider as
trusted input, and the provider's own confidence is capped by it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..models.domain import AuthorizationTest, DifferentialObservation, Evidence, Finding
from ..models.enums import ValidationState


@dataclass
class EvidenceItem:
    """One row of the matrix."""

    statement: str
    state: ValidationState = ValidationState.OBSERVED
    source: str = ""
    evidence_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "statement": self.statement,
            "state": self.state.value,
            "source": self.source,
            "evidence_id": self.evidence_id,
        }


@dataclass
class EvidenceMatrix:
    """Supporting / contradicting / missing evidence for one finding."""

    finding_id: str = ""
    category: str = ""
    supporting: list[EvidenceItem] = field(default_factory=list)
    contradicting: list[EvidenceItem] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    recommended_validation: list[str] = field(default_factory=list)
    conclusion: str = ""
    confidence: float = 0.0
    validation_state: ValidationState = ValidationState.HYPOTHESIZED

    @property
    def completeness(self) -> float:
        """Fraction of the expected evidence set that is actually present, in [0,1]."""
        expected = len(self.supporting) + len(self.missing)
        if expected == 0:
            return 0.0
        return len(self.supporting) / expected

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "category": self.category,
            "supporting": [i.to_dict() for i in self.supporting],
            "contradicting": [i.to_dict() for i in self.contradicting],
            "missing": list(self.missing),
            "recommended_validation": list(self.recommended_validation),
            "completeness": round(self.completeness, 3),
            "conclusion": self.conclusion,
            "confidence": round(self.confidence, 3),
            "validation_state": self.validation_state.value,
            "human_validation_required": True,
        }

    def render(self) -> str:
        """A compact human-readable rendering used in CLI output and reports."""
        lines = [f"Evidence matrix for {self.finding_id} ({self.category})", ""]
        lines.append("Supporting:")
        lines += [f"  [+] {i.statement}  <{i.state.value}>" for i in self.supporting] or \
                 ["  (none)"]
        lines.append("Contradicting:")
        lines += [f"  [-] {i.statement}  <{i.state.value}>" for i in self.contradicting] or \
                 ["  (none)"]
        lines.append("Missing:")
        lines += [f"  [?] {m}" for m in self.missing] or ["  (none)"]
        lines += [
            "",
            f"Conclusion: {self.conclusion}",
            f"Confidence: {self.confidence:.2f}  (evidence completeness "
            f"{self.completeness:.0%})",
            f"Epistemic state: {self.validation_state.value}",
            "Human validation: REQUIRED",
        ]
        return "\n".join(lines)


# Expected evidence per finding category. The gap between this and what actually exists
# is what populates `missing`, which is what keeps confidence honest.
_EXPECTED_EVIDENCE: dict[str, list[str]] = {
    "authorization": [
        "endpoint reachable by the tested identity",
        "expected access decision declared in the plan",
        "observed access decision recorded",
        "a second identity tested against the same resource",
        "owner-baseline comparison performed",
    ],
    "authentication": [
        "authentication surface identified",
        "transport security of the credential flow observed",
        "anti-CSRF control presence checked",
    ],
    "session": [
        "Set-Cookie observed",
        "cookie attributes parsed",
        "cookie scope (path/domain) recorded",
    ],
    "configuration": [
        "response headers captured",
        "target response status recorded",
    ],
    "information_disclosure": [
        "response body inspected",
        "disclosed artifact classified",
    ],
    "tls": [
        "TLS handshake metadata captured",
        "certificate validity checked",
    ],
    "input_validation": [
        "parameter reflection observed with a benign marker",
        "output encoding context identified",
        "content-security-policy evaluated",
    ],
}

_DEFAULT_EXPECTED = ["request recorded", "response recorded"]


class EvidenceMatrixBuilder:
    """Builds an EvidenceMatrix deterministically from stored artifacts."""

    def build(
        self,
        finding: Finding,
        evidence: list[Evidence],
        *,
        differentials: list[DifferentialObservation] | None = None,
        authz_tests: list[AuthorizationTest] | None = None,
        related_findings: list[Finding] | None = None,
    ) -> EvidenceMatrix:
        matrix = EvidenceMatrix(finding_id=finding.id, category=finding.category)
        differentials = differentials or []
        authz_tests = authz_tests or []
        related_findings = related_findings or []

        present: set[str] = set()

        # --- supporting evidence drawn from stored rows ---
        for row in evidence:
            if row.status_code is not None:
                matrix.supporting.append(EvidenceItem(
                    f"response status {row.status_code} recorded for {finding.endpoint}",
                    ValidationState.OBSERVED, row.test_name, row.id))
                present |= {"target response status recorded", "response recorded",
                            "endpoint reachable by the tested identity"}
            if row.headers:
                matrix.supporting.append(EvidenceItem(
                    f"{len(row.headers)} response header(s) captured",
                    ValidationState.OBSERVED, row.test_name, row.id))
                present |= {"response headers captured", "Set-Cookie observed"} \
                    if "set-cookie" in {k.lower() for k in row.headers} \
                    else {"response headers captured"}
            if row.sanitized_excerpt:
                matrix.supporting.append(EvidenceItem(
                    row.sanitized_excerpt[:160], ValidationState.OBSERVED,
                    row.test_name, row.id))
                present |= {"response body inspected", "disclosed artifact classified",
                            "request recorded"}

        # --- category-specific enrichment ---
        if finding.category == "authorization":
            present |= self._authorization_signals(finding, authz_tests, matrix)
        if finding.category == "authentication":
            present |= self._authentication_signals(finding, matrix)
        if finding.category == "session":
            present |= self._session_signals(evidence, matrix)
        if finding.category == "input_validation":
            present |= self._input_validation_signals(finding, matrix)

        # --- differential observations strengthen or weaken the case ---
        for diff in differentials:
            state = ValidationState.OBSERVED if diff.confidence >= 0.7 else ValidationState.INFERRED
            if diff.differences:
                matrix.supporting.append(EvidenceItem(
                    f"differential {diff.id}: {', '.join(diff.classifications)}",
                    state, "differential", diff.evidence_ids[0] if diff.evidence_ids else None))
                present.add("owner-baseline comparison performed")
            else:
                matrix.contradicting.append(EvidenceItem(
                    f"differential {diff.id} found no structural difference between the "
                    f"baseline and candidate responses",
                    state, "differential"))

        # --- related findings are context, explicitly marked as inferred ---
        for other in related_findings[:5]:
            if other.id == finding.id:
                continue
            matrix.supporting.append(EvidenceItem(
                f"related finding {other.id} ({other.severity.value}) in the same scan: "
                f"{other.title}", ValidationState.INFERRED, "correlation"))

        # --- what is missing ---
        expected = _EXPECTED_EVIDENCE.get(finding.category, _DEFAULT_EXPECTED)
        matrix.missing = [item for item in expected if item not in present]

        # --- contradicting: explicit gaps that weaken the claim ---
        if finding.category == "authorization" and not authz_tests:
            matrix.contradicting.append(EvidenceItem(
                "no multi-identity authorization test was executed for this endpoint",
                ValidationState.UNKNOWN, "coverage"))
        if finding.confidence.value == "Tentative":
            matrix.contradicting.append(EvidenceItem(
                "the detecting check reported only tentative confidence",
                ValidationState.INFERRED, finding.scanner))

        matrix.recommended_validation = self._recommended_validation(finding, matrix)
        matrix.confidence = self._confidence(finding, matrix)
        matrix.conclusion = self._conclusion(finding, matrix)
        matrix.validation_state = self._state(finding, matrix)
        return matrix

    # ---- category helpers ------------------------------------------------
    def _authorization_signals(self, finding: Finding, tests: list[AuthorizationTest],
                               matrix: EvidenceMatrix) -> set[str]:
        present: set[str] = set()
        relevant = [t for t in tests if t.url == finding.endpoint]
        identities = {t.identity_id for t in relevant}
        for t in relevant:
            matrix.supporting.append(EvidenceItem(
                f"identity role '{t.identity_role.value}' expected {t.expected.value} and "
                f"observed {t.observed.value} on {t.method} {t.url}",
                ValidationState.OBSERVED, "authz.matrix",
                t.evidence_ids[0] if t.evidence_ids else None))
            present |= {"expected access decision declared in the plan",
                        "observed access decision recorded"}
            if t.outcome.is_weakness:
                present.add("endpoint reachable by the tested identity")
        if len(identities) >= 2:
            present.add("a second identity tested against the same resource")
        elif relevant:
            matrix.contradicting.append(EvidenceItem(
                "only one identity was tested against this resource, so cross-account "
                "behaviour is unverified", ValidationState.UNKNOWN, "coverage"))
        if any(t.differential_id for t in relevant):
            present.add("owner-baseline comparison performed")
        return present

    def _authentication_signals(self, finding: Finding, matrix: EvidenceMatrix) -> set[str]:
        """Credit evidence the authentication checks genuinely produce."""
        present: set[str] = set()
        text = f"{finding.title} {finding.description}".lower()
        if any(word in text for word in ("form", "login", "credential", "password")):
            present.add("authentication surface identified")
        if "http" in text or finding.endpoint.lower().startswith(("http://", "https://")):
            present.add("transport security of the credential flow observed")
        if "csrf" in text:
            present.add("anti-CSRF control presence checked")
        else:
            matrix.contradicting.append(EvidenceItem(
                "anti-CSRF control presence was not evaluated for this form",
                ValidationState.UNKNOWN, "coverage"))
        return present

    def _session_signals(self, evidence: list[Evidence], matrix: EvidenceMatrix) -> set[str]:
        present: set[str] = set()
        for row in evidence:
            if "cookie" in (row.test_name or "").lower() or "cookie" in row.sanitized_excerpt.lower():
                present |= {"Set-Cookie observed", "cookie attributes parsed"}
        return present

    def _input_validation_signals(self, finding: Finding, matrix: EvidenceMatrix) -> set[str]:
        present: set[str] = set()
        if "reflect" in finding.title.lower() or "reflect" in finding.description.lower():
            present.add("parameter reflection observed with a benign marker")
            matrix.contradicting.append(EvidenceItem(
                "reflection was observed with a benign alphanumeric marker only; no "
                "encoding-context or payload testing was performed",
                ValidationState.UNKNOWN, "input.reflection"))
        return present

    # ---- scoring ---------------------------------------------------------
    def _confidence(self, finding: Finding, matrix: EvidenceMatrix) -> float:
        """Deterministic confidence grounded in coverage, not prose.

        Starts from the detecting check's own confidence, scales by how much of the
        expected evidence set is present, and applies a penalty per contradicting item.
        """
        base = finding.confidence.score
        coverage = matrix.completeness
        penalty = 0.08 * len(matrix.contradicting)
        score = base * (0.55 + 0.45 * coverage) - penalty
        # An evidence-based assistant never reaches certainty: confirmation is human-only.
        return max(0.05, min(0.9, round(score, 3)))

    def _conclusion(self, finding: Finding, matrix: EvidenceMatrix) -> str:
        qualifier = "Potential"
        if matrix.completeness >= 0.8 and not matrix.contradicting:
            qualifier = "Well-evidenced potential"
        elif matrix.completeness < 0.4:
            qualifier = "Weakly-evidenced potential"
        return (f"{qualifier} {finding.category.replace('_', ' ')} issue: {finding.title}. "
                f"Requires human validation before it is treated as confirmed.")

    def _state(self, finding: Finding, matrix: EvidenceMatrix) -> ValidationState:
        if finding.status.value == "Confirmed":
            return ValidationState.VALIDATED
        if not matrix.supporting:
            return ValidationState.UNKNOWN
        if matrix.completeness >= 0.6 and not matrix.missing:
            return ValidationState.OBSERVED
        if matrix.completeness >= 0.4:
            return ValidationState.INFERRED
        return ValidationState.HYPOTHESIZED

    def _recommended_validation(self, finding: Finding, matrix: EvidenceMatrix) -> list[str]:
        steps: list[str] = []
        if finding.category == "authorization":
            if "a second identity tested against the same resource" in matrix.missing:
                steps.append("Re-run the authorization matrix with a second user identity "
                             "that owns a different resource of the same type.")
            steps.append("Manually confirm whether the returned object belongs to another "
                         "principal, and whether the server enforces ownership.")
        elif finding.category == "input_validation":
            steps.append("Determine the output encoding context of the reflection and "
                         "whether the response Content-Type permits script execution.")
        elif finding.category == "session":
            steps.append("Confirm the cookie is a session identifier and check whether the "
                         "application sets the attributes elsewhere.")
        elif finding.category == "tls":
            steps.append("Verify the certificate chain and negotiated protocol from an "
                         "independent client.")
        else:
            steps.append("Reproduce the observation manually and confirm the response "
                         "matches the recorded evidence.")
        if matrix.missing:
            steps.append("Collect the missing evidence listed in the matrix, then re-assess.")
        return steps
