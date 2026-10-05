import unittest

from velora.ai.evidence_matrix import EvidenceMatrixBuilder
from velora.models.domain import AuthorizationTest, DifferentialObservation, Evidence, Finding
from velora.models.enums import (
    AccessExpectation,
    AccessObservation,
    AuthzOutcome,
    Confidence,
    FindingStatus,
    IdentityRole,
    Severity,
    ValidationState,
)


def finding(category="authorization", confidence=Confidence.FIRM, status=FindingStatus.POTENTIAL):
    return Finding(scan_id="S1", title="Test finding", category=category, severity=Severity.HIGH,
                   confidence=confidence, status=status, endpoint="http://lab/api/orders/1",
                   scanner="authz.matrix", description="d")


def evidence(**kw):
    base = dict(scan_id="S1", finding_id="F1", test_name="authz.matrix",
                status_code=200, sanitized_excerpt="observed something")
    base.update(kw)
    return Evidence(**base)


def authz_test(role=IdentityRole.USER_B, outcome=AuthzOutcome.HORIZONTAL_AUTHORIZATION_WEAKNESS,
               identity_id="I1"):
    return AuthorizationTest(
        scan_id="S1", identity_id=identity_id, identity_role=role,
        url="http://lab/api/orders/1", method="GET",
        expected=AccessExpectation.DENY, observed=AccessObservation.GRANTED,
        outcome=outcome, status_code=200, evidence_ids=["EV1"])


class TestEvidenceMatrix(unittest.TestCase):
    def setUp(self):
        self.builder = EvidenceMatrixBuilder()

    def test_missing_evidence_is_reported_when_coverage_is_thin(self):
        m = self.builder.build(finding(), [])
        self.assertTrue(m.missing)
        self.assertLess(m.completeness, 1.0)

    def test_single_identity_produces_a_contradicting_entry(self):
        m = self.builder.build(finding(), [evidence()], authz_tests=[authz_test()])
        text = " ".join(i.statement for i in m.contradicting)
        self.assertIn("only one identity", text.lower())

    def test_two_identities_satisfy_the_second_identity_requirement(self):
        tests = [authz_test(identity_id="I1"),
                 authz_test(identity_id="I2", role=IdentityRole.USER_A,
                            outcome=AuthzOutcome.AS_EXPECTED)]
        m = self.builder.build(finding(), [evidence()], authz_tests=tests)
        self.assertNotIn("a second identity tested against the same resource", m.missing)

    def test_more_coverage_yields_higher_confidence(self):
        thin = self.builder.build(finding(), [])
        rich = self.builder.build(
            finding(), [evidence(), evidence(headers={"Server": "x"})],
            authz_tests=[authz_test(identity_id="I1"),
                         authz_test(identity_id="I2", outcome=AuthzOutcome.AS_EXPECTED)],
            differentials=[DifferentialObservation(
                scan_id="S1", baseline_url="http://lab/api/orders/1",
                candidate_url="http://lab/api/orders/1",
                differences=[{"classification": "NO_CHANGE"}], confidence=0.9)])
        self.assertGreater(rich.confidence, thin.confidence)

    def test_confidence_never_reaches_certainty(self):
        """An automated assistant must never be certain — confirmation is human-only."""
        m = self.builder.build(
            finding(confidence=Confidence.CERTAIN),
            [evidence(), evidence(headers={"a": "b"})],
            authz_tests=[authz_test(identity_id=f"I{i}") for i in range(4)])
        self.assertLessEqual(m.confidence, 0.9)

    def test_empty_evidence_yields_unknown_state(self):
        m = self.builder.build(finding(category="tls"), [])
        self.assertEqual(m.validation_state, ValidationState.UNKNOWN)

    def test_confirmed_finding_is_validated_state(self):
        m = self.builder.build(finding(status=FindingStatus.CONFIRMED), [evidence()])
        self.assertEqual(m.validation_state, ValidationState.VALIDATED)

    def test_no_difference_differential_is_contradicting_not_supporting(self):
        diff = DifferentialObservation(scan_id="S1", baseline_url="u", candidate_url="u",
                                       differences=[], confidence=0.9)
        m = self.builder.build(finding(), [evidence()], differentials=[diff])
        text = " ".join(i.statement for i in m.contradicting)
        self.assertIn("no structural difference", text)

    def test_recommended_validation_is_always_present(self):
        for category in ("authorization", "input_validation", "session", "tls", "configuration"):
            m = self.builder.build(finding(category=category), [evidence()])
            self.assertTrue(m.recommended_validation, f"no guidance for {category}")

    def test_conclusion_always_says_potential_and_requires_validation(self):
        m = self.builder.build(finding(), [evidence()])
        self.assertIn("otential", m.conclusion)
        self.assertIn("human validation", m.conclusion.lower())

    def test_render_marks_human_validation_required(self):
        rendered = self.builder.build(finding(), [evidence()]).render()
        self.assertIn("Human validation: REQUIRED", rendered)

    def test_serialization_always_sets_human_validation_required(self):
        d = self.builder.build(finding(), [evidence()]).to_dict()
        self.assertTrue(d["human_validation_required"])

    def test_tentative_scanner_confidence_adds_contradicting_note(self):
        m = self.builder.build(finding(confidence=Confidence.TENTATIVE), [evidence()])
        text = " ".join(i.statement for i in m.contradicting)
        self.assertIn("tentative", text.lower())


if __name__ == "__main__":
    unittest.main()
