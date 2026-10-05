import unittest

from velora.models.enums import Confidence, Severity
from velora.risk import PriorityInputs, compute_priority


class TestRisk(unittest.TestCase):
    def test_severity_anchors_band(self):
        info = compute_priority(PriorityInputs(Severity.INFO, Confidence.CERTAIN))
        crit = compute_priority(PriorityInputs(Severity.CRITICAL, Confidence.CERTAIN))
        self.assertLess(info.score, 20)
        self.assertGreaterEqual(crit.score, 80)
        self.assertEqual(info.band, "Informational")
        self.assertEqual(crit.band, "Critical")

    def test_monotonic_in_severity(self):
        scores = [compute_priority(PriorityInputs(s, Confidence.FIRM)).score
                  for s in (Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)]
        self.assertEqual(scores, sorted(scores))

    def test_unauth_increases_score(self):
        auth = compute_priority(PriorityInputs(Severity.HIGH, Confidence.FIRM, unauthenticated=False))
        unauth = compute_priority(PriorityInputs(Severity.HIGH, Confidence.FIRM, unauthenticated=True))
        self.assertGreater(unauth.score, auth.score)

    def test_score_capped(self):
        r = compute_priority(PriorityInputs(Severity.CRITICAL, Confidence.CERTAIN,
                                            exposure=1, asset_importance=1, evidence_quality=1))
        self.assertLessEqual(r.score, 100.0)


if __name__ == "__main__":
    unittest.main()
