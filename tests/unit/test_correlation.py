import unittest

from velora.correlation import CorrelationEngine
from velora.models import Finding
from velora.models.enums import Severity


def _f(cat, title):
    return Finding(scan_id="S", title=title, category=cat, severity=Severity.MEDIUM)


class TestCorrelation(unittest.TestCase):
    def test_produces_hypothesis_for_authz_plus_infodisc(self):
        findings = [_f("authorization", "admin reachable"),
                    _f("information_disclosure", "secret leak")]
        corrs = CorrelationEngine().correlate(findings)
        self.assertTrue(any(c.title == "Unauthorized access to sensitive data" for c in corrs))
        self.assertTrue(all(c.hypothesis for c in corrs))

    def test_no_correlation_when_single_category(self):
        corrs = CorrelationEngine().correlate([_f("configuration", "missing header")])
        self.assertEqual(corrs, [])


if __name__ == "__main__":
    unittest.main()
