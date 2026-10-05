import unittest

from velora.knowledge import UNKNOWN, assess, base_score, mapping_for_check, parse_vector
from velora.knowledge.cvss import InvalidVectorError, severity_for


class TestCVSS(unittest.TestCase):
    """Reference vectors from the CVSS v3.1 specification."""

    KNOWN = [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "Critical"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "Critical"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "High"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "None"),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", 4.3, "Medium"),
    ]

    def test_known_vectors_score_correctly(self):
        for vector, expected, severity in self.KNOWN:
            self.assertAlmostEqual(base_score(vector), expected, places=9, msg=vector)
            self.assertEqual(severity_for(base_score(vector)), severity)

    def test_scope_changed_raises_score(self):
        unchanged = base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        changed = base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        self.assertGreater(changed, unchanged)

    def test_zero_impact_is_zero_regardless_of_exploitability(self):
        self.assertEqual(base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"), 0.0)

    def test_scores_are_bounded(self):
        for vector, _, _ in self.KNOWN:
            score = base_score(vector)
            self.assertGreaterEqual(score, 0.0)
            self.assertLessEqual(score, 10.0)

    def test_malformed_vectors_rejected(self):
        for bad in ("garbage", "CVSS:2.0/AV:N", "CVSS:3.1/AV:N/AC:L",
                    "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"):
            with self.assertRaises(InvalidVectorError, msg=bad):
                parse_vector(bad)

    def test_assess_never_guesses(self):
        """No vector => Not Assessed, never a fabricated score."""
        for bad in (None, "", "garbage", "CVSS:3.1/AV:N/AC:L"):
            result = assess(bad)
            self.assertFalse(result.assessed)
            self.assertIsNone(result.base_score)
            self.assertEqual(result.to_dict()["status"], "Not Assessed")

    def test_assess_valid_vector(self):
        result = assess("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", source="manual")
        self.assertTrue(result.assessed)
        self.assertEqual(result.base_score, 7.5)
        self.assertEqual(result.severity, "High")
        self.assertEqual(result.version, "3.1")


class TestCatalog(unittest.TestCase):
    def test_known_checks_have_verified_mappings(self):
        expected = {
            "headers.security_headers": ("CWE-693", "A05:2021"),
            "cookies.attributes": ("CWE-1004", "A05:2021"),
            "tls.configuration": ("CWE-326", "A02:2021"),
            "auth.indicators": ("CWE-319", "A02:2021"),
            "input.reflection": ("CWE-79", "A03:2021"),
            "config.directory_exposure": ("CWE-548", "A05:2021"),
        }
        for check, (cwe, owasp) in expected.items():
            mapping = mapping_for_check(check)
            self.assertEqual(mapping.cwe_id, cwe, check)
            self.assertEqual(mapping.owasp, owasp, check)

    def test_unmappable_check_reports_unknown_not_a_guess(self):
        mapping = mapping_for_check("config.security_txt")
        self.assertEqual(mapping.cwe_id, UNKNOWN)
        self.assertEqual(mapping.owasp, UNKNOWN)
        self.assertIn("No CWE or OWASP category is claimed", mapping.note)

    def test_unknown_check_id_yields_unknown(self):
        mapping = mapping_for_check("does.not.exist")
        self.assertEqual(mapping.cwe_id, UNKNOWN)

    def test_reflection_mapping_is_documented_as_not_proof(self):
        self.assertIn("not proof of it", mapping_for_check("input.reflection").note)

    def test_every_referenced_cwe_exists_in_the_catalog(self):
        from velora.knowledge.catalog import CHECK_MAPPINGS, CWE

        for check, mapping in CHECK_MAPPINGS.items():
            if mapping.cwe_id != UNKNOWN:
                self.assertIn(mapping.cwe_id, CWE, f"{check} references an uncatalogued CWE")
            for alt in mapping.alternates:
                self.assertIn(alt, CWE, f"{check} alternate {alt} is uncatalogued")

    def test_every_referenced_owasp_exists_in_the_catalog(self):
        from velora.knowledge.catalog import CHECK_MAPPINGS, OWASP

        for check, mapping in CHECK_MAPPINGS.items():
            if mapping.owasp != UNKNOWN:
                self.assertIn(mapping.owasp, OWASP, f"{check} references an unknown category")


if __name__ == "__main__":
    unittest.main()
