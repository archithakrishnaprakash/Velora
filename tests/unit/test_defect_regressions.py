"""Regression tests for defects found during the 2.0 documentation audit.

Each test pins one behaviour that was wrong and is now fixed. They are grouped here,
rather than scattered, so the reason each assertion exists stays visible.
"""
import os
import tempfile
import unittest

from velora.config import load_settings
from velora.core.http import HttpResponse
from velora.database import Database
from velora.database.repository import Repository
from velora.differential.engine import DifferentialEngine
from velora.differential.fingerprint import _parse_cookies, fingerprint_response
from velora.findings import fingerprint as fp
from velora.findings.service import FindingService
from velora.models.domain import (
    Finding,
    RegressionResult,
    RemediationAction,
    Scan,
    SecurityPostureSnapshot,
    Target,
)
from velora.models.enums import (
    AuthorizationStatus,
    FindingStatus,
    RegressionChange,
    RemediationStatus,
    ScanStatus,
    Severity,
    ValidationState,
)
from velora.posture import band_for
from velora.posture.engine import PostureEngine


def response(status=200, headers=None, body="<html>hi</html>"):
    return HttpResponse(
        url="http://lab.local/x", final_url="http://lab.local/x", method="GET",
        status_code=status, headers=headers or {"content-type": "text/html"},
        content_type="text/html", body=body, response_size=len(body), elapsed_ms=5.0)


class TestDifferentialDoesNotOverclaim(unittest.TestCase):
    """`indicates_access_change` used to fire on any status change at all."""

    def setUp(self):
        self.engine = DifferentialEngine()

    def compare(self, a, b):
        return self.engine.compare(fingerprint_response(response(a)),
                                   fingerprint_response(response(b)))

    def test_a_server_error_is_not_an_access_boundary_crossing(self):
        result = self.compare(200, 500)
        self.assertFalse(result.indicates_access_change)
        self.assertNotIn("crossed an allow/deny boundary", result.interpretation)

    def test_a_real_allow_deny_crossing_still_reports_one(self):
        for a, b in ((403, 200), (200, 403), (401, 200)):
            with self.subTest(transition=f"{a}->{b}"):
                result = self.compare(a, b)
                self.assertTrue(result.indicates_access_change)
                self.assertIn("crossed an allow/deny boundary", result.interpretation)

    def test_access_adjacent_changes_are_mentioned_without_being_claimed(self):
        result = self.compare(200, 500)
        self.assertTrue(result.has_access_adjacent_change)
        self.assertIn("does not indicate an authorization difference",
                      result.interpretation)

    def test_purely_structural_differences_claim_nothing(self):
        a = fingerprint_response(response(200, body="<html><p>one</p></html>"))
        b = fingerprint_response(response(200, body="<html><p>one</p><p>two</p></html>"))
        result = self.engine.compare(a, b)
        self.assertFalse(result.indicates_access_change)


class TestCookieParsing(unittest.TestCase):
    """Repeated Set-Cookie headers arrive joined; the second name was being lost."""

    def test_two_cookies_joined_with_a_comma_are_parsed_separately(self):
        names, flags = _parse_cookies("a=1; HttpOnly, b=2; Secure")
        self.assertEqual(names, ["a", "b"])
        self.assertEqual(flags["a"], ["httponly"])
        self.assertEqual(flags["b"], ["secure"])

    def test_a_comma_inside_an_expires_attribute_is_not_a_separator(self):
        names, flags = _parse_cookies(
            "sid=x; Expires=Wed, 21 Oct 2026 07:28:00 GMT; HttpOnly")
        self.assertEqual(names, ["sid"])
        self.assertIn("httponly", flags["sid"])

    def test_a_single_cookie_is_unchanged(self):
        self.assertEqual(_parse_cookies("only=1; Secure")[0], ["only"])

    def test_a_cookie_swap_between_responses_is_now_visible(self):
        a = fingerprint_response(response(headers={"set-cookie": "a=1; HttpOnly, b=2"}))
        b = fingerprint_response(response(headers={"set-cookie": "a=1; HttpOnly, c=3"}))
        self.assertNotEqual(a.cookie_names, b.cookie_names)


class TestPostureBandsAgree(unittest.TestCase):
    """The CLI and the dashboard used two different sets of thresholds."""

    def test_one_band_function_is_the_source_of_truth(self):
        self.assertEqual(band_for(95), "Strong")
        self.assertEqual(band_for(87), "Adequate")
        self.assertEqual(band_for(60), "Weak")
        self.assertEqual(band_for(20), "Poor")

    def test_an_unscored_posture_is_not_assessed_not_poor(self):
        self.assertEqual(band_for(None), "Not Assessed")

    def test_the_dashboard_uses_the_same_function(self):
        import velora.api.app as app_module
        self.assertIs(app_module.band_for, band_for)

    def test_boundaries_are_inclusive_as_documented(self):
        self.assertEqual(band_for(90), "Strong")
        self.assertEqual(band_for(89.9), "Adequate")
        self.assertEqual(band_for(75), "Adequate")
        self.assertEqual(band_for(55), "Weak")


class DbBase(unittest.TestCase):
    def setUp(self):
        os.environ["VELORA_DATA_DIR"] = tempfile.mkdtemp()
        self.settings = load_settings("/nonexistent.yaml")
        self.db = Database(self.settings)
        self.db.init()
        self.repo = Repository(self.db.conn)
        self.target = Target(name="t", url="http://lab.local/",
                             authorization_status=AuthorizationStatus.LAB_ONLY)
        self.repo.add_target(self.target)
        self.scan = Scan(target_id=self.target.id, status=ScanStatus.COMPLETED)
        self.repo.add_scan(self.scan)

    def tearDown(self):
        self.db.close()

    def finding(self, **kw):
        defaults = dict(scan_id=self.scan.id, title="Issue", category="configuration",
                        severity=Severity.MEDIUM, endpoint="http://lab.local/x",
                        scanner="headers.security_headers")
        defaults.update(kw)
        f = Finding(**defaults)
        self.repo.add_finding(f)
        return f


class TestValidationStateIsRecorded(DbBase):
    """Confirming a finding never moved it to VALIDATED."""

    def test_confirming_a_finding_sets_the_validated_state(self):
        f = self.finding()
        self.assertEqual(f.validation_state, ValidationState.OBSERVED)
        FindingService(self.repo).validate(f.id, operator="alice", note="reproduced")
        reloaded = self.repo.get_finding(f.id)
        self.assertEqual(reloaded.status, FindingStatus.CONFIRMED)
        self.assertEqual(reloaded.validation_state, ValidationState.VALIDATED)

    def test_rejecting_a_finding_moves_the_state_to_unknown(self):
        f = self.finding()
        FindingService(self.repo).reject(f.id, operator="alice", note="false positive")
        self.assertEqual(self.repo.get_finding(f.id).validation_state,
                         ValidationState.UNKNOWN)

    def test_validated_is_a_fact_state(self):
        self.assertTrue(ValidationState.VALIDATED.is_fact)


class TestRejectedFindingsLeaveTheComparison(DbBase):
    """A rejected finding was still reported as PERSISTING on every later scan."""

    def test_rejected_findings_are_excluded_from_the_fingerprint_index(self):
        live = self.finding(title="live")
        rejected = self.finding(title="rejected", status=FindingStatus.REJECTED)
        index = fp.index_by_fingerprint([live, rejected])
        self.assertIn(fp.ensure(live), index)
        self.assertNotIn(fp.ensure(rejected), index)

    def test_rejected_findings_can_still_be_included_explicitly(self):
        rejected = self.finding(title="rejected", status=FindingStatus.REJECTED)
        index = fp.index_by_fingerprint([rejected], include_rejected=True)
        self.assertIn(fp.ensure(rejected), index)

    def test_the_fingerprint_still_ignores_severity(self):
        low = Finding(scan_id=self.scan.id, title="Issue", category="configuration",
                      severity=Severity.LOW, endpoint="http://lab.local/x",
                      scanner="headers.security_headers")
        high = Finding(scan_id=self.scan.id, title="Issue", category="configuration",
                       severity=Severity.HIGH, endpoint="http://lab.local/x",
                       scanner="headers.security_headers")
        self.assertEqual(fp.compute(low), fp.compute(high))


class TestPostureSnapshotKeepsUnassessed(DbBase):
    """Persisted snapshots silently dropped the categories that were not assessed."""

    def test_unassessed_categories_survive_persistence_as_none(self):
        snap = SecurityPostureSnapshot(
            scan_id=self.scan.id,
            categories={"transport security": 90.0, "authorization": None})
        self.repo.add_posture(snap)
        reloaded = self.repo.list_postures()[-1]
        self.assertIn("authorization", reloaded.categories)
        self.assertIsNone(reloaded.categories["authorization"])

    def test_an_unassessed_category_is_not_stored_as_zero(self):
        snap = SecurityPostureSnapshot(scan_id=self.scan.id,
                                       categories={"authorization": None})
        self.repo.add_posture(snap)
        self.assertNotEqual(self.repo.list_postures()[-1].categories["authorization"], 0.0)


class TestRemediationCreditIsScoped(DbBase):
    """The credit was computed over every remediation in the database."""

    def test_credit_ignores_remediations_for_other_scans(self):
        other_scan = Scan(target_id=self.target.id, status=ScanStatus.COMPLETED)
        self.repo.add_scan(other_scan)
        other_finding = Finding(scan_id=other_scan.id, title="elsewhere",
                                category="configuration", severity=Severity.HIGH,
                                endpoint="http://lab.local/y", scanner="s")
        self.repo.add_finding(other_finding)
        self.repo.add_remediation(RemediationAction(
            finding_id=other_finding.id, status=RemediationStatus.FIX_VERIFIED))

        self.finding()   # this scan has a finding with no verified fix
        engine = PostureEngine(self.repo)
        self.assertEqual(engine._remediation_credit(self.scan.id), 0.0)

    def test_credit_counts_a_verified_fix_for_this_scan(self):
        f = self.finding()
        self.repo.add_remediation(RemediationAction(
            finding_id=f.id, status=RemediationStatus.FIX_VERIFIED))
        self.assertGreater(PostureEngine(self.repo)._remediation_credit(self.scan.id), 0.0)


class TestCorruptJsonColumn(DbBase):
    """A damaged JSON column made the whole row unreadable."""

    def test_a_corrupt_column_falls_back_to_the_field_default(self):
        self.db.conn.execute("UPDATE scans SET stats = ? WHERE id = ?;",
                             ("{not json", self.scan.id))
        reloaded = self.repo.get_scan(self.scan.id)
        self.assertIsNotNone(reloaded)
        self.assertEqual(reloaded.stats, {})
        self.assertEqual(reloaded.id, self.scan.id)


if __name__ == "__main__":
    unittest.main()
