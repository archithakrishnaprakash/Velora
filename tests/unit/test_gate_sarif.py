import json
import os
import tempfile
import unittest

from velora.config import load_settings
from velora.database import Database
from velora.database.repository import Repository
from velora.gate import GatePolicy, SecurityGate
from velora.models.domain import Finding, Scan, Target
from velora.models.enums import (
    AuthorizationStatus,
    FindingStatus,
    GateDecision,
    ScanStatus,
    Severity,
)
from velora.reporting.sarif import build_sarif
from velora.utils.errors import ConfigError


class GateBase(unittest.TestCase):
    def setUp(self):
        os.environ["VELORA_DATA_DIR"] = tempfile.mkdtemp()
        self.settings = load_settings("/nonexistent.yaml")
        self.db = Database(self.settings)
        self.db.init()
        self.repo = Repository(self.db.conn)
        self.target = Target(name="t", url="http://lab.local/",
                             authorization_status=AuthorizationStatus.LAB_ONLY)
        self.repo.add_target(self.target)
        self.scan = Scan(target_id=self.target.id, status=ScanStatus.COMPLETED,
                         operator="t", authorization_ack=True)
        self.repo.add_scan(self.scan)

    def tearDown(self):
        self.db.close()

    def add_finding(self, severity=Severity.HIGH, status=FindingStatus.POTENTIAL,
                    priority=80.0, cvss=None, title="Issue"):
        finding = Finding(scan_id=self.scan.id, title=title, category="configuration",
                          severity=severity, status=status, endpoint="http://lab.local/x",
                          scanner="headers.security_headers", priority_score=priority,
                          cvss_base_score=cvss, fingerprint=f"VF-{title}")
        self.repo.add_finding(finding)
        return finding


class TestGatePolicy(unittest.TestCase):
    def test_exit_codes_are_the_documented_contract(self):
        self.assertEqual(GateDecision.PASS.exit_code, 0)
        self.assertEqual(GateDecision.FAIL.exit_code, 1)
        self.assertEqual(GateDecision.ERROR.exit_code, 2)

    def test_unknown_severity_is_rejected(self):
        with self.assertRaises(ConfigError):
            GatePolicy.from_dict({"gate": {"fail_on": ["nonsense"]}})

    def test_policy_with_no_rules_is_rejected(self):
        with self.assertRaises(ConfigError):
            GatePolicy.from_dict({"gate": {"fail_on_regression": False}})

    def test_non_numeric_threshold_is_rejected(self):
        with self.assertRaises(ConfigError):
            GatePolicy.from_dict({"gate": {"max_cvss": "high"}})

    def test_negative_new_finding_limit_rejected(self):
        with self.assertRaises(ConfigError):
            GatePolicy.from_dict({"gate": {"max_new_findings": -1}})


class TestGateEvaluation(GateBase):
    def test_pass_when_no_violation(self):
        self.add_finding(severity=Severity.LOW, priority=10)
        policy = GatePolicy.from_dict({"gate": {"fail_on": ["critical"]}})
        result = SecurityGate(self.repo).evaluate(self.scan.id, policy)
        self.assertEqual(result.decision, GateDecision.PASS)
        self.assertEqual(result.exit_code, 0)

    def test_fail_on_severity(self):
        self.add_finding(severity=Severity.HIGH)
        policy = GatePolicy.from_dict({"gate": {"fail_on": ["high"]}})
        result = SecurityGate(self.repo).evaluate(self.scan.id, policy)
        self.assertEqual(result.decision, GateDecision.FAIL)
        self.assertEqual(result.exit_code, 1)

    def test_missing_scan_is_error_not_pass(self):
        policy = GatePolicy.from_dict({"gate": {"fail_on": ["high"]}})
        result = SecurityGate(self.repo).evaluate("SCAN-NOPE", policy)
        self.assertEqual(result.decision, GateDecision.ERROR)
        self.assertEqual(result.exit_code, 2)

    def test_incomplete_scan_is_error_not_pass(self):
        self.scan.status = ScanStatus.FAILED
        self.repo.update_scan(self.scan)
        policy = GatePolicy.from_dict({"gate": {"fail_on": ["high"]}})
        result = SecurityGate(self.repo).evaluate(self.scan.id, policy)
        self.assertEqual(result.decision, GateDecision.ERROR)

    def test_max_cvss_only_applies_to_scored_findings(self):
        self.add_finding(severity=Severity.LOW, cvss=None, title="unscored")
        policy = GatePolicy.from_dict({"gate": {"max_cvss": 5.0}})
        self.assertEqual(SecurityGate(self.repo).evaluate(self.scan.id, policy).decision,
                         GateDecision.PASS)
        self.add_finding(severity=Severity.LOW, cvss=9.1, title="scored")
        self.assertEqual(SecurityGate(self.repo).evaluate(self.scan.id, policy).decision,
                         GateDecision.FAIL)

    def test_max_priority_score(self):
        self.add_finding(priority=95.0)
        policy = GatePolicy.from_dict({"gate": {"max_priority_score": 50}})
        self.assertEqual(SecurityGate(self.repo).evaluate(self.scan.id, policy).decision,
                         GateDecision.FAIL)

    def test_rejected_findings_are_excluded(self):
        self.add_finding(severity=Severity.HIGH, status=FindingStatus.REJECTED)
        policy = GatePolicy.from_dict({"gate": {"fail_on": ["high"]}})
        self.assertEqual(SecurityGate(self.repo).evaluate(self.scan.id, policy).decision,
                         GateDecision.PASS)

    def test_ignore_unvalidated_counts_only_confirmed(self):
        self.add_finding(severity=Severity.HIGH, status=FindingStatus.POTENTIAL)
        policy = GatePolicy.from_dict(
            {"gate": {"fail_on": ["high"], "ignore_unvalidated": True}})
        self.assertEqual(SecurityGate(self.repo).evaluate(self.scan.id, policy).decision,
                         GateDecision.PASS)

    def test_unvalidated_findings_count_by_default(self):
        self.add_finding(severity=Severity.HIGH, status=FindingStatus.POTENTIAL)
        policy = GatePolicy.from_dict({"gate": {"fail_on": ["high"]}})
        self.assertEqual(SecurityGate(self.repo).evaluate(self.scan.id, policy).decision,
                         GateDecision.FAIL)

    def test_result_is_persisted(self):
        self.add_finding(severity=Severity.HIGH)
        policy = GatePolicy.from_dict({"gate": {"fail_on": ["high"]}})
        SecurityGate(self.repo).evaluate(self.scan.id, policy)
        self.assertTrue(self.repo.list_gate_results(self.scan.id))


class TestSarif(GateBase):
    def test_document_shape(self):
        self.add_finding()
        doc = build_sarif(self.repo, self.scan.id)
        self.assertEqual(doc["version"], "2.1.0")
        self.assertIn("$schema", doc)
        self.assertEqual(len(doc["runs"]), 1)
        self.assertEqual(doc["runs"][0]["tool"]["driver"]["name"], "Velora")

    def test_no_invented_source_locations(self):
        self.add_finding()
        run = build_sarif(self.repo, self.scan.id)["runs"][0]
        for result in run["results"]:
            physical = result["locations"][0]["physicalLocation"]
            self.assertNotIn("region", physical)
            self.assertTrue(physical["artifactLocation"]["uri"].startswith("http"))

    def test_fingerprint_is_exported_for_tracking(self):
        self.add_finding()
        run = build_sarif(self.repo, self.scan.id)["runs"][0]
        self.assertIn("veloraFingerprint/v1", run["results"][0]["partialFingerprints"])

    def test_validation_state_is_visible_not_hidden(self):
        self.add_finding(status=FindingStatus.POTENTIAL)
        run = build_sarif(self.repo, self.scan.id)["runs"][0]
        result = run["results"][0]
        self.assertIn("[Potential]", result["message"]["text"])
        self.assertIn("requires human validation", result["message"]["text"])

    def test_unscored_cvss_is_reported_as_not_assessed(self):
        self.add_finding(cvss=None)
        run = build_sarif(self.repo, self.scan.id)["runs"][0]
        self.assertEqual(run["results"][0]["properties"]["velora/cvss"], "Not Assessed")

    def test_security_severity_only_from_real_cvss(self):
        self.add_finding(cvss=7.5, title="scored")
        run = build_sarif(self.repo, self.scan.id)["runs"][0]
        scored = next(r for r in run["results"]
                      if r["properties"].get("velora/cvssBaseScore") == 7.5)
        self.assertEqual(scored["properties"]["security-severity"], "7.5")

    def test_rejected_findings_are_suppressed_not_deleted(self):
        self.add_finding(status=FindingStatus.REJECTED, title="rejected")
        run = build_sarif(self.repo, self.scan.id, include_rejected=True)["runs"][0]
        suppressed = [r for r in run["results"] if "suppressions" in r]
        self.assertTrue(suppressed)

    def test_severity_maps_to_sarif_levels(self):
        self.add_finding(severity=Severity.CRITICAL, title="crit")
        self.add_finding(severity=Severity.MEDIUM, title="med")
        self.add_finding(severity=Severity.INFO, title="info")
        run = build_sarif(self.repo, self.scan.id)["runs"][0]
        levels = {r["properties"]["velora/severity"]: r["level"] for r in run["results"]}
        self.assertEqual(levels["Critical"], "error")
        self.assertEqual(levels["Medium"], "warning")
        self.assertEqual(levels["Informational"], "note")

    def test_serializable(self):
        self.add_finding()
        json.dumps(build_sarif(self.repo, self.scan.id))


if __name__ == "__main__":
    unittest.main()


class TestSarifNeverFabricatesScores(GateBase):
    """security-severity reads as CVSS, so it may only come from a real CVSS score."""

    def test_rule_properties_do_not_carry_a_derived_security_severity(self):
        self.add_finding(severity=Severity.CRITICAL, cvss=None)
        run = build_sarif(self.repo, self.scan.id)["runs"][0]
        for rule in run["tool"]["driver"]["rules"]:
            self.assertNotIn("security-severity", rule["properties"])
            self.assertIn("velora/severityRank", rule["properties"])

    def test_result_security_severity_is_absent_without_cvss(self):
        self.add_finding(cvss=None)
        run = build_sarif(self.repo, self.scan.id)["runs"][0]
        self.assertNotIn("security-severity", run["results"][0]["properties"])

    def test_result_security_severity_equals_the_real_cvss_score(self):
        self.add_finding(cvss=8.2, title="scored")
        run = build_sarif(self.repo, self.scan.id)["runs"][0]
        scored = next(r for r in run["results"]
                      if r["properties"].get("velora/cvssBaseScore") == 8.2)
        self.assertEqual(scored["properties"]["security-severity"], "8.2")


class TestGateErrorsAreRecorded(GateBase):
    """An ERROR is the outcome a pipeline most needs to look up later."""

    def test_missing_scan_error_is_persisted_and_audited(self):
        policy = GatePolicy.from_dict({"gate": {"fail_on": ["high"]}})
        SecurityGate(self.repo).evaluate("SCAN-NOPE", policy)
        stored = self.repo.list_gate_results("SCAN-NOPE")
        self.assertTrue(stored)
        self.assertEqual(stored[-1].decision, GateDecision.ERROR)
        actions = {entry.action for entry in self.repo.list_audit()}
        self.assertIn("security_gate_error", actions)

    def test_incomplete_scan_error_is_persisted(self):
        self.scan.status = ScanStatus.FAILED
        self.repo.update_scan(self.scan)
        policy = GatePolicy.from_dict({"gate": {"fail_on": ["high"]}})
        SecurityGate(self.repo).evaluate(self.scan.id, policy)
        stored = self.repo.list_gate_results(self.scan.id)
        self.assertEqual(stored[-1].decision, GateDecision.ERROR)
        self.assertIn("not 'completed'", stored[-1].summary)

    def test_persist_false_still_records_nothing(self):
        policy = GatePolicy.from_dict({"gate": {"fail_on": ["high"]}})
        SecurityGate(self.repo).evaluate("SCAN-NOPE2", policy, persist=False)
        self.assertEqual(self.repo.list_gate_results("SCAN-NOPE2"), [])
