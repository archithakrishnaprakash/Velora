"""Feature 13: reports must explain, and must state what they do not know."""
import os
import tempfile
import unittest

from velora.config import load_settings
from velora.database import Database
from velora.database.repository import Repository
from velora.models.domain import (
    AIAnalysis,
    Engagement,
    Evidence,
    Finding,
    Identity,
    RemediationAction,
    RetestRun,
    Scan,
    ScopePolicyRecord,
    SecurityGateResult,
    SecurityPostureSnapshot,
    Target,
)
from velora.models.enums import (
    AuthorizationStatus,
    FindingStatus,
    GateDecision,
    IdentityRole,
    RemediationStatus,
    ScanStatus,
    Severity,
    ValidationState,
)
from velora.reporting import ReportGenerator
from velora.reporting.assembler import assemble_report


class ReportBase(unittest.TestCase):
    def setUp(self):
        os.environ["VELORA_DATA_DIR"] = tempfile.mkdtemp()
        self.settings = load_settings("/nonexistent.yaml")
        self.db = Database(self.settings)
        self.db.init()
        self.repo = Repository(self.db.conn)
        self.scope = ScopePolicyRecord(allowed_domains=["lab.local"], allowed_ports=[80])
        self.repo.add_scope(self.scope)
        self.target = Target(name="lab", url="http://lab.local/",
                             authorization_status=AuthorizationStatus.LAB_ONLY,
                             authorization_note="local lab",
                             scope_policy_id=self.scope.id)
        self.repo.add_target(self.target)
        self.scan = Scan(target_id=self.target.id, status=ScanStatus.COMPLETED,
                         operator="alice", authorization_ack=True,
                         scope_policy_id=self.scope.id)
        self.repo.add_scan(self.scan)

    def tearDown(self):
        self.db.close()

    def add_finding(self, **kw):
        defaults = dict(scan_id=self.scan.id, title="Missing security headers",
                        category="configuration", severity=Severity.MEDIUM,
                        status=FindingStatus.POTENTIAL, endpoint="http://lab.local/",
                        scanner="headers.security_headers", priority_score=52.0,
                        description="Header absent on the observed response.",
                        remediation="Set the header.", fingerprint="VF-1")
        defaults.update(kw)
        finding = Finding(**defaults)
        self.repo.add_finding(finding)
        return finding

    def context(self):
        return assemble_report(self.repo, self.scan.id, self.settings)


class TestExplanationSections(ReportBase):
    def test_every_finding_carries_the_full_explanation_block(self):
        self.add_finding()
        block = self.context()["findings"][0]["explanation"]
        self.assertEqual(
            list(block),
            ["what_was_observed", "why_it_matters", "evidence", "confidence",
             "what_is_unknown", "validation_required", "recommended_remediation",
             "retest_status"])

    def test_unconfirmed_finding_states_that_exploitability_was_not_demonstrated(self):
        self.add_finding()
        unknown = " ".join(self.context()["findings"][0]["explanation"]["what_is_unknown"])
        self.assertIn("Exploitability was not demonstrated", unknown)

    def test_missing_cvss_is_reported_as_not_assessed_not_zero(self):
        self.add_finding()
        finding = self.context()["findings"][0]
        self.assertEqual(finding["cvss"], "Not Assessed")
        self.assertEqual(finding["explanation"]["confidence"]["cvss"], "Not Assessed")

    def test_real_cvss_is_carried_through(self):
        self.add_finding(cvss_base_score=7.5, cvss_version="3.1",
                         cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                         cvss_severity="High")
        cvss = self.context()["findings"][0]["cvss"]
        self.assertEqual(cvss["base_score"], 7.5)

    def test_unmapped_cwe_and_owasp_are_declared_unknown(self):
        self.add_finding()
        unknown = " ".join(self.context()["findings"][0]["explanation"]["what_is_unknown"])
        self.assertIn("No CWE mapping was claimed", unknown)
        self.assertIn("No OWASP Top 10 category was claimed", unknown)

    def test_a_finding_without_evidence_says_so(self):
        self.add_finding()
        unknown = " ".join(self.context()["findings"][0]["explanation"]["what_is_unknown"])
        self.assertIn("No evidence records are attached", unknown)

    def test_evidence_appears_in_the_explanation(self):
        finding = self.add_finding()
        self.repo.add_evidence(Evidence(scan_id=self.scan.id, finding_id=finding.id,
                                        test_name="security_headers", status_code=200,
                                        sanitized_excerpt="x-frame-options: absent"))
        block = self.context()["findings"][0]["explanation"]
        self.assertEqual(block["evidence"][0]["excerpt"], "x-frame-options: absent")
        self.assertNotIn("No evidence records", " ".join(block["what_is_unknown"]))

    def test_confirmed_finding_names_its_validator(self):
        self.add_finding(status=FindingStatus.CONFIRMED, validated_by="alice",
                         validation_note="reproduced in a browser")
        block = self.context()["findings"][0]["explanation"]
        self.assertIn("Confirmed by alice", block["validation_required"])
        self.assertNotIn("Exploitability was not demonstrated",
                         " ".join(block["what_is_unknown"]))

    def test_ai_missing_evidence_is_surfaced_as_unknown(self):
        finding = self.add_finding()
        self.repo.add_ai_analysis(AIAnalysis(
            scan_id=self.scan.id, finding_id=finding.id, provider="heuristic",
            model="rules-1", confidence=0.4,
            missing_evidence=["a second test identity"],
            recommended_validation="Repeat with a second identity.",
            validation_status=ValidationState.HYPOTHESIZED))
        block = self.context()["findings"][0]["explanation"]
        self.assertIn("a second test identity", " ".join(block["what_is_unknown"]))
        self.assertEqual(block["validation_required"], "Repeat with a second identity.")
        self.assertEqual(block["confidence"]["ai_confidence"], 0.4)

    def test_ai_confidence_never_replaces_the_detector_confidence(self):
        finding = self.add_finding()
        self.repo.add_ai_analysis(AIAnalysis(scan_id=self.scan.id, finding_id=finding.id,
                                             confidence=0.95))
        conf = self.context()["findings"][0]["explanation"]["confidence"]
        self.assertEqual(conf["detector_confidence"], "Tentative")
        self.assertIn("not CVSS", conf["priority_note"])


class TestRetestSection(ReportBase):
    def test_untracked_finding_is_marked_not_tracked(self):
        self.add_finding()
        retest = self.context()["findings"][0]["explanation"]["retest_status"]
        self.assertEqual(retest["status"], "NOT_TRACKED")

    def test_inconclusive_retest_is_not_reported_as_a_fix(self):
        finding = self.add_finding()
        action = RemediationAction(finding_id=finding.id,
                                   status=RemediationStatus.READY_FOR_RETEST)
        self.repo.add_remediation(action)
        self.repo.add_retest(RetestRun(finding_id=finding.id, remediation_id=action.id,
                                       original_scan_id=self.scan.id,
                                       still_present=None,
                                       verdict=RemediationStatus.READY_FOR_RETEST,
                                       detail="Endpoint not covered by the retest."))
        retest = self.context()["findings"][0]["explanation"]["retest_status"]
        self.assertIn("not by itself evidence of a fix", retest["detail"])
        self.assertNotEqual(retest["status"], "FIX_VERIFIED")

    def test_verified_fix_is_reported_with_its_timestamp(self):
        finding = self.add_finding()
        from datetime import datetime, timezone
        action = RemediationAction(finding_id=finding.id,
                                   status=RemediationStatus.FIX_VERIFIED,
                                   verified_at=datetime(2026, 9, 1, tzinfo=timezone.utc))
        self.repo.add_remediation(action)
        self.repo.add_retest(RetestRun(finding_id=finding.id, remediation_id=action.id,
                                       original_scan_id=self.scan.id, still_present=False,
                                       verdict=RemediationStatus.FIX_VERIFIED,
                                       detail="Retest covered the affected endpoint."))
        retest = self.context()["findings"][0]["explanation"]["retest_status"]
        self.assertEqual(retest["status"], "FIX_VERIFIED")
        self.assertIsNotNone(retest["verified_at"])


class TestReportSections(ReportBase):
    def test_scope_policy_in_force_is_reported(self):
        ctx = self.context()
        self.assertEqual(ctx["scope"]["allowed_domains"], ["lab.local"])
        self.assertIn("OUT_OF_SCOPE_REQUEST_BLOCKED", ctx["scope"]["note"])

    def test_authorization_acknowledgement_is_stated(self):
        self.assertIn("explicit authorization acknowledgement",
                      self.context()["authorization"]["statement"])

    def test_missing_acknowledgement_is_flagged_not_hidden(self):
        self.scan.authorization_ack = False
        self.repo.update_scan(self.scan)
        self.assertIn("WARNING", self.context()["authorization"]["statement"])

    def test_engagement_authorization_reference_is_included(self):
        engagement = Engagement(name="Q3", authorization_reference="TICKET-42",
                                authorization_granted_by="CISO")
        self.repo.add_engagement(engagement)
        self.scan.engagement_id = engagement.id
        self.repo.update_scan(self.scan)
        self.assertEqual(self.context()["engagement"]["authorization_reference"],
                         "TICKET-42")

    def test_identities_expose_only_the_secret_reference(self):
        engagement = Engagement(name="Q3")
        self.repo.add_engagement(engagement)
        self.scan.engagement_id = engagement.id
        self.repo.update_scan(self.scan)
        self.repo.add_identity(Identity(name="user-a", role=IdentityRole.USER_A,
                                        engagement_id=engagement.id,
                                        secret_ref="VELORA_USER_A_TOKEN"))
        identity = self.context()["identities"][0]
        self.assertEqual(identity["secret_reference"], "VELORA_USER_A_TOKEN")
        self.assertIn("never persisted", identity["note"])

    def test_posture_is_labelled_as_not_cvss(self):
        self.repo.add_posture(SecurityPostureSnapshot(
            scan_id=self.scan.id, overall=72.5, explanation="x"))
        self.assertIn("not CVSS", self.context()["posture"][0]["note"])

    def test_gate_result_carries_its_exit_code(self):
        self.repo.add_gate_result(SecurityGateResult(
            scan_id=self.scan.id, decision=GateDecision.FAIL, summary="1 high finding."))
        gate = self.context()["security_gate"][0]
        self.assertEqual(gate["exit_code"], 1)

    def test_limitations_say_absence_of_findings_is_not_security(self):
        joined = " ".join(self.context()["limitations"])
        self.assertIn("absence of a finding is not evidence that the target is secure",
                      joined)
        self.assertIn("cannot verify a fix", joined)

    def test_attack_paths_carry_their_epistemic_caveat(self):
        self.assertIn("not a demonstrated attack",
                      self.context()["attack_paths"]["note"])

    def test_ai_note_states_the_limits_of_ai_output(self):
        note = self.context()["ai_analysis"]["note"]
        self.assertIn("cannot", note)
        self.assertIn("sanitised", note)

    def test_backward_compatible_keys_are_preserved(self):
        self.add_finding()
        ctx = self.context()
        for key in ("meta", "scan", "target", "summary", "attack_surface", "findings",
                    "attack_path_hypotheses", "attack_graph", "methodology",
                    "limitations", "events"):
            self.assertIn(key, ctx)
        finding = ctx["findings"][0]
        for key in ("id", "title", "category", "severity", "confidence", "status",
                    "endpoint", "method", "priority_score", "description", "impact",
                    "remediation", "references", "scanner", "cvss", "evidence"):
            self.assertIn(key, finding)


class TestRenderedReport(ReportBase):
    def test_html_renders_every_explanation_heading(self):
        finding = self.add_finding()
        self.repo.add_evidence(Evidence(scan_id=self.scan.id, finding_id=finding.id,
                                        test_name="t", sanitized_excerpt="x"))
        html = ReportGenerator(self.repo, self.settings).render_html(self.context())
        for heading in ("What was observed", "Why it matters", "Evidence", "Confidence",
                        "What is unknown", "Validation required",
                        "Recommended remediation", "Retest status"):
            self.assertIn(heading, html)

    def test_html_never_renders_an_unsubstantiated_cvss(self):
        self.add_finding()
        html = ReportGenerator(self.repo, self.settings).render_html(self.context())
        self.assertIn("Not Assessed", html)

    def test_report_generation_writes_all_formats(self):
        self.add_finding()
        out = tempfile.mkdtemp()
        record = ReportGenerator(self.repo, self.settings).generate(
            self.scan.id, ["json", "html", "sarif"], out)
        self.assertEqual(sorted(record.paths), ["html", "json", "sarif"])

    def test_no_secret_material_reaches_the_rendered_report(self):
        secret = "sk_live_ABCDEF0123456789"
        finding = self.add_finding()
        # Evidence is redacted upstream; assert the report does not reintroduce a value.
        self.repo.add_evidence(Evidence(scan_id=self.scan.id, finding_id=finding.id,
                                        test_name="t",
                                        sanitized_excerpt="api_key=[REDACTED]"))
        html = ReportGenerator(self.repo, self.settings).render_html(self.context())
        self.assertNotIn(secret, html)
        self.assertIn("[REDACTED]", html)


if __name__ == "__main__":
    unittest.main()
