"""Benchmark, remediation, regression and posture against the local lab app."""
import os
import tempfile
import unittest

from labapp import LabApp

from velora.benchmark import BenchmarkRunner, LABSHOP_SUITE
from velora.config import load_settings
from velora.core.orchestrator import ScanOrchestrator
from velora.database import Database
from velora.database.repository import Repository
from velora.models.domain import Finding, ScopePolicyRecord, Target
from velora.models.enums import (
    AuthorizationStatus,
    FindingStatus,
    RegressionChange,
    RemediationStatus,
    ScanProfile,
    Severity,
)
from velora.posture import PostureEngine
from velora.regression import RegressionEngine
from velora.remediation import RemediationService


class LifecycleBase(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        os.environ["VELORA_DATA_DIR"] = tempfile.mkdtemp()
        self.app = LabApp()
        self.app.__enter__()
        self.settings = load_settings("/nonexistent.yaml")
        self.db = Database(self.settings)
        self.db.init()
        self.repo = Repository(self.db.conn)
        scope = ScopePolicyRecord(allowed_ips=["127.0.0.1"], allowed_ports=[self.app.port],
                                  allow_private_targets=True, request_delay=0.0)
        self.repo.add_scope(scope)
        self.target = Target(name="lab", url=self.app.base_url + "/",
                             authorization_status=AuthorizationStatus.LAB_ONLY,
                             scope_policy_id=scope.id)
        self.repo.add_target(self.target)
        self.orch = ScanOrchestrator(self.settings, self.db)

    async def asyncTearDown(self):
        self.db.close()
        self.app.__exit__(None, None, None)

    async def scan(self, profile=ScanProfile.SAFE):
        return await self.orch.run_scan(self.target, profile=profile, operator="t",
                                        authorization_ack=True)


class TestBenchmark(LifecycleBase):
    async def test_metrics_are_measured_from_a_real_scan(self):
        scan = await self.scan()
        report = BenchmarkRunner(self.repo).score(LABSHOP_SUITE, scan.id, self.target.url)
        m = report.metrics
        self.assertEqual(len(report.case_results), len(LABSHOP_SUITE.cases))
        self.assertEqual(m.true_positives + m.false_negatives, len(LABSHOP_SUITE.positive_cases))
        self.assertEqual(m.false_positives + m.true_negatives,
                         len(LABSHOP_SUITE.negative_cases))

    async def test_positive_cases_are_detected(self):
        scan = await self.scan()
        report = BenchmarkRunner(self.repo).score(LABSHOP_SUITE, scan.id, self.target.url)
        self.assertGreaterEqual(report.metrics.true_positives, 5)
        self.assertEqual(report.metrics.false_negatives, 0)

    async def test_negative_cases_do_not_fire(self):
        """No false positives on weaknesses the fixture deliberately lacks."""
        scan = await self.scan()
        report = BenchmarkRunner(self.repo).score(LABSHOP_SUITE, scan.id, self.target.url)
        self.assertEqual(report.metrics.false_positives, 0)
        self.assertEqual(report.metrics.true_negatives, len(LABSHOP_SUITE.negative_cases))

    async def test_uncovered_detections_are_not_counted_as_false_positives(self):
        scan = await self.scan()
        report = BenchmarkRunner(self.repo).score(LABSHOP_SUITE, scan.id, self.target.url)
        self.assertGreater(report.metrics.uncovered_detections, 0)
        self.assertEqual(report.metrics.false_positives, 0)

    async def test_ai_agreement_is_none_when_no_ai_ran(self):
        scan = await self.scan()
        report = BenchmarkRunner(self.repo).score(LABSHOP_SUITE, scan.id, self.target.url)
        self.assertIsNone(report.ai_agreement)

    async def test_run_is_persisted_with_measured_values(self):
        scan = await self.scan()
        runner = BenchmarkRunner(self.repo)
        report = runner.score(LABSHOP_SUITE, scan.id, self.target.url)
        run = runner.persist(report)
        stored = self.repo.get_benchmark_run(run.id)
        self.assertEqual(stored.true_positives, report.metrics.true_positives)
        self.assertEqual(stored.precision, report.metrics.precision)


class TestRemediationAndRegression(LifecycleBase):
    async def test_retest_of_unfixed_issue_is_fix_failed(self):
        scan1 = await self.scan()
        finding = self.repo.list_findings(scan1.id)[0]
        service = RemediationService(self.repo)
        service.start(finding.id, owner="dev")
        scan2 = await self.scan()
        result = service.verify_against_scan(finding.id, scan2, operator="qa")
        self.assertEqual(result.verdict, RemediationStatus.FIX_FAILED)
        self.assertTrue(result.still_present)

    async def test_uncovered_endpoint_is_inconclusive_not_verified(self):
        """Absence of detection without coverage must never read as a verified fix."""
        scan1 = await self.scan()
        orphan = Finding(scan_id=scan1.id, title="Synthetic issue",
                         category="configuration", severity=Severity.HIGH,
                         endpoint="http://127.0.0.1:1/never-scanned",
                         scanner="synthetic.check")
        self.repo.add_finding(orphan)
        scan2 = await self.scan()
        result = RemediationService(self.repo).verify_against_scan(orphan.id, scan2)
        self.assertEqual(result.verdict, RemediationStatus.READY_FOR_RETEST)
        self.assertFalse(result.covered)
        self.assertIn("not evidence of a fix", result.detail)

    async def test_lifecycle_transitions_are_recorded(self):
        scan = await self.scan()
        finding = self.repo.list_findings(scan.id)[0]
        service = RemediationService(self.repo)
        service.start(finding.id, owner="dev")
        self.assertEqual(self.repo.get_finding(finding.id).remediation_status,
                         RemediationStatus.REMEDIATION_IN_PROGRESS)
        service.ready_for_retest(finding.id, owner="dev")
        self.assertEqual(self.repo.get_finding(finding.id).remediation_status,
                         RemediationStatus.READY_FOR_RETEST)

    async def test_identical_rescan_reports_everything_persisting(self):
        scan1 = await self.scan()
        scan2 = await self.scan()
        summary = RegressionEngine(self.repo).compare(scan1, scan2)
        counts = summary.counts()
        self.assertEqual(counts.get(RegressionChange.NEW_FINDING.value, 0), 0)
        self.assertEqual(counts.get(RegressionChange.FIXED_FINDING.value, 0), 0)
        self.assertGreater(counts.get(RegressionChange.PERSISTING_FINDING.value, 0), 0)
        self.assertFalse(summary.has_regression)

    async def test_removed_finding_reports_as_fixed_with_a_caveat(self):
        scan1 = await self.scan()
        scan2 = await self.scan()
        # Simulate a fix by rejecting one finding out of the current scan.
        victim = self.repo.list_findings(scan2.id)[0]
        victim.status = FindingStatus.REJECTED
        self.repo.update_finding(victim)
        # Remove it from the comparison by deleting its row's fingerprint match.
        self.repo.conn.execute("DELETE FROM findings WHERE id = ?;", (victim.id,))
        summary = RegressionEngine(self.repo).compare(scan1, scan2)
        fixed = summary.by_change(RegressionChange.FIXED_FINDING)
        self.assertTrue(fixed)
        self.assertIn("not proof of a fix", fixed[0].detail["note"])

    async def test_regression_results_are_persisted(self):
        scan1 = await self.scan()
        scan2 = await self.scan()
        RegressionEngine(self.repo).compare(scan1, scan2)
        self.assertTrue(self.repo.list_regressions(scan2.id))


class TestPosture(LifecycleBase):
    async def test_score_is_bounded_and_explained(self):
        scan = await self.scan()
        result = PostureEngine(self.repo).compute(scan.id)
        self.assertGreaterEqual(result.overall, 0.0)
        self.assertLessEqual(result.overall, 100.0)
        self.assertTrue(result.explanation)
        self.assertIn("not a CVSS score", result.explanation)

    async def test_unassessed_category_is_none_not_full_marks(self):
        scan = await self.scan(ScanProfile.SAFE)
        result = PostureEngine(self.repo).compute(scan.id)
        # The safe profile does not run the reflection check.
        self.assertIsNone(result.categories.get("Input Handling"))

    async def test_contributors_are_traceable_to_findings(self):
        scan = await self.scan()
        result = PostureEngine(self.repo).compute(scan.id)
        ids = {f.id for f in self.repo.list_findings(scan.id)}
        for contributor in result.contributors:
            self.assertIn(contributor["finding_id"], ids)

    async def test_rejected_findings_stop_depressing_the_score(self):
        scan = await self.scan()
        before = PostureEngine(self.repo).compute(scan.id).overall
        for finding in self.repo.list_findings(scan.id):
            finding.status = FindingStatus.REJECTED
            self.repo.update_finding(finding)
        after = PostureEngine(self.repo).compute(scan.id).overall
        self.assertGreater(after, before)

    async def test_snapshot_and_trend(self):
        scan = await self.scan()
        engine = PostureEngine(self.repo)
        engine.snapshot(scan.id, target_id=self.target.id)
        trend = engine.trend(self.target.id)
        self.assertEqual(len(trend), 1)
        self.assertIn("overall", trend[0])


if __name__ == "__main__":
    unittest.main()
