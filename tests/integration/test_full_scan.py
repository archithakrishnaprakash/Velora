import os
import tempfile
import unittest

from labapp import LabApp

from velora.config import load_settings
from velora.core.orchestrator import ScanOrchestrator
from velora.database import Database
from velora.database.repository import Repository
from velora.findings.service import FindingService
from velora.models import ScopePolicyRecord, Target
from velora.models.enums import AuthorizationStatus, FindingStatus, ScanProfile, ScanStatus
from velora.reporting import ReportGenerator


class TestFullScan(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        os.environ["VELORA_DATA_DIR"] = tempfile.mkdtemp()
        self.app = LabApp(); self.app.__enter__()
        self.settings = load_settings("/nonexistent.yaml")
        self.db = Database(self.settings); self.db.init(); self.repo = Repository(self.db.conn)
        sc = ScopePolicyRecord(allowed_ips=["127.0.0.1"], allowed_ports=[self.app.port],
                               allow_private_targets=True, request_delay=0.0)
        self.repo.add_scope(sc)
        self.target = Target(name="lab", url=self.app.base_url + "/",
                             authorization_status=AuthorizationStatus.LAB_ONLY, scope_policy_id=sc.id)
        self.repo.add_target(self.target)

    async def asyncTearDown(self):
        self.db.close(); self.app.__exit__(None, None, None)

    async def test_scan_produces_findings_and_graph(self):
        scan = await ScanOrchestrator(self.settings, self.db).run_scan(
            self.target, profile=ScanProfile.LAB, operator="t", authorization_ack=True)
        self.assertEqual(scan.status, ScanStatus.COMPLETED)
        findings = self.repo.list_findings(scan.id)
        self.assertGreaterEqual(len(findings), 5)
        # Every finding starts Potential (never auto-Confirmed).
        self.assertTrue(all(f.status == FindingStatus.POTENTIAL for f in findings))
        # Every finding has at least one evidence record.
        for f in findings:
            self.assertTrue(f.evidence_ids)
        self.assertTrue(self.repo.list_nodes(scan.id))
        self.assertTrue(self.repo.list_edges(scan.id))

    async def test_human_validation_workflow(self):
        scan = await ScanOrchestrator(self.settings, self.db).run_scan(
            self.target, profile=ScanProfile.SAFE, operator="t", authorization_ack=True)
        f = self.repo.list_findings(scan.id)[0]
        svc = FindingService(self.repo)
        svc.validate(f.id, "analyst", "verified")
        self.assertEqual(self.repo.get_finding(f.id).status, FindingStatus.CONFIRMED)
        svc.reject(f.id, "analyst", "actually fine")
        self.assertEqual(self.repo.get_finding(f.id).status, FindingStatus.REJECTED)

    async def test_reports_generated(self):
        scan = await ScanOrchestrator(self.settings, self.db).run_scan(
            self.target, profile=ScanProfile.SAFE, operator="t", authorization_ack=True)
        out = tempfile.mkdtemp()
        rec = ReportGenerator(self.repo, self.settings).generate(scan.id, ["json", "html"], out)
        self.assertIn("json", rec.paths)
        self.assertIn("html", rec.paths)
        self.assertTrue(os.path.getsize(rec.paths["html"]) > 1000)


if __name__ == "__main__":
    unittest.main()
