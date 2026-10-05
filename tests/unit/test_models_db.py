import os
import tempfile
import unittest

from velora.config import load_settings
from velora.database import Database
from velora.database.repository import Repository
from velora.models import Evidence, Finding, Scan, Target
from velora.models.enums import (
    AuthorizationStatus, Confidence, FindingStatus, ScanProfile, Severity,
)


class TestModelsDB(unittest.TestCase):
    def setUp(self):
        os.environ["VELORA_DATA_DIR"] = tempfile.mkdtemp()
        self.settings = load_settings("/nonexistent.yaml")
        self.db = Database(self.settings)
        self.db.init()
        self.repo = Repository(self.db.conn)

    def tearDown(self):
        self.db.close()

    def test_migrations_applied_once(self):
        # Re-init should apply nothing new.
        again = self.db.init()
        self.assertEqual(again, [])

    def test_target_roundtrip_enum(self):
        t = Target(name="Lab", url="http://lab/", authorization_status=AuthorizationStatus.LAB_ONLY)
        self.repo.add_target(t)
        got = self.repo.get_target(t.id)
        self.assertEqual(got.authorization_status, AuthorizationStatus.LAB_ONLY)
        self.assertTrue(got.authorization_status.scannable)

    def test_finding_json_and_enum_roundtrip(self):
        t = Target(name="t", url="http://t/")
        self.repo.add_target(t)
        s = Scan(target_id=t.id, profile=ScanProfile.SAFE)
        self.repo.add_scan(s)
        f = Finding(scan_id=s.id, title="X", severity=Severity.HIGH, confidence=Confidence.FIRM,
                    references=["a", "b"], evidence_ids=["E1"])
        self.repo.add_finding(f)
        got = self.repo.get_finding(f.id)
        self.assertEqual(got.severity, Severity.HIGH)
        self.assertEqual(got.references, ["a", "b"])
        self.assertEqual(got.status, FindingStatus.POTENTIAL)

    def test_evidence_linked_to_finding(self):
        t = Target(name="t2", url="http://t2/")
        self.repo.add_target(t)
        s = Scan(target_id=t.id)
        self.repo.add_scan(s)
        e = Evidence(scan_id=s.id, finding_id="F1", test_name="t", sanitized_excerpt="ok")
        self.repo.add_evidence(e)
        self.assertEqual(len(self.repo.list_evidence_for_finding("F1")), 1)

    def test_audit_is_appendable(self):
        from velora.models import AuditLog
        self.repo.audit(AuditLog(action="x"))
        self.repo.audit(AuditLog(action="y"))
        self.assertGreaterEqual(len(self.repo.list_audit()), 2)


if __name__ == "__main__":
    unittest.main()
