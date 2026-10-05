import os
import tempfile
import unittest

from labapp import LabApp

from velora.config import load_settings
from velora.core.orchestrator import ScanOrchestrator
from velora.database import Database
from velora.database.repository import Repository
from velora.models import ScopePolicyRecord, Target
from velora.models.enums import AuthorizationStatus, ScanProfile
from velora.utils.errors import AuthorizationError


class TestAuthorizationGate(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        os.environ["VELORA_DATA_DIR"] = tempfile.mkdtemp()
        self.app = LabApp(); self.app.__enter__()
        self.settings = load_settings("/nonexistent.yaml")
        self.db = Database(self.settings); self.db.init(); self.repo = Repository(self.db.conn)
        self.sc = ScopePolicyRecord(allowed_ips=["127.0.0.1"], allowed_ports=[self.app.port],
                                    allow_private_targets=True, request_delay=0.0)
        self.repo.add_scope(self.sc)

    async def asyncTearDown(self):
        self.db.close(); self.app.__exit__(None, None, None)

    async def test_unauthorized_target_refused(self):
        t = Target(name="x", url=self.app.base_url + "/",
                   authorization_status=AuthorizationStatus.UNAUTHORIZED, scope_policy_id=self.sc.id)
        self.repo.add_target(t)
        with self.assertRaises(AuthorizationError):
            await ScanOrchestrator(self.settings, self.db).run_scan(
                t, profile=ScanProfile.SAFE, authorization_ack=True)

    async def test_missing_ack_refused(self):
        t = Target(name="x", url=self.app.base_url + "/",
                   authorization_status=AuthorizationStatus.LAB_ONLY, scope_policy_id=self.sc.id)
        self.repo.add_target(t)
        with self.assertRaises(AuthorizationError):
            await ScanOrchestrator(self.settings, self.db).run_scan(
                t, profile=ScanProfile.SAFE, authorization_ack=False)


if __name__ == "__main__":
    unittest.main()
