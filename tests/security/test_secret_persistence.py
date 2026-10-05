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


class TestSecretNeverPersisted(unittest.IsolatedAsyncioTestCase):
    async def test_no_raw_secret_in_db_after_scan(self):
        os.environ["VELORA_DATA_DIR"] = tempfile.mkdtemp()
        with LabApp() as app:
            settings = load_settings("/nonexistent.yaml")
            db = Database(settings); db.init(); repo = Repository(db.conn)
            sc = ScopePolicyRecord(allowed_ips=["127.0.0.1"], allowed_ports=[app.port],
                                   allow_private_targets=True, request_delay=0.0)
            repo.add_scope(sc)
            t = Target(name="lab", url=app.base_url + "/",
                       authorization_status=AuthorizationStatus.LAB_ONLY, scope_policy_id=sc.id)
            repo.add_target(t)
            scan = await ScanOrchestrator(settings, db).run_scan(
                t, profile=ScanProfile.LAB, operator="tester", authorization_ack=True)
            # Dump the entire sqlite file and confirm the raw secret never appears.
            db.close()
            with open(settings.database.sqlite_path, "rb") as fh:
                raw = fh.read()
            self.assertNotIn(b"sk_live_ABCDEF0123456789ABCDEF", raw)
            self.assertGreater(scan.stats["findings"], 0)


if __name__ == "__main__":
    unittest.main()
