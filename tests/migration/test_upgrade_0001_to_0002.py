"""Migration tests: a real 0.1.0 database must upgrade without data loss."""
import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from velora.config import load_settings
from velora.database import Database
from velora.database.columns import ensure_columns, existing_columns
from velora.database.repository import Repository
from velora.models import Engagement, Identity, IdentityRole

MIGRATIONS = Path(__file__).resolve().parents[2] / "velora" / "database" / "migrations"


def build_legacy_db(path: Path) -> None:
    """Create a database at the 0.1.0 schema level (migration 0001 only)."""
    conn = sqlite3.connect(str(path), isolation_level=None)
    conn.executescript((MIGRATIONS / "0001_initial.sql").read_text())
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations "
        "(version TEXT PRIMARY KEY, applied_at TEXT NOT NULL);"
    )
    now = datetime.now(timezone.utc).isoformat()
    conn.execute("INSERT INTO schema_migrations VALUES ('0001_initial', ?);", (now,))
    conn.execute(
        "INSERT INTO targets (id,name,url,description,owner,authorization_status,"
        "authorization_note,created_at,updated_at) VALUES "
        "('TGT-L','Legacy','http://legacy.local/','','op','LAB_ONLY','',?,?);", (now, now))
    conn.execute(
        "INSERT INTO scans (id,target_id,profile,status,operator,authorization_ack,stats,"
        "created_at) VALUES ('SCAN-L','TGT-L','safe','completed','op',1,'{}',?);", (now,))
    conn.execute(
        "INSERT INTO findings (id,scan_id,title,description,category,severity,confidence,"
        "status,endpoint,method,evidence_ids,references_json,impact,remediation,scanner,"
        "created_at,updated_at) VALUES ('WEB-L','SCAN-L','Legacy finding','d','configuration',"
        "'High','Firm','Confirmed','http://legacy.local/','GET','[\"EV-1\"]','[]','i','r',"
        "'headers',?,?);", (now, now))
    conn.execute(
        "INSERT INTO attack_graph_nodes (id,scan_id,kind,label,attributes) VALUES "
        "('NODE-L','SCAN-L','Endpoint','/legacy','{}');")
    conn.execute(
        "INSERT INTO attack_graph_edges (id,scan_id,source_id,target_id,relation,attributes,"
        "hypothesis) VALUES ('EDGE-L','SCAN-L','NODE-L','NODE-L','LEADS_TO','{}',1);")
    conn.close()


class TestUpgradeMigration(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        os.environ["VELORA_DATA_DIR"] = str(self.dir)
        self.db_path = self.dir / "legacy.db"
        build_legacy_db(self.db_path)
        self.settings = load_settings("/nonexistent.yaml")
        self.settings.database.url = f"sqlite:///{self.db_path}"
        self.db = Database(self.settings)

    def tearDown(self):
        self.db.close()

    def test_0002_applies_to_legacy_db(self):
        applied = self.db.init()
        self.assertIn("0002_v2", applied)

    def test_legacy_rows_survive_and_read_through_new_models(self):
        self.db.init()
        repo = Repository(self.db.conn)
        target = repo.get_target("TGT-L")
        finding = repo.get_finding("WEB-L")
        self.assertIsNotNone(target)
        self.assertEqual(target.name, "Legacy")
        self.assertEqual(finding.title, "Legacy finding")
        self.assertEqual(finding.status.value, "Confirmed")
        # New columns take their model defaults, not None.
        self.assertEqual(finding.cwe_id, "UNKNOWN")
        self.assertEqual(finding.remediation_status.value, "OPEN")
        self.assertIsNone(target.engagement_id)

    def test_null_added_columns_fall_back_to_model_defaults(self):
        """A non-Optional field whose column is NULL must use the model default."""
        self.db.init()
        repo = Repository(self.db.conn)
        node = repo.list_nodes("SCAN-L")[0]
        edge = repo.list_edges("SCAN-L")[0]
        self.assertIsNotNone(node.created_at)      # backfilled
        self.assertIsNotNone(edge.created_at)
        self.assertEqual(node.validation_status.value, "OBSERVED")
        self.assertEqual(edge.validation_status.value, "INFERRED")
        self.assertTrue(edge.hypothesis)            # legacy semantics preserved

    def test_new_tables_created_and_writable(self):
        self.db.init()
        repo = Repository(self.db.conn)
        eng = Engagement(name="E1")
        repo.add_engagement(eng)
        repo.add_identity(Identity(engagement_id=eng.id, name="a", role=IdentityRole.USER_A,
                                   secret_ref="VELORA_X"))
        self.assertEqual(repo.get_engagement(eng.id).name, "E1")
        self.assertEqual(len(repo.list_identities(eng.id)), 1)

    def test_migration_is_idempotent(self):
        self.db.init()
        self.assertEqual(self.db.init(), [])
        # ensure_columns can also be re-run safely on its own.
        self.assertEqual(ensure_columns(self.db.conn), [])

    def test_no_table_dropped(self):
        before = {r[0] for r in sqlite3.connect(str(self.db_path))
                  .execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()}
        self.db.init()
        after = {r[0] for r in self.db.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table';").fetchall()}
        self.assertTrue(before.issubset(after), f"tables lost: {before - after}")

    def test_expected_columns_present_after_upgrade(self):
        self.db.init()
        cols = existing_columns(self.db.conn, "findings")
        for expected in ("cwe_id", "owasp_category", "remediation_status", "fingerprint",
                         "engagement_id", "validation_state"):
            self.assertIn(expected, cols)


if __name__ == "__main__":
    unittest.main()
