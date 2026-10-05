"""End-to-end authorization testing against the local lab app.

The lab app contains two DELIBERATELY broken access controls and two correct ones, so
this suite proves both detection and the absence of false positives.
"""
import os
import tempfile
import unittest

from labapp import LabApp

from velora.authz import AuthorizationTestingService, AuthzRunner, IdentityResolver, build_matrix
from velora.authz.matrix import ResourceSpec
from velora.config import load_settings
from velora.core.http import SafeHTTPClient
from velora.database import Database
from velora.database.repository import Repository
from velora.models.domain import Identity, Scan, Target
from velora.models.enums import (
    AuthorizationStatus,
    AuthzOutcome,
    FindingStatus,
    IdentityRole,
    ScanStatus,
)
from velora.scope import ScopeManager, ScopePolicy

ENV = {"A_TOK": "alice-token", "B_TOK": "bob-token", "AD_TOK": "admin-token"}


def identities():
    return [
        Identity(name="anonymous", role=IdentityRole.ANONYMOUS, auth_scheme="none"),
        Identity(name="alice", role=IdentityRole.USER_A, secret_ref="A_TOK"),
        Identity(name="bob", role=IdentityRole.USER_B, secret_ref="B_TOK"),
        Identity(name="admin", role=IdentityRole.ADMIN, secret_ref="AD_TOK"),
    ]


class TestAuthzFlow(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        os.environ["VELORA_DATA_DIR"] = tempfile.mkdtemp()
        self.app = LabApp()
        self.app.__enter__()
        self.settings = load_settings("/nonexistent.yaml")
        self.db = Database(self.settings)
        self.db.init()
        self.repo = Repository(self.db.conn)
        self.target = Target(name="lab", url=self.app.base_url + "/",
                             authorization_status=AuthorizationStatus.LAB_ONLY)
        self.repo.add_target(self.target)
        self.scan = Scan(target_id=self.target.id, operator="tester",
                         authorization_ack=True, status=ScanStatus.RUNNING)
        self.repo.add_scan(self.scan)
        self.ids = identities()
        for i in self.ids:
            self.repo.add_identity(i)

    async def asyncTearDown(self):
        self.db.close()
        self.app.__exit__(None, None, None)

    def _resources(self):
        base = self.app.base_url
        return [
            ResourceSpec(url=f"{base}/api/orders/1", owner="alice", name="alice order"),
            ResourceSpec(url=f"{base}/admin/console", requires_role=IdentityRole.ADMIN,
                         name="admin console (broken)"),
            ResourceSpec(url=f"{base}/admin/settings", requires_role=IdentityRole.ADMIN,
                         name="admin settings (correct)"),
            ResourceSpec(url=f"{base}/api/profile", name="profile",
                         expectations={"anonymous": "DENY", "alice": "ALLOW",
                                       "bob": "ALLOW", "admin": "ALLOW"}),
        ]

    async def _run(self):
        matrix = build_matrix(self.ids, self._resources())
        policy = ScopePolicy(allowed_ips=["127.0.0.1"], allowed_ports=[self.app.port],
                             allow_private_targets=True, max_requests=300)
        sm = ScopeManager(policy, scan_id=self.scan.id)
        async with SafeHTTPClient(sm, request_delay=0) as client:
            runner = AuthzRunner(client, resolver=IdentityResolver(env=ENV))
            return await runner.run(matrix)

    async def test_detects_horizontal_weakness(self):
        results = await self._run()
        horizontal = [r for r in results
                      if r.outcome == AuthzOutcome.HORIZONTAL_AUTHORIZATION_WEAKNESS]
        self.assertTrue(horizontal, "expected the intentional IDOR to be detected")
        self.assertEqual(horizontal[0].case.identity.name, "bob")

    async def test_detects_vertical_weakness(self):
        results = await self._run()
        vertical = [r for r in results
                    if r.outcome == AuthzOutcome.VERTICAL_AUTHORIZATION_WEAKNESS]
        names = {r.case.identity.name for r in vertical}
        self.assertTrue({"alice", "bob"}.issubset(names))

    async def test_correct_control_is_not_flagged(self):
        """The properly-enforced endpoint must produce zero weaknesses."""
        results = await self._run()
        settings_results = [r for r in results if "settings" in r.case.resource.url]
        self.assertTrue(settings_results)
        for r in settings_results:
            self.assertFalse(r.is_weakness,
                             f"false positive on a correct control: {r.reason}")

    async def test_anonymous_denied_is_as_expected(self):
        results = await self._run()
        anon = [r for r in results
                if r.case.identity.name == "anonymous" and "profile" in r.case.resource.url]
        self.assertEqual(anon[0].outcome, AuthzOutcome.AS_EXPECTED)

    async def test_findings_created_as_potential_only(self):
        results = await self._run()
        service = AuthorizationTestingService(self.repo)
        summary = service.record(results, scan=self.scan)
        self.assertGreater(summary.weaknesses, 0)
        self.assertEqual(len(summary.findings), summary.weaknesses)
        for finding in summary.findings:
            self.assertEqual(finding.status, FindingStatus.POTENTIAL)
            self.assertEqual(finding.category, "authorization")
            self.assertNotEqual(finding.cwe_id, "UNKNOWN")
            self.assertTrue(finding.evidence_ids)

    async def test_no_credentials_persisted_anywhere(self):
        results = await self._run()
        service = AuthorizationTestingService(self.repo)
        service.record(results, scan=self.scan)
        self.db.close()
        with open(self.settings.database.sqlite_path, "rb") as fh:
            raw = fh.read()
        for token in ENV.values():
            self.assertNotIn(token.encode(), raw,
                             f"credential {token} leaked into the database")

    async def test_tests_are_persisted_with_expected_and_observed(self):
        results = await self._run()
        AuthorizationTestingService(self.repo).record(results, scan=self.scan)
        stored = self.repo.list_authz_tests(self.scan.id)
        self.assertEqual(len(stored), len(results))
        self.assertTrue(all(t.expected is not None and t.observed is not None for t in stored))


if __name__ == "__main__":
    unittest.main()
