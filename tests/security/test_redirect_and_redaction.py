import unittest

from labapp import LabApp

from velora.core.http import SafeHTTPClient
from velora.scope import ScopeManager, ScopePolicy


class TestRedirectAndRedaction(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.app = LabApp()
        self.app.__enter__()
        self.policy = ScopePolicy(allowed_ips=["127.0.0.1"], allowed_ports=[self.app.port],
                                  allow_private_targets=True, max_requests=100)

    async def asyncTearDown(self):
        self.app.__exit__(None, None, None)

    async def test_out_of_scope_redirect_blocked(self):
        sm = ScopeManager(self.policy, scan_id="T")
        async with SafeHTTPClient(sm, request_delay=0) as client:
            r = await client.get(
                self.app.base_url + "/redirect?to=http://external.example.net/",
                follow_redirects=True,
            )
            self.assertIsNotNone(r.error)
            self.assertIn("redirect-blocked", r.error)

    async def test_in_scope_redirect_followed(self):
        sm = ScopeManager(self.policy, scan_id="T")
        async with SafeHTTPClient(sm, request_delay=0) as client:
            r = await client.get(self.app.base_url + "/redirect?to=/login", follow_redirects=True)
            self.assertEqual(r.status_code, 200)
            self.assertTrue(r.redirect_chain)

    async def test_body_secret_is_redacted(self):
        sm = ScopeManager(self.policy, scan_id="T")
        async with SafeHTTPClient(sm, request_delay=0) as client:
            r = await client.get(self.app.base_url + "/")
            self.assertNotIn("sk_live_ABCDEF0123456789ABCDEF", r.body)
            self.assertIn("[REDACTED]", r.body)


if __name__ == "__main__":
    unittest.main()
