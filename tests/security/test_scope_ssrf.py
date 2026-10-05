import unittest

from velora.scope import ScopeManager, ScopePolicy
from velora.utils.errors import ScopeViolation


def resolver(mapping):
    return lambda host: mapping.get(host, [])


class TestSSRF(unittest.TestCase):
    def test_dns_rebinding_to_metadata_blocked(self):
        # Domain is in scope, but resolves to cloud metadata IP -> must be blocked.
        m = ScopeManager(ScopePolicy(allowed_domains=["*.example.com"]),
                         resolver=resolver({"app.example.com": ["169.254.169.254"]}))
        d = m.check("http://app.example.com/")
        self.assertFalse(d.allowed)
        self.assertIn("metadata", d.reason)

    def test_dns_rebinding_to_loopback_blocked(self):
        m = ScopeManager(ScopePolicy(allowed_domains=["*.example.com"]),
                         resolver=resolver({"app.example.com": ["127.0.0.1"]}))
        self.assertFalse(m.check("http://app.example.com/").allowed)

    def test_private_ip_blocked_by_default(self):
        m = ScopeManager(ScopePolicy(allowed_domains=["x.com"]),
                         resolver=resolver({"x.com": ["10.0.0.5"]}))
        self.assertFalse(m.check("http://x.com/").allowed)

    def test_private_ip_allowed_when_lab_opt_in(self):
        m = ScopeManager(ScopePolicy(allowed_domains=["x.com"], allow_private_targets=True),
                         resolver=resolver({"x.com": ["10.0.0.5"]}))
        self.assertTrue(m.check("http://x.com/").allowed)

    def test_metadata_blocked_even_in_lab_mode(self):
        m = ScopeManager(ScopePolicy(allowed_domains=["x.com"], allow_private_targets=True),
                         resolver=resolver({"x.com": ["169.254.169.254"]}))
        self.assertFalse(m.check("http://x.com/").allowed)

    def test_authorize_raises_and_logs(self):
        m = ScopeManager(ScopePolicy(allowed_domains=["x.com"]),
                         resolver=resolver({"x.com": ["10.0.0.5"]}))
        with self.assertRaises(ScopeViolation):
            m.authorize("http://x.com/")
        self.assertEqual(m.blocked_count, 1)


if __name__ == "__main__":
    unittest.main()
