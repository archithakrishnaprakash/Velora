import unittest

from velora.scope import ScopeManager, ScopePolicy


class TestScopeBypass(unittest.TestCase):
    def setUp(self):
        self.m = ScopeManager(
            ScopePolicy(allowed_domains=["target.local"], allowed_ports=[80, 443],
                        allow_private_targets=True),
            resolver=lambda h: {"target.local": ["10.0.0.9"], "evil.com": ["1.2.3.4"],
                                "target.local.evil.com": ["1.2.3.4"]}.get(h, []),
        )

    def test_scheme_bypass_blocked(self):
        self.assertFalse(self.m.check("file:///etc/passwd").allowed)
        self.assertFalse(self.m.check("gopher://target.local/").allowed)

    def test_port_bypass_blocked(self):
        self.assertFalse(self.m.check("http://target.local:22/").allowed)

    def test_suffix_confusion_blocked(self):
        # target.local.evil.com must NOT match target.local
        self.assertFalse(self.m.check("http://target.local.evil.com/").allowed)

    def test_case_and_trailing_dot_normalized(self):
        self.assertTrue(self.m.check("http://TARGET.local./").allowed)

    def test_unlisted_ip_literal_blocked(self):
        self.assertFalse(self.m.check("http://10.0.0.9/").allowed)  # domain-only scope

    def test_excluded_path_blocked(self):
        m = ScopeManager(ScopePolicy(allowed_domains=["target.local"], excluded_paths=["/admin"],
                                     allow_private_targets=True),
                         resolver=lambda h: {"target.local": ["10.0.0.9"]}.get(h, []))
        self.assertFalse(m.check("http://target.local/admin").allowed)
        self.assertTrue(m.check("http://target.local/public").allowed)


if __name__ == "__main__":
    unittest.main()
