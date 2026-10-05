import unittest

from velora.integrations import NmapAdapter, NucleiAdapter
from velora.integrations.base import ToolAdapter
from velora.scope import ScopeManager, ScopePolicy
from velora.utils.errors import IntegrationError, ScopeViolation


class TestCommandInjection(unittest.TestCase):
    def setUp(self):
        self.scope = ScopeManager(
            ScopePolicy(allowed_domains=["lab.local"], allow_private_targets=True),
            resolver=lambda h: {"lab.local": ["10.0.0.5"], "evil.com": ["1.2.3.4"]}.get(h, []),
        )

    def test_adapter_never_uses_shell_string(self):
        # _run builds an argument list; even shell metacharacters stay a single argv element.
        a = ToolAdapter(scope=None)
        a.executable = "echo"  # available on PATH
        res = a._run(["hello; rm -rf /", "&& whoami"])
        self.assertIsInstance(res.command, list)
        self.assertIn("hello; rm -rf /", res.command)
        self.assertEqual(res.returncode, 0)
        self.assertNotIn("root", res.stdout)  # whoami never executed

    def test_non_string_args_rejected(self):
        a = ToolAdapter(scope=None)
        a.executable = "echo"
        with self.assertRaises(IntegrationError):
            a._run(["ok", 123])  # type: ignore[list-item]

    def test_out_of_scope_target_refused(self):
        with self.assertRaises(ScopeViolation):
            NucleiAdapter(scope=self.scope).scan_url("http://evil.com/")

    def test_missing_tool_is_graceful(self):
        r = NmapAdapter(scope=self.scope).scan_host("http://lab.local/")
        # nmap not installed in CI -> available False, no exception
        self.assertFalse(r.ok)
        self.assertFalse(r.available)


if __name__ == "__main__":
    unittest.main()
