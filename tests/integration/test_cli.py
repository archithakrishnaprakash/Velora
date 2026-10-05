import os
import tempfile
import unittest

from click.testing import CliRunner

from labapp import LabApp

from velora.cli.main import cli


class TestCLI(unittest.TestCase):
    def setUp(self):
        os.environ["VELORA_DATA_DIR"] = tempfile.mkdtemp()
        os.environ["VELORA_CONFIG_DIR"] = tempfile.mkdtemp()
        self.runner = CliRunner()

    def test_version(self):
        res = self.runner.invoke(cli, ["version"])
        self.assertEqual(res.exit_code, 0)
        self.assertIn("Velora", res.output)

    def test_plugins_list(self):
        res = self.runner.invoke(cli, ["plugins", "list"])
        self.assertEqual(res.exit_code, 0)
        self.assertIn("headers.security_headers", res.output)

    def test_scan_requires_authorization_flag(self):
        res = self.runner.invoke(cli, ["scan", "--target", "http://127.0.0.1:1/"])
        self.assertNotEqual(res.exit_code, 0)
        self.assertIn("i-am-authorized", res.output)

    def test_scan_and_findings_flow(self):
        with LabApp() as app:
            res = self.runner.invoke(cli, [
                "scan", "--target", app.base_url + "/", "--profile", "lab",
                "--operator", "t", "--allow-private", "--i-am-authorized",
            ])
            self.assertEqual(res.exit_code, 0, res.output)
            self.assertIn("completed", res.output)
            # extract scan id
            import re
            m = re.search(r"SCAN-[A-Z0-9]+", res.output)
            self.assertIsNotNone(m)
            sid = m.group(0)
            res2 = self.runner.invoke(cli, ["findings", "--scan", sid])
            self.assertEqual(res2.exit_code, 0)
            self.assertIn("WEB-", res2.output)


if __name__ == "__main__":
    unittest.main()
