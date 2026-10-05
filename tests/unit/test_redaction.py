import unittest

from velora.utils import redaction as r


class TestRedaction(unittest.TestCase):
    def test_redacts_jwt(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEF123456"
        self.assertNotIn(jwt, r.redact_text(f"token {jwt} here"))
        self.assertIn("[REDACTED]", r.redact_text(f"token {jwt} here"))

    def test_redacts_aws_key(self):
        self.assertIn("[REDACTED]", r.redact_text("AKIAIOSFODNN7EXAMPLE in config"))

    def test_redacts_kv_pairs(self):
        out = r.redact_text('password=hunter2 and api_key: sk_test_abc12345')
        self.assertNotIn("hunter2", out)
        self.assertIn("password=[REDACTED]", out)

    def test_redacts_headers(self):
        headers = {"Authorization": "Bearer secret", "Cookie": "s=1", "Accept": "text/html"}
        red = r.redact_headers(headers)
        self.assertEqual(red["Authorization"], "[REDACTED]")
        self.assertEqual(red["Cookie"], "[REDACTED]")
        self.assertEqual(red["Accept"], "text/html")

    def test_redacts_nested_mapping(self):
        data = {"user": {"password": "x", "name": "alice"}, "list": [{"token": "t"}]}
        out = r.redact_mapping(data)
        self.assertEqual(out["user"]["password"], "[REDACTED]")
        self.assertEqual(out["user"]["name"], "alice")
        self.assertEqual(out["list"][0]["token"], "[REDACTED]")

    def test_empty_inputs(self):
        self.assertEqual(r.redact_text(None), "")
        self.assertEqual(r.redact_headers(None), {})
        self.assertEqual(r.redact_params(None), {})


if __name__ == "__main__":
    unittest.main()
