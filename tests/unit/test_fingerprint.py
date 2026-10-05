import unittest

from velora.core.http import HttpResponse
from velora.fingerprint import FingerprintEngine


def _resp(headers, body=""):
    return HttpResponse(url="http://x/", final_url="http://x/", method="GET", status_code=200,
                        headers=headers, content_type="text/html", body=body, response_size=len(body),
                        elapsed_ms=1.0)


class TestFingerprint(unittest.TestCase):
    def setUp(self):
        self.fp = FingerprintEngine()

    def test_detects_nginx_version(self):
        techs = self.fp.analyze(_resp({"Server": "nginx/1.25.3"}))
        nginx = next(t for t in techs if t.name == "nginx")
        self.assertEqual(nginx.version, "1.25.3")
        self.assertGreater(nginx.confidence, 0.8)

    def test_detects_php_powered_by(self):
        techs = self.fp.analyze(_resp({"X-Powered-By": "PHP/8.2.1"}))
        self.assertTrue(any(t.name == "PHP" for t in techs))

    def test_detects_jquery_in_body(self):
        techs = self.fp.analyze(_resp({}, '<script src="/js/jquery-3.6.0.min.js"></script>'))
        jq = next(t for t in techs if t.name == "jQuery")
        self.assertEqual(jq.version, "3.6.0")

    def test_no_false_positive(self):
        techs = self.fp.analyze(_resp({"Server": "LabShop/1.0"}, "<html>hi</html>"))
        self.assertEqual([t for t in techs if t.name in {"nginx", "Apache httpd"}], [])


if __name__ == "__main__":
    unittest.main()
