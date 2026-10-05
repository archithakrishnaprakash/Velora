import unittest

from velora.core.http import HttpResponse
from velora.differential import DifferentialEngine, fingerprint_response
from velora.models.enums import DiffClassification


def resp(status=200, headers=None, body="", ct="text/html", ms=10.0, err=None, size=None):
    h = dict(headers or {})
    h.setdefault("Content-Type", ct)
    return HttpResponse(
        url="http://lab/x", final_url="http://lab/x", method="GET", status_code=status,
        headers=h, content_type=ct, body=body,
        response_size=size if size is not None else len(body), elapsed_ms=ms, error=err,
    )


class TestFingerprint(unittest.TestCase):
    def test_volatile_headers_excluded(self):
        fp = fingerprint_response(resp(headers={"Date": "x", "ETag": "y", "X-Request-Id": "z",
                                                "X-Custom": "keep"}))
        self.assertIn("x-custom", fp.header_names)
        for volatile in ("date", "etag", "x-request-id"):
            self.assertNotIn(volatile, fp.header_names)

    def test_json_shape_ignores_values(self):
        a = fingerprint_response(resp(body='{"id":1,"name":"alice"}', ct="application/json"))
        b = fingerprint_response(resp(body='{"id":999,"name":"zoe"}', ct="application/json"))
        self.assertEqual(a.body_shape, b.body_shape)

    def test_html_skeleton_ignores_text(self):
        a = fingerprint_response(resp(body="<html><body><p>hello</p></body></html>"))
        b = fingerprint_response(resp(body="<html><body><p>different text</p></body></html>"))
        self.assertEqual(a.body_shape, b.body_shape)

    def test_cookie_flags_captured(self):
        fp = fingerprint_response(resp(headers={"Set-Cookie": "SID=1; HttpOnly; Secure"}))
        self.assertEqual(fp.cookie_names, ["SID"])
        self.assertIn("httponly", fp.cookie_flags["SID"])


class TestDifferentialEngine(unittest.TestCase):
    def setUp(self):
        self.engine = DifferentialEngine()

    def test_identical_responses_produce_no_difference(self):
        r = self.engine.compare_responses(resp(body="<html>same</html>"),
                                          resp(body="<html>same</html>"))
        self.assertFalse(r.changed)
        self.assertEqual(r.confidence, 0.0)
        # Must not overclaim equivalence.
        self.assertIn("does not prove", r.interpretation)

    def test_volatile_content_is_not_a_difference(self):
        a = resp(body="<html><i>3f2504e0-4f89-11d3-9a0c-0305e82c3301</i></html>",
                 headers={"Date": "Mon, 22 Sep 2026 10:00:00 GMT"})
        b = resp(body="<html><i>9a1204e0-1189-41d3-9a0c-0305e82c9999</i></html>",
                 headers={"Date": "Mon, 22 Sep 2026 11:22:33 GMT"})
        self.assertFalse(self.engine.compare_responses(a, b).changed)

    def test_deny_to_allow_flagged_as_authorization_behavior_change(self):
        r = self.engine.compare_responses(resp(403, body="denied"), resp(200, body="<html>x</html>"))
        self.assertIn(DiffClassification.AUTHORIZATION_BEHAVIOR_CHANGE.value, r.classifications)
        self.assertTrue(r.indicates_access_change)
        self.assertGreaterEqual(r.confidence, 0.9)

    def test_plain_status_change_is_not_authorization_change(self):
        r = self.engine.compare_responses(resp(200, body="a"), resp(500, body="b"))
        self.assertIn(DiffClassification.STATUS_CHANGE.value, r.classifications)
        self.assertNotIn(DiffClassification.AUTHORIZATION_BEHAVIOR_CHANGE.value, r.classifications)

    def test_json_field_addition_detected(self):
        a = resp(body='{"id":1}', ct="application/json")
        b = resp(body='{"id":1,"is_admin":true}', ct="application/json")
        r = self.engine.compare_responses(a, b)
        self.assertIn(DiffClassification.JSON_FIELD_CHANGE.value, r.classifications)

    def test_cookie_change_detected(self):
        r = self.engine.compare_responses(
            resp(headers={"Set-Cookie": "SID=a; HttpOnly"}),
            resp(headers={"Set-Cookie": "SID=b"}))
        self.assertIn(DiffClassification.COOKIE_CHANGE.value, r.classifications)

    def test_redirect_change_detected(self):
        r = self.engine.compare_responses(
            resp(302, headers={"Location": "/login"}),
            resp(302, headers={"Location": "/dashboard"}))
        self.assertIn(DiffClassification.REDIRECT_CHANGE.value, r.classifications)

    def test_transport_error_lowers_confidence(self):
        r = self.engine.compare_responses(resp(body="ok"), resp(status=0, err="timeout"))
        self.assertLessEqual(r.confidence, 0.3)
        self.assertIn("unreliable", r.interpretation)

    def test_validation_always_required(self):
        r = self.engine.compare_responses(resp(200, body="a"), resp(200, body="b"))
        self.assertTrue(r.validation_required)

    def test_interpretation_never_asserts_vulnerability(self):
        r = self.engine.compare_responses(resp(403), resp(200, body="<html>x</html>"))
        text = r.interpretation.lower()
        self.assertIn("indicator", text)
        self.assertNotIn("vulnerable", text)
        self.assertNotIn("confirmed", text)

    def test_secrets_redacted_in_serialized_result(self):
        import json
        a = resp(body='{"a":1}', ct="application/json")
        b = resp(body='{"a":1,"api_key":"sk_live_ABCDEF0123456789"}', ct="application/json")
        blob = json.dumps(self.engine.compare_responses(a, b).to_dict())
        self.assertNotIn("sk_live_ABCDEF0123456789", blob)

    def test_ignore_timing_option(self):
        engine = DifferentialEngine(ignore_timing=True)
        r = engine.compare_responses(resp(body="x", ms=1.0), resp(body="x", ms=9000.0))
        self.assertNotIn(DiffClassification.TIMING_CHANGE.value, r.classifications)


if __name__ == "__main__":
    unittest.main()
