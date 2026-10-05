"""Feature 19: a hostile or merely broken target must not exhaust Velora.

These tests run against a local stdlib server that misbehaves on purpose: it streams an
endless body, lies about Content-Length, stalls, and returns malformed structures.
Nothing here touches the network.
"""
import asyncio
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from velora.core.http import MAX_BODY_CAPTURE, MAX_BODY_DOWNLOAD, SafeHTTPClient
from velora.scope import ScopeManager, ScopePolicy
from velora.utils.errors import RateLimitExceeded


class HostileHandler(BaseHTTPRequestHandler):
    """Serves responses designed to break a naive client."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        return

    def do_GET(self):  # noqa: N802
        path = self.path.split("?")[0]
        if path == "/endless":
            # Claims to be small, then streams far more than it promised.
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            block = b"A" * 64_000
            sent = 0
            try:
                while sent < MAX_BODY_DOWNLOAD * 3:
                    self.wfile.write(b"%x\r\n" % len(block) + block + b"\r\n")
                    sent += len(block)
                self.wfile.write(b"0\r\n\r\n")
            except (BrokenPipeError, ConnectionResetError, OSError):
                return          # the client cut us off, which is the point
            return
        if path == "/big":
            body = b"B" * (MAX_BODY_CAPTURE * 3)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/headerbomb":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            for i in range(200):
                self.send_header(f"X-Pad-{i}", "z" * 200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
            return
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class HostileApp:
    def __init__(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), HostileHandler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def base_url(self):
        return f"http://127.0.0.1:{self.port}"

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()


def scope_for(port, **kw):
    policy = ScopePolicy(allowed_ips=["127.0.0.1"], allowed_ports=[port],
                         allow_private_targets=True, request_delay=0.0, **kw)
    return ScopeManager(policy, resolver=lambda h: ["127.0.0.1"])


class TestResponseSizeLimits(unittest.IsolatedAsyncioTestCase):
    async def test_endless_body_is_cut_off_at_the_download_ceiling(self):
        with HostileApp() as app:
            client = SafeHTTPClient(scope_for(app.port), request_delay=0.0, timeout=20.0)
            try:
                resp = await client.get(f"{app.base_url}/endless")
            finally:
                await client.aclose()
        self.assertIsNone(resp.error)
        self.assertTrue(resp.truncated)
        # Read a bounded amount, not the several-times-larger stream the server offered.
        self.assertLess(resp.response_size, MAX_BODY_DOWNLOAD + 200_000)

    async def test_stored_body_is_capped_independently_of_what_was_downloaded(self):
        with HostileApp() as app:
            client = SafeHTTPClient(scope_for(app.port), request_delay=0.0, timeout=20.0)
            try:
                resp = await client.get(f"{app.base_url}/big")
            finally:
                await client.aclose()
        self.assertLessEqual(len(resp.body.encode("utf-8", errors="ignore")),
                             MAX_BODY_CAPTURE * 2)
        self.assertGreater(resp.response_size, MAX_BODY_CAPTURE)

    async def test_truncation_is_recorded_in_the_evidence_metadata(self):
        with HostileApp() as app:
            client = SafeHTTPClient(scope_for(app.port), request_delay=0.0, timeout=20.0)
            try:
                resp = await client.get(f"{app.base_url}/endless")
            finally:
                await client.aclose()
        self.assertTrue(resp.evidence_response()["truncated"])

    async def test_a_normal_response_is_not_marked_truncated(self):
        with HostileApp() as app:
            client = SafeHTTPClient(scope_for(app.port), request_delay=0.0)
            try:
                resp = await client.get(f"{app.base_url}/ok")
            finally:
                await client.aclose()
        self.assertFalse(resp.truncated)
        self.assertEqual(resp.body, "ok")

    async def test_many_response_headers_do_not_break_capture(self):
        with HostileApp() as app:
            client = SafeHTTPClient(scope_for(app.port), request_delay=0.0)
            try:
                resp = await client.get(f"{app.base_url}/headerbomb")
            finally:
                await client.aclose()
        self.assertEqual(resp.status_code, 200)
        self.assertGreater(len(resp.headers), 100)


class TestRequestBudget(unittest.IsolatedAsyncioTestCase):
    async def test_the_request_budget_is_enforced_and_terminal(self):
        with HostileApp() as app:
            scope = scope_for(app.port, max_requests=3)
            client = SafeHTTPClient(scope, request_delay=0.0)
            try:
                for _ in range(3):
                    await client.get(f"{app.base_url}/ok")
                with self.assertRaises(RateLimitExceeded):
                    await client.get(f"{app.base_url}/ok")
            finally:
                await client.aclose()

    async def test_budget_accounting_is_visible_and_blocked_requests_are_counted(self):
        with HostileApp() as app:
            scope = scope_for(app.port, max_requests=50)
            client = SafeHTTPClient(scope, request_delay=0.0)
            try:
                await client.get(f"{app.base_url}/ok")
                self.assertEqual(scope.request_count, 1)
                self.assertEqual(scope.remaining_budget(), 49)
                # An out-of-scope attempt is refused and counted as blocked, so the
                # audit trail shows what was attempted, not only what was sent.
                with self.assertRaises(Exception):
                    await client.get("http://169.254.169.254/latest/meta-data/")
                self.assertEqual(scope.blocked_count, 1)
                self.assertEqual(scope.request_count, 1)
            finally:
                await client.aclose()

    async def test_concurrency_limit_is_passed_to_the_transport(self):
        with HostileApp() as app:
            scope = scope_for(app.port, max_concurrency=2)
            client = SafeHTTPClient(scope, request_delay=0.0)
            try:
                self.assertEqual(client._client._transport._pool._max_connections, 2)
            finally:
                await client.aclose()

    async def test_concurrent_requests_still_respect_the_budget(self):
        with HostileApp() as app:
            scope = scope_for(app.port, max_requests=5, max_concurrency=5)
            client = SafeHTTPClient(scope, request_delay=0.0)
            try:
                results = await asyncio.gather(
                    *[client.get(f"{app.base_url}/ok") for _ in range(12)],
                    return_exceptions=True)
            finally:
                await client.aclose()
        allowed = [r for r in results if not isinstance(r, Exception)]
        blocked = [r for r in results if isinstance(r, RateLimitExceeded)]
        self.assertLessEqual(len(allowed), 5)
        self.assertTrue(blocked)


if __name__ == "__main__":
    unittest.main()
