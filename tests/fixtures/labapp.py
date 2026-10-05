"""A tiny, self-contained, intentionally-imperfect web app for local testing.

Runs on 127.0.0.1 with stdlib http.server (no external deps). It deliberately exhibits
common *configuration* weaknesses (missing security headers, insecure cookie flags,
verbose Server header, permissive methods, exposed robots paths) so the passive scanners
have real, non-faked evidence to detect. It performs NO real attacks and stores nothing.
"""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

INDEX_HTML = """<!doctype html><html><head><title>LabShop</title>
<script src="/static/app.js"></script></head><body>
<h1>LabShop</h1>
<a href="/login">Login</a> <a href="/admin">Admin</a> <a href="/products?id=1">Products</a>
<a href="/products?id=2">Product 2</a> <a href="http://external.example.net/">External</a>
<form action="/login" method="post">
  <input name="username"><input name="password" type="password">
  <button>go</button>
</form>
<div>contact api_key=sk_live_ABCDEF0123456789ABCDEF for support</div>
</body></html>"""

ROBOTS = "User-agent: *\nDisallow: /admin\nDisallow: /backup\nSitemap: /sitemap.xml\n"
SITEMAP = ('<?xml version="1.0"?><urlset><url><loc>/</loc></url>'
           "<url><loc>/login</loc></url><url><loc>/products?id=1</loc></url></urlset>")


class Handler(BaseHTTPRequestHandler):
    server_version = "LabShop/1.4.2"
    sys_version = "Python/3.11-lab"

    def log_message(self, *args):  # silence
        return

    def _send(self, code, body, ctype="text/html", extra=None):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        # Deliberately insecure cookie (no HttpOnly/Secure/SameSite) for detection.
        if self.path == "/login":
            self.send_header("Set-Cookie", "SESSIONID=abc123deadbeef; Path=/")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    # ---- authorization-testing surface -------------------------------
    # Tokens are fixtures, not secrets. Two endpoints are DELIBERATELY broken so the
    # authorization matrix has real weaknesses to find, and two are correct so a
    # false positive would be visible.
    TOKENS = {"alice-token": "alice", "bob-token": "bob", "admin-token": "admin"}
    ORDERS = {"1": "alice", "2": "bob"}
    CARTS: set = set()

    def _identity(self):
        auth = self.headers.get("Authorization", "")
        token = auth[7:].strip() if auth.lower().startswith("bearer ") else auth.strip()
        return self.TOKENS.get(token)

    def _authz_routes(self, path):
        """Return True if the path was handled."""
        who = self._identity()

        if path == "/api/public":
            self._send(200, '{"status":"ok"}', "application/json")   # correct: public
            return True

        if path == "/api/profile":
            if not who:  # correct: rejects anonymous
                self._send(401, '{"error":"unauthorized"}', "application/json")
            else:
                self._send(200, '{"user":"%s","email":"%s@lab.local"}' % (who, who),
                           "application/json")
            return True

        if path.startswith("/api/orders/"):
            order_id = path.rsplit("/", 1)[-1]
            owner = self.ORDERS.get(order_id)
            if owner is None:
                self._send(404, '{"error":"not found"}', "application/json")
            elif not who:
                self._send(401, '{"error":"unauthorized"}', "application/json")
            else:
                # BROKEN (intentional): no ownership check -> horizontal weakness.
                self._send(200, '{"order":%s,"owner":"%s","total":42.5}' % (order_id, owner),
                           "application/json")
            return True

        if path == "/admin/console":
            if not who:
                self._send(401, '{"error":"unauthorized"}', "application/json")
            else:
                # BROKEN (intentional): any authenticated user -> vertical weakness.
                self._send(200, '{"panel":"admin","users":2}', "application/json")
            return True

        if path == "/admin/settings":
            if who != "admin":  # correct: enforces role
                self._send(403, '{"error":"forbidden"}', "application/json")
            else:
                self._send(200, '{"settings":{"debug":false}}', "application/json")
            return True

        # ---- business-logic workflow surface --------------------------
        # /cart/add is a required step; /checkout DELIBERATELY does not verify that it
        # happened, so the step-skip probe has a real flaw to find.
        if path == "/cart/add":
            if not who:
                self._send(401, '{"error":"unauthorized"}', "application/json")
            else:
                self.CARTS.add(who)
                self._send(200, '{"cart":{"items":1}}', "application/json")
            return True

        if path == "/checkout":
            if not who:
                self._send(401, '{"error":"unauthorized"}', "application/json")
            else:
                # BROKEN (intentional): no check that the cart was ever filled.
                self._send(200, '{"order":"ORD-1","status":"placed"}', "application/json")
            return True

        return False

    def do_GET(self):
        p = self.path.split("?")[0]
        if self._authz_routes(p):
            return
        if p == "/":
            self._send(200, INDEX_HTML)
        elif p == "/login":
            self._send(200, "<html><title>Login</title><form method=post>"
                            "<input name=username><input name=password type=password></form></html>")
        elif p == "/admin":
            self._send(200, "<html><title>Admin</title><a href='/admin/users'>users</a></html>")
        elif p == "/admin/users":
            self._send(200, "<html>admin users</html>")
        elif p == "/products":
            self._send(200, "<html><title>Products</title>product page</html>")
        elif p == "/api/users":
            self._send(200, '{"users":[{"id":1,"name":"alice"}],"token":"secret-xyz"}',
                       "application/json")
        elif p == "/static/app.js":
            self._send(200, "console.log('/api/orders');", "application/javascript")
        elif p == "/robots.txt":
            self._send(200, ROBOTS, "text/plain")
        elif p == "/sitemap.xml":
            self._send(200, SITEMAP, "application/xml")
        elif p == "/redirect":
            to = self.path.split("to=", 1)[-1] if "to=" in self.path else "/"
            self._send(302, "", extra={"Location": to})
        else:
            self._send(404, "<html>not found</html>")

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        p = self.path.split("?")[0]
        if self._authz_routes(p):
            return
        if p == "/login":
            self._send(200, '{"status":"authenticated"}', "application/json")
            return
        self._send(200, "<html>posted</html>")

    def do_OPTIONS(self):
        self._send(200, "", extra={"Allow": "GET, HEAD, POST, OPTIONS, TRACE, PUT, DELETE"})


class LabApp:
    """Context manager that runs the lab app on an ephemeral loopback port."""

    def __init__(self, host: str = "127.0.0.1") -> None:
        self.host = host
        self.server = ThreadingHTTPServer((host, 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def __enter__(self) -> "LabApp":
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.server.shutdown()
        self.server.server_close()


if __name__ == "__main__":
    with LabApp() as app:
        print("LabApp on", app.base_url)
        import time
        time.sleep(60)
