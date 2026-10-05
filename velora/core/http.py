"""Scope-enforcing async HTTP client.

Every request is authorized by the ScopeManager *before* it is sent. Redirects are
never followed automatically: the client reads the ``Location`` header and re-checks it
against the redirect policy and full scope, so an in-scope page cannot bounce the
scanner to an out-of-scope or internal address (SSRF via redirect). A per-worker delay
and the scan-wide request budget are both enforced here.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

import httpx

from ..scope.manager import ScopeManager
from ..utils.errors import ScopeViolation
from ..utils.logging import get_logger
from ..utils.redaction import redact_headers, redact_text

log = get_logger("core.http")

MAX_BODY_CAPTURE = 200_000  # cap stored/parsed body size (bytes) to bound memory

#: Hard ceiling on what is read off the wire, whatever the server claims. Responses are
#: streamed and the transfer is abandoned the moment this is exceeded, so a target that
#: serves an endless or enormous body cannot exhaust Velora's memory. This is separate
#: from MAX_BODY_CAPTURE, which bounds what is stored and parsed: a hostile server is
#: not obliged to send a truthful Content-Length, so the limit has to be enforced while
#: reading, not from the header.
MAX_BODY_DOWNLOAD = 5_000_000


@dataclass
class HttpResponse:
    """A captured HTTP exchange with redacted, evidence-ready metadata."""

    url: str
    final_url: str
    method: str
    status_code: int
    headers: dict[str, str]
    content_type: str
    body: str
    response_size: int
    elapsed_ms: float
    redirect_chain: list[str] = field(default_factory=list)
    request_headers: dict[str, str] = field(default_factory=dict)
    error: str | None = None
    #: True when the download hit MAX_BODY_DOWNLOAD. A check that reasons about the
    #: absence of something in the body must treat a truncated body as inconclusive.
    truncated: bool = False

    @property
    def ok(self) -> bool:
        return self.error is None and 200 <= self.status_code < 400

    def header(self, name: str) -> str | None:
        for key, value in self.headers.items():
            if key.lower() == name.lower():
                return value
        return None

    def evidence_request(self) -> dict[str, Any]:
        return {"url": self.url, "method": self.method, "headers": self.request_headers}

    def evidence_response(self) -> dict[str, Any]:
        return {
            "final_url": self.final_url,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "response_size": self.response_size,
            "redirect_chain": self.redirect_chain,
            "elapsed_ms": round(self.elapsed_ms, 1),
            "truncated": self.truncated,
        }


class SafeHTTPClient:
    """Async HTTP client gated by a ScopeManager."""

    def __init__(
        self,
        scope: ScopeManager,
        *,
        user_agent: str = "Velora/0.1 (+authorized-security-assessment)",
        timeout: float = 15.0,
        verify_tls: bool = True,
        request_delay: float = 0.2,
        max_redirects: int = 5,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.scope = scope
        self.user_agent = user_agent
        self.timeout = timeout
        self.request_delay = request_delay
        self.max_redirects = max_redirects
        self._default_headers = {"User-Agent": user_agent, "Accept": "*/*"}
        if extra_headers:
            self._default_headers.update(extra_headers)
        self._client = httpx.AsyncClient(
            follow_redirects=False,  # we handle redirects manually under scope control
            timeout=timeout,
            verify=verify_tls,
            headers=self._default_headers,
            limits=httpx.Limits(max_connections=scope.policy.max_concurrency),
        )

    async def __aenter__(self) -> "SafeHTTPClient":
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        body: str | bytes | None = None,
        follow_redirects: bool = False,
    ) -> HttpResponse:
        """Authorize and send a single request, optionally following in-scope redirects.

        ``body`` is sent only on verbs that carry one. It is never replayed across a
        redirect: a body resent to a new location is a request the operator did not
        authorize against that location.
        """
        method = method.upper()
        if body is not None and method in {"GET", "HEAD", "OPTIONS"}:
            raise ValueError(f"{method} requests do not carry a body")
        redirect_chain: list[str] = []
        current = url
        for hop in range(self.max_redirects + 1):
            # Authorization gate — consumes budget, raises ScopeViolation if blocked.
            self.scope.authorize(current)
            if self.request_delay:
                await asyncio.sleep(self.request_delay)
            resp = await self._send_once(method, current, headers,
                                         body if hop == 0 else None)
            if not follow_redirects or resp.error is not None:
                resp.redirect_chain = redirect_chain
                return resp
            location = resp.header("location")
            if not (300 <= resp.status_code < 400 and location):
                resp.redirect_chain = redirect_chain
                return resp
            # Resolve and scope-check the redirect target.
            target = str(httpx.URL(current).join(location))
            decision = self.scope.check_redirect(current, target)
            if not decision.allowed:
                resp.redirect_chain = redirect_chain
                resp.error = f"redirect-blocked:{decision.reason}"
                return resp
            redirect_chain.append(target)
            current = target
            if hop == self.max_redirects:
                resp.redirect_chain = redirect_chain
                resp.error = "too-many-redirects"
                return resp
        # Unreachable, but keeps type-checkers happy.
        raise RuntimeError("redirect loop exited unexpectedly")

    async def _send_once(
        self, method: str, url: str, headers: dict[str, str] | None,
        body: str | bytes | None = None,
    ) -> HttpResponse:
        merged = dict(self._default_headers)
        if headers:
            merged.update(headers)
        content = body.encode("utf-8") if isinstance(body, str) else body
        request = self._client.build_request(method, url, headers=merged, content=content)
        try:
            resp = await self._client.send(request, stream=True)
        except httpx.TimeoutException:
            return self._error_response(url, method, merged, "timeout")
        except httpx.HTTPError as exc:
            return self._error_response(url, method, merged, f"http-error:{type(exc).__name__}")

        # Read the body in chunks and stop at the hard ceiling. A server that advertises
        # a small Content-Length and then streams gigabytes gets cut off here.
        chunks: list[bytes] = []
        downloaded = 0
        truncated = False
        try:
            async for chunk in resp.aiter_bytes():
                downloaded += len(chunk)
                if len(b"".join(chunks)) < MAX_BODY_CAPTURE:
                    chunks.append(chunk)
                if downloaded >= MAX_BODY_DOWNLOAD:
                    truncated = True
                    log.warning("RESPONSE_SIZE_LIMIT_REACHED url=%s bytes=%d", url, downloaded)
                    break
        except httpx.TimeoutException:
            await resp.aclose()
            return self._error_response(url, method, merged, "timeout")
        except httpx.HTTPError as exc:
            await resp.aclose()
            return self._error_response(url, method, merged,
                                        f"http-error:{type(exc).__name__}")
        finally:
            await resp.aclose()

        capped = b"".join(chunks)[:MAX_BODY_CAPTURE]
        try:
            body = capped.decode(resp.encoding or "utf-8", errors="replace")
        except (LookupError, ValueError):
            body = capped.decode("utf-8", errors="replace")
        content_type = resp.headers.get("content-type", "").split(";")[0].strip()
        response = HttpResponse(
            url=url,
            final_url=str(resp.url),
            method=method,
            status_code=resp.status_code,
            headers={k: v for k, v in resp.headers.items()},
            content_type=content_type,
            body=redact_text(body),
            response_size=downloaded,
            elapsed_ms=resp.elapsed.total_seconds() * 1000 if resp.elapsed else 0.0,
            request_headers=redact_headers(merged),
        )
        if truncated:
            # Recorded, not silent: a truncated body must not be read as a complete one.
            response.truncated = True
        return response

    def _error_response(
        self, url: str, method: str, headers: dict[str, str], error: str
    ) -> HttpResponse:
        return HttpResponse(
            url=url,
            final_url=url,
            method=method,
            status_code=0,
            headers={},
            content_type="",
            body="",
            response_size=0,
            elapsed_ms=0.0,
            request_headers=redact_headers(headers),
            error=error,
        )

    async def get(self, url: str, **kw: Any) -> HttpResponse:
        return await self.request("GET", url, **kw)

    async def head(self, url: str, **kw: Any) -> HttpResponse:
        return await self.request("HEAD", url, **kw)

    async def options(self, url: str, **kw: Any) -> HttpResponse:
        return await self.request("OPTIONS", url, **kw)

    async def safe_get(self, url: str, **kw: Any) -> HttpResponse | None:
        """GET that returns None instead of raising on a scope violation."""
        try:
            return await self.get(url, **kw)
        except ScopeViolation:
            return None
