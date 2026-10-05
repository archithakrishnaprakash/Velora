"""Async crawler with strict scope and origin control.

Features: configurable depth and page budget, concurrency control, URL and
parameter-signature de-duplication, form discovery, API/JS resource discovery, and
redirect tracking. Out-of-scope links are never requested (the ScopeManager blocks
them) and off-origin links are recorded but not followed.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from ..core.http import HttpResponse, SafeHTTPClient
from ..utils.errors import RateLimitExceeded, ScopeViolation
from ..utils.logging import get_logger
from ..utils.urlutil import normalize_url, param_signature, same_origin

log = get_logger("crawler")


@dataclass
class DiscoveredEndpoint:
    url: str
    method: str = "GET"
    status_code: int | None = None
    content_type: str = ""
    response_size: int = 0
    parent_url: str | None = None
    parameters: list[str] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    is_api: bool = False
    depth: int = 0


@dataclass
class CrawlResult:
    endpoints: list[DiscoveredEndpoint] = field(default_factory=list)
    off_origin_links: list[str] = field(default_factory=list)
    js_resources: list[str] = field(default_factory=list)
    api_endpoints: list[str] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    pages_fetched: int = 0
    blocked: int = 0


class Crawler:
    def __init__(
        self,
        client: SafeHTTPClient,
        *,
        max_depth: int = 3,
        max_pages: int = 200,
        concurrency: int | None = None,
    ) -> None:
        self.client = client
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.concurrency = concurrency or client.scope.policy.max_concurrency
        self._seen_urls: set[str] = set()
        self._seen_param_sigs: set[str] = set()
        self._seen_form_sigs: set[tuple] = set()

    async def crawl(self, start_url: str) -> CrawlResult:
        result = CrawlResult()
        origin = start_url
        queue: asyncio.Queue[tuple[str, int, str | None]] = asyncio.Queue()
        await queue.put((normalize_url(start_url), 0, None))
        self._seen_urls.add(normalize_url(start_url))
        sem = asyncio.Semaphore(self.concurrency)
        stop = asyncio.Event()

        async def worker() -> None:
            while not stop.is_set():
                try:
                    url, depth, parent = await asyncio.wait_for(queue.get(), timeout=0.2)
                except asyncio.TimeoutError:
                    if queue.empty():
                        return
                    continue
                try:
                    if result.pages_fetched >= self.max_pages:
                        stop.set()
                        queue.task_done()
                        return
                    async with sem:
                        await self._visit(url, depth, parent, origin, result, queue)
                finally:
                    queue.task_done()

        workers = [asyncio.create_task(worker()) for _ in range(self.concurrency)]
        await queue.join()
        stop.set()
        for w in workers:
            w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
        return result

    async def _visit(
        self,
        url: str,
        depth: int,
        parent: str | None,
        origin: str,
        result: CrawlResult,
        queue: asyncio.Queue,
    ) -> None:
        try:
            resp = await self.client.get(url)
        except ScopeViolation:
            result.blocked += 1
            return
        except RateLimitExceeded:
            return

        if resp.error:
            return
        result.pages_fetched += 1

        params = sorted({k for k in _query_names(resp.final_url)})
        endpoint = DiscoveredEndpoint(
            url=url,
            method="GET",
            status_code=resp.status_code,
            content_type=resp.content_type,
            response_size=resp.response_size,
            parent_url=parent,
            parameters=params,
            is_api=_looks_like_api(resp),
            depth=depth,
        )
        if endpoint.is_api and url not in result.api_endpoints:
            result.api_endpoints.append(url)

        if "html" in resp.content_type and depth < self.max_depth:
            links, forms, js, apis = self._extract(resp, url)
            endpoint.forms = forms
            for form in forms:
                sig = (form.get("action"), form.get("method"),
                       tuple(sorted(i.get("name") or "" for i in form.get("inputs", []))))
                if sig not in self._seen_form_sigs:
                    self._seen_form_sigs.add(sig)
                    result.forms.append(form)
            for src in js:
                if src not in result.js_resources:
                    result.js_resources.append(src)
            for api in apis:
                if api not in result.api_endpoints:
                    result.api_endpoints.append(api)
            for link in links:
                self._enqueue(link, depth + 1, url, origin, result, queue)

        result.endpoints.append(endpoint)

    def _enqueue(
        self,
        link: str,
        depth: int,
        parent: str,
        origin: str,
        result: CrawlResult,
        queue: asyncio.Queue,
    ) -> None:
        if not link.lower().startswith(("http://", "https://")):
            return
        if not same_origin(link, origin):
            if link not in result.off_origin_links:
                result.off_origin_links.append(link)
            return
        norm = normalize_url(link)
        sig = param_signature(link)
        if norm in self._seen_urls:
            return
        # Collapse many value-variations of the same parameterized endpoint.
        if sig in self._seen_param_sigs and _query_names(link):
            return
        self._seen_urls.add(norm)
        if _query_names(link):
            self._seen_param_sigs.add(sig)
        if len(self._seen_urls) <= self.max_pages * 3:
            queue.put_nowait((norm, depth, parent))

    def _extract(
        self, resp: HttpResponse, base: str
    ) -> tuple[list[str], list[dict], list[str], list[str]]:
        soup = BeautifulSoup(resp.body, "html.parser")
        links: list[str] = []
        for a in soup.find_all("a", href=True):
            links.append(urljoin(base, a["href"]))
        js: list[str] = []
        for script in soup.find_all("script", src=True):
            js.append(urljoin(base, script["src"]))
        forms: list[dict] = []
        for form in soup.find_all("form"):
            action = urljoin(base, form.get("action") or base)
            method = (form.get("method") or "GET").upper()
            inputs = [
                {"name": i.get("name"), "type": i.get("type", "text")}
                for i in form.find_all(["input", "textarea", "select"])
                if i.get("name")
            ]
            forms.append({"action": action, "method": method, "inputs": inputs})
        # Heuristic API endpoint discovery from inline JS.
        apis = _api_hints(resp.body, base)
        return links, forms, js, apis


def _query_names(url: str) -> list[str]:
    from urllib.parse import parse_qsl

    return [k for k, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)]


def _looks_like_api(resp: HttpResponse) -> bool:
    ct = resp.content_type.lower()
    return "json" in ct or "/api/" in urlsplit(resp.url).path.lower() or ct.endswith("+json")


def _api_hints(body: str, base: str) -> list[str]:
    import re

    hints: set[str] = set()
    for m in re.finditer(r"[\"'](/api/[A-Za-z0-9_\-/]+)[\"']", body):
        hints.add(urljoin(base, m.group(1)))
    return sorted(hints)
