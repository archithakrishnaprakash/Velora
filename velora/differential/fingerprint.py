"""Normalized response fingerprints.

A fingerprint captures the *shape* of a response while deliberately discarding values
that legitimately change between two identical requests (dates, request ids, nonces,
CSRF tokens, session identifiers). Without that normalization every comparison would
report a difference and the engine would be useless.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from bs4 import BeautifulSoup

from ..core.http import HttpResponse

# Headers whose values change on every response and carry no comparison value.
VOLATILE_HEADERS: frozenset[str] = frozenset({
    "date", "expires", "last-modified", "etag", "age", "x-request-id", "x-correlation-id",
    "x-trace-id", "x-runtime", "x-amzn-requestid", "x-amz-cf-id", "cf-ray", "report-to",
    "keep-alive", "content-length", "set-cookie", "nel", "server-timing",
})

# Headers that are security-relevant: compare their VALUES, not just their presence.
SECURITY_HEADERS: frozenset[str] = frozenset({
    "content-security-policy", "strict-transport-security", "x-frame-options",
    "x-content-type-options", "referrer-policy", "permissions-policy",
    "access-control-allow-origin", "access-control-allow-credentials", "www-authenticate",
    "cache-control", "location", "content-type",
})

# Body tokens that legitimately vary between otherwise-identical responses.
_VOLATILE_BODY_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),
    re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\b"),
    re.compile(r"(?i)\bcsrf[_-]?token\b\s*[=:]\s*[\"']?[A-Za-z0-9_\-]{8,}"),
    re.compile(r"(?i)\bnonce\b\s*[=:]\s*[\"']?[A-Za-z0-9_\-]{8,}"),
    re.compile(r"\b[0-9a-fA-F]{32,}\b"),
)

# Size buckets (bytes). Small deltas inside a bucket are treated as noise.
_SIZE_BUCKETS = (0, 256, 1024, 4096, 16384, 65536, 262144)

# Timing buckets (ms).
_TIME_BUCKETS = (0, 50, 150, 500, 1500, 5000)


def _bucket(value: float, edges: tuple[int, ...]) -> int:
    idx = 0
    for i, edge in enumerate(edges):
        if value >= edge:
            idx = i
    return idx


def normalize_body(text: str) -> str:
    out = text
    for pattern in _VOLATILE_BODY_PATTERNS:
        out = pattern.sub("<VOLATILE>", out)
    return out


def _json_shape(data: Any, prefix: str = "", depth: int = 0) -> list[str]:
    """Return sorted 'path:type' descriptors for a JSON document (structure, not values)."""
    if depth > 6:
        return [f"{prefix}:<deep>"]
    out: list[str] = []
    if isinstance(data, dict):
        for key in sorted(data.keys()):
            out.extend(_json_shape(data[key], f"{prefix}.{key}" if prefix else str(key), depth + 1))
    elif isinstance(data, list):
        out.append(f"{prefix}[]:len={len(data)}")
        if data:
            out.extend(_json_shape(data[0], f"{prefix}[]", depth + 1))
    else:
        out.append(f"{prefix}:{type(data).__name__}")
    return out


def _html_skeleton(body: str) -> list[str]:
    """Tag skeleton + key landmarks. Ignores text content so wording changes are not diffs."""
    try:
        soup = BeautifulSoup(body, "html.parser")
    except Exception:  # noqa: BLE001 - malformed HTML must never crash a scan
        return []
    tags: dict[str, int] = {}
    for el in soup.find_all(True):
        tags[el.name] = tags.get(el.name, 0) + 1
    skeleton = [f"{name}={count}" for name, count in sorted(tags.items())]
    title = soup.title.get_text(strip=True) if soup.title else ""
    if title:
        skeleton.append(f"title={title[:80]}")
    for form in soup.find_all("form"):
        names = sorted((i.get("name") or "") for i in form.find_all(["input", "select", "textarea"]))
        skeleton.append(f"form:{form.get('method', 'GET').upper()}:{form.get('action', '')}:{','.join(names)}")
    return skeleton


@dataclass
class ResponseFingerprint:
    """A normalized, comparable description of one HTTP response."""

    url: str = ""
    method: str = "GET"
    status_code: int = 0
    content_type: str = ""
    header_names: list[str] = field(default_factory=list)
    security_headers: dict[str, str] = field(default_factory=dict)
    cookie_names: list[str] = field(default_factory=list)
    cookie_flags: dict[str, list[str]] = field(default_factory=dict)
    redirect_target: str = ""
    size_bucket: int = 0
    response_size: int = 0
    timing_bucket: int = 0
    body_kind: str = "other"          # json | html | text | other | empty
    body_shape: list[str] = field(default_factory=list)
    body_hash: str = ""
    auth_challenge: bool = False
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "header_names": self.header_names,
            "security_headers": self.security_headers,
            "cookie_names": self.cookie_names,
            "cookie_flags": self.cookie_flags,
            "redirect_target": self.redirect_target,
            "size_bucket": self.size_bucket,
            "response_size": self.response_size,
            "timing_bucket": self.timing_bucket,
            "body_kind": self.body_kind,
            "body_shape": self.body_shape[:200],
            "body_hash": self.body_hash,
            "auth_challenge": self.auth_challenge,
            "error": self.error,
        }


#: A ", " inside a Set-Cookie value is only a cookie separator when what follows looks
#: like the start of a new ``name=value`` pair. Expires attributes legitimately contain
#: a comma ("Expires=Wed, 21 Oct 2026 ..."), so a blind split would corrupt them.
_COOKIE_JOIN = re.compile(r",\s*(?=[A-Za-z0-9!#$%&\'*+\-.^_`|~]+=)")


def _split_joined_cookies(raw: str) -> list[str]:
    return [part for part in _COOKIE_JOIN.split(raw) if part.strip()]


def _parse_cookies(raw: str | None) -> tuple[list[str], dict[str, list[str]]]:
    if not raw:
        return [], {}
    names: list[str] = []
    flags: dict[str, list[str]] = {}
    # Repeated Set-Cookie headers arrive joined. httpx joins them with ", " and some
    # captures use a newline, so both separators have to be handled — otherwise the
    # second cookie's name is swallowed into the first cookie's attribute list and a
    # cookie swap between baseline and candidate goes unreported.
    if "\n" in raw:
        parts = raw.split("\n")
    else:
        parts = _split_joined_cookies(raw)
    for part in parts:
        segs = [s.strip() for s in part.split(";") if s.strip()]
        if not segs or "=" not in segs[0]:
            continue
        name = segs[0].split("=", 1)[0].strip()
        names.append(name)
        attrs = sorted({s.split("=", 1)[0].strip().lower() for s in segs[1:]})
        flags[name] = attrs
    return sorted(names), flags


def fingerprint_response(resp: HttpResponse) -> ResponseFingerprint:
    """Build a normalized fingerprint from a captured exchange."""
    fp = ResponseFingerprint(
        url=resp.url,
        method=resp.method,
        status_code=resp.status_code,
        content_type=resp.content_type,
        response_size=resp.response_size,
        error=resp.error,
    )
    lowered = {k.lower(): v for k, v in (resp.headers or {}).items()}
    fp.header_names = sorted(k for k in lowered if k not in VOLATILE_HEADERS)
    fp.security_headers = {k: v for k, v in lowered.items() if k in SECURITY_HEADERS}
    fp.cookie_names, fp.cookie_flags = _parse_cookies(resp.header("set-cookie"))
    fp.auth_challenge = "www-authenticate" in lowered or resp.status_code in (401, 403)

    location = lowered.get("location")
    if location:
        parts = urlsplit(location)
        fp.redirect_target = f"{parts.scheme}://{parts.netloc}{parts.path}" if parts.netloc else parts.path

    fp.size_bucket = _bucket(resp.response_size, _SIZE_BUCKETS)
    fp.timing_bucket = _bucket(resp.elapsed_ms, _TIME_BUCKETS)

    body = resp.body or ""
    if not body.strip():
        fp.body_kind = "empty"
        fp.body_hash = ""
        return fp

    normalized = normalize_body(body)
    fp.body_hash = hashlib.sha256(normalized.encode("utf-8", "replace")).hexdigest()[:32]

    ct = (resp.content_type or "").lower()
    if "json" in ct or normalized.lstrip()[:1] in "{[":
        try:
            fp.body_kind = "json"
            fp.body_shape = sorted(_json_shape(json.loads(normalized)))
            return fp
        except (json.JSONDecodeError, ValueError):
            pass
    if "html" in ct or "<html" in normalized[:2000].lower():
        fp.body_kind = "html"
        fp.body_shape = _html_skeleton(normalized)
        return fp
    fp.body_kind = "text"
    fp.body_shape = [f"lines={normalized.count(chr(10))}", f"words={len(normalized.split())}"]
    return fp
