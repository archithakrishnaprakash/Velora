"""URL normalization and helpers used by scope, crawler, and dedup.

Normalization is deliberately conservative and security-relevant: it is used both
for de-duplication and as an input to scope decisions, so it must not accidentally
widen scope (e.g. by dropping the host or scheme).
"""
from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

DEFAULT_PORTS: dict[str, int] = {"http": 80, "https": 443}

# Query parameters that are pure tracking noise and safe to drop for dedup.
_TRACKING_PARAMS: frozenset[str] = frozenset(
    {"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "gclid", "fbclid"}
)


def normalize_host(host: str) -> str:
    """L-case host, strip a trailing dot, and IDNA-encode where possible."""
    host = (host or "").strip().rstrip(".").lower()
    try:
        return host.encode("idna").decode("ascii") if host else host
    except (UnicodeError, ValueError):
        return host


def default_port_for(scheme: str) -> int | None:
    return DEFAULT_PORTS.get(scheme.lower())


def effective_port(scheme: str, port: int | None) -> int | None:
    """Return the port, filling in the scheme default when unspecified."""
    if port is not None:
        return port
    return default_port_for(scheme)


def normalize_url(
    url: str,
    *,
    drop_fragment: bool = True,
    sort_query: bool = True,
    drop_tracking: bool = True,
) -> str:
    """Return a canonical form of ``url`` suitable for de-duplication.

    - lowercases scheme and host
    - removes default ports
    - optionally drops the fragment and tracking params
    - optionally sorts query parameters for stable comparison
    """
    parts = urlsplit(url.strip())
    scheme = parts.scheme.lower()
    host = normalize_host(parts.hostname or "")

    userinfo = ""
    if parts.username:
        userinfo = parts.username
        if parts.password:
            userinfo += f":{parts.password}"
        userinfo += "@"

    netloc = f"{userinfo}{host}"
    port = parts.port
    if port is not None and default_port_for(scheme) != port:
        netloc += f":{port}"

    path = parts.path or "/"
    # Collapse duplicate slashes but preserve a single leading slash.
    while "//" in path:
        path = path.replace("//", "/")

    query = ""
    if parts.query:
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        if drop_tracking:
            pairs = [(k, v) for k, v in pairs if k.lower() not in _TRACKING_PARAMS]
        if sort_query:
            pairs = sorted(pairs)
        query = urlencode(pairs)

    fragment = "" if drop_fragment else parts.fragment
    return urlunsplit((scheme, netloc, path, query, fragment))


def param_signature(url: str) -> str:
    """A signature of (path + parameter *names*) ignoring values.

    Used to avoid crawling the same endpoint many times with different values
    (e.g. /item?id=1, /item?id=2 collapse to one attack-surface endpoint).
    """
    parts = urlsplit(url)
    names = sorted({k for k, _ in parse_qsl(parts.query, keep_blank_values=True)})
    host = normalize_host(parts.hostname or "")
    return f"{parts.scheme.lower()}://{host}{parts.path}?{'&'.join(names)}"


def same_origin(a: str, b: str) -> bool:
    """True when scheme, host, and effective port all match."""
    pa, pb = urlsplit(a), urlsplit(b)
    return (
        pa.scheme.lower() == pb.scheme.lower()
        and normalize_host(pa.hostname or "") == normalize_host(pb.hostname or "")
        and effective_port(pa.scheme, pa.port) == effective_port(pb.scheme, pb.port)
    )
