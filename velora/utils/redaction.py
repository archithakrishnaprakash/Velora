"""Secret redaction engine.

Every value that leaves the scanner boundary (persisted evidence, logs, reports)
passes through redaction so that credentials, tokens, and session material are never
stored in the clear. Redaction is deterministic and conservative: when in doubt, redact.
"""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from typing import Any

REDACTED = "[REDACTED]"

# Header names whose values must always be masked.
SENSITIVE_HEADERS: frozenset[str] = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "x-amz-security-token",
        "x-csrf-token",
        "www-authenticate",
    }
)

# Query/body/form parameter names (case-insensitive) whose values must be masked.
SENSITIVE_PARAM_NAMES: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "api_key",
        "apikey",
        "auth",
        "session",
        "sessionid",
        "sid",
        "otp",
        "private_key",
        "client_secret",
    }
)

# Patterns for secrets embedded in free text (response excerpts, JSON blobs).
_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # JWT: three base64url segments separated by dots. The signature segment may be
    # short or empty (an `alg: none` token ends in a bare dot), so it is not given a
    # minimum length — a token is still a token when it is unsigned.
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")),
    # A bearer credential in free text, whatever its shape.
    ("bearer", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}")),
    ("basic_auth", re.compile(r"(?i)\bBasic\s+[A-Za-z0-9+/=]{12,}")),
    # Common vendor API-key prefixes.
    ("api_key", re.compile(r"\b(?:sk|pk|rk|api|key)[-_](?:live|test|prod)?[-_]?[A-Za-z0-9]{16,}\b")),
    ("aws_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_pat", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    # key=value / "key": "value" pairs where the key name is sensitive.
    (
        "kv_pair",
        re.compile(
            r"(?i)\b(" + "|".join(sorted(SENSITIVE_PARAM_NAMES)) + r")\b\s*[=:]\s*"
            r"([\"']?)([^\s\"'&,;]{3,})\2"
        ),
    ),
)


def redact_text(text: str | None) -> str:
    """Redact secrets from a free-text string (response body excerpts, JSON, etc.)."""
    if not text:
        return text or ""
    out = text
    for name, pattern in _PATTERNS:
        if name == "kv_pair":
            out = pattern.sub(lambda m: f"{m.group(1)}={REDACTED}", out)
        else:
            out = pattern.sub(REDACTED, out)
    return out


def redact_headers(headers: dict[str, Any] | None) -> dict[str, str]:
    """Return a copy of ``headers`` with sensitive header values masked."""
    if not headers:
        return {}
    result: dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() in SENSITIVE_HEADERS:
            result[key] = REDACTED
        else:
            result[key] = redact_text(str(value))
    return result


def redact_params(params: dict[str, Any] | None) -> dict[str, str]:
    """Return a copy of query/form params with sensitive values masked."""
    if not params:
        return {}
    result: dict[str, str] = {}
    for key, value in params.items():
        if key.lower() in SENSITIVE_PARAM_NAMES:
            result[key] = REDACTED
        else:
            result[key] = redact_text(str(value))
    return result


def redact_url(url: str | None) -> str:
    """Return ``url`` with credentials and sensitive query values masked.

    URLs reach logs, audit events, reports and error messages, and a query string is a
    common place for a token to sit (``?access_token=...``). Anything printed or stored
    should go through this first. The path and the non-sensitive parameters are kept,
    because an audit trail that cannot say *what* was requested is not an audit trail.
    """
    if not url:
        return url or ""
    try:
        parts = urlsplit(url)
    except ValueError:
        return REDACTED

    netloc = parts.netloc
    if "@" in netloc:
        # userinfo in the authority is a credential by definition.
        netloc = REDACTED + "@" + netloc.rsplit("@", 1)[1]

    query = parts.query
    if query:
        rebuilt: list[str] = []
        for key, value in parse_qsl(query, keep_blank_values=True):
            if key.lower() in SENSITIVE_PARAM_NAMES:
                rebuilt.append((key, REDACTED))
            else:
                rebuilt.append((key, redact_text(value)))
        query = urlencode(rebuilt, safe="[]")

    fragment = redact_text(parts.fragment) if parts.fragment else parts.fragment
    return urlunsplit((parts.scheme, netloc, redact_text(parts.path), query, fragment))


def redact_mapping(data: Any) -> Any:
    """Recursively redact secrets in nested dict/list structures (e.g. JSON evidence)."""
    if isinstance(data, dict):
        out: dict[Any, Any] = {}
        for key, value in data.items():
            if isinstance(key, str) and key.lower() in SENSITIVE_PARAM_NAMES:
                out[key] = REDACTED
            else:
                out[key] = redact_mapping(value)
        return out
    if isinstance(data, list):
        return [redact_mapping(item) for item in data]
    if isinstance(data, str):
        return redact_text(data)
    return data
