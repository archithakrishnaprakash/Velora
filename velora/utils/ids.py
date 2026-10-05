"""Deterministic-ish human-readable identifiers used across the framework."""
from __future__ import annotations

import secrets
import time

_ALPHABET = "ABCDEFGHJKMNPQRSTVWXYZ23456789"  # no ambiguous chars


def _token(n: int = 6) -> str:
    return "".join(secrets.choice(_ALPHABET) for _ in range(n))


def new_id(prefix: str) -> str:
    """Return an id like 'SCAN-LX3F9A' or 'WEB-7QK2MN'."""
    return f"{prefix.upper()}-{_token()}"


def timestamp_id(prefix: str) -> str:
    """Return a sortable id like 'SCAN-20260922-LX3F9A'."""
    day = time.strftime("%Y%m%d", time.gmtime())
    return f"{prefix.upper()}-{day}-{_token()}"
