"""Structured logging with a custom SECURITY level.

Log levels: DEBUG, INFO, WARNING, ERROR, and a custom SECURITY level (between
ERROR and CRITICAL) reserved for security-relevant events such as blocked
out-of-scope requests and secret redaction. Records are emitted as plain text to
the console and (optionally) as JSON lines to a file so they can be shipped to a
SIEM. All messages pass through redaction before emission.
"""
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .redaction import redact_text

SECURITY_LEVEL = 45
logging.addLevelName(SECURITY_LEVEL, "SECURITY")

_CONFIGURED = False


def security(self: logging.Logger, message: str, *args: Any, **kwargs: Any) -> None:
    if self.isEnabledFor(SECURITY_LEVEL):
        self._log(SECURITY_LEVEL, message, args, **kwargs)


# Attach .security() to the Logger class once.
logging.Logger.security = security  # type: ignore[attr-defined]


class RedactingFormatter(logging.Formatter):
    """Console formatter that redacts secrets from the final message."""

    def format(self, record: logging.LogRecord) -> str:
        formatted = super().format(record)
        return redact_text(formatted)


class JsonLinesFormatter(logging.Formatter):
    """Emit one JSON object per line for machine ingestion (SIEM-friendly)."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": redact_text(record.getMessage()),
        }
        for key in ("event", "target", "scan_id", "url"):
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = redact_text(str(value))
        if record.exc_info:
            payload["exc"] = redact_text(self.formatException(record.exc_info))
        return json.dumps(payload, ensure_ascii=False)


def configure_logging(
    level: str = "INFO",
    *,
    json_file: str | Path | None = None,
    force: bool = False,
) -> None:
    """Configure root logging once. Idempotent unless ``force`` is set."""
    global _CONFIGURED
    if _CONFIGURED and not force:
        return

    root = logging.getLogger("velora")
    root.handlers.clear()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.propagate = False

    console = logging.StreamHandler(stream=sys.stderr)
    console.setFormatter(RedactingFormatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
    root.addHandler(console)

    if json_file:
        path = Path(json_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(path, encoding="utf-8")
        file_handler.setFormatter(JsonLinesFormatter())
        root.addHandler(file_handler)

    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """Return a namespaced child logger (e.g. ``velora.scope``)."""
    if not name.startswith("velora"):
        name = f"velora.{name}"
    return logging.getLogger(name)
