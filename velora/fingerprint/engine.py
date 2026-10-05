"""Signature-driven technology fingerprinting.

Detections are conservative and always carry evidence and a confidence score. A version
is reported only when a signature confidently extracts one from a header or body match.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..core.http import HttpResponse
from ..utils.logging import get_logger

log = get_logger("fingerprint")

_SIG_PATH = Path(__file__).parent / "signatures" / "signatures.yaml"


@dataclass
class TechDetection:
    name: str
    categories: list[str] = field(default_factory=list)
    version: str | None = None
    evidence: str = ""
    confidence: float = 0.5

    def merge(self, other: "TechDetection") -> None:
        self.confidence = max(self.confidence, other.confidence)
        if not self.version and other.version:
            self.version = other.version
        if other.evidence and other.evidence not in self.evidence:
            self.evidence = f"{self.evidence}; {other.evidence}".strip("; ")
        for cat in other.categories:
            if cat not in self.categories:
                self.categories.append(cat)


class FingerprintEngine:
    def __init__(self, signatures: list[dict[str, Any]] | None = None) -> None:
        self.signatures = signatures if signatures is not None else self._load()

    @staticmethod
    def _load() -> list[dict[str, Any]]:
        try:
            data = yaml.safe_load(_SIG_PATH.read_text(encoding="utf-8"))
            return data or []
        except (OSError, yaml.YAMLError) as exc:
            log.warning("failed to load fingerprint signatures: %s", exc)
            return []

    def analyze(
        self, response: HttpResponse, cookies: list[str] | None = None
    ) -> list[TechDetection]:
        cookie_names = _cookie_names(response, cookies)
        results: dict[str, TechDetection] = {}
        for sig in self.signatures:
            name = sig.get("name", "")
            for match in sig.get("matches", []):
                det = self._eval_match(name, sig.get("categories", []), match, response, cookie_names)
                if det is None:
                    continue
                if name in results:
                    results[name].merge(det)
                else:
                    results[name] = det
        return sorted(results.values(), key=lambda d: (-d.confidence, d.name))

    def _eval_match(
        self,
        name: str,
        categories: list[str],
        match: dict[str, Any],
        response: HttpResponse,
        cookie_names: set[str],
    ) -> TechDetection | None:
        mtype = match.get("type")
        conf = float(match.get("confidence", 0.5))
        if mtype == "header_present":
            header = match["header"]
            if response.header(header) is not None:
                return TechDetection(name, list(categories), None, f"{header} header present", conf)
            return None
        if mtype == "header":
            value = response.header(match["header"])
            if value is None:
                return None
            m = re.search(match["regex"], value)
            if not m:
                return None
            version = _extract_version(m, match)
            return TechDetection(
                name, list(categories), version, f"{match['header']}: {value[:80]}", conf
            )
        if mtype == "body":
            if not response.body:
                return None
            m = re.search(match["regex"], response.body)
            if not m:
                return None
            version = _extract_version(m, match)
            return TechDetection(name, list(categories), version, "matched response body", conf)
        if mtype == "cookie":
            if match["cookie"].lower() in cookie_names:
                return TechDetection(name, list(categories), None, f"cookie {match['cookie']}", conf)
            return None
        return None


def _extract_version(match: re.Match[str], spec: dict[str, Any]) -> str | None:
    group = spec.get("version_group")
    if group is None:
        return None
    try:
        return match.group(group) or None
    except IndexError:
        return None


def _cookie_names(response: HttpResponse, extra: list[str] | None) -> set[str]:
    names: set[str] = set()
    set_cookie = response.header("set-cookie")
    if set_cookie:
        for chunk in set_cookie.split(","):
            if "=" in chunk:
                names.add(chunk.split("=", 1)[0].strip().lower())
    for c in extra or []:
        if "=" in c:
            names.add(c.split("=", 1)[0].strip().lower())
    return names
