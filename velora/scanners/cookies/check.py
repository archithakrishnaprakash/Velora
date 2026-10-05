"""Insecure cookie attribute / session configuration check (passive)."""
from __future__ import annotations

from ...models.enums import Confidence, Severity
from ..base import CheckOutput, EvidenceItem, ScanContext, SecurityCheck, register

_SESSION_HINTS = ("sess", "sid", "auth", "token", "jwt")


def _parse_set_cookie(raw: str) -> list[dict]:
    cookies = []
    # Set-Cookie values may be joined by newlines (httpx) or by ", " (rare, ambiguous).
    parts = raw.split("\n") if "\n" in raw else [raw]
    for part in parts:
        segs = [s.strip() for s in part.split(";") if s.strip()]
        if not segs:
            continue
        name = segs[0].split("=", 1)[0].strip()
        attrs = {s.split("=", 1)[0].strip().lower() for s in segs[1:]}
        samesite = next((s.split("=", 1)[1].strip() for s in segs[1:]
                         if s.lower().startswith("samesite=")), None)
        cookies.append({
            "name": name,
            "httponly": "httponly" in attrs,
            "secure": "secure" in attrs,
            "samesite": samesite,
        })
    return cookies


@register
class CookieSecurityCheck(SecurityCheck):
    id = "cookies.attributes"
    name = "Insecure cookie attributes"
    description = "Flags cookies missing HttpOnly / Secure / SameSite, especially session cookies."
    category = "session"
    severity = Severity.MEDIUM
    safe_mode = True
    references = [
        "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
        "https://owasp.org/www-community/controls/SecureCookieAttribute",
    ]

    async def run(self, ctx: ScanContext) -> list[CheckOutput]:
        # Check the base target and any discovered endpoints that set cookies.
        urls = [ctx.target]
        if ctx.crawl:
            urls += [e.url for e in ctx.crawl.endpoints if e.url != ctx.target]
        urls = urls[:15]
        outputs: list[CheckOutput] = []
        seen_names: set[str] = set()
        for url in urls:
            resp = await ctx.client.safe_get(url)
            if resp is None or resp.error:
                continue
            raw = resp.header("set-cookie")
            if not raw:
                continue
            is_https = url.lower().startswith("https://")
            for cookie in _parse_set_cookie(raw):
                if cookie["name"] in seen_names:
                    continue
                seen_names.add(cookie["name"])
                problems = []
                if not cookie["httponly"]:
                    problems.append("HttpOnly")
                if is_https and not cookie["secure"]:
                    problems.append("Secure")
                if not cookie["samesite"]:
                    problems.append("SameSite")
                if not problems:
                    continue
                looks_session = any(h in cookie["name"].lower() for h in _SESSION_HINTS)
                sev = Severity.MEDIUM if looks_session else Severity.LOW
                ev = EvidenceItem(
                    test_name=self.id,
                    request=resp.evidence_request(),
                    response=resp.evidence_response(),
                    headers={"set-cookie": "[REDACTED]"},
                    status_code=resp.status_code,
                    excerpt=(
                        f"Cookie '{cookie['name']}' missing attribute(s): "
                        f"{', '.join(problems)} (value redacted)."
                    ),
                    confidence=Confidence.CERTAIN.score,
                )
                outputs.append(
                    CheckOutput(
                        title=f"Insecure cookie attributes: {cookie['name']}",
                        category=self.category,
                        severity=sev,
                        confidence=Confidence.CERTAIN,
                        endpoint=resp.final_url,
                        description=(
                            f"The cookie '{cookie['name']}' is set without "
                            f"{', '.join(problems)}. "
                            "Session cookies without these attributes are exposed to theft via "
                            "XSS (HttpOnly), plaintext transport (Secure), or cross-site requests (SameSite)."
                        ),
                        impact="Increases risk of session hijacking and CSRF.",
                        remediation=(
                            "Set HttpOnly and SameSite on all cookies, and Secure on all "
                            "cookies served over HTTPS. Prefer SameSite=Lax or Strict."
                        ),
                        references=self.references,
                        evidence=[ev],
                    )
                )
        return outputs
