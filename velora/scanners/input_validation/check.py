"""Input-validation indicator: reflected-parameter detection (light active).

Only runs outside 'safe' mode (standard/lab). It sends a BENIGN, non-executable marker
(random alphanumerics — no HTML, quotes, or script) as a parameter value and checks
whether it is reflected unencoded in the response. This detects a reflection *surface*;
it does NOT attempt XSS/injection and never sends a payload. Results REQUIRE manual
validation.
"""
from __future__ import annotations

import secrets
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ...models.enums import Confidence, Severity
from ..base import CheckOutput, EvidenceItem, ScanContext, SecurityCheck, register


@register
class InputReflectionCheck(SecurityCheck):
    id = "input.reflection"
    name = "Input reflection indicator"
    description = "Detects reflected parameters using a benign non-executable marker (needs review)."
    category = "input_validation"
    severity = Severity.LOW
    safe_mode = False  # light active check; standard/lab profiles only
    references = ["https://owasp.org/www-community/attacks/xss/"]

    async def run(self, ctx: ScanContext) -> list[CheckOutput]:
        if not ctx.crawl:
            return []
        outputs: list[CheckOutput] = []
        tested: set[str] = set()
        for ep in ctx.crawl.endpoints:
            if not ep.parameters:
                continue
            parts = urlsplit(ep.url)
            base_key = f"{parts.path}?{','.join(sorted(ep.parameters))}"
            if base_key in tested:
                continue
            tested.add(base_key)
            marker = "vf" + secrets.token_hex(6)  # benign, alphanumeric only
            pairs = parse_qsl(parts.query, keep_blank_values=True)
            probed = [(k, marker) for k, _ in pairs] or [(p, marker) for p in ep.parameters]
            new_url = urlunsplit((parts.scheme, parts.netloc, parts.path,
                                  urlencode(probed), ""))
            resp = await ctx.client.safe_get(new_url)
            if resp is None or resp.error:
                continue
            if marker in resp.body:
                reflected_params = [k for k, _ in probed]
                outputs.append(
                    CheckOutput(
                        title=f"Reflected parameter(s) at {parts.path}",
                        category=self.category,
                        severity=Severity.LOW,
                        confidence=Confidence.FIRM,
                        endpoint=ep.url,
                        description=(
                            f"Parameter(s) {reflected_params} are reflected unencoded in the "
                            "response. A benign marker was used (no payload). This marks a "
                            "reflection surface that REQUIRES manual validation for XSS; it is "
                            "not proof of a vulnerability."
                        ),
                        impact="Potential reflected-XSS surface — must be manually validated.",
                        remediation=(
                            "Contextually output-encode reflected input and apply a strong CSP."
                        ),
                        references=self.references,
                        evidence=[EvidenceItem(test_name=self.id,
                                               request={"url": new_url, "method": "GET"},
                                               excerpt=f"Benign marker reflected for {reflected_params}.",
                                               status_code=resp.status_code,
                                               confidence=Confidence.FIRM.score)],
                    )
                )
        return outputs
