"""Curated security-knowledge catalog.

Maps Velora's deterministic checks to standard identifiers (CWE, OWASP Top 10 2021).
Every mapping here is hand-verified. Where a check has no defensible standard mapping —
for example the informational ``security.txt`` availability check — the entry is
``UNKNOWN`` rather than an invented identifier.

Identifiers Velora will never synthesize: **CVE** and **CPE**. Those describe specific
published vulnerabilities in specific product versions; Velora's checks observe
configuration and behaviour, not package versions with known advisories. Those fields
stay ``UNKNOWN`` unless an operator or an integration supplies them.
"""
from __future__ import annotations

from dataclasses import dataclass, field

UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class CweEntry:
    cwe_id: str
    title: str
    url: str = ""

    @property
    def reference(self) -> str:
        if self.url:
            return self.url
        number = self.cwe_id.split("-")[-1]
        return f"https://cwe.mitre.org/data/definitions/{number}.html"


@dataclass(frozen=True)
class OwaspEntry:
    category: str
    title: str
    url: str = ""

    @property
    def reference(self) -> str:
        return self.url or "https://owasp.org/Top10/"


# --- CWE entries actually referenced by Velora's checks -------------------
CWE: dict[str, CweEntry] = {
    "CWE-79": CweEntry("CWE-79", "Improper Neutralization of Input During Web Page Generation "
                                 "(Cross-site Scripting)"),
    "CWE-200": CweEntry("CWE-200", "Exposure of Sensitive Information to an Unauthorized Actor"),
    "CWE-209": CweEntry("CWE-209", "Generation of Error Message Containing Sensitive Information"),
    "CWE-269": CweEntry("CWE-269", "Improper Privilege Management"),
    "CWE-285": CweEntry("CWE-285", "Improper Authorization"),
    "CWE-306": CweEntry("CWE-306", "Missing Authentication for Critical Function"),
    "CWE-319": CweEntry("CWE-319", "Cleartext Transmission of Sensitive Information"),
    "CWE-326": CweEntry("CWE-326", "Inadequate Encryption Strength"),
    "CWE-352": CweEntry("CWE-352", "Cross-Site Request Forgery (CSRF)"),
    "CWE-538": CweEntry("CWE-538", "Insertion of Sensitive Information into Externally-Accessible "
                                   "File or Directory"),
    "CWE-548": CweEntry("CWE-548", "Exposure of Information Through Directory Listing"),
    "CWE-614": CweEntry("CWE-614", "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute"),
    "CWE-639": CweEntry("CWE-639", "Authorization Bypass Through User-Controlled Key"),
    "CWE-650": CweEntry("CWE-650", "Trusting HTTP Permission Methods on the Server Side"),
    "CWE-693": CweEntry("CWE-693", "Protection Mechanism Failure"),
    "CWE-1004": CweEntry("CWE-1004", "Sensitive Cookie Without 'HttpOnly' Flag"),
    "CWE-1275": CweEntry("CWE-1275", "Sensitive Cookie with Improper SameSite Attribute"),
}

# --- OWASP Top 10 (2021) categories referenced by Velora ------------------
OWASP: dict[str, OwaspEntry] = {
    "A01:2021": OwaspEntry("A01:2021", "Broken Access Control",
                           "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"),
    "A02:2021": OwaspEntry("A02:2021", "Cryptographic Failures",
                           "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"),
    "A03:2021": OwaspEntry("A03:2021", "Injection",
                           "https://owasp.org/Top10/A03_2021-Injection/"),
    "A05:2021": OwaspEntry("A05:2021", "Security Misconfiguration",
                           "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"),
    "A07:2021": OwaspEntry("A07:2021", "Identification and Authentication Failures",
                           "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"),
}


@dataclass(frozen=True)
class Mapping:
    """A check's standards mapping. ``UNKNOWN`` is a valid, honest answer."""

    cwe_id: str = UNKNOWN
    owasp: str = UNKNOWN
    #: Additional CWEs that may apply depending on the specific observation.
    alternates: tuple[str, ...] = field(default_factory=tuple)
    note: str = ""


# --- check id -> standards mapping ---------------------------------------
CHECK_MAPPINGS: dict[str, Mapping] = {
    "headers.security_headers": Mapping(
        "CWE-693", "A05:2021",
        note="Missing response hardening headers are a protection-mechanism failure."),
    "headers.server_version": Mapping(
        "CWE-200", "A05:2021",
        note="Version banners disclose information useful for targeting."),
    "cookies.attributes": Mapping(
        "CWE-1004", "A05:2021", alternates=("CWE-614", "CWE-1275"),
        note="Primary mapping is HttpOnly; Secure maps to CWE-614 and SameSite to CWE-1275."),
    "tls.configuration": Mapping(
        "CWE-326", "A02:2021",
        note="Weak protocol or cipher selection."),
    "infodisc.indicators": Mapping(
        "CWE-200", "A05:2021", alternates=("CWE-209", "CWE-538"),
        note="Verbose errors map to CWE-209; exposed metadata files to CWE-538."),
    "config.http_methods": Mapping(
        "CWE-650", "A05:2021",
        note="Write-capable or diagnostic HTTP methods left enabled."),
    "config.directory_exposure": Mapping(
        "CWE-548", "A05:2021"),
    "config.security_txt": Mapping(
        UNKNOWN, UNKNOWN,
        note="Absence of a disclosure policy is a best-practice gap, not a weakness class. "
             "No CWE or OWASP category is claimed."),
    "auth.indicators": Mapping(
        "CWE-319", "A02:2021", alternates=("CWE-352",),
        note="Credentials over cleartext map to CWE-319; a missing anti-CSRF token to CWE-352."),
    "authz.consistency": Mapping(
        "CWE-285", "A01:2021",
        note="Indicator only — a name-based heuristic, not a verified authorization test."),
    "input.reflection": Mapping(
        "CWE-79", "A03:2021",
        note="Reflection is a precondition for XSS, not proof of it. The mapping describes "
             "the weakness class under investigation, not a confirmed vulnerability."),
    # Authorization matrix outcomes.
    "authz.matrix": Mapping(
        "CWE-285", "A01:2021", alternates=("CWE-639", "CWE-269", "CWE-306"),
        note="Specific CWE depends on the outcome class; set by the authorization service."),
    "differential.compare": Mapping(
        UNKNOWN, UNKNOWN,
        note="A behavioural difference is not itself a weakness class."),
}

# Outcome-specific mappings used by the authorization service.
AUTHZ_OUTCOME_MAPPINGS: dict[str, Mapping] = {
    "HORIZONTAL_AUTHORIZATION_WEAKNESS": Mapping("CWE-639", "A01:2021"),
    "VERTICAL_AUTHORIZATION_WEAKNESS": Mapping("CWE-269", "A01:2021"),
    "UNAUTHENTICATED_ACCESS": Mapping("CWE-306", "A01:2021"),
    "PRIVILEGE_BOUNDARY_WEAKNESS": Mapping("CWE-285", "A01:2021"),
}


def mapping_for_check(check_id: str) -> Mapping:
    """Return the curated mapping for a check id, or an explicit UNKNOWN mapping."""
    return CHECK_MAPPINGS.get(check_id, Mapping(note="no curated mapping for this check"))


def cwe_entry(cwe_id: str) -> CweEntry | None:
    return CWE.get(cwe_id)


def owasp_entry(category: str) -> OwaspEntry | None:
    # Accept both "A01:2021" and "A01:2021-Broken Access Control".
    key = category.split("-")[0].strip() if category else ""
    return OWASP.get(key)


def references_for(cwe_id: str, owasp: str) -> list[str]:
    """Authoritative reference URLs for a mapping. Empty when nothing is known."""
    refs: list[str] = []
    entry = cwe_entry(cwe_id)
    if entry:
        refs.append(entry.reference)
    owasp_ref = owasp_entry(owasp)
    if owasp_ref:
        refs.append(owasp_ref.reference)
    return refs
