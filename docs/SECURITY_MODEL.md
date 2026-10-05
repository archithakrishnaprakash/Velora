# Security model

Velora is an assessment platform, not an attack tool. This document states what it is
for, what it deliberately will not do, and where the guarantees actually come from.

## Authorized use only

Velora is built for:

* systems you own
* explicitly authorized security assessments
* controlled security labs
* intentionally vulnerable applications
* staging and test environments you control

Running it against anything else is likely illegal in most jurisdictions and is not what
the tool is for. Every scan records an authorization acknowledgement and prints it in
the report. That acknowledgement is a statement **by the operator**; Velora cannot
verify a right to test and does not pretend to.

## What Velora deliberately does not implement

None of the following exists in the codebase, and none is planned:

* credential theft or harvesting
* persistence or backdoors
* malware, ransomware, or destructive payloads
* stealth, evasion, or anti-forensics
* botnet or C2 functionality
* denial-of-service generation
* mass scanning of arbitrary internet targets

The scanners observe and report. `PUT`, `PATCH`, `DELETE`, `CONNECT` and `TRACE` cannot
be issued by a plugin at all — the SDK refuses to register one that declares them.

## The five load-bearing guarantees

**1. Every request passes ScopePolicy.** There is one gate,
`ScopeManager.authorize(url)`, and no component has its own HTTP client. A refusal
raises and writes `OUT_OF_SCOPE_REQUEST_BLOCKED`. Crawler, checks, plugins, workflows,
the planner and the external-tool adapters all go through it. See
[SCOPE_MODEL.md](SCOPE_MODEL.md).

**2. Only a human confirms a finding.** Findings enter at `Potential`. No check, plugin,
correlation rule or AI response can change that; `velora finding validate` can, and it
requires an operator name. See [EVIDENCE_MODEL.md](EVIDENCE_MODEL.md).

**3. Secrets are redacted before storage.** Response bodies, headers, URLs, logs, audit
events, reports and AI prompts all pass through redaction. Credentials are referenced by
environment-variable *name*, never stored. `tests/security/test_secret_persistence.py`
reads the database as raw bytes to check.

**4. The AI cannot act.** It has no client, no subprocess path, no scope access, and no
way to confirm a finding. Its confidence is capped by a deterministic evidence matrix.
See [AI_SECURITY_MODEL.md](AI_SECURITY_MODEL.md).

**5. Nothing is fabricated.** Where a CWE, OWASP category, CVSS vector or CVE cannot be
established from evidence, Velora writes `UNKNOWN` or `Not Assessed`. It never derives a
CVE from a version string, never synthesises a CVSS vector, and never publishes a
CVSS-like `security-severity` it did not compute from a real vector.

## Defaults

| Default | Value | Reason |
|---|---|---|
| Scan profile | `safe` | Passive and non-mutating checks only |
| Private/loopback targets | blocked | Opt-in per target, for labs |
| Cloud metadata | blocked | Not waived by the private-target opt-in |
| Redirects | not followed automatically | Re-checked against scope first |
| Dashboard bind | `127.0.0.1` | Not reachable off-host without a deliberate change |
| AI provider | `heuristic` | No network, no third party, works offline |
| AI confirmation | disabled | And ineffective even if enabled |
| TLS verification | on | |

## Running the dashboard

The dashboard is **read-only**. It renders stored data; it cannot start a scan, validate
a finding, approve a plan, or change configuration. Those actions live in the CLI, where
authorization acknowledgement, scope enforcement and audit logging apply.

Do not run it as root, and do not expose it without putting authentication in front of
it — it has none of its own. It binds to loopback by default for that reason. It sets
`Content-Security-Policy: default-src 'none'`, `X-Frame-Options: DENY`,
`X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control:
no-store` and a restrictive `Permissions-Policy`. CORS is off unless origins are
explicitly configured, and `*` is refused.

## Audit trail

Structured, append-only events cover the security-relevant transitions:

`SCAN_STARTED`, `SCAN_COMPLETED`, `OUT_OF_SCOPE_REQUEST_BLOCKED`, `FINDING_CREATED`,
`finding_validated`, `finding_rejected`, `AI_ANALYSIS_CREATED`, `PLAN_CREATED`,
`PLAN_APPROVED`, `AUTHZ_TEST_EXECUTED`, `RETEST_STARTED`, `RETEST_COMPLETED`,
`REGRESSION_DETECTED`, `security_gate_passed`, `security_gate_failed`,
`security_gate_error`, `report_generated`, `PLUGIN_LOADED`, `PLUGIN_LOAD_REJECTED`.

URLs are redacted before they reach a log line, because a blocked request is often the
one carrying a token in its query string.

## Plugins and external tools

Loading a plugin executes its Python in the Velora process. The loader validates each
SDK plugin's declared contract, refuses symlinks that escape the named directory, caps
file size, and refuses a plugin that would shadow a built-in check. **None of that
sandboxes hostile code** — read a plugin before you load it, as you would any other code
you are about to run. See [PLUGIN_DEVELOPMENT.md](PLUGIN_DEVELOPMENT.md).

External tool adapters (nmap, ZAP, nuclei) execute argument arrays, never shell strings,
validate the target against scope first, run under a timeout, and kill the process group
on expiry. Their output is shown to the operator and is **not** auto-converted into
Velora findings — a third-party tool's claim is that tool's claim.

## Reporting a security issue in Velora itself

Velora's own hardening is tested in `tests/security/`: SSRF, DNS rebinding, scope and
redirect bypass, IPv4/IPv6 and CIDR edge cases, path traversal, command and argument
injection, prompt injection, secret redaction and credential logging, unsafe
deserialization, oversized responses, resource exhaustion, concurrency and rate limits,
and malicious plugin metadata. See [THREAT_MODEL.md](THREAT_MODEL.md) for what is in and
out of scope for that work.
