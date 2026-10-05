# Scope model

Scope is the boundary between an authorized assessment and an attack. Everything else
in Velora is built on the assumption that this boundary holds, so it is enforced in one
place, on every request, with no way around it.

```
caller (crawler / check / plugin / workflow / AI plan / integration)
        │
        ▼
ScopeManager.authorize(url)   ← consumes budget, raises on refusal
        │
        ▼
SafeHTTPClient  ──────────────► the network
```

There is no second path. A component does not get its own HTTP client; it receives the
scan's scope-gated one. A refusal raises `ScopeViolation` and writes an audit event.

## The checks, in order

`ScopeManager.check(url)` runs these in sequence and stops at the first refusal. The
order matters: the cheap structural checks run before anything that resolves DNS.

| # | Check | Refusal reason |
|---|---|---|
| 1 | URL parses | `malformed-url` |
| 2 | Scheme and host present | `missing-scheme-or-host` |
| 3 | Scheme is allowed | `scheme-not-allowed:<scheme>` |
| 4 | Port is allowed | `port-not-allowed:<port>` |
| 5 | Path is not excluded | `path-excluded:<path>` |
| 6 | Literal IP is in `allowed_ips` | `ip-not-in-scope:<host>` |
| 7 | Named host matches `allowed_domains` | `domain-not-in-scope:<host>` |
| 8 | Host resolves at all | `dns-resolution-failed:<host>` |
| 9 | **Every** resolved address passes the SSRF guard | `metadata-address-blocked:<ip>`, `private-or-reserved-address-blocked:<ip>` |
| 10 | Every resolved address is inside `allowed_ips`, when pinned | `resolved-address-outside-allowed-ips:<ip>` |

`authorize(url)` wraps `check()`, consumes one unit of request budget, logs a refusal as
`OUT_OF_SCOPE_REQUEST_BLOCKED`, and raises.

## Policy fields

| Field | Meaning |
|---|---|
| `allowed_domains` | Named hosts in scope. Suffix matching is exact-label, so `evil-lab.local` does not match `lab.local`. |
| `allowed_ips` | Literal addresses and CIDRs. When non-empty, they also constrain what a named host may resolve to. |
| `allowed_ports` | Ports that may be contacted. |
| `allowed_schemes` | Defaults to `http`, `https`. |
| `excluded_paths` | Paths the operator has ruled out. Matched after normalisation — see below. |
| `max_requests` | Total request budget for the scan. |
| `max_concurrency` | Simultaneous connections. |
| `request_delay` | Per-worker delay between requests. |
| `timeout` | Per-request timeout. |
| `redirect_policy` | `never`, `same-scope`, or `same-origin`. |
| `allow_private_targets` | Opt-in for RFC1918 and loopback. Off by default. |
| `block_cloud_metadata` | Blocks known metadata endpoints. On by default. |

## Design decisions worth knowing

**Every resolved address is validated, not just the first.** A host that answers with
one public address and one internal address is refused. Checking only the first answer
is how a split-horizon or rebinding setup gets a scanner to reach an internal service.

**Link-local is blocked even in lab mode.** `169.254.0.0/16` and IPv6 `fe80::/10` are
where cloud metadata services live. Allowing a private lab target is a statement about
RFC1918, not a reason to expose IMDS, so the metadata guard is not waived by
`allow_private_targets`.

**Pinned IPs constrain named hosts too.** If the operator listed `allowed_ips`, a domain
in scope that resolves outside that range is refused. Without this, pinning addresses
would be advisory.

**Excluded paths survive the obvious spellings.** An exclusion is the operator saying
"do not touch this", so `/admin`, `/./admin`, `/x/../admin`, `/ADMIN`, `/%61dmin` and
`/%2561dmin` all match a `/admin` rule. The path is percent-decoded (twice, to catch
double-encoding), dot segments are resolved, and comparison is case-insensitive.

**Redirects are re-checked, never followed blindly.** The client never lets httpx follow
a redirect. It reads `Location`, resolves it, and runs the redirect policy plus the full
scope check against the target. An in-scope page cannot bounce the scanner somewhere
else. A request body is never replayed across a redirect.

**The budget is consumed at authorization, not at send.** A refused request increments
the blocked counter, not the request counter, so the audit trail distinguishes what was
attempted from what was sent.

## What scope does not do

Scope enforces a boundary. It cannot tell you whether you are allowed to test what is
inside it — only you know that. Velora records an authorization acknowledgement against
every scan and prints it in every report, but a recorded acknowledgement is a statement
by the operator, not a verification by the tool.

## Checking a policy

```bash
velora scope validate --target labshop --url http://lab.local/admin
velora scope validate --target labshop --url http://169.254.169.254/latest/meta-data/
```

Tests: `tests/security/test_scope_bypass.py`, `tests/security/test_scope_ssrf.py`,
`tests/security/test_hardening.py`.
