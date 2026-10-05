# Threat model

This is a threat model for **Velora itself**, not for the applications it assesses. A
security tool processes hostile input by design: every response it reads comes from a
system that may be trying to attack the tool reading it.

## Assets

| Asset | Why it matters |
|---|---|
| Operator credentials for test identities | Compromise gives an attacker the access Velora was given |
| AI provider API key | Billable, and usable to exfiltrate through a third party |
| The findings database | Contains an unremediated map of a real system's weaknesses |
| Reports | Same, in a form designed to be shared |
| The host Velora runs on | Often an operator workstation with access to the target network |
| The operator's authorization boundary | Exceeding it turns an assessment into an incident |

## Trust boundaries

```
  UNTRUSTED                    │  TRUSTED
                               │
  target responses ────────────┼──► redaction ──► evidence store
  target page content ─────────┼──► sanitisation ──► AI prompt
  external tool output ────────┼──► shown to operator, never auto-converted
  plugin code ─────────────────┼──► (NOT a boundary — see below)
                               │
  operator config / CLI input ─┼──► trusted
  the stored database ─────────┼──► trusted (integrity assumed)
```

## Adversaries and what stops them

### A hostile scanned application

This is the primary adversary. It controls every byte Velora reads.

| Attack | Mitigation |
|---|---|
| Redirect to an internal address (SSRF) | Redirects are never auto-followed; `Location` is resolved and re-checked against the full scope policy |
| DNS rebinding | Every resolved address is validated, not just the first; a split answer with one internal address is refused |
| Cloud metadata access | `169.254.0.0/16` and IPv6 link-local blocked, and not waived by `allow_private_targets` |
| Prompt injection via page content | Nonce-fenced untrusted blocks, injection-marker neutralisation, size bounds, structural separation |
| Credential echo via page content | Redaction runs before storage and before the prompt |
| Memory exhaustion | Responses are streamed with a hard download ceiling; the transfer is abandoned past it and the result is flagged `truncated` |
| Endless response / slowloris | Per-request timeout, bounded read, connection cap |
| Header injection / response splitting | Headers are parsed as a mapping; a `\r\n` inside a value stays inside that value |
| Malicious content in a report | The HTML template autoescapes; a finding title containing a `<script>` tag renders as text |
| Resource exhaustion via crawl explosion | Request budget, crawl depth and page caps, concurrency limit, per-worker delay |

### A malicious or careless plugin

**Plugins are not sandboxed.** Loading one executes its Python in the Velora process,
with the operator's privileges. This is stated plainly rather than papered over.

What the loader does provide: contract validation before registration, refusal of
symlinks escaping the named directory, a file-size cap, refusal to shadow a built-in
check id, and refusal of metadata carrying control characters, terminal escapes or
prompt-injection markers. What it does not provide: containment of code that wants to do
harm. The mitigation is procedural — read the plugin.

### A hostile external tool binary

Adapters resolve the executable, refuse to guess, execute argument arrays rather than
shell strings, validate the target against scope first, enforce a timeout, kill the
process group on expiry, and cap captured output. Their output is never auto-converted
into findings.

### A local attacker on the Velora host

Out of scope for the tool's own controls. Velora stores an unremediated weakness map in
a local SQLite file; protect it with filesystem permissions and disk encryption. Do not
run the dashboard as root. Do not expose it without authentication in front of it.

### The operator

Velora cannot distinguish an authorized assessment from an unauthorized one. It records
the acknowledgement, enforces the scope the operator declared, and writes an audit
trail. Those are accountability controls, not authorization controls.

## Explicitly out of scope

* **Plugin sandboxing.** Would require a separate process with reduced privileges.
* **Multi-user access control.** Velora is single-operator. There are no accounts, roles
  or permissions, and the dashboard has no authentication.
* **Database integrity against a local attacker.** Anyone who can write the SQLite file
  can write findings.
* **Protecting the target.** Velora minimises its footprint (safe default profile,
  non-mutating verbs, rate limits) but an assessment is not risk-free. Run it against
  systems you can afford to have disturbed.
* **Network-level anonymity.** Velora identifies itself in its User-Agent, on purpose.

## Residual risks

1. A plugin can do anything the operator can. Accepted; mitigated procedurally.
2. A truncated response makes absence-based reasoning unreliable. Flagged in evidence;
   a reviewer must notice.
3. Redaction is pattern-based. A credential in an unusual format can survive it. The
   patterns cover JWTs (including unsigned), bearer and basic credentials, common vendor
   key prefixes, AWS keys, GitHub PATs, Slack tokens, private-key blocks, and sensitive
   key/value pairs — but the set is not exhaustive.
4. Scope depends on correct resolution. A compromised resolver could in principle answer
   differently between the check and the connection. The per-address validation narrows
   this but does not eliminate it.
5. The AI provider, if configured to a remote service, receives sanitised evidence.
   Evidence is not secret material, but it does describe a real system's weaknesses.
   The `heuristic` default sends nothing anywhere.

## Testing

`tests/security/` covers scope bypass, SSRF and DNS rebinding, redirect bypass,
IPv4/IPv6 and CIDR edge cases, path traversal, command and argument injection, prompt
injection across nine attack classes, secret redaction and credential logging, unsafe
deserialization, oversized and hostile responses, resource exhaustion, concurrency and
rate limits, and malicious plugin metadata.
