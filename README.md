# Velora

**AI-Assisted Web Application Security Assessment & Validation Platform**

Velora is an evidence-driven platform for assessing web applications you are authorized
to test. It runs deterministic security checks, collects the evidence behind every
detection, models the attack surface as a graph, uses a language model to *explain* that
evidence, and requires a human to confirm anything before it counts as a finding. It
then tracks the fix, verifies it with a targeted retest, and watches for the issue
coming back.

> **Authorized use only.** Velora is for systems you own, explicitly authorized
> assessments, controlled labs, intentionally vulnerable applications, and staging
> environments you control. It records an authorization acknowledgement on every scan.
> That acknowledgement is your statement — Velora cannot verify a right to test.

## What Velora is not

It is not an AI that hacks websites. The AI layer has no HTTP client, no subprocess
path, no access to scope, and no ability to mark a finding as confirmed. Remove it
entirely and Velora still finds, records and reports everything it found.

The distinction is the point of the project:

> **Security evidence first. AI second.**

Deterministic scanner output, HTTP evidence and human validation are the source of
truth. The model helps a person read it faster.

## The lifecycle

```
DISCOVER → MAP → ASSESS → COLLECT EVIDENCE → CORRELATE → AI ANALYSIS
    → HUMAN VALIDATION → RISK → REMEDIATE → RETEST → REGRESSION
    → CI/CD GATE → REPORT
```

## Features

| Area | What it does |
|---|---|
| **Scope enforcement** | Every request passes one gate. SSRF, DNS-rebinding and metadata protection; per-address validation; redirect re-checking. |
| **Recon, crawl, fingerprint** | Same-origin crawling, technology fingerprinting, attack-surface mapping. |
| **Security checks** | 11 deterministic detectors (10 safe-profile) across headers, cookies, TLS, configuration, information disclosure, authentication, authorization and input handling. |
| **Differential analysis** | Structured response comparison with volatile fields normalised away. |
| **Multi-identity authorization testing** | Identity × resource × expectation matrix. Credentials are never stored — only the name of an environment variable. |
| **Evidence-driven AI** | Structured prompts, injection defense, a deterministic evidence matrix that caps confidence. |
| **Attack graph 2.0** | Typed nodes and edges carrying epistemic state, confidence and evidence. Path confidence is the weakest link. |
| **Knowledge graph** | CWE, OWASP, CVSS, CPE mapping — `UNKNOWN` where no defensible mapping exists. |
| **Business-logic workflows** | State machines with security assertions and a step-skip probe. |
| **Benchmark** | Ground-truth measurement with precision, recall, F1, FPR, FNR and coverage. |
| **Remediation and retest** | Fix tracking with coverage-aware verification. |
| **Regression** | Scan-to-scan comparison on stable finding fingerprints. |
| **Security posture** | A Velora-specific aggregate score. Not CVSS. |
| **CI/CD gate** | Exit-code contract, GitHub Actions / GitLab CI / Jenkins. |
| **SARIF 2.1.0** | Endpoint-URI locations — no invented source-code positions. |
| **Reporting** | HTML, JSON, SARIF, PDF. Every finding explained, including what is unknown. |
| **Plugin SDK 2.0** | Declared, validated contracts; lifecycle hooks; config schemas. |
| **Dashboard** | 24 read-only pages over real stored data. |

## Install

```bash
git clone <your-repo> velora && cd velora
./install.sh          # venv, dependencies, database, config, CLI
velora doctor         # verify the installation
```

Requires Python 3.11+. Works on Kali Linux, Debian/Ubuntu, and in Docker. See
[INSTALLATION.md](docs/INSTALLATION.md) and [KALI_SETUP.md](docs/KALI_SETUP.md).

## A first assessment

Against a lab you control:

```bash
# 1. Register the target and its scope
velora target add --name labshop --url http://lab.local:8080/ \
  --authorization LAB_ONLY --allow-private

# 2. Confirm the boundary before you cross it
velora scope validate --target labshop --url http://lab.local:8080/admin

# 3. Scan
velora scan --target labshop --profile safe --operator you --i-am-authorized

# 4. Review, then confirm what is real
velora findings --scan SCAN-XXXXXX
velora finding show WEB-XXXXXX
velora finding validate WEB-XXXXXX --operator you --note "reproduced in a browser"

# 5. Report
velora report --scan SCAN-XXXXXX --format html --format json --format sarif

# 6. Dashboard
velora dashboard          # http://127.0.0.1:8787
```

Full command reference: [CLI.md](docs/CLI.md).

## Security model

Five guarantees carry the design:

1. **Every request passes `ScopePolicy`.** One gate, no bypass, audited refusals.
2. **Only a human confirms a finding.** Everything else produces `Potential`.
3. **Secrets are redacted before storage** — database, logs, reports, AI prompts.
4. **The AI cannot act.** No client, no commands, no scope access, capped confidence.
5. **Nothing is fabricated.** `UNKNOWN` and `Not Assessed` where evidence is absent.

Details: [SECURITY_MODEL.md](docs/SECURITY_MODEL.md),
[SCOPE_MODEL.md](docs/SCOPE_MODEL.md), [THREAT_MODEL.md](docs/THREAT_MODEL.md).

## AI architecture

Provider-abstracted (`null`, `heuristic`, OpenAI-compatible), defaulting to `heuristic`
so Velora runs fully offline and sends nothing anywhere unless configured to. API keys
come from an environment variable named in the config; the value is never stored,
logged or reported.

Target content is untrusted input: prompts use structural separation, per-request nonce
fencing, injection-marker neutralisation and size bounds. A deterministic evidence
matrix caps AI confidence at 0.9 — it cannot reach certainty by construction.

Details: [AI_SECURITY_MODEL.md](docs/AI_SECURITY_MODEL.md).

## Benchmark methodology

Velora measures itself against ground-truth cases in a local lab and reports precision,
recall, F1, false-positive rate, false-negative rate, detection coverage and evidence
completeness.

Two honesty rules govern it. A detection no case describes is an *uncovered detection* —
counted as neither a true nor a false positive, and reported separately, because
counting it either way would be dishonest. True negatives come only from explicit
negative cases, never from "everything the scanner didn't say".

Results describe the measured suite against the measured application. They are not a
detection rate for arbitrary web applications, and Velora does not extrapolate one.

Details: [BENCHMARK.md](docs/BENCHMARK.md).

## Testing

```bash
make test            # pytest if installed, unittest otherwise
```

415 tests across unit, integration, API, CLI, migration and security suites, covering
scope enforcement, differential comparison, authorization logic, AI evidence analysis,
attack-graph construction, remediation verification, regression detection, posture
scoring, benchmark metrics, SARIF generation, CI gate exit codes, prompt-injection
resistance, secret redaction and SSRF resistance. No test touches a public website.

## Limitations

* Automated checks detect indicators. They do not prove exploitability.
* The absence of a finding is not evidence that a target is secure.
* Plugins are not sandboxed; loading one runs its code in the Velora process.
* Velora is single-operator. The dashboard has no authentication and binds to loopback.
* Redaction is pattern-based and not exhaustive.
* The external tool adapters (nmap, ZAP, nuclei) are run explicitly via
  `velora integrations run`; their output is shown, never auto-converted into findings.
* PDF output needs the optional `pdf` extra.

## Roadmap

Honest about what is not built yet:

* Plugin sandboxing in a separate process.
* Multi-operator support with authentication and roles.
* PostgreSQL backend (the repository layer is SQL-agnostic; only SQLite is implemented).
* Richer business-logic modelling beyond linear state machines.
* Benchmark suites for Juice Shop, DVWA and WebGoat beyond the bundled LabShop suite.

## Documentation

| | |
|---|---|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | How the pieces fit |
| [INSTALLATION.md](docs/INSTALLATION.md) · [KALI_SETUP.md](docs/KALI_SETUP.md) | Getting it running |
| [CLI.md](docs/CLI.md) · [API.md](docs/API.md) | Command and endpoint reference |
| [SECURITY_MODEL.md](docs/SECURITY_MODEL.md) · [SCOPE_MODEL.md](docs/SCOPE_MODEL.md) · [THREAT_MODEL.md](docs/THREAT_MODEL.md) | What Velora will and will not do |
| [EVIDENCE_MODEL.md](docs/EVIDENCE_MODEL.md) · [AI_SECURITY_MODEL.md](docs/AI_SECURITY_MODEL.md) | How Velora knows what it claims |
| [DIFFERENTIAL_ANALYSIS.md](docs/DIFFERENTIAL_ANALYSIS.md) · [AUTHORIZATION_TESTING.md](docs/AUTHORIZATION_TESTING.md) · [WORKFLOW_ENGINE.md](docs/WORKFLOW_ENGINE.md) · [ATTACK_GRAPH.md](docs/ATTACK_GRAPH.md) | Assessment subsystems |
| [REMEDIATION.md](docs/REMEDIATION.md) · [REGRESSION.md](docs/REGRESSION.md) · [POSTURE.md](docs/POSTURE.md) · [BENCHMARK.md](docs/BENCHMARK.md) | Lifecycle and measurement |
| [REPORTING.md](docs/REPORTING.md) · [SARIF.md](docs/SARIF.md) · [CI_CD.md](docs/CI_CD.md) | Output and integration |
| [PLUGIN_DEVELOPMENT.md](docs/PLUGIN_DEVELOPMENT.md) | Writing your own checks |
| [V2_UPGRADE_AUDIT.md](docs/V2_UPGRADE_AUDIT.md) | The 1.x → 2.0 audit |

## License

See [LICENSE](LICENSE).
