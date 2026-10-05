# Reporting

A Velora report has one job beyond listing findings: to make clear what is *not* known.
A report that only states what was found invites the reader to treat silence as safety.

## Formats

```bash
velora report --scan SCAN-XXXXXX --format html --format json --format sarif
velora report --scan SCAN-XXXXXX --format pdf --output-dir ./reports
```

| Format | Use |
|---|---|
| `html` | The human deliverable. Self-contained, dark-themed, printable. |
| `json` | The machine-readable context — everything the HTML renders, plus more. |
| `sarif` | Tooling interoperability. See [SARIF.md](SARIF.md). |
| `pdf` | Requires the `pdf` extra (WeasyPrint). |

If a requested format cannot be produced, Velora says so and exits non-zero. A PDF
request that silently degrades to HTML would let a pipeline proceed as though it got a
PDF.

## Report structure

Cover · Executive summary · Scope and authorization · Scope policy in force ·
Methodology · Attack surface · Findings summary · **Findings detail** · Authorization
testing · Differential analysis · AI analysis · Attack paths · Risk assessment ·
Security posture · Regression · Benchmark results · CI/CD gate · Limitations ·
Appendix (scan events).

## Every finding is explained the same way

Each finding carries eight fixed sections:

| Section | What it contains |
|---|---|
| **What was observed** | The observation, in plain terms |
| **Why it matters** | Impact, or an explicit statement that none was assessed |
| **Evidence** | The redacted records that produced the finding |
| **Confidence** | Detector confidence, Velora priority, CVSS (or *Not Assessed*), AI confidence and its epistemic state |
| **What is unknown** | The gaps — see below |
| **Validation required** | What a human must do to confirm it |
| **Recommended remediation** | The fix, or an explicit absence |
| **Retest status** | Whether it has been retested, and what that retest actually established |

**"What is unknown" is the section that matters.** It is generated from the finding's
real state, not written by hand, and says things like:

* Exploitability was not demonstrated — this is a detector observation, not a proven
  attack.
* No CVSS vector was derived, so no standardised score is available.
* No CWE mapping was claimed for this detector.
* AI analysis flagged missing evidence: *&lt;what is missing&gt;*.
* This finding has not been retested.

## Scores and what they are not

**Velora Priority Score** (0–100) is a triage aid: severity-anchored, modulated by
confidence, exposure, evidence quality and unauthenticated reachability. It is not CVSS.

**Velora Security Posture Score** (0–100) is an aggregate trend metric. It is not CVSS
and not an industry standard. Unassessed categories are excluded from it, never scored
as perfect. See [POSTURE.md](POSTURE.md).

**CVSS** appears only where a vector was actually derived from the evidence. Otherwise
the report says `Not Assessed`. It is never inferred from severity.

## Standing limitations

Every report carries these, generated rather than optional:

* Automated checks detect indicators; they do not prove exploitability.
* AI-generated content is advisory and must be validated by a human analyst.
* Testing was limited to the authorized scope and the configured request budget.
* No destructive, exploitative or evasion techniques were used.
* **The absence of a finding is not evidence that the target is secure.**
* Attack paths marked INFERRED or HYPOTHESIZED are reasoning about observed
  relationships, not demonstrated attacks.
* A retest that did not cover the affected endpoint cannot verify a fix.
* Where a CWE, OWASP category, CVSS vector or CVE could not be established, the report
  says UNKNOWN or Not Assessed rather than supplying a value.

## Secrets

Reports contain no credentials, tokens, cookie values or API keys. Evidence excerpts are
redacted before storage, so there is nothing to leak at render time; the AI section names
the environment variable holding a key, never the key.

## Reproducibility

Reports record the Velora version, scan timestamp, profile, operator, the scope policy
that was in force, and per-finding evidence ids. A finding with a reproduction package
also carries the scope hash and the exact commands to run it again.
