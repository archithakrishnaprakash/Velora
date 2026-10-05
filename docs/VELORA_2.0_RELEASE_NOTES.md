# Velora 2.0 release notes

Velora 2.0 is an in-place upgrade of the 0.1.0 framework. Nothing was rewritten from
scratch, no working functionality was removed, and every 1.x CLI command, database
table, API route and test still works.

## Upgrading

```bash
git pull && ./install.sh
velora doctor
```

Migration is **additive only**: new tables use `CREATE TABLE IF NOT EXISTS`, new columns
are applied through a `PRAGMA table_info` check that tolerates a partially-migrated
database, and no statement drops or rewrites data. A 0.1.0 database opens, migrates and
reads correctly, verified against a real one.

Two compatibility details made that work:

* Row deserialization skips a `NULL` in a column added by a later migration when the
  model field does not accept `None`, so the field's default applies instead of the read
  failing. Without this, every additive column would break reads of pre-existing rows.
* Timestamp columns added to `attack_graph_nodes` and `attack_graph_edges` are
  backfilled, because those fields are not optional on the model.

## What is new

**Differential request analysis** — normalised response fingerprints, typed difference
classifications, and an interpretation that never asserts a vulnerability.

**Multi-identity authorization testing** — an identity × resource × expectation matrix
with horizontal, vertical and privilege-boundary outcomes. Credentials are never stored;
an identity holds the *name* of an environment variable.

**Evidence-driven AI reasoning** — a deterministic evidence matrix (supporting,
contradicting, missing) computed before the model runs, which caps its confidence at
0.9. Structured output with an auditable reasoning summary; no hidden chain-of-thought
is stored.

**Prompt-injection defense** — structural separation, per-request nonce fencing,
neutralisation of eight injection-marker classes, size bounds. Tested against nine
attack classes.

**Attack graph 2.0** — typed nodes and edges carrying epistemic state, confidence,
evidence ids and the asserting component. Path confidence is the minimum edge
confidence; path validation status is its weakest link.

**Security knowledge graph** — CWE, OWASP, CVSS and CPE relationships, with `UNKNOWN`
wherever no defensible mapping exists. CVEs are never synthesised.

**Security benchmark** — ground-truth cases with precision, recall, F1, FPR, FNR,
coverage and evidence completeness. Uncovered detections are excluded from scoring and
reported separately.

**Remediation verification** — six-state fix tracking with coverage-aware retests. A
retest that did not cover the affected endpoint cannot verify a fix.

**Regression engine** — scan-to-scan comparison on stable finding fingerprints, with
new, fixed, persisting, reintroduced, endpoint and technology changes.

**Security posture engine** — a category-weighted aggregate score, explicitly not CVSS.
Unassessed categories are excluded, never scored as perfect.

**Business-logic workflow engine** — state machines with security assertions, refused
destructive verbs, an explicit authorization requirement, and a step-skip probe.

**AI assessment planner** — proposals filtered against a fixed capability catalog, with
human approval and a scope re-check at execution time.

**CI/CD security gate** — the 0 / 1 / 2 exit-code contract with GitHub Actions, GitLab
CI and Jenkins integrations. An ERROR never silently passes.

**SARIF 2.1.0** — endpoint-URI locations with no region, stable partial fingerprints,
and `security-severity` emitted only from a real CVSS score.

**Explainable reports** — every finding carries what was observed, why it matters, the
evidence, confidence, **what is unknown**, validation required, recommended remediation
and retest status.

**Reproducibility packages** — version, profile, scope hash, bounded request/response
metadata and the steps to run it again. No secrets.

**Engagement workspace** — authorization reference, targets, identities, scans,
findings and reports under one engagement.

**Professional dashboard** — 24 read-only pages with server-rendered charts over real
stored data. Read-only by design: scans, approvals and validation stay in the CLI.

**Plugin SDK 2.0** — declared contracts validated before registration, lifecycle hooks,
configuration schemas, and a hardened loader. Two working example plugins ship.

## Defects found and fixed during the upgrade

The documentation and hardening passes audited the code against what it claimed. These
were real defects, and each is now pinned by a test.

**Correctness of claims**

* Differential analysis reported "crossed an access-behaviour boundary" for any status
  change, including `200 → 500`, overriding the classifier's own restraint.
* SARIF published a `security-severity` derived from Velora's severity at rule level —
  a CVSS-shaped number that was not a CVSS score.
* `velora finding validate` never set `ValidationState.VALIDATED`, so the field did not
  record what its definition said it recorded.
* Posture band thresholds differed between the CLI (90/75/55) and the dashboard
  (85/70/50); a score of 87 was "Adequate" in one and "Strong" in the other. There is
  now one `band_for()` used everywhere.
* Persisted posture snapshots dropped unassessed categories, making them
  indistinguishable from fully-assessed ones — the exact confusion the metric exists to
  avoid.
* The benchmark's endpoint constraint was disabled for every root-path case by an
  `or expected == "/"` escape hatch, inflating true positives.
* `detection_coverage` was the same formula as recall. It now measures what fraction of
  Velora's detections the suite can judge at all.
* `uncovered_detections` — the benchmark's central honesty number — was computed,
  printed and then dropped on persist.

**Silent failures**

* `velora diff create` was registered with no options at all and could not be invoked.
* External plugins did not survive the process, so a loaded plugin never ran in a scan.
  `plugins load --save` now records the directory and every command loads it.
* Gate `ERROR` outcomes were never persisted or audited, so `gate history` could never
  show one.
* `velora authz run` without `--target` executed every case and persisted nothing, while
  still printing a weakness count.
* A workflow step's `body` was parsed, stored and never sent.
* `report --format pdf` degraded to HTML and exited 0 with no PDF.
* `/api/scans/{id}/graph` returned an empty graph for an unknown scan id.
* `velora posture trend --target <name>` reported "no snapshots" instead of resolving
  the name.
* A credential-bearing authorization plan produced a Python traceback instead of the
  clean refusal the guard had been written to give.

**Security hardening**

* Responses were fully downloaded before being capped, so a hostile server could exhaust
  memory. Responses are now streamed with a hard ceiling and flagged `truncated`.
* Path exclusions were defeated by `/./admin`, `/x/../admin`, `/ADMIN` and
  percent-encoding. Paths are now normalised before matching.
* Pinned `allowed_ips` did not constrain what a named host resolved to.
* IPv6 link-local — where IMDS lives — was reachable when `allow_private_targets` was
  set.
* Blocked-request audit lines logged the full URL including a token in its query string.
  URLs are redacted before logging.
* Redaction missed unsigned JWTs and bare bearer/basic credentials.
* A corrupt JSON column made an entire row unreadable instead of falling back to the
  field default.

**Correctness of data**

* Rejected findings were still compared and reported as `PERSISTING_FINDING` on every
  later scan, keeping false positives alive indefinitely.
* Posture remediation credit was computed over every remediation in the database rather
  than the scan's own findings.
* `RemediationStatus.REGRESSION_DETECTED` existed but was never assigned; a verified fix
  that came back still showed as verified.
* The owner-baseline differential was computed and discarded, making an evidence-matrix
  signal unreachable.
* A reused retest scan was not marked as a retest.
* Workflow findings hardcoded `POST` regardless of the step's verb — and method is part
  of the fingerprint, so a finding failed to match itself across scans.
* A stray control character (`U+25A0`) sat inside a correlation path label and reached
  reports.
* `doctor` looked for `zap.sh` while the adapter runs `zap-baseline.py`.
* Two declared runtime dependencies (`pydantic-settings`, `python-multipart`) were never
  imported, and an empty `api/static/` was shipped as package data.

## Breaking changes

None to the 1.x CLI, database schema or API. Three behaviour changes are deliberate and
could surprise:

1. `report --format pdf` exits non-zero when WeasyPrint is absent, instead of exiting 0
   with an HTML file. A pipeline that relied on the old behaviour will now fail — which
   is the point.
2. Pinned `allowed_ips` now also constrain named hosts. A policy that set both
   `allowed_domains` and an unrelated `allowed_ips` will refuse requests it previously
   allowed. This is the safer reading of "allowed IPs".
3. Rejected findings no longer participate in regression comparison.

## Known limitations

* Plugins are not sandboxed.
* Single-operator; the dashboard has no authentication and binds to loopback.
* Only SQLite is implemented, though the repository layer is SQL-agnostic.
* Redaction is pattern-based, not exhaustive.
* The bundled benchmark suite covers the local LabShop application; Juice Shop, DVWA and
  WebGoat suites are not yet written.
