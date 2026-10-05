# Velora 2.0 — Pre-Upgrade Repository Audit

**Audited version:** Velora 0.1.0
**Audit date:** 2026-09-22
**Method:** static inspection of the full repository plus a baseline execution of the test suite,
the CLI, and the dashboard. Every item below was observed in the running code — nothing here is
aspirational.

---

## 1. Baseline verification (before any modification)

| Check | Result |
|---|---|
| `python -m unittest discover -s tests -t . -p "test_*.py"` | **67 tests, OK** (41.7s) |
| `python -m compileall velora tests` | clean |
| Import of every submodule via `pkgutil.walk_packages` | all OK |
| `velora --help`, `velora version`, `velora doctor` | working (`doctor` = 0 failures, 4 warnings) |
| Dashboard `/`, `/scans/{id}`, `/api/*` | HTTP 200 |

**Baseline is green.** All upgrade work starts from a known-good state.

---

## 2. Current architecture

Layered, with scope enforcement as the bottom-most safety control:

```
config → utils → scope → core(http, orchestrator) → collection(recon, crawler, fingerprint)
→ scanners → analysis(evidence, findings, risk, correlation, attack_graph) → ai → reporting
→ interfaces(cli, api)          [persistence: database/ used by all analysis layers]
```

**Size:** 84 Python files, 6,221 LOC (package) + 871 LOC tests.

| Package | Files | LOC | Role |
|---|---|---|---|
| `scanners` | 19 | 1,101 | Check framework + 11 built-in checks |
| `cli` | 5 | 739 | click CLI, doctor, context |
| `core` | 4 | 458 | scope-gated HTTP client, orchestrator, scope factory |
| `ai` | 6 | 442 | provider abstraction + 3 providers + service |
| `utils` | 7 | 438 | logging (SECURITY level), redaction, urlutil, errors, ids, console |
| `database` | 3 | 398 | sqlite3 connection, migration runner, repository |
| `models` | 3 | 366 | Pydantic domain models + enums |
| `scope` | 3 | 338 | ScopePolicy + ScopeManager (SSRF guard) |
| `reporting` | 3 | 242 | assembler + generator (+ HTML template) |
| `crawler` | 2 | 231 | async same-origin crawler |
| `integrations` | 5 | 202 | nmap / zap / nuclei safe adapters |
| `reconnaissance` | 2 | 170 | recon engine |
| `fingerprint` | 2 | 137 | signature engine |
| `findings` | 2 | 126 | finding lifecycle service |
| `api` | 2 | 117 | Starlette app + routes |
| `risk` | 2 | 108 | Velora Priority Score |
| `correlation` | 2 | 106 | rule-based hypothesis engine |
| `attack_graph` | 2 | 101 | node/edge builder |
| `plugins` | 2 | 93 | PluginManager |
| `evidence` | 2 | 38 | EvidenceStore (redaction) |
| `workers` | 2 | 28 | `bounded_gather` |

---

## 3. Existing features (observed)

- **Scope enforcement** — deny-by-default domains/IPs/ports/schemes, excluded paths/domains,
  request budget, concurrency, delay, timeout, redirect policy (`never`/`same-origin`/`same-scope`),
  `allow_private_targets`, `block_cloud_metadata`. SSRF guard resolves hostnames and validates
  **every** returned address (DNS-rebinding + metadata + private/reserved blocking).
- **Authorization gate** — target must be `LAB_ONLY`/`AUTHORIZED` *and* the caller must pass an
  explicit acknowledgement, else `AuthorizationError` before any request.
- **Scope-gated async HTTP client** — manual redirect handling with re-check, body redaction,
  200KB body cap, per-request delay.
- **Recon** — DNS, TLS handshake metadata, headers, cookies, HTTP methods via OPTIONS,
  robots.txt, sitemap, security.txt, fingerprinting.
- **Crawler** — async, same-origin, depth/page budgets, URL + parameter-signature dedup,
  form/API/JS discovery, off-origin links recorded but not followed, form dedup.
- **Fingerprinting** — YAML signature engine (11 signatures), evidence + confidence, version
  extraction only when a capture group matches.
- **Scanners** — `SecurityCheck` ABC + registry + profile selection + per-check failure isolation.
  11 checks (see §5).
- **Evidence** — `EvidenceStore` re-redacts defensively before persistence.
- **Findings** — created as `Potential`; `validate`/`reject`/`mark_remediated`/`mark_needs_review`;
  audit-logged.
- **Risk** — Velora Priority Score (severity-anchored, context-modulated, auth multiplier).
- **Correlation** — 4 deterministic rules producing hypotheses.
- **Attack graph** — Application/Endpoint/Technology/Finding/Path nodes, CONTAINS/USES/AFFECTS/
  LEADS_TO edges, `hypothesis` boolean.
- **AI** — `AIProvider` ABC; `heuristic` (offline default), `null`, `openai_compatible`;
  `enforce_safety()` clamps confidence, forces `human_validation_required`, neutralizes
  confirmation language.
- **Reporting** — JSON + HTML (dark VAPT template); PDF via WeasyPrint when installed, otherwise
  degrades to HTML with a warning.
- **Integrations** — nmap/zap/nuclei adapters: argv arrays only, executable path validation,
  scope pre-check, timeout, process-group kill, graceful absence.
- **Plugins** — registry-backed list/enable/disable persisted in `plugins`; external module loader.
- **Ops** — `install.sh`, non-root systemd unit, Dockerfile + compose, Makefile, examples, 9 docs.

---

## 4. Database (existing)

Engine: stdlib `sqlite3` + forward-only migration runner (`schema_migrations` table).
Single migration: `0001_initial.sql`.

**Tables (16):** `users`, `scope_policies`, `targets`, `scans`, `scan_events`, `hosts`,
`endpoints`, `technologies`, `evidence`, `findings`, `attack_graph_nodes`, `attack_graph_edges`,
`ai_analyses`, `reports`, `audit_logs`, `plugins`.

**Domain models (16):** `ScopePolicyRecord`, `Target`, `Scan`, `ScanEvent`, `Host`, `Endpoint`,
`Technology`, `Evidence`, `Finding`, `AttackNode`, `AttackEdge`, `AIAnalysis`, `ReportRecord`,
`AuditLog`, `Plugin` (+ `Base`).

**Enums (6):** `Severity`, `Confidence`, `FindingStatus`, `ScanStatus`, `ScanProfile`,
`AuthorizationStatus`.

Mapping is generic: `to_row`/`from_row` inspect Pydantic annotations to JSON-encode list/dict
fields; `_COLUMN_OVERRIDES` remaps reserved words (`references` → `references_json`).

---

## 5. Existing security checks (11)

| ID | Category | Mode | Severity |
|---|---|---|---|
| `headers.security_headers` | configuration | safe | Medium |
| `headers.server_version` | information_disclosure | safe | Low |
| `cookies.attributes` | session | safe | Medium |
| `tls.configuration` | tls | safe | Medium |
| `infodisc.indicators` | information_disclosure | safe | Medium |
| `config.http_methods` | configuration | safe | Low |
| `config.directory_exposure` | configuration | safe | Medium |
| `config.security_txt` | configuration | safe | Informational |
| `auth.indicators` | authentication | safe | Medium |
| `authz.consistency` | authorization | safe | Medium |
| `input.reflection` | input_validation | **active** | Low |

---

## 6. Existing CLI (20 top-level commands)

`analyze`, `attack-map`, `config`, `crawl`, `dashboard`, `doctor`, `evidence`, `finding`,
`findings`, `fingerprint`, `init`, `plugins`, `recon`, `report`, `scan`, `scan-show`, `scans`,
`scope`, `target`, `version`.

Subgroups: `target {add,list,show}`, `finding {show,validate,reject,remediated}`,
`plugins {list,show,enable,disable}`.

---

## 7. Existing API routes (7)

`GET /`, `GET /scans/{scan_id}` (HTML) · `GET /api/health`, `/api/scans`, `/api/findings`,
`/api/scans/{scan_id}/graph`, `/api/plugins` (JSON).
`SecurityHeadersMiddleware` sets nosniff / DENY / no-referrer / CSP on every response.

**Dashboard pages (2):** Dashboard, Scan detail.

---

## 8. Existing tests (67)

| Suite | Files | Tests |
|---|---|---|
| unit | 8 | 34 |
| security | 6 | 22 |
| integration | 3 | 11 |

Security suite covers: SSRF/DNS-rebinding, scope bypass (scheme/port/suffix-confusion/case/
IP-literal/excluded-path), command injection (argv arrays, non-string rejection, out-of-scope
refusal, missing tool), out-of-scope redirects, body redaction, secret non-persistence
(greps the raw sqlite file), authorization gate.

Fixture: `tests/fixtures/labapp.py` — a stdlib intentionally-imperfect web app (no external deps,
no internet).

---

## 9. Strengths to preserve

1. **Scope engine is genuinely defence-in-depth** — resolves and validates every address, not just
   the hostname. This is the single most important asset; do not weaken it.
2. **Evidence-first invariant is enforced structurally**, not by convention: findings are created
   `Potential`, AI results are clamped, only humans confirm.
3. **Double redaction** (client + evidence store) with a test that greps the database file.
4. **Per-check failure isolation** in `ScanRunner` — one bad check cannot kill a scan.
5. **Generic row mapper** — new model fields need no repository changes.
6. **Zero external-tool dependency** — everything degrades gracefully.
7. **Deterministic scanner ordering** — reproducible reports.

---

## 10. Technical debt / gaps (observed)

| # | Issue | Impact |
|---|---|---|
| D1 | `Finding` has no engagement/identity linkage | cannot group work into engagements |
| D2 | No baseline/candidate request comparison capability | no behavioural testing |
| D3 | Authorization check is a *name heuristic* (`/admin` in path) only | high false-positive rate; no real access-control testing |
| D4 | AI input is flat; target content is not trust-separated | prompt-injection exposure |
| D5 | Attack-graph edges carry only a `hypothesis` bool — no confidence, evidence ids, or validation state | cannot distinguish observed vs inferred |
| D6 | No CWE/OWASP/CVSS/CVE metadata anywhere; CVSS fields exist but are never populated | findings lack standards mapping |
| D7 | No scan-to-scan comparison | no regression detection |
| D8 | No remediation lifecycle beyond a single `Remediated` status | no retest verification |
| D9 | No SARIF output; no CI gate; no exit-code contract | not CI-integrable |
| D10 | No measurement of Velora's own accuracy | cannot claim precision/recall |
| D11 | Dashboard is 2 pages, no charts | not a usable console |
| D12 | Plugin interface lacks config schema, scope requirements, cleanup | limited extensibility |
| D13 | No response-size/time guards beyond a 200KB body cap | resource-exhaustion surface |
| D14 | `scan-show`/`scans` are flat commands, not a `scan` subgroup | CLI inconsistency (must stay for compat) |
| D15 | Reporting lacks reproducibility metadata (scope hash, versions) | findings not reproducible |

---

## 11. Proposed integration points (where v2 attaches)

| New capability | Attaches to | Mechanism |
|---|---|---|
| Differential analysis | `core/http.py` `HttpResponse` | new `differential/` package consumes responses; no client change |
| Authorization testing | `core/http.py` + `scope` | new `authz/` package; identities supply headers via secret refs |
| Evidence-driven AI | `ai/base.py` `AnalysisInput` | extend input with typed evidence matrix; providers unchanged |
| Prompt-injection defense | `ai/` | new `ai/envelope.py` sanitizer between evidence and provider |
| Attack graph 2.0 | `models.AttackEdge` | add nullable columns (`confidence`, `evidence_ids`, `validation_status`, `source`, `created_at`) — additive |
| Knowledge graph | `models.Finding` | new `knowledge/` package + `knowledge_*` tables; finding gains `cwe_id`/`owasp_category` |
| Benchmark | `core/orchestrator.py` | new `benchmark/` runs scans and scores against ground truth |
| Remediation/retest | `findings/service.py` | new statuses + `remediation_actions`/`retest_runs` tables |
| Regression | `database/repository.py` | new `regression/` compares two scan ids |
| Posture | `risk/` | new `posture/` aggregates stored data |
| Workflows | `core/http.py` | new `workflow/` state machine, scope-gated |
| AI planner | `ai/service.py` | new `planning/` producing scope-validated steps |
| SARIF + gate | `reporting/` | new `reporting/sarif.py` + `gate/` |
| Engagements | `models` | new parent entity; `targets.engagement_id` nullable |

---

## 12. Potential breaking changes (and mitigation)

| Risk | Mitigation chosen |
|---|---|
| Adding NOT NULL columns to existing tables | **All new columns are nullable with defaults**; migration `0002` is additive only — no `DROP`, no `ALTER ... NOT NULL` |
| `Finding.status` gaining new values | New statuses are added to the enum; existing values keep their exact strings, so old rows deserialize unchanged |
| `AttackEdge.hypothesis` superseded by `validation_status` | `hypothesis` is **kept** and derived from `validation_status` for backward compatibility |
| CLI command renames | **No renames.** `scan-show`/`scans` stay; new commands are added alongside |
| Repository method signatures | Additive only; existing methods keep their signatures |
| Report JSON shape | New keys added; no existing key removed or retyped |
| AI `AnalysisResult` | New optional fields default to empty; `enforce_safety()` contract unchanged |

**Migration safety rule adopted:** `0002_v2.sql` contains only `CREATE TABLE IF NOT EXISTS`,
`CREATE INDEX IF NOT EXISTS`, and `ALTER TABLE ... ADD COLUMN` guarded by a pre-flight column
check. No existing user data is destroyed.

---

## 13. Environment constraint affecting the upgrade

The build environment has **no outbound package egress** (pypi/apt return HTTP 403). Verified again
at the start of this audit. Consequently the upgrade continues on the libraries actually installed
and verified here — `click`, `httpx`, `beautifulsoup4`, `pydantic`, `pydantic-settings`, `jinja2`,
`pyyaml`, `cryptography`, `starlette`, `uvicorn` — rather than adding Typer/FastAPI/SQLAlchemy/
Alembic/pytest as new hard dependencies.

The mapping is documented in `docs/ARCHITECTURE.md`; `pyproject.toml` retains a `reference-stack`
extra so those libraries install on Kali where pip works. Tests remain `unittest.TestCase`
subclasses, which **pytest discovers and runs natively** — so `pytest` works on Kali with no test
rewrite. Type hints are maintained throughout so `mypy` runs cleanly where installed.

This is a deliberate, documented trade-off: every feature below is genuinely executed and tested
here rather than written against libraries that could not be imported or run.

---

## 16. Upgrade outcome (completed)

The upgrade described by this audit is complete. This section records what actually
happened, against the baseline captured above.

### Baseline vs. delivered

| | 0.1.0 baseline | 2.0.0 |
|---|---|---|
| Python files / LOC | 84 / 6,221 | 140 / 18,172 |
| CLI commands | 20 | 32 |
| Database tables | 16 | 35 |
| API routes | 7 | 24 pages + 23 JSON endpoints |
| Security checks | 11 | 11 built-in + external SDK plugins |
| Tests | 67 | 415 |
| Documentation files | 9 (1.x notes) | 24 current + 7 redirect stubs |

### Technical debt from §15, resolved

| Item | Resolution |
|---|---|
| D1–D4 | Addressed by the differential, authorization, evidence-matrix and attack-graph work |
| D5 | Attack-graph edge direction corrected (`Endpoint -EXPOSES-> Finding`) so path analysis works |
| D6–D9 | Fingerprint stability, regression matching, remediation tracking and posture scoring implemented |
| D10–D12 | SARIF, gate contract and reproducibility packages implemented |
| D13–D15 | Engagement workspace, dashboard rebuild and plugin SDK implemented |

### Verification performed

* 415 tests pass (`unittest discover`, no pytest required).
* `python -m compileall velora tests` clean.
* A real 0.1.0 database migrates with zero data loss — verified by row counts before
  and after.
* End-to-end run against the bundled lab: scan → validate → posture → gate → benchmark
  → regression → report (HTML/JSON/SARIF) → dashboard.
* All 24 dashboard pages and 23 JSON endpoints return 200; security headers verified.
* Gate exit codes verified live: 0 PASS, 1 FAIL, 2 ERROR, with ERROR persisted.
* Secret-leak sweep across databases, reports and logs: zero hits.

### Defects found and fixed

The documentation and hardening passes audited the implementation against its own
claims and found 28 real defects — from a differential analysis that overclaimed an
access-boundary crossing on any status change, to path exclusions defeated by
`/x/../admin`, to `uncovered_detections` being computed and then dropped on persist.
All are fixed and pinned by tests. The full list is in
[VELORA_2.0_RELEASE_NOTES.md](VELORA_2.0_RELEASE_NOTES.md).

### Environment constraint (unchanged)

PyPI, apt and docker.com are unreachable from the build environment (HTTP 403 from the
egress policy). The project was therefore built against the libraries already present,
with the mapping to the reference stack documented in §13 and in the `reference-stack`
extra of `pyproject.toml`. Two declared dependencies that nothing imported
(`pydantic-settings`, `python-multipart`) were removed during this pass.
