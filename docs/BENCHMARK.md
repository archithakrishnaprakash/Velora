# Benchmark

The benchmark measures Velora against written-down ground truth. Its purpose is to make
Velora's accuracy a number someone else can check, rather than a claim.

`velora/benchmark/runner.py` states the constraint in its first paragraph: "Every number
reported here is measured; none is assumed or hard-coded." The runner scores a real scan's
stored findings against a suite. There is no path in the code that produces a metric
without a scan behind it.

Code: `velora/benchmark/suite.py` (cases and suites), `velora/benchmark/runner.py`
(scoring), `velora/cli/commands/benchmark.py` (CLI), `velora/models/domain.py`
(`BenchmarkCase`, `BenchmarkRun`). Tests: `tests/integration/test_lifecycle.py`
(`TestBenchmark`).

## What these numbers do and do not describe

**A benchmark result describes Velora's behaviour on the measured suite, and nothing
else.** It is not a general detection rate, not a coverage claim about web
vulnerabilities, and not evidence that Velora would find the same class of issue in a
different application. `BenchmarkReport.to_dict()` ships that sentence inside every
report, in the `notes` array:

> These figures describe Velora's behaviour on this suite only and do not generalize to
> other applications.

`velora benchmark run` prints the same notes under a heading reading "Scope of these
numbers", and `tests/integration/test_dashboard.py::test_benchmark_page_states_suite_scope`
asserts the dashboard's benchmark page contains the phrase "on this suite only".

The `labshop` suite has nine cases. A precision of `1.0` on it means nine specific
statements held. It does not mean Velora has no false positives.

## Ground-truth case format

A benchmark case is a statement about a target: either "check X should fire here" or
"check X should **not** fire here". Both directions are needed — as the suite module puts
it, "a scanner that reports everything has perfect recall and useless precision."

`BenchmarkCase` fields, from `velora/models/domain.py`:

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `id` | str | `BC-XXXXXX` | Generated. |
| `suite` | str | `"default"` | Suite this case belongs to. |
| `application` | str | `""` | Application the suite describes. |
| `name` | str | `""` | Case name. Required in YAML. |
| `vulnerability_type` | str | `""` | Free-text grouping label. |
| `endpoint_path` | str | `"/"` | Path the detection is expected on. |
| `description` | str | `""` | Why this is the ground truth. |
| `expected_detection` | bool | `True` | `True` = positive case, `False` = negative case. |
| `expected_check_id` | str | `""` | The check id that should (or should not) fire. Required in YAML. |
| `expected_severity` | str | `""` | Declared, but never compared during scoring. |
| `evidence_requirements` | list[str] | `[]` | Phrases the finding's evidence must satisfy. |
| `cwe_id` | str | `"UNKNOWN"` | Declared, not compared during scoring. |
| `owasp_category` | str | `"UNKNOWN"` | Declared, not compared during scoring. |

A suite is a `Suite` dataclass with `name`, `application`, `description` and `cases`, plus
`positive_cases` and `negative_cases` properties.

### YAML suites

`load_suite_file()` reads a suite from YAML. The document must be a mapping containing
`name`; each entry under `cases` must be a mapping containing at least `name` and
`expected_check_id`; a file that defines no cases raises `ConfigError`.

```yaml
name: my-app
application: My Application
description: Ground truth for the staging build of My Application.
cases:
  - name: Missing Content-Security-Policy
    vulnerability_type: security-header
    endpoint_path: /
    expected_detection: true
    expected_check_id: headers.security_headers
    expected_severity: Medium
    evidence_requirements: ["response headers captured"]
    cwe_id: CWE-693
    owasp_category: "A05:2021"
    description: The application sends no CSP header.
```

`discover_suites(directory)` returns the built-in suites plus every `*.yaml` / `*.yml`
file in the directory that parses as a suite. A file that raises `ConfigError` is skipped
silently, which is why `examples/labs/workflow-checkout.yaml` — a workflow definition, not
a suite — does not appear in `velora benchmark list`.

## The LABSHOP_SUITE

`LABSHOP_SUITE` describes the bundled lab application. Its ground truth is authoritative
because the fixture's behaviour is defined in this repository, in
`tests/fixtures/labapp.py` — it is read off the code, not guessed from a scan.

Nine cases: seven positive, two negative.

| Ground truth | Case | Check id | Path | CWE | OWASP | Why |
| --- | --- | --- | --- | --- | --- | --- |
| detect | Missing Content-Security-Policy | `headers.security_headers` | `/` | CWE-693 | A05:2021 | The fixture sends no CSP header. |
| detect | Server version disclosure | `headers.server_version` | `/` | CWE-200 | A05:2021 | The fixture advertises `LabShop/1.4.2`. |
| detect | Insecure session cookie | `cookies.attributes` | `/login` | CWE-1004 | A05:2021 | `SESSIONID` is set without HttpOnly or SameSite. |
| detect | Secret disclosed in response body | `infodisc.indicators` | `/` | CWE-200 | A05:2021 | The index page embeds an `api_key`-shaped token. |
| detect | Risky HTTP methods enabled | `config.http_methods` | `/` | CWE-650 | A05:2021 | OPTIONS advertises TRACE, PUT and DELETE. |
| detect | Credentials submitted over plaintext HTTP | `auth.indicators` | `/login` | CWE-319 | A02:2021 | The login form posts over HTTP. |
| detect | No security.txt published | `config.security_txt` | `/.well-known/security.txt` | UNKNOWN | UNKNOWN | The fixture publishes no disclosure policy. |
| stay silent | No directory listing exposed | `config.directory_exposure` | `/` | UNKNOWN | UNKNOWN | The fixture never emits an auto-index page. Reporting one would be a false positive. |
| stay silent | No TLS weakness on a plaintext target | `tls.configuration` | `/` | UNKNOWN | UNKNOWN | The fixture serves HTTP only, so the TLS check must stay silent rather than inventing a transport finding. |

The two negative cases are the interesting half. The TLS case in particular tests a
failure mode that matters: a scanner that emits a transport finding for a target with no
TLS at all is manufacturing a result from the absence of something to measure.

Declared severities on the positive cases are documentation only. `config.http_methods`
carries `expected_severity: "Medium"` in the suite while the check class declares
`Severity.LOW`; nothing compares the two, because the runner never reads
`expected_severity`.

## Scoring

`BenchmarkRunner.score(suite, scan_id, target_url)` loads the scan's findings and walks
every case.

### Matching a case to a finding

`_matches(case, finding)`:

1. `finding.scanner` must equal `case.expected_check_id`, else no match.
2. If `case.endpoint_path` is `""` or `"*"`, that is enough.
3. Otherwise the finding's endpoint is passed through
   `velora.findings.fingerprint.normalize_endpoint()` (which collapses numeric, UUID and
   long-hex path segments to `{id}`), its path is compared to the case path, and a case
   path of `/` matches anything.

The first finding that matches is the one scored; `next(...)` takes it and the rest are
left unmatched.

### Outcomes

| Case | Detected | Outcome | Counter |
| --- | --- | --- | --- |
| `expected_detection: true` | yes | `TRUE_POSITIVE` | `true_positives` |
| `expected_detection: true` | no | `FALSE_NEGATIVE` | `false_negatives` |
| `expected_detection: false` | yes | `FALSE_POSITIVE` | `false_positives` |
| `expected_detection: false` | no | `TRUE_NEGATIVE` | `true_negatives` |

Every outcome carries a `detail` string explaining it — a false negative reads "expected
`<check>` to fire, but it did not", a false positive reads "`<check>` reported '<title>'
where ground truth says there is nothing to report".

### Metrics, exactly as implemented

All of these are properties on `Metrics` in `velora/benchmark/runner.py`. Every one
returns `0.0` when its denominator is zero, and every one is rounded to 4 decimal places.

| Metric | Formula | Denominator-zero result |
| --- | --- | --- |
| `precision` | `TP / (TP + FP)` | `0.0` |
| `recall` | `TP / (TP + FN)` | `0.0` |
| `f1` | `2 × precision × recall / (precision + recall)` | `0.0` |
| `false_positive_rate` | `FP / (FP + TN)` | `0.0` |
| `false_negative_rate` | `FN / (FN + TP)` | `0.0` |
| `detection_coverage` | `TP / (TP + FN)` | `0.0` |

`detection_coverage` is documented as "fraction of positive ground-truth cases that were
detected". As implemented it is arithmetically identical to `recall` — both divide `TP` by
`TP + FN`. The two are reported separately.

Three further figures live on `BenchmarkReport` rather than on `Metrics`:

| Figure | Formula | When it is `None` |
| --- | --- | --- |
| `evidence_completeness` | `satisfied / positive_detected` | never `None`; `0.0` when no positive case was detected |
| `ai_agreement` | fraction of AI-analysed findings whose category stem appears in the analysis `classification` | when no finding has an `ai_analysis_id` |
| `human_validation_rate` | findings whose status is `Confirmed`, `Rejected` or `Remediated`, over all findings | when the scan has no findings |

`satisfied` counts true positives whose matched finding also passed
`_evidence_satisfied()`; `positive_detected` is the number of true positives.

`ai_agreement` returns `None` rather than `0.0` when no AI analysis has been run, and the
method's docstring gives the reason: "reporting 0.0 would be misleading." A metric that
was never measured is not a metric that scored zero. The CLI prints "not measured (no AI
analysis run)" for it, and
`tests/integration/test_lifecycle.py::test_ai_agreement_is_none_when_no_ai_ran` asserts
the `None`.

### Evidence completeness

`_evidence_satisfied(case, finding)`:

- With no `evidence_requirements`, the test is simply whether the finding has any evidence
  ids at all.
- With requirements, the finding's evidence rows are loaded and joined into one lowercase
  haystack of test names, sanitized excerpts and header names. A requirement is satisfied
  when any of its words longer than three characters appears in that haystack. Failing
  that, a requirement mentioning "header" is satisfied structurally if any evidence row has
  headers, and one mentioning "body" is satisfied if any row has a sanitized excerpt.
- A finding with no evidence rows fails immediately.

This is a coarse check, and it under-counts: on the `labshop` suite the measured
`evidence_completeness` is `0.7143`, with `config.http_methods` and `auth.indicators`
reported as not satisfied. That is the metric being pessimistic about its own matching
rather than those checks producing no evidence.

## Uncovered detections

This is the most important honesty property in the module.

After scoring every case, the runner walks the scan's findings again and counts every one
that no case matched:

```python
for finding in findings:
    if finding.id not in matched_finding_ids:
        report.metrics.uncovered_detections += 1
        report.uncovered.append({...})
```

`uncovered_detections` appears in `Metrics.to_dict()` and in the report's `uncovered` list.
**It appears in no formula.** Precision, recall, F1, FPR, FNR and detection coverage are
computed from `TP`, `TN`, `FP` and `FN` only.

The module docstring states the rule and the reasoning:

> **Uncovered detections are not false positives.** A finding that no benchmark case
> describes is reported separately as an *uncovered detection*. Counting it as a false
> positive would punish Velora for finding something the suite simply does not know about;
> counting it as a true positive would be self-congratulation. It is neither.

Both mistakes are real and both are tempting.

Scoring an uncovered detection as a **false positive** assumes the suite is complete — that
anything not in the ground truth is wrong. No suite is complete. Under that rule, adding a
genuinely useful new check would make Velora's precision fall, which creates a standing
incentive to detect less.

Scoring it as a **true positive** assumes the detection is correct because Velora made it.
That is the framework grading its own homework: any check could then improve its own score
by reporting more, and the benchmark would measure output volume instead of accuracy.

Neither is defensible, so uncovered detections are reported and excluded. They are printed
under their own heading, with the line "Findings no benchmark case describes. Counted as
NEITHER true nor false positives", and carried in the report's `notes`.

The second rule in the same docstring closes the matching gap:

> **True negatives come only from explicit negative cases.** TN is not "everything the
> scanner didn't say", which would be unbounded and meaningless.

If TN counted every vulnerability Velora did not report, it would be effectively infinite,
FPR would round to zero for any scanner, and the number would say nothing. TN is bounded
by the negative cases someone wrote down.

`tests/integration/test_lifecycle.py::test_uncovered_detections_are_not_counted_as_false_positives`
pins this: it asserts `uncovered_detections > 0` and `false_positives == 0` on the same
run.

### What that looks like in practice

A `safe`-profile scan of the bundled lab app, scored against `labshop`:

```
true_positives      7        precision             1.0
true_negatives      2        recall                1.0
false_positives     0        f1                    1.0
false_negatives     0        false_positive_rate   0.0
uncovered           7        detection_coverage    1.0
```

Seven detections were scored and seven were not. The uncovered ones are a second
`auth.indicators` finding, two `authz.consistency` findings and four additional
`headers.security_headers` findings — real, evidence-backed detections that the suite
simply does not have cases for, plus the second and later findings from checks whose first
finding already matched a case.

A reader who assumed `precision = 1.0` meant "Velora reported nothing wrong" would be
wrong by seven findings. That is precisely why the count is printed next to the metrics
rather than dropped.

## Persistence

`BenchmarkRunner.persist(report)` writes a `BenchmarkRun` row: suite, scan id, target URL,
total cases, the four counters, `precision`, `recall`, `f1`, `false_positive_rate`,
`false_negative_rate`, `detection_coverage`, `evidence_completeness`, the per-case list
and the Velora version.

`uncovered_detections`, `ai_agreement` and `human_validation_rate` have no column on
`BenchmarkRun` and are not persisted. They are present in the JSON written by
`--output` and in the terminal output, but a stored run re-read with
`velora benchmark report` does not carry them.

## CLI

```
velora benchmark list   [--suite-dir TEXT] [--json]
velora benchmark run    --target TEXT [--suite TEXT] [--suite-dir TEXT] [--profile safe|standard|lab]
                        [--scan TEXT] [--allow-private] [--operator TEXT] [--output PATH]
                        [--i-am-authorized]
velora benchmark report [--run TEXT] [--json]
```

| Command | Flag | Type | Default | Notes |
| --- | --- | --- | --- | --- |
| `list` | `--suite-dir` | text | `examples/labs` | Directory searched for YAML suites. |
| | `--json` | flag | off | |
| `run` | `--suite` | text | `labshop` | Unknown name is an error listing the available suites. |
| | `--suite-dir` | text | `examples/labs` | |
| | `--target` | text | — | Required. URL or stored target id. |
| | `--profile` | choice | `safe` | `safe`, `standard` or `lab`. |
| | `--scan` | text | none | Score an existing scan instead of running a new one. |
| | `--allow-private` | flag | off | |
| | `--operator` | text | `""` | |
| | `--output` | path | none | Writes the full JSON report. |
| | `--i-am-authorized` | flag | off | Required unless `--scan` is used. |
| `report` | `--run` | text | latest | Benchmark run id. |
| | `--json` | flag | off | |

`--scan` scores a scan that already exists, so it does not call
`require_authorization()` and does not send any request. Without it, the command runs a
real scan first and the authorization acknowledgement is required like any other scan.

`velora benchmark run` prints, in order: a per-case table (outcome, case, check, detected,
evidence-ok), the measured-metrics table, the uncovered-detections list when there is one,
and the scope notes.
