# Velora Security Posture Score

## This is not CVSS

The Velora Security Posture Score is a **Velora-specific metric**. It is not CVSS, not
OWASP Risk Rating, and not any industry standard. The weights, penalties and bands below
exist only inside this codebase and are not comparable to any score produced by another
tool.

CVSS scores the technical severity of a single vulnerability. This score is an aggregate
0–100 indicator of how one target looked across its **assessed** attack surface at one
point in time. It exists for trend lines and executive summaries. It is not an input to a
risk-acceptance decision, and it must not be presented as one.

A high score means "nothing significant was found in what was assessed". It is not a
statement that the target is secure. Findings Velora cannot detect do not appear in it.

The implementation is `velora/posture/engine.py` (`PostureEngine`, `PostureResult`), with
the CLI in `velora/cli/commands/posture.py`. The current methodology version is `1.0`,
exported as `METHODOLOGY_VERSION`.

## The formula

Exactly as implemented.

### 1. Map findings to posture categories

`CATEGORY_MAP` translates a finding's `category` string to a posture category. Findings
whose category is not in this map are ignored entirely.

| Finding category | Posture category |
| --- | --- |
| `authentication` | Authentication |
| `authorization` | Authorization |
| `session` | Session Management |
| `tls` | Transport Security |
| `configuration` | Configuration |
| `information_disclosure` | Information Exposure |
| `input_validation` | Input Handling |

### 2. Exclude findings that should not count

A finding is skipped if `finding.status.value` is `"Rejected"` or `"Remediated"`. A false
positive an analyst has dismissed, and an issue a retest has verified as fixed, both stop
depressing the score.

`Remediated` is reachable only through a coverage-checked retest (see
`docs/REMEDIATION.md`), so a fix cannot be credited here by editing a status by hand.

### 3. Deduct per finding

Each assessed category starts at **100**. Every surviving finding deducts:

    penalty = SEVERITY_PENALTY[severity] × confidence_weight

| Severity | `SEVERITY_PENALTY` |
| --- | --- |
| Critical | 40.0 |
| High | 24.0 |
| Medium | 11.0 |
| Low | 4.0 |
| Informational | 1.0 |

    confidence_weight = 0.55 + 0.45 × finding.confidence.score

`Confidence.score` comes from `velora/models/enums.py`. The weight floor of 0.55 means a
tentative detection still costs more than half of its severity penalty — a weak signal is
discounted, never ignored.

| Confidence | `score` | `confidence_weight` |
| --- | --- | --- |
| Tentative | 0.40 | 0.730 |
| Firm | 0.70 | 0.865 |
| Certain | 0.95 | 0.9775 |

Effective per-finding deductions:

| Severity | Tentative | Firm | Certain |
| --- | --- | --- | --- |
| Critical | 29.20 | 34.60 | 39.10 |
| High | 17.52 | 20.76 | 23.46 |
| Medium | 8.03 | 9.52 | 10.75 |
| Low | 2.92 | 3.46 | 3.91 |
| Informational | 0.73 | 0.87 | 0.98 |

### 4. Clamp each category

    category_score = max(0.0, 100.0 - total_penalties_for_that_category)

Penalties accumulate linearly and are clamped only at zero. Four Critical findings in one
category floor that category at 0.

### 5. Combine into the overall score

    overall = Σ(category_score × CATEGORY_WEIGHT) / Σ(CATEGORY_WEIGHT)

summed over **assessed categories only**.

| Posture category | Weight |
| --- | --- |
| Authentication | 1.2 |
| Authorization | 1.3 |
| Session Management | 1.0 |
| Transport Security | 1.1 |
| Configuration | 0.9 |
| Information Exposure | 1.0 |
| Input Handling | 1.0 |

If no category was assessed, `overall` is `0.0` and the explanation says so explicitly
rather than implying a bad target.

These are fixed constants. Both the engine docstring and `velora posture methodology`
describe this as a "coverage-weighted mean", which is misleading: the number of findings or
endpoints in a category plays no part in the weighting. It is a fixed-weight weighted mean
over the assessed subset.

### 6. Bounded adjustments

Applied when `include_adjustments` is true, which is the default and what the CLI uses:

    overall = clamp(overall + remediation_credit − regression_penalty, 0, 100)

| Adjustment | Formula | Cap |
| --- | --- | --- |
| `remediation_credit` | `8.0 × (FIX_VERIFIED remediations / all remediations)` | `MAX_REMEDIATION_CREDIT = 8.0` |
| `regression_penalty` | `min(12.0, 4.0 × reintroduced findings)` | `MAX_REGRESSION_PENALTY = 12.0` |

The caps exist so no single factor can dominate the score. `regression_penalty` is stored
negated in `result.adjustments`.

`_remediation_credit` takes a `scan_id` argument but does not use it: the ratio is computed
over every `RemediationAction` in the database, not the ones relevant to this scan or
target. `_regression_penalty` does filter, counting `REINTRODUCED_FINDING` rows whose
`current_scan_id` is this scan.

## Unassessed categories are never scored as perfect

This is the part of the design that matters most, and it is where the "security evidence
first" principle shows up in the arithmetic.

A category that was not assessed is reported as `None` — rendered as `not assessed` / `-`
in the CLI — and is **excluded from the overall average entirely**. It is never scored 100,
and never scored 0.

```python
for category in CATEGORIES:
    if category not in exercised:
        result.categories[category] = None   # unassessed != healthy
    else:
        result.categories[category] = max(0.0, 100.0 - penalties[category])
```

Scoring an unassessed category as 100 would mean that the less Velora looked, the better
the target scored — the tool would reward incomplete assessment. Scoring it 0 would be
equally wrong: it would report a finding that does not exist. The honest answer is that the
value is unknown, and an unknown must not be averaged in.

The consequence is that the overall score is always a statement about the assessed subset
only, and the size of that subset is reported alongside it. The explanation string names
the unassessed categories directly:

> Not assessed (reported as unknown, not as healthy): Input Handling.

The integration test `tests/integration/test_lifecycle.py::
test_unassessed_category_is_none_not_full_marks` pins this. It runs a `safe`-profile scan,
which does not include the input-validation check (`safe_mode = False` on that check), and
asserts `result.categories["Input Handling"] is None`.

### Assessed-but-clean vs. unassessed

These are different states and the engine distinguishes them:

| State | `categories[c]` | In the average? | Meaning |
| --- | --- | --- | --- |
| Assessed, findings | 0–99.x | Yes | Checks ran and detected issues |
| Assessed, clean | 100.0 | Yes | Checks ran and detected nothing |
| Not assessed | `None` | No | No check for this category ran |

Only the middle row is a claim, and it is a bounded one: the checks that ran did not detect
anything.

### How "assessed" is decided

`_exercised_categories`:

1. Every category that produced at least one finding in this scan is exercised — including
   categories whose findings were later rejected or remediated, since the check still ran.
2. Additionally, if the scan's status is `completed` and `scan.stats["checks_run"]` is a
   positive integer, every category reachable from `registry.for_profile(scan.profile.value)` is
   marked exercised. A check that ran and found nothing still counts as coverage.

Step 2 is what lets a clean category score 100 honestly. Without it, a category with no
findings would be indistinguishable from a category that was never checked. A failed or
incomplete scan does not get this treatment: its categories fall back to step 1 and the
rest are reported as unassessed.

## Contributors and coverage

`result.contributors` is the top 10 findings by penalty, sorted descending, each carrying
`finding_id`, `title`, `category`, `severity`, `confidence` and the rounded `penalty`. Any
number the score produces can be traced back to specific finding rows; the integration test
`test_contributors_are_traceable_to_findings` asserts every contributor id exists in the
scan.

`result.coverage` is a `{category: int}` map, but the name is misleading. It holds the
**count of findings that were penalised** in that category, not a measure of coverage. A
category can be fully assessed and clean, and appear here as `0`. Read `categories[c] is
None` to determine whether a category was assessed; `coverage` cannot tell you that.

## Bands

`PostureResult.band`:

| Band | Range |
| --- | --- |
| Strong | `overall >= 90` |
| Adequate | `75 <= overall < 90` |
| Weak | `55 <= overall < 75` |
| Poor | `overall < 55` |

The web dashboard uses **different** thresholds. `velora/api/app.py` computes the band
inline as Strong `>= 85`, Adequate `>= 70`, Weak `>= 50`, Poor below that, in both the
overview and the posture page. A score of 87 is reported as "Adequate" by the CLI and
"Strong" by the dashboard. The CLI's progress-bar colouring uses a third set of thresholds
(85 / 70 / 50), though that affects colour only.

## Persistence and trend

`PostureEngine.snapshot(scan_id, target_id=..., engagement_id=...)` computes the score and
stores a `SecurityPostureSnapshot`:

| Field | Type | Notes |
| --- | --- | --- |
| `id` | str | `POST-...` |
| `engagement_id` / `target_id` | str \| None | Falls back to the scan's values |
| `scan_id` | str | |
| `overall` | float | |
| `categories` | dict[str, float] | **Unassessed categories are dropped, not stored as `None`** |
| `contributors` | list[dict] | Top 10, as above |
| `explanation` | str | The generated prose |
| `methodology_version` | str | `"1.0"` |
| `created_at` | datetime | |

The `categories` field is typed `dict[str, float]` and the snapshot filters out `None`
values:

```python
categories={k: v for k, v in result.categories.items() if v is not None},
```

A stored snapshot therefore records which categories were assessed by their presence, but a
consumer reading it must not assume a missing key means anything other than "not assessed".
The live `PostureResult` keeps the explicit `None`; the persisted record does not.

`PostureEngine.trend(target_id)` returns `{scan_id, overall, categories, at}` per snapshot,
oldest first. Because the methodology version is stored per snapshot, a trend line that
spans a methodology change is comparing two different metrics.

## CLI reference

Verified against `velora --help` output.

### `velora posture show`

| Option | Notes |
| --- | --- |
| `--scan TEXT` | Scan to score (required) |
| `--save` | Persist a posture snapshot |
| `--json` | Emit JSON instead of tables |

Prints the score and band, then the line "This is a Velora-specific aggregate metric. It is
NOT a CVSS score.", then per-category scores (unassessed categories show `-` and `not
assessed`), major contributors, adjustments, the explanation, and the methodology version.

The JSON form carries `"metric": "Velora Security Posture Score"` and `"not_cvss": true` as
explicit fields, so downstream consumers cannot mistake it for a CVSS value. Unassessed
categories are `null` in the JSON.

### `velora posture trend`

| Option | Notes |
| --- | --- |
| `--target TEXT` | Target id (required) |
| `--json` | Emit JSON |

Shows stored snapshots oldest first with a per-row delta. If there are no snapshots it says
so and points at `velora posture show --save` rather than rendering an empty chart.

### `velora posture methodology`

Takes no options. Prints the severity penalties, the confidence-weight formula, the
category weights and the adjustment caps, read live from the engine constants, so the
printed methodology cannot drift from the code.

## Worked example

From a `safe`-profile scan of the bundled lab application (14 findings):

| Category | Score | Penalised findings |
| --- | --- | --- |
| Authentication | 76.32 | 2 |
| Authorization | 83.94 | 2 |
| Session Management | 89.25 | 1 |
| Transport Security | 100.00 | 0 |
| Configuration | 68.98 | 7 |
| Information Exposure | 75.33 | 2 |
| Input Handling | *not assessed* | 0 |

Six categories assessed, total weight 1.2 + 1.3 + 1.0 + 1.1 + 0.9 + 1.0 = 6.5.

    (76.32×1.2 + 83.94×1.3 + 89.2475×1.0 + 100×1.1 + 68.98×0.9 + 75.33×1.0) / 6.5
    = 537.3655 / 6.5
    = 82.67  →  "Adequate"

Transport Security scores 100 with zero findings because the TLS check ran and detected
nothing. Input Handling is excluded from the average because the `safe` profile does not
run the input-validation check at all. If Input Handling had instead been scored 100 as
"clean", the overall would have risen to roughly 85.0 — a better score earned purely by
having tested less.

## What the score does not tell you

- It says nothing about categories Velora does not model. The seven posture categories are
  the whole universe of this metric.
- It says nothing about vulnerabilities Velora's checks cannot detect. The explanation
  string states this: the score is "not a statement that unfound issues do not exist".
- It is not comparable across targets assessed with different profiles, or across
  methodology versions.
- It is not comparable to any other tool's score, because no other tool computes this.
