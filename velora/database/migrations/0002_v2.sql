-- Velora 2.0 schema. ADDITIVE ONLY.
-- No DROP, no destructive ALTER. New columns on existing tables are added
-- idempotently in Python (see velora/database/columns.py) so repeated upgrades
-- and partially-migrated databases are both safe.

CREATE TABLE IF NOT EXISTS engagements (
    id                       TEXT PRIMARY KEY,
    name                     TEXT NOT NULL,
    client                   TEXT NOT NULL DEFAULT '',
    description              TEXT NOT NULL DEFAULT '',
    status                   TEXT NOT NULL DEFAULT 'PLANNED',
    operator                 TEXT NOT NULL DEFAULT '',
    authorization_reference  TEXT NOT NULL DEFAULT '',
    authorization_granted_by TEXT NOT NULL DEFAULT '',
    starts_at                TEXT,
    ends_at                  TEXT,
    created_at               TEXT NOT NULL,
    updated_at               TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS identities (
    id                    TEXT PRIMARY KEY,
    engagement_id         TEXT,
    name                  TEXT NOT NULL,
    role                  TEXT NOT NULL DEFAULT 'anonymous',
    description           TEXT NOT NULL DEFAULT '',
    secret_ref            TEXT NOT NULL DEFAULT '',
    auth_scheme           TEXT NOT NULL DEFAULT 'bearer',
    auth_header_name      TEXT NOT NULL DEFAULT 'Authorization',
    owned_resource_hints  TEXT NOT NULL DEFAULT '[]',
    created_at            TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS differential_observations (
    id                    TEXT PRIMARY KEY,
    scan_id               TEXT,
    engagement_id         TEXT,
    label                 TEXT NOT NULL DEFAULT '',
    baseline_url          TEXT NOT NULL DEFAULT '',
    candidate_url         TEXT NOT NULL DEFAULT '',
    baseline_method       TEXT NOT NULL DEFAULT 'GET',
    candidate_method      TEXT NOT NULL DEFAULT 'GET',
    baseline_fingerprint  TEXT NOT NULL DEFAULT '{}',
    candidate_fingerprint TEXT NOT NULL DEFAULT '{}',
    differences           TEXT NOT NULL DEFAULT '[]',
    classifications       TEXT NOT NULL DEFAULT '[]',
    confidence            REAL NOT NULL DEFAULT 0.0,
    interpretation        TEXT NOT NULL DEFAULT '',
    validation_required   INTEGER NOT NULL DEFAULT 1,
    evidence_ids          TEXT NOT NULL DEFAULT '[]',
    created_at            TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS authorization_tests (
    id                           TEXT PRIMARY KEY,
    scan_id                      TEXT,
    engagement_id                TEXT,
    plan_id                      TEXT,
    identity_id                  TEXT NOT NULL DEFAULT '',
    identity_role                TEXT NOT NULL DEFAULT 'anonymous',
    resource_owner_identity_id   TEXT,
    url                          TEXT NOT NULL DEFAULT '',
    method                       TEXT NOT NULL DEFAULT 'GET',
    expected                     TEXT NOT NULL DEFAULT 'UNKNOWN',
    observed                     TEXT NOT NULL DEFAULT 'INCONCLUSIVE',
    outcome                      TEXT NOT NULL DEFAULT 'INCONCLUSIVE',
    status_code                  INTEGER,
    response_size                INTEGER NOT NULL DEFAULT 0,
    differential_id              TEXT,
    evidence_ids                 TEXT NOT NULL DEFAULT '[]',
    notes                        TEXT NOT NULL DEFAULT '',
    created_at                   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS workflows (
    id            TEXT PRIMARY KEY,
    engagement_id TEXT,
    target_id     TEXT,
    name          TEXT NOT NULL,
    description   TEXT NOT NULL DEFAULT '',
    identity_id   TEXT,
    initial_state TEXT NOT NULL DEFAULT 'start',
    authorized    INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS workflow_steps (
    id                   TEXT PRIMARY KEY,
    workflow_id          TEXT NOT NULL,
    order_index          INTEGER NOT NULL DEFAULT 0,
    name                 TEXT NOT NULL DEFAULT '',
    method               TEXT NOT NULL DEFAULT 'GET',
    url                  TEXT NOT NULL DEFAULT '',
    from_state           TEXT NOT NULL DEFAULT '',
    to_state             TEXT NOT NULL DEFAULT '',
    expected_status      TEXT NOT NULL DEFAULT '[]',
    assertion            TEXT NOT NULL DEFAULT '',
    assert_status_in     TEXT NOT NULL DEFAULT '[]',
    assert_body_contains TEXT NOT NULL DEFAULT '',
    assert_body_absent   TEXT NOT NULL DEFAULT '',
    outcome              TEXT NOT NULL DEFAULT 'PENDING',
    observed_status      INTEGER,
    observed_state       TEXT NOT NULL DEFAULT '',
    evidence_ids         TEXT NOT NULL DEFAULT '[]',
    created_at           TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS remediation_actions (
    id             TEXT PRIMARY KEY,
    finding_id     TEXT NOT NULL,
    engagement_id  TEXT,
    status         TEXT NOT NULL DEFAULT 'OPEN',
    owner          TEXT NOT NULL DEFAULT '',
    note           TEXT NOT NULL DEFAULT '',
    opened_at      TEXT NOT NULL,
    updated_at     TEXT NOT NULL,
    verified_at    TEXT,
    last_retest_id TEXT
);

CREATE TABLE IF NOT EXISTS retest_runs (
    id               TEXT PRIMARY KEY,
    finding_id       TEXT NOT NULL,
    remediation_id   TEXT,
    original_scan_id TEXT NOT NULL DEFAULT '',
    retest_scan_id   TEXT,
    still_present    INTEGER,
    verdict          TEXT NOT NULL DEFAULT 'READY_FOR_RETEST',
    detail           TEXT NOT NULL DEFAULT '',
    evidence_ids     TEXT NOT NULL DEFAULT '[]',
    created_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS regression_results (
    id               TEXT PRIMARY KEY,
    engagement_id    TEXT,
    previous_scan_id TEXT NOT NULL DEFAULT '',
    current_scan_id  TEXT NOT NULL DEFAULT '',
    change           TEXT NOT NULL DEFAULT 'PERSISTING_FINDING',
    subject          TEXT NOT NULL DEFAULT '',
    severity         TEXT NOT NULL DEFAULT '',
    detail           TEXT NOT NULL DEFAULT '{}',
    created_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS benchmark_cases (
    id                    TEXT PRIMARY KEY,
    suite                 TEXT NOT NULL DEFAULT 'default',
    application           TEXT NOT NULL DEFAULT '',
    name                  TEXT NOT NULL DEFAULT '',
    vulnerability_type    TEXT NOT NULL DEFAULT '',
    endpoint_path         TEXT NOT NULL DEFAULT '/',
    description           TEXT NOT NULL DEFAULT '',
    expected_detection    INTEGER NOT NULL DEFAULT 1,
    expected_check_id     TEXT NOT NULL DEFAULT '',
    expected_severity     TEXT NOT NULL DEFAULT '',
    evidence_requirements TEXT NOT NULL DEFAULT '[]',
    cwe_id                TEXT NOT NULL DEFAULT 'UNKNOWN',
    owasp_category        TEXT NOT NULL DEFAULT 'UNKNOWN',
    created_at            TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS benchmark_runs (
    id                   TEXT PRIMARY KEY,
    suite                TEXT NOT NULL DEFAULT 'default',
    scan_id              TEXT,
    target_url           TEXT NOT NULL DEFAULT '',
    total_cases          INTEGER NOT NULL DEFAULT 0,
    true_positives       INTEGER NOT NULL DEFAULT 0,
    true_negatives       INTEGER NOT NULL DEFAULT 0,
    false_positives      INTEGER NOT NULL DEFAULT 0,
    false_negatives      INTEGER NOT NULL DEFAULT 0,
    precision            REAL NOT NULL DEFAULT 0.0,
    recall               REAL NOT NULL DEFAULT 0.0,
    f1                   REAL NOT NULL DEFAULT 0.0,
    false_positive_rate  REAL NOT NULL DEFAULT 0.0,
    false_negative_rate  REAL NOT NULL DEFAULT 0.0,
    detection_coverage   REAL NOT NULL DEFAULT 0.0,
    evidence_completeness REAL NOT NULL DEFAULT 0.0,
    per_case             TEXT NOT NULL DEFAULT '[]',
    velora_version       TEXT NOT NULL DEFAULT '',
    created_at           TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS security_posture_snapshots (
    id                  TEXT PRIMARY KEY,
    engagement_id       TEXT,
    target_id           TEXT,
    scan_id             TEXT NOT NULL DEFAULT '',
    overall             REAL NOT NULL DEFAULT 0.0,
    categories          TEXT NOT NULL DEFAULT '{}',
    contributors        TEXT NOT NULL DEFAULT '[]',
    explanation         TEXT NOT NULL DEFAULT '',
    methodology_version TEXT NOT NULL DEFAULT '1.0',
    created_at          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS assessment_plans (
    id            TEXT PRIMARY KEY,
    engagement_id TEXT,
    target_id     TEXT NOT NULL DEFAULT '',
    scan_id       TEXT,
    title         TEXT NOT NULL DEFAULT '',
    rationale     TEXT NOT NULL DEFAULT '',
    generated_by  TEXT NOT NULL DEFAULT 'heuristic',
    approved_by   TEXT NOT NULL DEFAULT '',
    approved_at   TEXT,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS assessment_plan_steps (
    id                     TEXT PRIMARY KEY,
    plan_id                TEXT NOT NULL,
    order_index            INTEGER NOT NULL DEFAULT 0,
    title                  TEXT NOT NULL DEFAULT '',
    reason                 TEXT NOT NULL DEFAULT '',
    capability             TEXT NOT NULL DEFAULT '',
    target_scope           TEXT NOT NULL DEFAULT '',
    required_permission    TEXT NOT NULL DEFAULT '',
    expected_evidence      TEXT NOT NULL DEFAULT '',
    risk                   TEXT NOT NULL DEFAULT 'low',
    validation_requirement TEXT NOT NULL DEFAULT '',
    status                 TEXT NOT NULL DEFAULT 'PROPOSED',
    scope_ok               INTEGER,
    scope_reason           TEXT NOT NULL DEFAULT '',
    executed_at            TEXT,
    result_summary         TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS knowledge_entities (
    id          TEXT PRIMARY KEY,
    kind        TEXT NOT NULL DEFAULT 'CWE',
    identifier  TEXT NOT NULL DEFAULT 'UNKNOWN',
    title       TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    references_json TEXT NOT NULL DEFAULT '[]',
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS knowledge_relationships (
    id                TEXT PRIMARY KEY,
    source_kind       TEXT NOT NULL DEFAULT 'FINDING',
    source_id         TEXT NOT NULL DEFAULT '',
    target_kind       TEXT NOT NULL DEFAULT 'CWE',
    target_id         TEXT NOT NULL DEFAULT '',
    relation          TEXT NOT NULL DEFAULT 'MAPS_TO',
    validation_status TEXT NOT NULL DEFAULT 'INFERRED',
    confidence        REAL NOT NULL DEFAULT 0.5,
    created_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reproduction_records (
    id                TEXT PRIMARY KEY,
    finding_id        TEXT NOT NULL,
    velora_version    TEXT NOT NULL DEFAULT '',
    scanner_id        TEXT NOT NULL DEFAULT '',
    scan_id           TEXT NOT NULL DEFAULT '',
    scan_profile      TEXT NOT NULL DEFAULT '',
    scope_policy_hash TEXT NOT NULL DEFAULT '',
    scope_summary     TEXT NOT NULL DEFAULT '',
    request_metadata  TEXT NOT NULL DEFAULT '{}',
    response_metadata TEXT NOT NULL DEFAULT '{}',
    evidence_ids      TEXT NOT NULL DEFAULT '[]',
    validation_state  TEXT NOT NULL DEFAULT 'Potential',
    steps             TEXT NOT NULL DEFAULT '[]',
    created_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS security_gate_results (
    id            TEXT PRIMARY KEY,
    scan_id       TEXT NOT NULL DEFAULT '',
    engagement_id TEXT,
    decision      TEXT NOT NULL DEFAULT 'PASS',
    policy        TEXT NOT NULL DEFAULT '{}',
    violations    TEXT NOT NULL DEFAULT '[]',
    summary       TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_identities_engagement ON identities(engagement_id);
CREATE INDEX IF NOT EXISTS idx_diff_scan ON differential_observations(scan_id);
CREATE INDEX IF NOT EXISTS idx_authz_scan ON authorization_tests(scan_id);
CREATE INDEX IF NOT EXISTS idx_wfsteps_workflow ON workflow_steps(workflow_id);
CREATE INDEX IF NOT EXISTS idx_remediation_finding ON remediation_actions(finding_id);
CREATE INDEX IF NOT EXISTS idx_retest_finding ON retest_runs(finding_id);
CREATE INDEX IF NOT EXISTS idx_regression_current ON regression_results(current_scan_id);
CREATE INDEX IF NOT EXISTS idx_bench_cases_suite ON benchmark_cases(suite);
CREATE INDEX IF NOT EXISTS idx_posture_scan ON security_posture_snapshots(scan_id);
CREATE INDEX IF NOT EXISTS idx_plansteps_plan ON assessment_plan_steps(plan_id);
CREATE INDEX IF NOT EXISTS idx_krel_source ON knowledge_relationships(source_id);
CREATE INDEX IF NOT EXISTS idx_repro_finding ON reproduction_records(finding_id);
CREATE INDEX IF NOT EXISTS idx_gate_scan ON security_gate_results(scan_id);
