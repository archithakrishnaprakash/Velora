-- Velora initial schema (SQLite dialect; PostgreSQL-compatible column choices).
-- All timestamps stored as ISO-8601 UTC text. JSON columns stored as text.

CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    role          TEXT NOT NULL DEFAULT 'operator',
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scope_policies (
    id                    TEXT PRIMARY KEY,
    allowed_domains       TEXT NOT NULL DEFAULT '[]',
    allowed_ips           TEXT NOT NULL DEFAULT '[]',
    allowed_ports         TEXT NOT NULL DEFAULT '[80,443]',
    allowed_schemes       TEXT NOT NULL DEFAULT '["http","https"]',
    excluded_paths        TEXT NOT NULL DEFAULT '[]',
    excluded_domains      TEXT NOT NULL DEFAULT '[]',
    max_requests          INTEGER NOT NULL DEFAULT 500,
    max_concurrency       INTEGER NOT NULL DEFAULT 5,
    request_delay         REAL NOT NULL DEFAULT 0.2,
    timeout               REAL NOT NULL DEFAULT 15.0,
    redirect_policy       TEXT NOT NULL DEFAULT 'same-scope',
    allow_private_targets INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS targets (
    id                   TEXT PRIMARY KEY,
    name                 TEXT NOT NULL,
    url                  TEXT NOT NULL,
    description          TEXT NOT NULL DEFAULT '',
    owner                TEXT NOT NULL DEFAULT '',
    authorization_status TEXT NOT NULL DEFAULT 'UNAUTHORIZED',
    authorization_note   TEXT NOT NULL DEFAULT '',
    scope_policy_id      TEXT REFERENCES scope_policies(id),
    created_at           TEXT NOT NULL,
    updated_at           TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id                TEXT PRIMARY KEY,
    target_id         TEXT NOT NULL REFERENCES targets(id),
    profile           TEXT NOT NULL DEFAULT 'safe',
    status            TEXT NOT NULL DEFAULT 'created',
    operator          TEXT NOT NULL DEFAULT '',
    authorization_ack INTEGER NOT NULL DEFAULT 0,
    scope_policy_id   TEXT REFERENCES scope_policies(id),
    started_at        TEXT,
    finished_at       TEXT,
    stats             TEXT NOT NULL DEFAULT '{}',
    created_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_events (
    id         TEXT PRIMARY KEY,
    scan_id    TEXT NOT NULL REFERENCES scans(id),
    level      TEXT NOT NULL DEFAULT 'INFO',
    event      TEXT NOT NULL DEFAULT '',
    message    TEXT NOT NULL DEFAULT '',
    data       TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS hosts (
    id           TEXT PRIMARY KEY,
    scan_id      TEXT NOT NULL REFERENCES scans(id),
    hostname     TEXT NOT NULL,
    ip_addresses TEXT NOT NULL DEFAULT '[]',
    ports        TEXT NOT NULL DEFAULT '[]',
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS endpoints (
    id            TEXT PRIMARY KEY,
    scan_id       TEXT NOT NULL REFERENCES scans(id),
    url           TEXT NOT NULL,
    method        TEXT NOT NULL DEFAULT 'GET',
    status_code   INTEGER,
    content_type  TEXT NOT NULL DEFAULT '',
    response_size INTEGER NOT NULL DEFAULT 0,
    parent_url    TEXT,
    parameters    TEXT NOT NULL DEFAULT '[]',
    forms         TEXT NOT NULL DEFAULT '[]',
    is_api        INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS technologies (
    id         TEXT PRIMARY KEY,
    scan_id    TEXT NOT NULL REFERENCES scans(id),
    name       TEXT NOT NULL,
    version    TEXT,
    categories TEXT NOT NULL DEFAULT '[]',
    evidence   TEXT NOT NULL DEFAULT '',
    confidence REAL NOT NULL DEFAULT 0.5,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence (
    id                TEXT PRIMARY KEY,
    scan_id           TEXT NOT NULL REFERENCES scans(id),
    finding_id        TEXT,
    test_name         TEXT NOT NULL DEFAULT '',
    request_metadata  TEXT NOT NULL DEFAULT '{}',
    response_metadata TEXT NOT NULL DEFAULT '{}',
    headers           TEXT NOT NULL DEFAULT '{}',
    status_code       INTEGER,
    content_type      TEXT NOT NULL DEFAULT '',
    response_size     INTEGER NOT NULL DEFAULT 0,
    sanitized_excerpt TEXT NOT NULL DEFAULT '',
    confidence        REAL NOT NULL DEFAULT 0.5,
    created_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id              TEXT PRIMARY KEY,
    scan_id         TEXT NOT NULL REFERENCES scans(id),
    title           TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    category        TEXT NOT NULL DEFAULT '',
    severity        TEXT NOT NULL DEFAULT 'Informational',
    confidence      TEXT NOT NULL DEFAULT 'Tentative',
    status          TEXT NOT NULL DEFAULT 'Potential',
    endpoint        TEXT NOT NULL DEFAULT '',
    method          TEXT NOT NULL DEFAULT 'GET',
    evidence_ids    TEXT NOT NULL DEFAULT '[]',
    cvss_version    TEXT,
    cvss_vector     TEXT,
    cvss_base_score REAL,
    cvss_severity   TEXT,
    references_json TEXT NOT NULL DEFAULT '[]',
    impact          TEXT NOT NULL DEFAULT '',
    remediation     TEXT NOT NULL DEFAULT '',
    scanner         TEXT NOT NULL DEFAULT '',
    priority_score  REAL,
    ai_analysis_id  TEXT,
    validated_by    TEXT,
    validation_note TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS attack_graph_nodes (
    id         TEXT PRIMARY KEY,
    scan_id    TEXT NOT NULL REFERENCES scans(id),
    kind       TEXT NOT NULL,
    label      TEXT NOT NULL,
    attributes TEXT NOT NULL DEFAULT '{}',
    ref_id     TEXT
);

CREATE TABLE IF NOT EXISTS attack_graph_edges (
    id         TEXT PRIMARY KEY,
    scan_id    TEXT NOT NULL REFERENCES scans(id),
    source_id  TEXT NOT NULL,
    target_id  TEXT NOT NULL,
    relation   TEXT NOT NULL,
    attributes TEXT NOT NULL DEFAULT '{}',
    hypothesis INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS ai_analyses (
    id                        TEXT PRIMARY KEY,
    scan_id                   TEXT NOT NULL REFERENCES scans(id),
    finding_id                TEXT,
    provider                  TEXT NOT NULL DEFAULT '',
    model                     TEXT NOT NULL DEFAULT '',
    classification            TEXT NOT NULL DEFAULT '',
    confidence                REAL NOT NULL DEFAULT 0.0,
    reasoning_summary         TEXT NOT NULL DEFAULT '',
    impact                    TEXT NOT NULL DEFAULT '',
    remediation               TEXT NOT NULL DEFAULT '',
    related_findings          TEXT NOT NULL DEFAULT '[]',
    human_validation_required INTEGER NOT NULL DEFAULT 1,
    ai_generated              INTEGER NOT NULL DEFAULT 1,
    raw                       TEXT NOT NULL DEFAULT '{}',
    created_at                TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reports (
    id         TEXT PRIMARY KEY,
    scan_id    TEXT NOT NULL REFERENCES scans(id),
    formats    TEXT NOT NULL DEFAULT '[]',
    paths      TEXT NOT NULL DEFAULT '{}',
    operator   TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id         TEXT PRIMARY KEY,
    action     TEXT NOT NULL,
    actor      TEXT NOT NULL DEFAULT '',
    target_ref TEXT NOT NULL DEFAULT '',
    detail     TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS plugins (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    version     TEXT NOT NULL DEFAULT '0.0.0',
    description TEXT NOT NULL DEFAULT '',
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_evidence_scan ON evidence(scan_id);
CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence(finding_id);
CREATE INDEX IF NOT EXISTS idx_endpoints_scan ON endpoints(scan_id);
CREATE INDEX IF NOT EXISTS idx_events_scan ON scan_events(scan_id);
CREATE INDEX IF NOT EXISTS idx_nodes_scan ON attack_graph_nodes(scan_id);
CREATE INDEX IF NOT EXISTS idx_edges_scan ON attack_graph_edges(scan_id);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at);
