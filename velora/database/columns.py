"""Idempotent column additions for existing tables.

SQLite has no ``ALTER TABLE ... ADD COLUMN IF NOT EXISTS``. Rather than putting bare
ALTER statements in a migration file (which would explode on a partially-migrated or
manually-patched database), every new column on a pre-existing table is declared here and
applied through a ``PRAGMA table_info`` check.

This is safe to run on every startup: existing columns are left untouched, and no data is
ever dropped or rewritten.
"""
from __future__ import annotations

import sqlite3

from ..utils.logging import get_logger

log = get_logger("database.columns")

# table -> [(column_name, column_definition)]
REQUIRED_COLUMNS: dict[str, list[tuple[str, str]]] = {
    "targets": [
        ("engagement_id", "TEXT"),
    ],
    "scans": [
        ("engagement_id", "TEXT"),
        ("baseline_scan_id", "TEXT"),
        ("is_retest", "INTEGER NOT NULL DEFAULT 0"),
    ],
    "findings": [
        ("engagement_id", "TEXT"),
        ("identity_id", "TEXT"),
        ("cwe_id", "TEXT NOT NULL DEFAULT 'UNKNOWN'"),
        ("owasp_category", "TEXT NOT NULL DEFAULT 'UNKNOWN'"),
        ("remediation_status", "TEXT NOT NULL DEFAULT 'OPEN'"),
        ("fingerprint", "TEXT NOT NULL DEFAULT ''"),
        ("first_seen_scan_id", "TEXT"),
        ("validation_state", "TEXT NOT NULL DEFAULT 'OBSERVED'"),
    ],
    "attack_graph_nodes": [
        ("confidence", "REAL NOT NULL DEFAULT 0.5"),
        ("validation_status", "TEXT NOT NULL DEFAULT 'OBSERVED'"),
        ("evidence_ids", "TEXT NOT NULL DEFAULT '[]'"),
        ("created_at", "TEXT"),
    ],
    "attack_graph_edges": [
        ("confidence", "REAL NOT NULL DEFAULT 0.5"),
        ("validation_status", "TEXT NOT NULL DEFAULT 'INFERRED'"),
        ("evidence_ids", "TEXT NOT NULL DEFAULT '[]'"),
        ("source", "TEXT NOT NULL DEFAULT ''"),
        ("created_at", "TEXT"),
    ],
    "reports": [
        ("unavailable", "TEXT NOT NULL DEFAULT '[]'"),
    ],
    "benchmark_runs": [
        ("uncovered_detections", "INTEGER NOT NULL DEFAULT 0"),
        ("uncovered", "TEXT NOT NULL DEFAULT '[]'"),
        ("ai_agreement", "REAL"),
        ("human_validation_rate", "REAL"),
    ],
    "ai_analyses": [
        ("supporting_evidence", "TEXT NOT NULL DEFAULT '[]'"),
        ("contradicting_evidence", "TEXT NOT NULL DEFAULT '[]'"),
        ("missing_evidence", "TEXT NOT NULL DEFAULT '[]'"),
        ("recommended_validation", "TEXT NOT NULL DEFAULT ''"),
        ("evidence_matrix", "TEXT NOT NULL DEFAULT '{}'"),
        ("validation_status", "TEXT NOT NULL DEFAULT 'HYPOTHESIZED'"),
        ("prompt_sanitized", "INTEGER NOT NULL DEFAULT 1"),
    ],
}


def existing_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    try:
        rows = conn.execute(f"PRAGMA table_info({table});").fetchall()
    except sqlite3.Error:
        return set()
    return {r[1] for r in rows}


def table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name = ?;", (table,)
    ).fetchone()
    return row is not None


# Columns that should be backfilled for rows that predate them.
# Maps "table.column" -> SQL expression used as the fill value.
BACKFILL: dict[str, str] = {
    "attack_graph_nodes.created_at": "datetime('now')",
    "attack_graph_edges.created_at": "datetime('now')",
}


def ensure_columns(conn: sqlite3.Connection) -> list[str]:
    """Add any missing columns. Returns the list of 'table.column' entries added."""
    added: list[str] = []
    for table, columns in REQUIRED_COLUMNS.items():
        if not table_exists(conn, table):
            continue  # table comes from a migration that has not run yet
        present = existing_columns(conn, table)
        for name, definition in columns:
            if name in present:
                continue
            try:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition};")
                added.append(f"{table}.{name}")
                fill = BACKFILL.get(f"{table}.{name}")
                if fill:
                    conn.execute(
                        f"UPDATE {table} SET {name} = {fill} WHERE {name} IS NULL;"  # noqa: S608
                    )
            except sqlite3.OperationalError as exc:
                # "duplicate column name" can still occur on a racing upgrade; tolerate it.
                if "duplicate column" not in str(exc).lower():
                    raise
    if added:
        log.info("schema columns added: %s", ", ".join(added))
    return added
