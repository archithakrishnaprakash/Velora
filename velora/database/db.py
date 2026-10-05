"""SQLite connection management and a small forward-only migration runner."""
from __future__ import annotations

import sqlite3
from pathlib import Path

from ..config.settings import Settings
from ..utils.logging import get_logger
from .columns import ensure_columns

log = get_logger("database")

MIGRATIONS_DIR = Path(__file__).parent / "migrations"


def _resolve_sqlite_path(settings: Settings) -> Path:
    if settings.database.is_sqlite:
        path = settings.database.sqlite_path
    else:
        # Non-sqlite URL: the architecture supports it, but the reference engine here
        # is sqlite. Fall back to a local file and warn.
        log.warning(
            "database.url is not sqlite (%s); the bundled engine uses sqlite. "
            "See docs/architecture.md for the PostgreSQL/SQLAlchemy path.",
            settings.database.url,
        )
        path = settings.data_dir / "velora.db"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def connect(settings: Settings) -> sqlite3.Connection:
    """Open a configured SQLite connection (foreign keys on, Row factory)."""
    path = _resolve_sqlite_path(settings)
    conn = sqlite3.connect(str(path), isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA busy_timeout = 5000;")
    return conn


def _ensure_migrations_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations ("
        " version TEXT PRIMARY KEY, applied_at TEXT NOT NULL);"
    )


def applied_versions(conn: sqlite3.Connection) -> set[str]:
    _ensure_migrations_table(conn)
    rows = conn.execute("SELECT version FROM schema_migrations;").fetchall()
    return {r[0] for r in rows}


def pending_migrations(conn: sqlite3.Connection) -> list[Path]:
    done = applied_versions(conn)
    files = sorted(MIGRATIONS_DIR.glob("*.sql"))
    return [f for f in files if f.stem not in done]


def migrate(conn: sqlite3.Connection) -> list[str]:
    """Apply pending migrations in filename order. Returns applied version names."""
    from datetime import datetime, timezone

    _ensure_migrations_table(conn)
    applied: list[str] = []
    for path in pending_migrations(conn):
        log.info("applying migration %s", path.stem)
        sql = path.read_text(encoding="utf-8")
        conn.executescript(sql)
        conn.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?);",
            (path.stem, datetime.now(timezone.utc).isoformat()),
        )
        applied.append(path.stem)
    # Idempotent column additions for tables that already existed (safe on every run).
    ensure_columns(conn)
    return applied


class Database:
    """A connection + repository handle for the framework."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.conn = connect(settings)

    def init(self) -> list[str]:
        return migrate(self.conn)

    def close(self) -> None:
        try:
            self.conn.close()
        except sqlite3.Error:
            pass

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
