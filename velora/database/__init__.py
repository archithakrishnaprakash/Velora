"""Persistence layer.

The default engine is stdlib ``sqlite3`` behind a thin repository API, chosen so the
framework runs with zero external dependencies and is fully testable. The schema and
repository boundary are deliberately ORM-agnostic: the DDL in ``migrations/`` uses
PostgreSQL-compatible column types, and the repository methods map cleanly onto a
SQLAlchemy 2.0 session if a production deployment prefers that (see docs/architecture.md).
"""
from .db import Database, connect, migrate
from .repository import Repository

__all__ = ["Database", "Repository", "connect", "migrate"]
