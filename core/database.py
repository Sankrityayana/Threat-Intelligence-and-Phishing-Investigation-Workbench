"""SQLite persistence layer for investigation records."""

from __future__ import annotations

import json
import sqlite3
from ast import literal_eval
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

DB_PATH = Path("investigations.sqlite")


@dataclass
class InvestigationRecord:
    id: int | None = None
    created_at: str = ""
    updated_at: str = ""
    original_url: str = ""
    normalized_url: str = ""
    scheme: str = ""
    hostname: str = ""
    ip_literal: str | None = None
    port: int = 0
    path: str = ""
    query_parameter_names: list[str] | None = None
    signals: list[dict[str, str]] | None = None
    enrichment_source: str | None = None
    enrichment_lookup_time: str | None = None
    enrichment_data: dict[str, Any] | None = None
    status: str = "New"
    notes: str = ""
    conclusion: str | None = None

    def __post_init__(self) -> None:
        if self.query_parameter_names is None:
            self.query_parameter_names = []
        if self.signals is None:
            self.signals = []
        if self.enrichment_data is None:
            self.enrichment_data = {}
        if not self.created_at:
            self.created_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        if not self.updated_at:
            self.updated_at = self.created_at


def _get_connection() -> sqlite3.Connection:
    """Get a connection to the SQLite database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Initialize the database and create tables if they don't exist."""
    with _get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS investigations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                original_url TEXT NOT NULL,
                normalized_url TEXT NOT NULL,
                scheme TEXT NOT NULL,
                hostname TEXT NOT NULL,
                ip_literal TEXT,
                port INTEGER NOT NULL,
                path TEXT NOT NULL,
                query_parameter_names TEXT NOT NULL,
                signals TEXT NOT NULL,
                enrichment_source TEXT,
                enrichment_lookup_time TEXT,
                enrichment_data TEXT,
                status TEXT NOT NULL DEFAULT 'New',
                notes TEXT NOT NULL DEFAULT '',
                conclusion TEXT
            )
        """)
        conn.commit()


def create_investigation(record: InvestigationRecord) -> int:
    """Create a new investigation record and return its ID."""
    with _get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO investigations (
                created_at, updated_at, original_url, normalized_url,
                scheme, hostname, ip_literal, port, path,
                query_parameter_names, signals, enrichment_source,
                enrichment_lookup_time, enrichment_data, status, notes, conclusion
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                record.created_at,
                record.updated_at,
                record.original_url,
                record.normalized_url,
                record.scheme,
                record.hostname,
                record.ip_literal,
                record.port,
                record.path,
                ",".join(record.query_parameter_names),
                json.dumps(record.signals),
                record.enrichment_source,
                record.enrichment_lookup_time,
                json.dumps(record.enrichment_data),
                record.status,
                record.notes,
                record.conclusion,
            ),
        )
        conn.commit()
        return cursor.lastrowid


def get_investigation(record_id: int) -> InvestigationRecord | None:
    """Retrieve an investigation record by ID."""
    with _get_connection() as conn:
        row = conn.execute(
            """
            SELECT * FROM investigations WHERE id = ?
        """,
            (record_id,),
        ).fetchone()
        if row is None:
            return None
        return _row_to_record(row)


def list_investigations(limit: int = 100, offset: int = 0) -> list[InvestigationRecord]:
    """List investigation records with pagination."""
    with _get_connection() as conn:
        rows = conn.execute(
            """
            SELECT * FROM investigations
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
        """,
            (limit, offset),
        ).fetchall()
        return [_row_to_record(row) for row in rows]


def search_investigations(query: str, limit: int = 100) -> list[InvestigationRecord]:
    """Search investigations by original URL, hostname, or notes."""
    with _get_connection() as conn:
        rows = conn.execute(
            """
            SELECT * FROM investigations
            WHERE original_url LIKE ? OR hostname LIKE ? OR notes LIKE ?
            ORDER BY created_at DESC
            LIMIT ?
        """,
            (f"%{query}%", f"%{query}%", f"%{query}%", limit),
        ).fetchall()
        return [_row_to_record(row) for row in rows]


def update_investigation(record: InvestigationRecord) -> None:
    """Update an existing investigation record."""
    if record.id is None:
        raise ValueError("Cannot update investigation without ID")
    with _get_connection() as conn:
        conn.execute(
            """
            UPDATE investigations SET
                updated_at = ?,
                original_url = ?,
                normalized_url = ?,
                scheme = ?,
                hostname = ?,
                ip_literal = ?,
                port = ?,
                path = ?,
                query_parameter_names = ?,
                signals = ?,
                enrichment_source = ?,
                enrichment_lookup_time = ?,
                enrichment_data = ?,
                status = ?,
                notes = ?,
                conclusion = ?
            WHERE id = ?
        """,
            (
                record.updated_at,
                record.original_url,
                record.normalized_url,
                record.scheme,
                record.hostname,
                record.ip_literal,
                record.port,
                record.path,
                ",".join(record.query_parameter_names),
                json.dumps(record.signals),
                record.enrichment_source,
                record.enrichment_lookup_time,
                json.dumps(record.enrichment_data),
                record.status,
                record.notes,
                record.conclusion,
                record.id,
            ),
        )
        conn.commit()


def delete_investigation(record_id: int) -> None:
    """Delete an investigation record by ID."""
    with _get_connection() as conn:
        conn.execute("DELETE FROM investigations WHERE id = ?", (record_id,))
        conn.commit()


def _row_to_record(row: sqlite3.Row) -> InvestigationRecord:
    """Convert a database row to an InvestigationRecord."""
    return InvestigationRecord(
        id=row["id"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        original_url=row["original_url"],
        normalized_url=row["normalized_url"],
        scheme=row["scheme"],
        hostname=row["hostname"],
        ip_literal=row["ip_literal"],
        port=row["port"],
        path=row["path"],
        query_parameter_names=(
            row["query_parameter_names"].split(",") if row["query_parameter_names"] else []
        ),
        signals=_decode_json_value(row["signals"], []),
        enrichment_source=row["enrichment_source"],
        enrichment_lookup_time=row["enrichment_lookup_time"],
        enrichment_data=_decode_json_value(row["enrichment_data"], {}),
        status=row["status"],
        notes=row["notes"],
        conclusion=row["conclusion"],
    )


def _decode_json_value(value: str | None, default: Any) -> Any:
    """Decode JSON while safely accepting records from the pre-JSON schema."""
    if not value:
        return default
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        legacy_value = literal_eval(value)
        if isinstance(legacy_value, type(default)):
            return legacy_value
        raise ValueError("Stored investigation data has an invalid shape")
