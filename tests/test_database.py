"""Tests for database module."""

from __future__ import annotations

import pytest

from core.database import (
    InvestigationRecord,
    _get_connection,
    create_investigation,
    delete_investigation,
    get_investigation,
    list_investigations,
    search_investigations,
    update_investigation,
)


def test_init_db():
    """Test database initialization."""
    # Database should be initialized by fixture
    conn = _get_connection()
    # Check that investigations table exists
    tables = conn.execute("""
        SELECT name FROM sqlite_master 
        WHERE type='table' AND name='investigations'
    """).fetchall()
    assert len(tables) == 1
    assert tables[0][0] == "investigations"
    conn.close()


def test_create_investigation():
    """Test creating an investigation record."""
    record = InvestigationRecord(
        original_url="http://example.com",
        normalized_url="http://example.com",
        scheme="http",
        hostname="example.com",
        port=80,
        path="/",
        query_parameter_names=[],
        signals=[],
        status="New",
    )

    record_id = create_investigation(record)
    assert record_id is not None
    assert isinstance(record_id, int)
    assert record_id > 0

    # Verify the record was stored correctly
    retrieved = get_investigation(record_id)
    assert retrieved is not None
    assert retrieved.id == record_id
    assert retrieved.original_url == "http://example.com"
    assert retrieved.hostname == "example.com"
    assert retrieved.status == "New"


def test_get_investigation():
    """Test retrieving an investigation record."""
    # Create a record
    record = InvestigationRecord(
        original_url="https://test.com/path",
        normalized_url="https://test.com/path",
        scheme="https",
        hostname="test.com",
        port=443,
        path="/path",
        query_parameter_names=["param"],
        signals=[
            {"name": "test_signal", "description": "Test", "evidence": "value", "severity": "low"}
        ],
        status="Investigating",
    )

    record_id = create_investigation(record)

    # Retrieve the record
    retrieved = get_investigation(record_id)
    assert retrieved is not None
    assert retrieved.id == record_id
    assert retrieved.original_url == "https://test.com/path"
    assert retrieved.hostname == "test.com"
    assert retrieved.scheme == "https"
    assert retrieved.port == 443
    assert retrieved.path == "/path"
    assert retrieved.query_parameter_names == ["param"]
    assert len(retrieved.signals) == 1
    assert retrieved.signals[0]["name"] == "test_signal"
    assert retrieved.status == "Investigating"


def test_get_investigation_not_found():
    """Test retrieving a non-existent investigation."""
    retrieved = get_investigation(99999)
    assert retrieved is None


def test_list_investigations():
    """Test listing investigation records."""
    # Create multiple records
    record1 = InvestigationRecord(
        original_url="http://first.com",
        normalized_url="http://first.com",
        scheme="http",
        hostname="first.com",
        port=80,
        path="/",
        query_parameter_names=[],
        signals=[],
        status="New",
    )

    record2 = InvestigationRecord(
        original_url="http://second.com",
        normalized_url="http://second.com",
        scheme="http",
        hostname="second.com",
        port=80,
        path="/",
        query_parameter_names=[],
        signals=[],
        status="Investigating",
    )

    id1 = create_investigation(record1)
    id2 = create_investigation(record2)

    # List all investigations
    records = list_investigations()
    assert len(records) == 2

    # Should be ordered by created_at descending (most recent first)
    # Since record2 was created after record1, it should be first
    assert records[0].id == id2
    assert records[1].id == id1


def test_list_investigations_pagination():
    """Test pagination of investigation records."""
    # Create three records
    for i in range(3):
        record = InvestigationRecord(
            original_url=f"http://site{i}.com",
            normalized_url=f"http://site{i}.com",
            scheme="http",
            hostname=f"site{i}.com",
            port=80,
            path="/",
            query_parameter_names=[],
            signals=[],
            status="New",
        )
        create_investigation(record)

    # Test limit
    records = list_investigations(limit=2)
    assert len(records) == 2

    # Test offset
    records = list_investigations(limit=2, offset=1)
    assert len(records) == 2

    # Test limit+offset
    records = list_investigations(limit=1, offset=1)
    assert len(records) == 1


def test_search_investigations():
    """Test searching investigation records."""
    # Create records with different content
    record1 = InvestigationRecord(
        original_url="http://malicious-site.com/login",
        normalized_url="http://malicious-site.com/login",
        scheme="http",
        hostname="malicious-site.com",
        port=80,
        path="/login",
        query_parameter_names=[],
        signals=[],
        status="New",
        notes="This looks suspicious",
    )

    record2 = InvestigationRecord(
        original_url="http://legitimate-site.com",
        normalized_url="http://legitimate-site.com",
        scheme="http",
        hostname="legitimate-site.com",
        port=80,
        path="/",
        query_parameter_names=[],
        signals=[],
        status="New",
        notes="This seems OK",
    )

    create_investigation(record1)
    create_investigation(record2)

    # Search by URL
    results = search_investigations("malicious-site")
    assert len(results) == 1
    assert results[0].hostname == "malicious-site.com"

    # Search by hostname
    results = search_investigations("legitimate")
    assert len(results) == 1
    assert results[0].hostname == "legitimate-site.com"

    # Search by notes
    results = search_investigations("suspicious")
    assert len(results) == 1
    assert results[0].notes == "This looks suspicious"

    # Search with no matches
    results = search_investigations("nonexistent")
    assert len(results) == 0


def test_update_investigation():
    """Test updating an investigation record."""
    # Create a record
    record = InvestigationRecord(
        original_url="http://example.com",
        normalized_url="http://example.com",
        scheme="http",
        hostname="example.com",
        port=80,
        path="/",
        query_parameter_names=[],
        signals=[],
        status="New",
        notes="Initial notes",
    )

    record_id = create_investigation(record)
    # Set the ID on the record object (matching the pattern used elsewhere)
    record.id = record_id

    # Update the record
    record.notes = "Updated notes"
    record.status = "Investigating"
    update_investigation(record)

    # Verify the update
    retrieved = get_investigation(record_id)
    assert retrieved.notes == "Updated notes"
    assert retrieved.status == "Investigating"
    # updated_at should be newer than created_at
    assert retrieved.updated_at >= retrieved.created_at


def test_delete_investigation():
    """Test deleting an investigation record."""
    # Create a record
    record = InvestigationRecord(
        original_url="http://example.com",
        normalized_url="http://example.com",
        scheme="http",
        hostname="example.com",
        port=80,
        path="/",
        query_parameter_names=[],
        signals=[],
        status="New",
    )

    record_id = create_investigation(record)

    # Verify it exists
    assert get_investigation(record_id) is not None

    # Delete it
    delete_investigation(record_id)

    # Verify it's gone
    assert get_investigation(record_id) is None


if __name__ == "__main__":
    pytest.main([__file__])
