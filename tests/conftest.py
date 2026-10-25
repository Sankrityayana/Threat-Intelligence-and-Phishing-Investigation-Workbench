"""Shared pytest configuration and fixtures."""

from __future__ import annotations

import pytest

from core.database import init_db


@pytest.fixture(autouse=True)
def setup_temp_db(tmp_path, monkeypatch):
    """Set up a temporary database for testing."""
    # Create a temporary directory and set DB_PATH to it
    test_db_path = tmp_path / "test_investigations.sqlite"
    monkeypatch.setattr("core.database.DB_PATH", test_db_path)

    # Initialize the database
    init_db()
