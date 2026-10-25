"""Integration tests for the full workflow."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from core.analysis import analyze_url
from core.database import init_db
from core.investigations import (
    add_investigation_note,
    enrich_investigation,
    export_investigations_csv,
    get_investigation_counts,
    set_investigation_conclusion,
    start_investigation,
    update_investigation_status,
)
from core.reporting import generate_json_report, generate_markdown_report


def test_full_workflow():
    """Test the complete workflow from URL analysis to report generation."""
    # Initialize database
    init_db()

    # Step 1: Analyze a URL
    url = "http://admin:secret@192.168.1.100:8080/login.php"
    analysis = analyze_url(url)

    assert analysis["original_url"] == url
    assert analysis["scheme"] == "http"
    assert analysis["hostname"] == "192.168.1.100"
    assert analysis["ip_literal"] == "192.168.1.100"
    assert analysis["port"] == 8080
    assert analysis["path"] == "/login.php"
    assert analysis["query_parameter_names"] == []

    # Check for expected signals
    signal_names = {s["name"]: s for s in analysis["signals"]}
    assert "ip_literal_host" in signal_names
    assert signal_names["ip_literal_host"]["severity"] == "medium"
    assert "nonstandard_port" in signal_names
    assert signal_names["nonstandard_port"]["severity"] == "low"
    assert "embedded_credentials" in signal_names
    assert signal_names["embedded_credentials"]["severity"] == "high"

    # Step 2: Start investigation
    record = start_investigation(url)
    assert record.id is not None
    assert record.original_url == url
    assert record.status == "New"

    # Step 3: Update status to Investigating
    record = update_investigation_status(record.id, "Investigating")
    assert record.status == "Investigating"

    # Step 4: Add notes
    record = add_investigation_note(record.id, "Suspicious login page with credentials in URL")
    assert "Suspicious login page" in record.notes

    # Step 5: Enrich with threat intelligence (mock mode)
    with patch.dict(os.environ, {}, clear=True):
        record = enrich_investigation(record.id)
        assert record.enrichment_source == "Mock (simulated)"
        assert record.enrichment_lookup_time is not None
        assert record.enrichment_data is not None

    # Step 6: Set conclusion and close
    record = set_investigation_conclusion(
        record.id, "Confirmed: credentials embedded in URL pose security risk"
    )
    assert record.conclusion == "Confirmed: credentials embedded in URL pose security risk"

    record = update_investigation_status(record.id, "False Positive")
    assert record.status == "False Positive"

    # Step 7: Generate reports
    json_report = generate_json_report(record.id)
    assert '"report_type": "JSON Investigation Report"' in json_report
    assert '"id":' in json_report
    assert '"original_url"' in json_report

    md_report = generate_markdown_report(record.id)
    assert "# Threat Intelligence Investigation Report" in md_report
    assert f"Investigation ID:** #{record.id}" in md_report
    assert "Confirmed: credentials embedded in URL pose security risk" in md_report

    # Step 8: Export CSV
    csv_data = export_investigations_csv()
    assert "ID" in csv_data
    assert "Original URL" in csv_data
    assert url in csv_data
    assert "False Positive" in csv_data

    # Step 9: Check counts
    counts = get_investigation_counts()
    assert counts.get("False Positive", 0) == 1
    assert sum(counts.values()) == 1


def test_multiple_investigations():
    """Test managing multiple investigations."""
    init_db()

    # Create several investigations
    urls = [
        "http://example.com",
        "https://google.com/search?q=test",
        "http://10.0.0.1:8080/admin",
        "https://github.com/user/repo",
    ]

    record_ids = []
    for url in urls:
        record = start_investigation(url)
        record_ids.append(record.id)

    # Update some statuses
    update_investigation_status(record_ids[0], "Investigating")
    set_investigation_conclusion(record_ids[1], "Safe site")
    update_investigation_status(record_ids[1], "Closed")
    set_investigation_conclusion(record_ids[2], "Internal server - acceptable risk")
    update_investigation_status(record_ids[2], "Closed")
    # Leave record_ids[3] as New

    # Add notes
    add_investigation_note(record_ids[0], "Needs further investigation")
    add_investigation_note(record_ids[1], "Verified as safe")
    add_investigation_note(record_ids[2], "Internal admin interface")

    # Check counts
    counts = get_investigation_counts()
    assert counts.get("New", 0) == 1
    assert counts.get("Investigating", 0) == 1
    assert counts.get("Closed", 0) == 2
    assert counts.get("False Positive", 0) == 0
    assert sum(counts.values()) == 4

    # Test search
    from core.investigations import search_investigations

    results = search_investigations("google")
    assert len(results) == 1
    assert results[0].hostname == "google.com"

    results = search_investigations("10.0.0.1")
    assert len(results) == 1
    assert results[0].ip_literal == "10.0.0.1"

    results = search_investigations("internal")
    assert len(results) == 1
    assert "Internal" in results[0].notes

    # Test CSV export includes all records
    csv_data = export_investigations_csv()
    # Count lines in CSV (header + 4 records)
    lines = csv_data.strip().split("\n")
    assert len(lines) == 5  # header + 4 data rows


if __name__ == "__main__":
    pytest.main([__file__])
