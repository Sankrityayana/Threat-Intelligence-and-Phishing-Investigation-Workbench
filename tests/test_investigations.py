"""Tests for investigations module."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from core.analysis import URLAnalysisError
from core.enrichment import EnrichmentError
from core.investigations import (
    add_investigation_note,
    enrich_investigation,
    export_investigations_csv,
    get_investigation_counts,
    set_investigation_conclusion,
    start_investigation,
    update_investigation_status,
)


def test_start_investigation():
    """Test starting a new investigation."""
    record = start_investigation("http://example.com/path")

    assert record.id is not None
    assert record.original_url == "http://example.com/path"
    assert record.normalized_url == "http://example.com/path"
    assert record.scheme == "http"
    assert record.hostname == "example.com"
    assert record.port == 80
    assert record.path == "/path"
    assert record.query_parameter_names == []
    assert record.signals == []
    assert record.status == "New"
    assert record.notes == ""
    assert record.conclusion is None
    assert record.created_at == record.updated_at


def test_start_investigation_with_signals():
    """Test starting investigation with URL that produces signals."""
    record = start_investigation("http://192.168.1.1:8080/test")

    assert record.ip_literal == "192.168.1.1"
    assert record.port == 8080
    assert record.path == "/test"

    # Check for expected signals
    signal_names = {s["name"]: s for s in record.signals}
    assert "ip_literal_host" in signal_names
    assert signal_names["ip_literal_host"]["severity"] == "medium"
    assert "nonstandard_port" in signal_names
    assert signal_names["nonstandard_port"]["severity"] == "low"


def test_start_investigation_invalid_url():
    """Test starting investigation with invalid URL."""
    with pytest.raises(URLAnalysisError, match="Enter a URL to analyze"):
        start_investigation("")

    with pytest.raises(URLAnalysisError, match="Only HTTP and HTTPS URLs are supported"):
        start_investigation("ftp://example.com")


def test_update_investigation_status():
    """Test updating investigation status."""
    record = start_investigation("http://example.com")
    record_id = record.id

    # Update to Investigating
    updated = update_investigation_status(record_id, "Investigating")
    assert updated.status == "Investigating"
    assert updated.updated_at >= record.created_at

    # Update to Closed (should require conclusion)
    with pytest.raises(ValueError, match="Conclusion required when setting status to Closed"):
        update_investigation_status(record_id, "Closed")

    # Add conclusion and then close
    set_investigation_conclusion(record_id, "This was a false alarm")
    updated = update_investigation_status(record_id, "Closed")
    assert updated.status == "Closed"

    # Test invalid status
    with pytest.raises(ValueError, match="Invalid status: InvalidStatus"):
        update_investigation_status(record_id, "InvalidStatus")


def test_add_investigation_note():
    """Test adding notes to an investigation."""
    record = start_investigation("http://example.com")
    record_id = record.id

    # Add first note
    noted = add_investigation_note(record_id, "First observation")
    assert noted.notes == "First observation"

    # Add second note
    noted = add_investigation_note(record_id, "Second observation")
    assert "First observation" in noted.notes
    assert "Second observation" in noted.notes
    assert noted.notes.count("\n\n") == 1  # Separator between notes


def test_set_investigation_conclusion():
    """Test setting conclusion for an investigation."""
    record = start_investigation("http://example.com")
    record_id = record.id

    # Set conclusion
    concluded = set_investigation_conclusion(record_id, "This is malicious")
    assert concluded.conclusion == "This is malicious"

    # Update conclusion
    concluded = set_investigation_conclusion(record_id, "Actually, this is safe")
    assert concluded.conclusion == "Actually, this is safe"


def test_enrich_investigation_mock_mode():
    """Test enriching investigation in mock mode (no API key)."""
    with patch.dict("os.environ", {}, clear=True):
        record = start_investigation("http://example.com")
        record_id = record.id

        # Enrich the investigation
        enriched = enrich_investigation(record_id)

        assert enriched.enrichment_source == "Mock (simulated)"
        assert enriched.enrichment_lookup_time is not None
        assert enriched.enrichment_data is not None
        assert "data" in enriched.enrichment_data
        assert "attributes" in enriched.enrichment_data["data"]


def test_enrich_investigation_virus_total_success():
    """Test enriching investigation with successful VirusTotal response."""
    with patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": "test-key"}):
        with patch("core.enrichment.httpx.get") as mock_get:
            # Mock successful response
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"harmless": 10, "malicious": 2},
                        "reputation": 5,
                    }
                }
            }
            mock_response.raise_for_status.return_value = None
            mock_get.return_value = mock_response

            record = start_investigation("http://example.com")
            record_id = record.id

            # Enrich the investigation
            enriched = enrich_investigation(record_id)

            assert enriched.enrichment_source == "VirusTotal"
            assert (
                enriched.enrichment_data["data"]["attributes"]["last_analysis_stats"]["harmless"]
                == 10
            )
            assert (
                enriched.enrichment_data["data"]["attributes"]["last_analysis_stats"]["malicious"]
                == 2
            )
            assert enriched.enrichment_data["data"]["attributes"]["reputation"] == 5


def test_enrich_investigation_not_found():
    """Test enriching investigation that doesn't exist."""
    with pytest.raises(ValueError, match="Investigation 99999 not found"):
        enrich_investigation(99999)


def test_enrich_investigation_virus_total_error():
    """Test enriching investigation with VirusTotal error."""
    with patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": "invalid-key"}):
        with patch("core.enrichment.httpx.get") as mock_get:
            # Mock 401 response
            mock_response = MagicMock()
            mock_response.status_code = 401
            mock_response.raise_for_status.side_effect = EnrichmentError(
                "Invalid VirusTotal API key"
            )
            mock_get.return_value = mock_response

            record = start_investigation("http://example.com")
            record_id = record.id

            # Should raise EnrichmentError
            with pytest.raises(EnrichmentError, match="Invalid VirusTotal API key"):
                enrich_investigation(record_id)


def test_get_investigation_counts():
    """Test getting investigation counts by status."""
    # Start with clean state (handled by fixture)

    # Create investigations with different statuses
    record1 = start_investigation("http://site1.com")
    update_investigation_status(record1.id, "New")  # Already New, but explicit

    record2 = start_investigation("http://site2.com")
    update_investigation_status(record2.id, "Investigating")

    record3 = start_investigation("http://site3.com")
    set_investigation_conclusion(record3.id, "Malicious")
    update_investigation_status(record3.id, "Closed")

    record4 = start_investigation("http://site4.com")
    set_investigation_conclusion(record4.id, "Safe")
    update_investigation_status(record4.id, "False Positive")

    # Get counts
    counts = get_investigation_counts()

    assert counts.get("New", 0) == 1
    assert counts.get("Investigating", 0) == 1
    assert counts.get("Closed", 0) == 1
    assert counts.get("False Positive", 0) == 1


def test_export_investigations_csv():
    """Test exporting investigations as CSV."""
    # Create a few investigations
    start_investigation("http://example.com")
    record2 = start_investigation("http://test.com/path?param=value")
    update_investigation_status(record2.id, "Investigating")

    # Export CSV
    csv_data = export_investigations_csv()

    # Basic checks
    assert "ID" in csv_data
    assert "Original URL" in csv_data
    assert "http://example.com" in csv_data
    assert "http://test.com/path?param=value" in csv_data
    assert "New" in csv_data
    assert "Investigating" in csv_data


if __name__ == "__main__":
    pytest.main([__file__])
