"""Tests for enrichment module."""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest
from httpx import HTTPStatusError, RequestError

from core.enrichment import EnrichmentError, _get_vt_api_key, _is_mock_mode, enrich_url


def test_is_mock_mode_no_key():
    """Test that mock mode is enabled when no API key is set."""
    with patch.dict(os.environ, {}, clear=True):
        assert _is_mock_mode() is True


def test_is_mock_mode_with_key():
    """Test that mock mode is disabled when API key is set."""
    with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-key"}):
        assert _is_mock_mode() is False


def test_get_vt_api_key():
    """Test retrieving VirusTotal API key from environment."""
    with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-key-123"}):
        assert _get_vt_api_key() == "test-key-123"


def test_get_vt_api_key_missing():
    """Test retrieving VirusTotal API key when not set."""
    with patch.dict(os.environ, {}, clear=True):
        assert _get_vt_api_key() is None


def test_enrich_url_mock_mode():
    """Test enrichment in mock mode (no API key)."""
    with patch.dict(os.environ, {}, clear=True):
        result = enrich_url("http://example.com")

        assert result.source == "Mock (simulated)"
        assert result.is_mock is True
        assert "data" in result.data
        assert "attributes" in result.data["data"]
        assert "last_analysis_stats" in result.data["data"]["attributes"]


def test_enrich_url_virus_total_success():
    """Test successful enrichment with VirusTotal API."""
    with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-key"}):
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

            result = enrich_url("http://example.com")

            assert result.source == "VirusTotal"
            assert result.is_mock is False
            assert result.data["data"]["attributes"]["last_analysis_stats"]["harmless"] == 10
            assert result.data["data"]["attributes"]["last_analysis_stats"]["malicious"] == 2
            assert result.data["data"]["attributes"]["reputation"] == 5


def test_enrich_url_virus_total_not_found():
    """Test enrichment when URL not found in VirusTotal dataset."""
    with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-key"}):
        with patch("core.enrichment.httpx.get") as mock_get:
            # Mock 404 response
            mock_response = MagicMock()
            mock_response.status_code = 404
            mock_response.raise_for_status.side_effect = HTTPStatusError(
                "Not Found", request=MagicMock(), response=mock_response
            )
            mock_get.return_value = mock_response

            result = enrich_url("http://example.com")

            # Should return empty attributes for 404
            assert result.source == "VirusTotal"
            assert result.data["data"]["attributes"]["last_analysis_stats"] == {}


def test_enrich_url_virus_total_unauthorized():
    """Test enrichment with invalid VirusTotal API key."""
    with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "invalid-key"}):
        with patch("core.enrichment.httpx.get") as mock_get:
            # Mock 401 response
            mock_response = MagicMock()
            mock_response.status_code = 401
            mock_response.raise_for_status.side_effect = HTTPStatusError(
                "Unauthorized", request=MagicMock(), response=mock_response
            )
            mock_get.return_value = mock_response

            with pytest.raises(EnrichmentError, match="Invalid VirusTotal API key"):
                enrich_url("http://example.com")


def test_enrich_url_virus_total_rate_limit():
    """Test enrichment when VirusTotal rate limit is exceeded."""
    with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-key"}):
        with patch("core.enrichment.httpx.get") as mock_get:
            # Mock 429 response
            mock_response = MagicMock()
            mock_response.status_code = 429
            mock_response.raise_for_status.side_effect = HTTPStatusError(
                "Too Many Requests", request=MagicMock(), response=mock_response
            )
            mock_get.return_value = mock_response

            with pytest.raises(EnrichmentError, match="VirusTotal rate limit exceeded"):
                enrich_url("http://example.com")


def test_enrich_url_virus_total_http_error():
    """Test enrichment with generic HTTP error."""
    with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-key"}):
        with patch("core.enrichment.httpx.get") as mock_get:
            # Mock 500 response
            mock_response = MagicMock()
            mock_response.status_code = 500
            mock_response.raise_for_status.side_effect = HTTPStatusError(
                "Server Error", request=MagicMock(), response=mock_response
            )
            mock_get.return_value = mock_response

            with pytest.raises(EnrichmentError, match="VirusTotal HTTP error: 500"):
                enrich_url("http://example.com")


def test_enrich_url_network_error():
    """Test enrichment with network error."""
    with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-key"}):
        with patch("core.enrichment.httpx.get") as mock_get:
            # Mock network error
            mock_get.side_effect = RequestError("Network error", request=MagicMock())

            with pytest.raises(EnrichmentError, match="Network error while querying VirusTotal"):
                enrich_url("http://example.com")


if __name__ == "__main__":
    pytest.main([__file__])
