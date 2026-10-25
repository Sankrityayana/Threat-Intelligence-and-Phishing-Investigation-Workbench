"""Tests for URL analysis module."""

from __future__ import annotations

import pytest

from core.analysis import URLAnalysisError, analyze_url


def test_valid_http_url():
    """Test analysis of a valid HTTP URL."""
    result = analyze_url("http://example.com/path")
    assert result["original_url"] == "http://example.com/path"
    assert result["normalized_url"] == "http://example.com/path"
    assert result["scheme"] == "http"
    assert result["hostname"] == "example.com"
    assert result["ip_literal"] is None
    assert result["port"] == 80
    assert result["path"] == "/path"
    assert result["query_parameter_names"] == []


def test_valid_https_url():
    """Test analysis of a valid HTTPS URL."""
    result = analyze_url("https://example.com:443/path?param=value")
    assert result["original_url"] == "https://example.com:443/path?param=value"
    assert result["normalized_url"] == "https://example.com/path?param=value"
    assert result["scheme"] == "https"
    assert result["hostname"] == "example.com"
    assert result["ip_literal"] is None
    assert result["port"] == 443
    assert result["path"] == "/path"
    assert result["query_parameter_names"] == ["param"]


def test_ip_literal_host():
    """Test analysis of URL with IP literal host."""
    result = analyze_url("http://192.168.1.1:8080/test")
    assert result["original_url"] == "http://192.168.1.1:8080/test"
    assert result["normalized_url"] == "http://[192.168.1.1]:8080/test"
    assert result["scheme"] == "http"
    assert result["hostname"] == "192.168.1.1"
    assert result["ip_literal"] == "192.168.1.1"
    assert result["port"] == 8080
    assert result["path"] == "/test"
    assert result["query_parameter_names"] == []

    # Check for IP literal signal
    signals = {s["name"]: s for s in result["signals"]}
    assert "ip_literal_host" in signals
    assert signals["ip_literal_host"]["severity"] == "medium"


def test_nonstandard_port():
    """Test analysis of URL with non-standard port."""
    result = analyze_url("http://example.com:8080")
    assert result["port"] == 8080

    # Check for nonstandard_port signal
    signals = {s["name"]: s for s in result["signals"]}
    assert "nonstandard_port" in signals
    assert signals["nonstandard_port"]["severity"] == "low"


def test_https_default_port():
    """Test analysis of HTTPS URL with default port (should not show nonstandard_port signal)."""
    result = analyze_url("https://example.com:443")
    assert result["port"] == 443

    # Should not have nonstandard_port signal
    signals = {s["name"]: s for s in result["signals"]}
    assert "nonstandard_port" not in signals


def test_embedded_credentials():
    """Test analysis of URL with embedded credentials."""
    result = analyze_url("http://user:pass@example.com")
    assert result["hostname"] == "example.com"

    # Check for embedded_credentials signal
    signals = {s["name"]: s for s in result["signals"]}
    assert "embedded_credentials" in signals
    assert signals["embedded_credentials"]["severity"] == "high"


def test_punycode_hostname():
    """Test analysis of URL with punycode hostname."""
    result = analyze_url("http://xn--exmple-cua.com")
    assert result["hostname"] == "xn--exmple-cua.com"

    # Check for punycode_hostname signal
    signals = {s["name"]: s for s in result["signals"]}
    assert "punycode_hostname" in signals
    assert signals["punycode_hostname"]["severity"] == "medium"


def test_deep_subdomain():
    """Test analysis of URL with deep subdomain."""
    result = analyze_url("http://a.b.c.d.example.com")
    assert result["hostname"] == "a.b.c.d.example.com"

    # Check for deep_subdomain signal
    signals = {s["name"]: s for s in result["signals"]}
    assert "deep_subdomain" in signals
    assert signals["deep_subdomain"]["severity"] == "low"


def test_percent_encoded_content():
    """Test analysis of URL with percent-encoded content."""
    result = analyze_url("http://example.com/path%20with%20spaces")
    assert result["path"] == "/path%20with%20spaces"

    # Check for percent_encoded_content signal
    signals = {s["name"]: s for s in result["signals"]}
    assert "percent_encoded_content" in signals
    assert signals["percent_encoded_content"]["severity"] == "info"


def test_query_parameters():
    """Test extraction of query parameter names."""
    result = analyze_url("http://example.com?foo=1&bar=2&foo=3")
    assert result["query_parameter_names"] == ["bar", "foo"]  # Sorted alphabetically


def test_empty_url():
    """Test analysis of empty URL."""
    with pytest.raises(URLAnalysisError, match="Enter a URL to analyze"):
        analyze_url("")


def test_none_url():
    """Test analysis of None URL."""
    with pytest.raises(URLAnalysisError, match="Enter a URL to analyze"):
        analyze_url(None)


def test_control_characters():
    """Test analysis of URL with control characters."""
    with pytest.raises(URLAnalysisError, match="URL contains unsupported control characters"):
        analyze_url("http://example.com\x00path")


def test_invalid_scheme():
    """Test analysis of URL with invalid scheme."""
    with pytest.raises(URLAnalysisError, match="Only HTTP and HTTPS URLs are supported"):
        analyze_url("ftp://example.com")


def test_missing_hostname():
    """Test analysis of URL missing hostname."""
    with pytest.raises(URLAnalysisError, match="URL must contain a hostname"):
        analyze_url("http:///path")


def test_invalid_port():
    """Test analysis of URL with invalid port."""
    with pytest.raises(URLAnalysisError, match="URL contains an invalid hostname or port"):
        analyze_url("http://example.com:99999")


def test_long_url():
    """Test analysis of URL exceeding maximum length."""
    long_url = "http://example.com/" + "a" * 4096
    with pytest.raises(URLAnalysisError, match="URL exceeds the 4096-character limit"):
        analyze_url(long_url)


def test_idn_hostname():
    """Test analysis of URL with internationalized domain name."""
    result = analyze_url("http://例子.com")
    assert result["hostname"] == "xn--fsqu00a.com"  # IDNA encoded

    # Should have punycode signal since the hostname starts with xn--
    signals = {s["name"]: s for s in result["signals"]}
    assert "punycode_hostname" in signals
    assert signals["punycode_hostname"]["severity"] == "medium"


def test_normalization_remove_dot_segments():
    """Test that URL normalization removes dot segments."""
    result = analyze_url("http://example.com/./path/../other")
    assert result["normalized_url"] == "http://example.com/other"


def test_normalization_preserve_trailing_slash():
    """Test that URL normalization preserves meaningful trailing slashes."""
    result = analyze_url("http://example.com/path/")
    assert result["normalized_url"] == "http://example.com/path/"


if __name__ == "__main__":
    pytest.main([__file__])
