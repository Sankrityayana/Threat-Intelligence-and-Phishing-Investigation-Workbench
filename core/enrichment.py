"""Optional threat intelligence enrichment with VirusTotal and mock mode."""

from __future__ import annotations

import base64
import os
import time
from dataclasses import asdict, dataclass
from typing import Any

import httpx
from dotenv import load_dotenv

load_dotenv()  # Load .env file if present

VT_API_URL = "https://www.virustotal.com/api/v3/urls"
VT_HEADERS_TEMPLATE = {"accept": "application/json"}
REQUEST_TIMEOUT = 30.0


class EnrichmentError(RuntimeError):
    """Raised when enrichment fails due to configuration or network issues."""


@dataclass(frozen=True)
class EnrichmentResult:
    source: str
    lookup_time: str
    data: dict[str, Any]
    is_mock: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _get_vt_api_key() -> str | None:
    """Retrieve VirusTotal API key from environment."""
    return os.getenv("VIRUSTOTAL_API_KEY")


def _is_mock_mode() -> bool:
    """Determine if mock mode should be used (no API key)."""
    return _get_vt_api_key() is None


def _fetch_vt_url_report(url: str) -> dict[str, Any]:
    """Fetch URL report from VirusTotal API."""
    api_key = _get_vt_api_key()
    if not api_key:
        raise EnrichmentError("VirusTotal API key not configured.")

    headers = {**VT_HEADERS_TEMPLATE, "x-apikey": api_key}
    # VirusTotal expects a base64-encoded URL ID without padding
    url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").rstrip("=")
    response = httpx.get(
        f"{VT_API_URL}/{url_id}",
        headers=headers,
        timeout=REQUEST_TIMEOUT,
    )
    if response.status_code == 404:
        # URL not found in VT dataset
        return {"data": {"attributes": {"last_analysis_stats": {}}}}
    response.raise_for_status()
    return response.json()


def _build_mock_result(url: str) -> dict[str, Any]:
    """Build a clearly labeled mock enrichment result."""
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "harmless": 0,
                    "malicious": 0,
                    "suspicious": 0,
                    "undetected": 0,
                },
                "last_analysis_results": {},
                "total_votes": {"harmless": 0, "malicious": 0},
                "reputation": 0,
            }
        }
    }


def enrich_url(url: str) -> EnrichmentResult:
    """
    Enrich a URL with threat intelligence data.

    Args:
        url: The URL to enrich.

    Returns:
        EnrichmentResult with source, timestamp, and data.

    Raises:
        EnrichmentError: If enrichment fails due to configuration or network issues.
    """
    if _is_mock_mode():
        data = _build_mock_result(url)
        source = "Mock (simulated)"
    else:
        try:
            data = _fetch_vt_url_report(url)
            source = "VirusTotal"
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 401:
                raise EnrichmentError("Invalid VirusTotal API key.") from exc
            if exc.response.status_code == 429:
                raise EnrichmentError("VirusTotal rate limit exceeded.") from exc
            raise EnrichmentError(f"VirusTotal HTTP error: {exc.response.status_code}") from exc
        except httpx.RequestError as exc:
            raise EnrichmentError(f"Network error while querying VirusTotal: {exc}") from exc

    lookup_time = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    return EnrichmentResult(
        source=source,
        lookup_time=lookup_time,
        data=data,
        is_mock=_is_mock_mode(),
    )
