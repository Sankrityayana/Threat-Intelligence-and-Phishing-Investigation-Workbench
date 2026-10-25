"""Investigation business logic layer."""

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime

from .analysis import analyze_url
from .database import (
    InvestigationRecord,
    create_investigation,
    get_investigation,
    list_investigations,
    update_investigation,
)
from .database import (
    search_investigations as _search_investigations,
)
from .enrichment import EnrichmentError, enrich_url


def search_investigations(query: str, limit: int = 100) -> list[InvestigationRecord]:
    """Search investigations by URL, hostname, or notes."""
    return _search_investigations(query, limit)


def start_investigation(url: str) -> InvestigationRecord:
    """
    Start a new investigation from a URL.

    Args:
        url: The URL to investigate.

    Returns:
        InvestigationRecord with analysis results.

    Raises:
        URLAnalysisError: If the URL cannot be analyzed.
    """
    analysis = analyze_url(url)
    record = InvestigationRecord(
        original_url=analysis["original_url"],
        normalized_url=analysis["normalized_url"],
        scheme=analysis["scheme"],
        hostname=analysis["hostname"],
        ip_literal=analysis["ip_literal"],
        port=analysis["port"],
        path=analysis["path"],
        query_parameter_names=analysis["query_parameter_names"],
        signals=analysis["signals"],
        status="New",
    )
    record.id = create_investigation(record)
    return record


def enrich_investigation(record_id: int) -> InvestigationRecord:
    """
    Enrich an existing investigation with threat intelligence data.

    Args:
        record_id: The ID of the investigation to enrich.

    Returns:
        Updated InvestigationRecord.

    Raises:
        ValueError: If the investigation record is not found.
        EnrichmentError: If enrichment fails.
    """
    record = get_investigation(record_id)
    if record is None:
        raise ValueError(f"Investigation {record_id} not found")

    try:
        enrichment = enrich_url(record.normalized_url)
        record.enrichment_source = enrichment.source
        record.enrichment_lookup_time = enrichment.lookup_time
        record.enrichment_data = enrichment.data
        update_investigation(record)
        return record
    except EnrichmentError:
        # Re-raise enrichment errors for the API layer to handle
        raise


def update_investigation_status(record_id: int, status: str) -> InvestigationRecord:
    """
    Update the status of an investigation.

    Args:
        record_id: The ID of the investigation.
        status: The new status (New, Investigating, Closed, False Positive).

    Returns:
        Updated InvestigationRecord.

    Raises:
        ValueError: If the investigation record is not found or status is invalid.
    """
    valid_statuses = {"New", "Investigating", "Closed", "False Positive"}
    if status not in valid_statuses:
        raise ValueError(f"Invalid status: {status}. Must be one of {valid_statuses}")

    record = get_investigation(record_id)
    if record is None:
        raise ValueError(f"Investigation {record_id} not found")

    # Require conclusion for Closed or False Positive status
    if status in {"Closed", "False Positive"} and not record.conclusion:
        raise ValueError(f"Conclusion required when setting status to {status}")

    record.status = status
    record.updated_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    update_investigation(record)
    return record


def add_investigation_note(record_id: int, note: str) -> InvestigationRecord:
    """
    Add a note to an investigation.

    Args:
        record_id: The ID of the investigation.
        note: The note to add.

    Returns:
        Updated InvestigationRecord.

    Raises:
        ValueError: If the investigation record is not found.
    """
    record = get_investigation(record_id)
    if record is None:
        raise ValueError(f"Investigation {record_id} not found")

    if record.notes:
        record.notes += "\n\n" + note
    else:
        record.notes = note
    record.updated_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    update_investigation(record)
    return record


def set_investigation_conclusion(record_id: int, conclusion: str) -> InvestigationRecord:
    """
    Set the conclusion for an investigation.

    Args:
        record_id: The ID of the investigation.
        conclusion: The conclusion text.

    Returns:
        Updated InvestigationRecord.

    Raises:
        ValueError: If the investigation record is not found.
    """
    record = get_investigation(record_id)
    if record is None:
        raise ValueError(f"Investigation {record_id} not found")

    record.conclusion = conclusion
    record.updated_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    update_investigation(record)
    return record


def get_investigation_counts() -> dict[str, int]:
    """
    Get counts of investigations by status.

    Returns:
        Dictionary mapping status to count.
    """
    from .database import _get_connection

    with _get_connection() as conn:
        rows = conn.execute("""
            SELECT status, COUNT(*) as count
            FROM investigations
            GROUP BY status
        """).fetchall()
        return {row["status"]: row["count"] for row in rows}


def export_investigations_csv() -> str:
    """
    Export all investigations as CSV.

    Returns:
        CSV string with investigation data.

    Note:
        CSV output is protected against formula injection by prefixing
        cells that begin with '=', '+', '-', '@', or '\t' with a space.
    """
    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow(
        [
            "ID",
            "Created At",
            "Updated At",
            "Original URL",
            "Normalized URL",
            "Scheme",
            "Hostname",
            "IP Literal",
            "Port",
            "Path",
            "Query Parameter Names",
            "Signals",
            "Enrichment Source",
            "Enrichment Lookup Time",
            "Status",
            "Notes",
            "Conclusion",
        ]
    )

    # Data rows
    for record in list_investigations():
        # Protect against formula injection
        def protect_cell(value: str) -> str:
            if isinstance(value, str) and value and value[0] in {"=", "+", "-", "@", "\t"}:
                return "'" + value  # Prefix with apostrophe to neutralize
            return value

        writer.writerow(
            [
                record.id,
                protect_cell(record.created_at),
                protect_cell(record.updated_at),
                protect_cell(record.original_url),
                protect_cell(record.normalized_url),
                protect_cell(record.scheme),
                protect_cell(record.hostname),
                protect_cell(str(record.ip_literal) if record.ip_literal else ""),
                record.port,
                protect_cell(record.path),
                protect_cell(",".join(record.query_parameter_names)),
                protect_cell(str(record.signals)),
                protect_cell(record.enrichment_source or ""),
                protect_cell(record.enrichment_lookup_time or ""),
                protect_cell(record.status),
                protect_cell(record.notes),
                protect_cell(record.conclusion or ""),
            ]
        )

    return output.getvalue()
