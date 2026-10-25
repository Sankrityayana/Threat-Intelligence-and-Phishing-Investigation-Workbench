"""Report generation for investigation records."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from core.database import get_investigation


def generate_json_report(record_id: int) -> str:
    """
    Generate a JSON report for an investigation.

    Args:
        record_id: The ID of the investigation.

    Returns:
        JSON string containing the investigation report.

    Raises:
        ValueError: If the investigation record is not found.
    """
    record = get_investigation(record_id)
    if record is None:
        raise ValueError(f"Investigation {record_id} not found")

    # Prepare report data
    report_data = {
        "report_type": "JSON Investigation Report",
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "investigation": {
            "id": record.id,
            "timestamps": {"created_at": record.created_at, "updated_at": record.updated_at},
            "url_analysis": {
                "original_url": record.original_url,
                "normalized_url": record.normalized_url,
                "scheme": record.scheme,
                "hostname": record.hostname,
                "ip_literal": record.ip_literal,
                "port": record.port,
                "path": record.path,
                "query_parameter_names": record.query_parameter_names,
                "signals": record.signals,
            },
            "threat_intelligence": {
                "source": record.enrichment_source,
                "lookup_time": record.enrichment_lookup_time,
                "data": record.enrichment_data,
                "is_mock": record.enrichment_source == "Mock (simulated)"
                if record.enrichment_source
                else False,
            }
            if record.enrichment_source
            else None,
            "investigation_details": {
                "status": record.status,
                "notes": record.notes,
                "conclusion": record.conclusion,
            },
            "limitations": [
                "This is an educational prototype for static URL analysis only.",
                "No network requests are made to the submitted URL.",
                "Heuristic signals are not proof of maliciousness.",
                "Enrichment depends on third-party provider availability and rate limits.",
                "Mock enrichment results are simulated and not real threat intelligence.",
            ],
            "suggested_next_steps": [
                "Review the analysis signals and enrichment results.",
                "Consider additional context from internal logs or threat feeds.",
                "Determine if further investigation is warranted based on organizational policy.",
                "Document findings and share with relevant stakeholders.",
            ],
        },
    }

    return json.dumps(report_data, indent=2, ensure_ascii=False)


def generate_markdown_report(record_id: int) -> str:
    """
    Generate a Markdown report for an investigation.

    Args:
        record_id: The ID of the investigation.

    Returns:
        Markdown string containing the investigation report.

    Raises:
        ValueError: If the investigation record is not found.
    """
    record = get_investigation(record_id)
    if record is None:
        raise ValueError(f"Investigation {record_id} not found")

    # Format enrichment info
    enrichment_info = "Not performed"
    if record.enrichment_source:
        source_label = (
            f"{record.enrichment_source} (SIMULATED)"
            if record.enrichment_source == "Mock (simulated)"
            else record.enrichment_source
        )
        enrichment_info = (
            f"**Source:** {source_label}\n\n**Lookup Time:** {record.enrichment_lookup_time}\n\n"
        )
        if (
            record.enrichment_data
            and "data" in record.enrichment_data
            and "attributes" in record.enrichment_data["data"]
        ):
            attrs = record.enrichment_data["data"]["attributes"]
            if "last_analysis_stats" in attrs:
                stats = attrs["last_analysis_stats"]
                if any(stats.values()):
                    enrichment_info += "**Analysis Stats:**\n"
                    for key, value in stats.items():
                        if value > 0:
                            enrichment_info += f"- {key.capitalize()}: {value}\n"
                    enrichment_info += "\n"
            if "reputation" in attrs:
                enrichment_info += f"**Reputation Score:** {attrs['reputation']}\n\n"
            if "total_votes" in attrs:
                votes = attrs["total_votes"]
                if any(votes.values()):
                    enrichment_info += (
                        f"**Community Votes:** Harmless: {votes.get('harmless', 0)}, "
                        f"Malicious: {votes.get('malicious', 0)}\n\n"
                    )

    # Format signals
    signals_info = "No significant signals detected."
    if record.signals:
        signals_info = ""
        for signal in record.signals:
            signals_info += (
                f"- **[{signal['severity'].upper()}]** {signal['description']}: "
                f"`{signal['evidence']}`\n"
            )

    # Format query parameters
    query_params_info = (
        ", ".join(record.query_parameter_names) if record.query_parameter_names else "None"
    )

    report = f"""# Threat Intelligence Investigation Report

**Report Generated:** {datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")} UTC  
**Investigation ID:** #{record.id}

---

## Executive Summary
This report documents the static analysis of a suspicious URL conducted using the
Threat Intelligence & Phishing Investigation Workbench. The analysis includes URL
normalization, indicator extraction, heuristic signal detection, and optional
threat intelligence enrichment.

---

## Investigation Details

### URL Information
- **Original URL:** {record.original_url}
- **Normalized URL:** {record.normalized_url}
- **Scheme:** {record.scheme.upper()}
- **Hostname:** {record.hostname}
- **IP Literal:** {record.ip_literal or "None"}
- **Port:** {record.port}
- **Path:** {record.path}
- **Query Parameters:** {query_params_info}

### Analysis Signals
{signals_info}

### Threat Intelligence Enrichment
{enrichment_info}

### Investigation Metadata
- **Created At:** {record.created_at}
- **Updated At:** {record.updated_at}
- **Current Status:** {record.status}
- **Analyst Notes:** 
{record.notes if record.notes else "_No notes recorded._"}
- **Conclusion:** 
{record.conclusion if record.conclusion else "_No conclusion recorded._"}

---

## Limitations
1. This is an educational prototype for static URL analysis only.
2. No network requests are made to the submitted URL (no visiting, downloading,
   or executing content).
3. Heuristic signals are indicators for investigation, not proof of maliciousness.
4. Enrichment depends on third-party provider availability and may be subject to rate limits.
5. Mock enrichment results are simulated and clearly labeled as such—not real threat intelligence.
6. The tool does not perform DNS resolution or passive DNS lookups.

---

## Suggested Next Steps
1. Review the analysis signals and enrichment results in context of your environment.
2. Correlate findings with internal logs, security alerts, or threat intelligence feeds.
3. Determine if additional investigation is warranted based on organizational risk tolerance.
4. Escalate to appropriate teams if indicators suggest malicious activity.
5. Document findings and share with relevant stakeholders per incident response procedures.
6. Consider blocking or monitoring the indicator if confirmed malicious.
7. Update security controls based on lessons learned.

---
*Report generated by Threat Intelligence & Phishing Investigation Workbench*
"""

    return report
