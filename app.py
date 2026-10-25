"""Streamlit dashboard for the Threat Intelligence & Phishing Investigation Workbench."""

from __future__ import annotations

import time
from datetime import datetime
from typing import Any

import pandas as pd
import streamlit as st

from core.analysis import URLAnalysisError
from core.database import init_db
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
from core.reporting import generate_json_report, generate_markdown_report

# Initialize the database
init_db()

# Page configuration
st.set_page_config(
    page_title="Threat Intelligence Workbench",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)


# Helper functions
def _display_signal(signal: dict[str, str]) -> None:
    """Display a single signal with appropriate styling."""
    severity_colors = {
        "high": "red",
        "medium": "orange",
        "low": "blue",
        "info": "gray",
    }
    color = severity_colors.get(signal["severity"].lower(), "gray")
    st.markdown(
        f"<span style='color:{color}; font-weight:bold'>[{signal['severity'].upper()}] </span>"
        f"<span>{signal['description']}</span>: <code>{signal['evidence']}</code>",
        unsafe_allow_html=True,
    )


def _display_enrichment(
    enrichment_source: str | None,
    enrichment_lookup_time: str | None,
    enrichment_data: dict[str, Any] | None,
    is_mock: bool = False,
) -> None:
    """Display enrichment results."""
    if enrichment_source and enrichment_lookup_time and enrichment_data:
        source_label = f"{enrichment_source} (SIMULATED)" if is_mock else enrichment_source
        st.subheader("Threat Intelligence Enrichment")
        st.caption(f"Source: {source_label} | Lookup time: {enrichment_lookup_time}")

        if (
            enrichment_data
            and "data" in enrichment_data
            and "attributes" in enrichment_data["data"]
        ):
            attrs = enrichment_data["data"]["attributes"]

            # Last analysis stats
            if "last_analysis_stats" in attrs:
                stats = attrs["last_analysis_stats"]
                if any(stats.values()):
                    st.write("**Analysis Stats:**")
                    cols = st.columns(len([k for k, v in stats.items() if v > 0]))
                    col_idx = 0
                    for key, value in stats.items():
                        if value > 0:
                            with cols[col_idx]:
                                st.metric(key.capitalize(), value)
                            col_idx += 1

            # Reputation
            if "reputation" in attrs:
                st.write(f"**Reputation Score:** {attrs['reputation']}")

            # Total votes
            if "total_votes" in attrs:
                votes = attrs["total_votes"]
                if any(votes.values()):
                    st.write(
                        f"**Community Votes:** Harmless: {votes.get('harmless', 0)}, "
                        f"Malicious: {votes.get('malicious', 0)}"
                    )
        else:
            st.info("No detailed enrichment data available.")
    elif enrichment_source is None:
        st.info(
            "No enrichment performed. Click 'Enrich with Threat Intelligence' to lookup this URL."
        )


def _display_investigation_form(record_id: int | None = None, existing_record: Any = None) -> None:
    """Display the investigation form for creating or editing an investigation."""
    with st.form(key="investigation_form"):
        url = st.text_input(
            "URL to Investigate",
            value=existing_record.original_url if existing_record else "",
            placeholder="Enter a suspicious URL (e.g., https://example.com/login)",
            help="Enter the full URL including scheme (http/https)",
        )

        submitted = st.form_submit_button("Start Investigation")

        if submitted and url:
            try:
                with st.spinner("Analyzing URL..."):
                    new_record = start_investigation(url)
                    st.success(f"Investigation started! ID: {new_record.id}")
                    # Clear form and redirect to investigations view
                    time.sleep(1)
                    st.rerun()
            except URLAnalysisError as e:
                st.error(f"Invalid URL: {str(e)}")
            except Exception as e:
                st.error(f"Error starting investigation: {str(e)}")


def _display_investigation_details(record: Any) -> None:
    """Display detailed view of an investigation."""
    st.subheader(f"Investigation #{record.id}")

    col1, col2 = st.columns([2, 1])

    with col1:
        st.write("**Original URL:**", record.original_url)
        st.write("**Normalized URL:**", record.normalized_url)
        st.write("**Scheme:**", record.scheme.upper())
        st.write("**Hostname:**", record.hostname)
        if record.ip_literal:
            st.write("**IP Literal:**", record.ip_literal)
        st.write("**Port:**", record.port)
        st.write("**Path:**", record.path)
        if record.query_parameter_names:
            st.write("**Query Parameters:**", ", ".join(record.query_parameter_names))

        st.write("**Analysis Signals:**")
        if record.signals:
            for signal in record.signals:
                _display_signal(signal)
        else:
            st.info("No significant signals detected.")

    with col2:
        st.write("**Metadata:**")
        st.write("**Created:**", record.created_at)
        st.write("**Updated:**", record.updated_at)
        st.write("**Status:**", record.status)

        # Status update
        valid_statuses = ["New", "Investigating", "Closed", "False Positive"]
        current_status_index = (
            valid_statuses.index(record.status) if record.status in valid_statuses else 0
        )
        new_status = st.selectbox(
            "Update Status",
            options=valid_statuses,
            index=current_status_index,
            key=f"status_{record.id}",
        )
        if new_status != record.status:
            try:
                # For Closed/False Positive, require conclusion
                if new_status in ["Closed", "False Positive"] and not record.conclusion:
                    st.warning(
                        "Please add a conclusion before changing to Closed or "
                        "False Positive status."
                    )
                else:
                    update_investigation_status(record.id, new_status)
                    st.success(f"Status updated to {new_status}")
                    time.sleep(0.5)
                    st.rerun()
            except ValueError as e:
                st.error(str(e))

        # Enrichment button
        if st.button("Enrich with Threat Intelligence", key=f"enrich_{record.id}"):
            try:
                with st.spinner("Querying threat intelligence..."):
                    enrich_investigation(record.id)
                    st.success("Enrichment complete!")
                    time.sleep(0.5)
                    st.rerun()
            except EnrichmentError as e:
                st.error(f"Enrichment failed: {str(e)}")
            except Exception as e:
                st.error(f"Error during enrichment: {str(e)}")

        # Display enrichment results
        _display_enrichment(
            record.enrichment_source,
            record.enrichment_lookup_time,
            record.enrichment_data,
            is_mock=getattr(record, "is_mock", False) if hasattr(record, "is_mock") else False,
        )

    # Notes section
    st.subheader("Analyst Notes")
    current_notes = record.notes if record.notes else ""
    new_note = st.text_area(
        "Add a note",
        value=current_notes,
        height=100,
        key=f"notes_{record.id}",
        placeholder="Add your observations, hypotheses, or next steps...",
    )

    if st.button("Save Notes", key=f"save_notes_{record.id}"):
        if new_note != current_notes:
            try:
                add_investigation_note(record.id, new_note)
                st.success("Notes saved!")
                time.sleep(0.5)
                st.rerun()
            except Exception as e:
                st.error(f"Error saving notes: {str(e)}")

    # Conclusion section
    st.subheader("Conclusion")
    current_conclusion = record.conclusion if record.conclusion else ""
    new_conclusion = st.text_area(
        "Conclusion (required for Closed/False Positive status)",
        value=current_conclusion,
        height=80,
        key=f"conclusion_{record.id}",
        placeholder="Summarize your findings and determination...",
    )

    if st.button("Save Conclusion", key=f"save_conclusion_{record.id}"):
        if new_conclusion != current_conclusion:
            try:
                set_investigation_conclusion(record.id, new_conclusion)
                st.success("Conclusion saved!")
                time.sleep(0.5)
                st.rerun()
            except Exception as e:
                st.error(f"Error saving conclusion: {str(e)}")

    # Reports section
    st.subheader("Reports")
    col1, col2, col3 = st.columns(3)

    with col1:
        if st.button("Generate JSON Report", key=f"json_{record.id}"):
            try:
                json_report = generate_json_report(record.id)
                st.download_button(
                    label="Download JSON Report",
                    data=json_report,
                    file_name=f"investigation_{record.id}_report.json",
                    mime="application/json",
                    key=f"download_json_{record.id}",
                )
            except Exception as e:
                st.error(f"Error generating JSON report: {str(e)}")

    with col2:
        if st.button("Generate Markdown Report", key=f"md_{record.id}"):
            try:
                md_report = generate_markdown_report(record.id)
                st.download_button(
                    label="Download Markdown Report",
                    data=md_report,
                    file_name=f"investigation_{record.id}_report.md",
                    mime="text/markdown",
                    key=f"download_md_{record.id}",
                )
            except Exception as e:
                st.error(f"Error generating Markdown report: {str(e)}")

    with col3:
        if st.button("View Investigation in Table", key=f"table_{record.id}"):
            st.switch_page("Investigations")


# Main app
def main():
    """Main Streamlit application."""

    # Sidebar navigation
    st.sidebar.title("Threat Intelligence Workbench")
    page = st.sidebar.radio("Navigate", ["Overview", "Analyze URL", "Investigations", "Reports"])

    if page == "Overview":
        show_overview()
    elif page == "Analyze URL":
        show_analyze_url()
    elif page == "Investigations":
        show_investigations()
    elif page == "Reports":
        show_reports()


def show_overview():
    """Show overview dashboard."""
    st.title("🔍 Threat Intelligence Workbench Overview")

    # Get counts
    counts = get_investigation_counts()

    # Display metrics
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("New Investigations", counts.get("New", 0))
    with col2:
        st.metric("Investigating", counts.get("Investigating", 0))
    with col3:
        st.metric("Closed", counts.get("Closed", 0))
    with col4:
        st.metric("False Positive", counts.get("False Positive", 0))

    st.divider()

    # Recent investigations
    st.subheader("Recent Investigations")
    from core.investigations import list_investigations

    recent = list_investigations(limit=5)

    if recent:
        df_data = []
        for record in recent:
            df_data.append(
                {
                    "ID": record.id,
                    "URL": record.original_url[:50] + "..."
                    if len(record.original_url) > 50
                    else record.original_url,
                    "Status": record.status,
                    "Created": record.created_at[:10] if record.created_at else "",
                    "Signals": len(record.signals),
                }
            )
        df = pd.DataFrame(df_data)
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.info("No investigations found. Start by analyzing a URL in the 'Analyze URL' section.")


def show_analyze_url():
    """Show URL analysis page."""
    st.title("🔎 Analyze URL")
    st.write("Submit a suspicious URL for safe analysis and investigation.")

    # Investigation form
    _display_investigation_form()

    st.divider()

    # Information about analysis
    with st.expander("About URL Analysis"):
        st.write("""
        This tool performs static analysis of URLs without making network requests
        or visiting the URL.
        
        **Analysis includes:**
        - URL validation and normalization
        - Extraction of hostname, domain, IP address, port, and path
        - Detection of explainable characteristics:
          - IP-literal hosts (using IP address instead of domain)
          - Non-standard ports (not 80 for HTTP, 443 for HTTPS)
          - Embedded credentials (username/password in URL)
          - Punycode hostnames (internationalized domain names)
          - Deep subdomains (4+ subdomain levels)
          - Percent-encoded content
        
        **Important:** These signals are heuristics, not proof of maliciousness.
        Many legitimate URLs exhibit these characteristics.
        """)


def show_investigations():
    """Show investigations list and management."""
    st.title("📋 Investigations")

    # Search and filters
    col1, col2 = st.columns([3, 1])
    with col1:
        search_query = st.text_input(
            "🔍 Search investigations", placeholder="Search by URL, hostname, or notes"
        )
    with col2:
        st.write("")
        st.write("")
        if st.button("Clear Search"):
            st.rerun()

    # Get investigations
    from core.investigations import list_investigations, search_investigations

    if search_query:
        investigations = search_investigations(search_query)
        if investigations:
            st.info(f"Found {len(investigations)} investigation(s) matching '{search_query}'")
        else:
            st.warning(f"No investigations found matching '{search_query}'")
    else:
        investigations = list_investigations()

    if investigations:
        # Convert to DataFrame for display
        df_data = []
        for record in investigations:
            df_data.append(
                {
                    "ID": record.id,
                    "URL": record.original_url,
                    "Hostname": record.hostname,
                    "Status": record.status,
                    "Created": record.created_at[:16] if record.created_at else "",
                    "Signals": len(record.signals),
                    "Enriched": "Yes" if record.enrichment_source else "No",
                }
            )
        df = pd.DataFrame(df_data)

        # Configure column display
        column_config = {
            "ID": st.column_config.NumberColumn("ID", width="small"),
            "URL": st.column_config.TextColumn("URL", width="medium"),
            "Hostname": st.column_config.TextColumn("Hostname", width="small"),
            "Status": st.column_config.TextColumn("Status", width="small"),
            "Created": st.column_config.DatetimeColumn("Created", width="small"),
            "Signals": st.column_config.NumberColumn("Signals", width="small"),
            "Enriched": st.column_config.TextColumn("Enriched", width="small"),
        }

        # Display table with selection
        event = st.dataframe(
            df,
            column_config=column_config,
            use_container_width=True,
            hide_index=True,
            on_select="rerun",
            selection_mode="single-row",
        )

        # Show details of selected investigation
        if event.selection.rows:
            selected_idx = event.selection.rows[0]
            selected_record = investigations[selected_idx]
            st.divider()
            _display_investigation_details(selected_record)
    else:
        st.info("No investigations found. Start by analyzing a URL in the 'Analyze URL' section.")


def show_reports():
    """Show reports export page."""
    st.title("📊 Reports")
    st.write("Export investigation data in various formats.")

    tab1, tab2, tab3 = st.tabs(["CSV Export", "JSON Reports", "Markdown Reports"])

    with tab1:
        st.subheader("CSV Export")
        st.write("Export all investigations as a CSV file for spreadsheet analysis.")

        if st.button("Generate CSV Export", type="primary"):
            try:
                with st.spinner("Generating CSV export..."):
                    csv_data = export_investigations_csv()
                    st.download_button(
                        label="Download CSV Report",
                        data=csv_data,
                        file_name=f"investigations_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        mime="text/csv",
                        key="download_csv",
                    )
                    st.success("CSV export ready for download!")
            except Exception as e:
                st.error(f"Error generating CSV export: {str(e)}")

        with st.expander("About CSV Export"):
            st.write("""
            The CSV export includes all investigation fields:
            - ID, timestamps, URLs, scheme, hostname, IP literal, port, path
            - Query parameter names, signals, enrichment source and time
            - Status, notes, conclusion
            
            **Security Note:** CSV cells that begin with '=', '+', '-', '@', or tab 
            characters are prefixed with an apostrophe to prevent formula injection 
            in spreadsheet applications.
            """)

    with tab2:
        st.subheader("JSON Reports")
        st.write("Export individual investigations as JSON files.")

        from core.investigations import list_investigations

        investigations = list_investigations()

        if investigations:
            selected_id = st.selectbox(
                "Select Investigation",
                options=[r.id for r in investigations],
                format_func=lambda x: (
                    f"#{x} - {[r.original_url for r in investigations if r.id == x][0][:50]}..."
                ),
                key="json_select",
            )

            if st.button("Generate JSON Report", key="generate_json"):
                try:
                    with st.spinner("Generating JSON report..."):
                        json_report = generate_json_report(selected_id)
                        st.download_button(
                            label="Download JSON Report",
                            data=json_report,
                            file_name=f"investigation_{selected_id}_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                            mime="application/json",
                            key="download_json_report",
                        )
                        st.success("JSON report ready for download!")
                except Exception as e:
                    st.error(f"Error generating JSON report: {str(e)}")
        else:
            st.info("No investigations available for reporting.")

    with tab3:
        st.subheader("Markdown Reports")
        st.write("Export individual investigations as formatted Markdown files.")

        from core.investigations import list_investigations

        investigations = list_investigations()

        if investigations:
            selected_id = st.selectbox(
                "Select Investigation",
                options=[r.id for r in investigations],
                format_func=lambda x: (
                    f"#{x} - {[r.original_url for r in investigations if r.id == x][0][:50]}..."
                ),
                key="md_select",
            )

            if st.button("Generate Markdown Report", key="generate_md"):
                try:
                    with st.spinner("Generating Markdown report..."):
                        md_report = generate_markdown_report(selected_id)
                        st.download_button(
                            label="Download Markdown Report",
                            data=md_report,
                            file_name=f"investigation_{selected_id}_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                            mime="text/markdown",
                            key="download_md_report",
                        )
                        st.success("Markdown report ready for download!")
                except Exception as e:
                    st.error(f"Error generating Markdown report: {str(e)}")
        else:
            st.info("No investigations available for reporting.")


if __name__ == "__main__":
    main()
