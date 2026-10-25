"""FastAPI backend for the Threat Intelligence & Phishing Investigation Workbench."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException, Path, status
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

from core.analysis import URLAnalysisError
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

# Initialize the database on startup
init_db()

app = FastAPI(
    title="Threat Intelligence & Phishing Investigation Workbench",
    description="Local defensive analysis tool for URL investigation and reporting",
    version="0.1.0",
)


# Pydantic models for request/response validation
class URLSubmission(BaseModel):
    url: str = Field(..., description="The URL to analyze and investigate")


class AnalysisResponse(BaseModel):
    original_url: str
    normalized_url: str
    scheme: str
    hostname: str
    ip_literal: str | None = None
    port: int
    path: str
    query_parameter_names: list[str]
    signals: list[dict[str, str]]
    note: str


class InvestigationResponse(BaseModel):
    id: int
    created_at: str
    updated_at: str
    original_url: str
    normalized_url: str
    scheme: str
    hostname: str
    ip_literal: str | None = None
    port: int
    path: str
    query_parameter_names: list[str]
    signals: list[dict[str, str]]
    enrichment_source: str | None = None
    enrichment_lookup_time: str | None = None
    enrichment_data: dict[str, Any] | None = None
    status: str
    notes: str
    conclusion: str | None = None


class StatusUpdate(BaseModel):
    status: str = Field(
        ...,
        description="New status: New, Investigating, Closed, or False Positive",
    )


class NoteAddition(BaseModel):
    note: str = Field(..., description="Note to add to the investigation")


class ConclusionUpdate(BaseModel):
    conclusion: str = Field(..., description="Conclusion for the investigation")


class InvestigationCountsResponse(BaseModel):
    New: int = 0
    Investigating: int = 0
    Closed: int = 0
    FalsePositive: int = 0


# API endpoints
@app.get("/health", tags=["Health"])
async def health_check() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy"}


@app.post("/api/investigations", tags=["Investigations"], status_code=status.HTTP_201_CREATED)
async def create_investigation_endpoint(submission: URLSubmission) -> InvestigationResponse:
    """Submit a URL to start a new investigation."""
    try:
        record = start_investigation(submission.url)
        return InvestigationResponse(**record.__dict__)
    except URLAnalysisError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except Exception as exc:  # Catch-all for unexpected errors
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error"
        ) from exc


@app.get("/api/investigations", tags=["Investigations"])
async def list_investigations_endpoint(
    limit: int = 100, offset: int = 0
) -> list[InvestigationResponse]:
    """List investigation records with pagination."""
    from core.investigations import list_investigations

    records = list_investigations(limit=limit, offset=offset)
    return [InvestigationResponse(**record.__dict__) for record in records]


@app.get("/api/investigations/{investigation_id}", tags=["Investigations"])
async def get_investigation_endpoint(
    investigation_id: int = Path(..., gt=0, description="The ID of the investigation"),
) -> InvestigationResponse:
    """Get a specific investigation by ID."""
    from core.investigations import get_investigation

    record = get_investigation(investigation_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation {investigation_id} not found",
        )
    return InvestigationResponse(**record.__dict__)


@app.patch("/api/investigations/{investigation_id}/status", tags=["Investigations"])
async def update_investigation_status_endpoint(
    investigation_id: int = Path(..., gt=0, description="The ID of the investigation"),
    status_update: StatusUpdate = ...,
) -> InvestigationResponse:
    """Update the status of an investigation."""
    try:
        record = update_investigation_status(investigation_id, status_update.status)
        return InvestigationResponse(**record.__dict__)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except Exception as exc:  # Catch-all for unexpected errors
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error"
        ) from exc


@app.post("/api/investigations/{investigation_id}/notes", tags=["Investigations"])
async def add_investigation_note_endpoint(
    investigation_id: int = Path(..., gt=0, description="The ID of the investigation"),
    note_addition: NoteAddition = ...,
) -> InvestigationResponse:
    """Add a note to an investigation."""
    try:
        record = add_investigation_note(investigation_id, note_addition.note)
        return InvestigationResponse(**record.__dict__)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except Exception as exc:  # Catch-all for unexpected errors
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error"
        ) from exc


@app.post("/api/investigations/{investigation_id}/conclusion", tags=["Investigations"])
async def set_investigation_conclusion_endpoint(
    investigation_id: int = Path(..., gt=0, description="The ID of the investigation"),
    conclusion_update: ConclusionUpdate = ...,
) -> InvestigationResponse:
    """Set the conclusion for an investigation."""
    try:
        record = set_investigation_conclusion(investigation_id, conclusion_update.conclusion)
        return InvestigationResponse(**record.__dict__)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except Exception as exc:  # Catch-all for unexpected errors
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error"
        ) from exc


@app.post("/api/investigations/{investigation_id}/enrich", tags=["Investigations"])
async def enrich_investigation_endpoint(
    investigation_id: int = Path(..., gt=0, description="The ID of the investigation"),
) -> InvestigationResponse:
    """Enrich an investigation with threat intelligence data."""
    try:
        record = enrich_investigation(investigation_id)
        return InvestigationResponse(**record.__dict__)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except Exception as exc:  # Includes EnrichmentError and other unexpected errors
        # Check if it's an enrichment-specific error
        from core.investigations import EnrichmentError

        if isinstance(exc, EnrichmentError):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
            ) from exc
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error"
        ) from exc


@app.get("/api/investigations/counts", tags=["Investigations"])
async def get_investigation_counts_endpoint() -> InvestigationCountsResponse:
    """Get counts of investigations by status."""
    counts = get_investigation_counts()
    # Map statuses to the expected response format (handle case variations)
    return InvestigationCountsResponse(
        New=counts.get("New", 0),
        Investigating=counts.get("Investigating", 0),
        Closed=counts.get("Closed", 0),
        FalsePositive=counts.get("False Positive", 0),
    )


@app.get("/api/reports/csv", tags=["Reports"])
async def export_csv_endpoint() -> JSONResponse:
    """Export all investigations as CSV."""
    try:
        csv_data = export_investigations_csv()
        return JSONResponse(content={"csv": csv_data}, media_type="application/json")
    except Exception as exc:  # Catch-all for unexpected errors
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error"
        ) from exc


@app.get(
    "/api/investigations/{investigation_id}/report.json",
    tags=["Reports"],
    response_class=PlainTextResponse,
)
async def json_report_endpoint(
    investigation_id: int = Path(..., gt=0, description="The ID of the investigation"),
) -> PlainTextResponse:
    """Download a JSON report for one investigation."""
    try:
        return PlainTextResponse(
            content=generate_json_report(investigation_id),
            media_type="application/json",
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc


@app.get(
    "/api/investigations/{investigation_id}/report.md",
    tags=["Reports"],
    response_class=PlainTextResponse,
)
async def markdown_report_endpoint(
    investigation_id: int = Path(..., gt=0, description="The ID of the investigation"),
) -> PlainTextResponse:
    """Download a Markdown report for one investigation."""
    try:
        return PlainTextResponse(
            content=generate_markdown_report(investigation_id),
            media_type="text/markdown",
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc


# Error handlers
@app.exception_handler(URLAnalysisError)
async def url_analysis_error_handler(request, exc: URLAnalysisError):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": str(exc)},
    )


@app.exception_handler(Exception)
async def general_exception_handler(request, exc: Exception):
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"},
    )
