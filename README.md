# Threat Intelligence & Phishing Investigation Workbench

A local defensive analysis tool for extracting indicators from suspicious URLs, reviewing explainable URL signals, optionally enriching indicators through VirusTotal, tracking investigations, and exporting reports.

> Educational prototype. URL signals are not proof of phishing. Enrichment is optional and may disclose queried indicators to an external provider. The application never visits or executes submitted URLs.

## Features

- URL validation, normalization, and IOC extraction.
- Explainable URL structure signals.
- Optional VirusTotal API v3 URL reputation lookup.
- Clearly labeled offline mock enrichment for demonstrations.
- SQLite-backed investigation records, notes, status and conclusion.
- JSON, CSV, and Markdown report exports.
- FastAPI backend and Streamlit UI.

## Requirements

Python 3.11+ (Python 3.12 recommended).

## Windows PowerShell setup

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements-dev.txt
Copy-Item .env.example .env
```

Edit `.env` only if using VirusTotal. Set `VIRUSTOTAL_API_KEY` to your own key. Never commit `.env`.

## Run

Terminal 1, from the repository root:

```powershell
uvicorn api:app --reload
```

Terminal 2:

```powershell
streamlit run app.py
```

Open the Streamlit URL shown in the terminal. The API docs are available at `http://127.0.0.1:8000/docs`.

## Intelligence lookup

The app works without an API key. Use mock mode for offline demonstrations; mock results are explicitly marked as simulated. VirusTotal enrichment is an explicit action and uses lookup-only API behavior. Do not submit sensitive URLs: querying an external service may disclose the indicator to that provider.

## Tests and quality checks

```powershell
python -m pytest
ruff check .
ruff format --check .
python -m compileall -q app.py api.py core
```

Tests use fixtures and do not require a live API key.

## Scope and limitations

- Local educational prototype; no authentication or multi-user isolation.
- Heuristic URL signals are not a malware verdict or calibrated probability.
- No automatic URL fetching, DNS resolution, crawling, or file scanning.
- VirusTotal results depend on provider availability, rate limits, and the queried indicator.
- Mock data is synthetic and must not be presented as live threat intelligence.

## Project structure

- `core/analysis.py`: URL validation, IOC extraction and explainable signals.
- `core/enrichment.py`: optional VirusTotal lookup and clearly labeled mock results.
- `core/database.py`: SQLite persistence.
- `core/investigations.py`: investigation operations and statuses.
- `core/reporting.py`: report serialization and safe CSV export.
- `api.py`: REST endpoints.
- `app.py`: Streamlit analyst interface.
