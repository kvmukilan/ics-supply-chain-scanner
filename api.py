"""FastAPI REST API for ICS Supply Chain Vulnerability Scanner.

Endpoints:
  POST /scan          - Upload inventory and run full scan
  POST /scan/score    - Score a single asset+CVE pair (no NVD lookup)
  GET  /kev/{cve_id}  - Check if a CVE is in CISA KEV
  GET  /health        - Health check
"""

from __future__ import annotations

import tempfile
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from analytics import compute_analytics
from config import ScannerConfig
from inventory import load_inventory
from kev_client import KEVClient
from models import (
    Asset,
    CVEEntry,
    Finding,
    ScanResult,
    Severity,
)
from rate_limiter import RateLimiterMiddleware
from report import generate_csv_report, generate_html_report, generate_json_report
from risk_scorer import OTRiskScorer
from scanner import ICSScanner

app = FastAPI(
    title="ICS Supply Chain Vulnerability Scanner API",
    version="1.0.0",
    description="OT vulnerability assessment: NVD CVE + CISA KEV + OT risk scoring + IEC 62443 remediation",
)

# Intended for self-hosted internal use; restrict origins in production
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(
    RateLimiterMiddleware,
    requests_per_minute=30,
    burst=10,
    exempt_paths={"/health", "/docs", "/openapi.json", "/redoc"},
)

# Shared state
_config = ScannerConfig()
_kev_client: KEVClient | None = None
_last_scan_result: ScanResult | None = None


async def get_kev_client() -> KEVClient:
    global _kev_client
    if _kev_client is None or not _kev_client.is_loaded:
        _kev_client = KEVClient(_config.kev)
        await _kev_client.load_catalog()
    return _kev_client


# --- Request/Response Models ---

class ScoreRequest(BaseModel):
    """Single asset + CVE scoring request."""
    asset_name: str
    vendor: str
    model: str
    firmware_version: str
    cpe: str
    purdue_level: float = Field(ge=0, le=5)
    network_zone: str = "unknown"
    exposure: str = "isolated"
    patch_status: str = "available"
    cve_id: str
    cvss_base_score: float = Field(ge=0, le=10)
    cvss_vector: str = ""
    description: str = ""


class ScoreResponse(BaseModel):
    ot_risk_score: float
    ot_severity: str
    in_kev: bool
    score_breakdown: dict
    iec_62443_mappings: list[str]


class ScanResponse(BaseModel):
    scan_id: str
    timestamp: str
    total_assets: int
    total_cves: int
    kev_matches: int
    severity_distribution: dict
    top_findings: list[dict]
    report_json: str
    report_html: str
    report_csv: str
    errors: list[str]


# --- Endpoints ---

@app.get("/health")
async def health():
    kev = await get_kev_client()
    return {
        "status": "ok",
        "kev_catalog_loaded": kev.is_loaded,
        "kev_catalog_size": kev.catalog_size,
        "llm_configured": bool(_config.llm.endpoint and _config.llm.api_key),
    }


@app.post("/scan", response_model=ScanResponse)
async def run_scan(
    inventory: UploadFile = File(..., description="CSV or JSON asset inventory"),
    skip_llm: bool = Query(False, description="Skip LLM remediation, use templates"),
):
    """Upload an asset inventory and run the full vulnerability scan pipeline."""
    # Validate file type
    suffix = Path(inventory.filename or "").suffix.lower()
    if suffix not in (".csv", ".json"):
        raise HTTPException(400, "Inventory must be .csv or .json")

    # Save upload to temp file
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        content = await inventory.read()
        tmp.write(content)
        tmp_path = tmp.name

    try:
        # Validate inventory parses
        assets = load_inventory(tmp_path)
        if not assets:
            raise HTTPException(400, "Inventory contains no valid assets")

        # Build config
        config = ScannerConfig()
        if skip_llm:
            config.llm.endpoint = ""
            config.llm.api_key = ""

        # Run scan
        global _last_scan_result
        scanner = ICSScanner(config)
        result = await scanner.scan(tmp_path)
        _last_scan_result = result

        # Generate reports
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        output_dir = Path("output")
        output_dir.mkdir(exist_ok=True)

        prefix = str(output_dir / f"{result.scan_id}_{timestamp}")
        json_path = generate_json_report(result, f"{prefix}_report.json")
        html_path = generate_html_report(result, f"{prefix}_report.html")
        csv_path = generate_csv_report(result, f"{prefix}_report.csv")

        summary = result.summary()

        return ScanResponse(
            scan_id=result.scan_id,
            timestamp=result.timestamp,
            total_assets=result.total_assets,
            total_cves=result.total_cves,
            kev_matches=result.total_kev_hits,
            severity_distribution=summary["severity_distribution"],
            top_findings=summary["top_risk_findings"],
            report_json=json_path,
            report_html=html_path,
            report_csv=csv_path,
            errors=result.errors,
        )
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    finally:
        Path(tmp_path).unlink(missing_ok=True)


@app.post("/scan/score", response_model=ScoreResponse)
async def score_single(req: ScoreRequest):
    """Score a single asset + CVE pair without NVD lookup."""
    asset = Asset(
        name=req.asset_name,
        vendor=req.vendor,
        model=req.model,
        firmware_version=req.firmware_version,
        cpe=req.cpe,
        purdue_level=req.purdue_level,
        network_zone=req.network_zone,
        exposure=req.exposure,
        patch_status=req.patch_status,
    )

    cve = CVEEntry(
        cve_id=req.cve_id,
        description=req.description,
        cvss_base_score=req.cvss_base_score,
        cvss_vector=req.cvss_vector,
        severity=Severity.from_cvss(req.cvss_base_score),
        published="",
        last_modified="",
    )

    # KEV check
    kev = await get_kev_client()
    kev_entry = kev.lookup(req.cve_id)

    finding = Finding(
        asset=asset,
        cve=cve,
        in_kev=kev_entry is not None,
        kev_entry=kev_entry,
    )

    scorer = OTRiskScorer(_config.risk)
    scorer.score_finding(finding)

    # Template remediation (fast, no LLM call)
    from config import AzureOpenAIConfig
    from remediation import RemediationGenerator

    gen = RemediationGenerator(AzureOpenAIConfig())
    finding = await gen.generate(finding)

    return ScoreResponse(
        ot_risk_score=round(finding.ot_risk_score, 2),
        ot_severity=finding.ot_severity.value,
        in_kev=finding.in_kev,
        score_breakdown=finding.score_breakdown,
        iec_62443_mappings=finding.iec_62443_mappings,
    )


@app.get("/kev/{cve_id}")
async def check_kev(cve_id: str):
    """Check if a CVE is in CISA's Known Exploited Vulnerabilities catalog."""
    kev = await get_kev_client()
    entry = kev.lookup(cve_id.upper())

    if entry is None:
        return {"cve_id": cve_id, "in_kev": False}

    return {
        "cve_id": cve_id,
        "in_kev": True,
        "vendor": entry.vendor,
        "product": entry.product,
        "vulnerability_name": entry.vulnerability_name,
        "date_added": entry.date_added,
        "due_date": entry.due_date,
        "required_action": entry.required_action,
        "known_ransomware_use": entry.known_ransomware_use,
    }


@app.get("/report/{filename}")
async def download_report(filename: str):
    """Download a generated report by filename."""
    path = Path("output") / filename
    if not path.resolve().is_relative_to(Path("output").resolve()):
        raise HTTPException(status_code=403, detail="Access denied")
    if not path.exists():
        raise HTTPException(404, "Report not found")
    media_types = {
        ".json": "application/json",
        ".html": "text/html",
        ".csv": "text/csv",
    }
    media = media_types.get(path.suffix, "application/octet-stream")
    return FileResponse(path, media_type=media, filename=filename)


@app.get("/analytics")
async def get_analytics():
    """Get aggregate OT analytics from the most recent scan.

    Returns risk-by-Purdue-level, top vulnerable vendors, KEV coverage,
    CVE age stats, and severity distribution.
    """
    if _last_scan_result is None:
        raise HTTPException(404, "No scan results available. Run a /scan first.")
    return compute_analytics(_last_scan_result)
