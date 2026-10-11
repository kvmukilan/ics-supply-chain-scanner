# ICS Supply Chain Vulnerability Scanner

Automated OT vulnerability assessment pipeline: asset inventory → NVD CVE lookup → CISA KEV cross-reference → OT-specific risk scoring → IEC 62443-mapped remediation.

## Architecture

```
Asset Inventory (CSV/JSON)
        │
        ▼
┌─────────────────┐     ┌──────────────┐
│  NVD API v2     │────▶│  CVE Matches │
│  (CPE queries)  │     └──────┬───────┘
└─────────────────┘            │
                               ▼
                    ┌──────────────────┐
                    │  CISA KEV Check  │
                    │  (active exploit │
                    │   cross-ref)     │
                    └──────┬───────────┘
                           │
                           ▼
                    ┌──────────────────┐
                    │  OT Risk Scorer  │
                    │  CVSS × Purdue   │
                    │  × Exposure      │
                    │  × Patch × KEV   │
                    └──────┬───────────┘
                           │
                           ▼
                    ┌──────────────────┐
                    │  LLM Remediation │
                    │  Azure OpenAI    │
                    │  IEC 62443 map   │
                    └──────┬───────────┘
                           │
                           ▼
                  JSON + HTML Reports
```

## Quick Start

```bash
# Setup
cp .env.example .env  # Configure API keys
pip install -r requirements.txt

# Run scan
python main.py -i sample_inventory.csv

# With options
python main.py -i inventory.csv -o reports/ --log-level DEBUG
python main.py -i inventory.json --no-llm  # Template remediation only
```

## Asset Inventory Format

**CSV** — See `sample_inventory.csv`. Required columns: `name`, `vendor`, `model`, `firmware_version`, `cpe`, `purdue_level`. Optional: `network_zone`, `exposure`, `patch_status`, `location`, `asset_id`.

**JSON** — See `sample_inventory.json`. Same fields, wrapped in `{"assets": [...]}`.

### CPE Strings

Each asset needs a CPE 2.3 URI. Format: `cpe:2.3:PART:VENDOR:PRODUCT:VERSION:*:*:*:*:*:*:*`

Find CPEs at: https://nvd.nist.gov/products/cpe/search

### Exposure / Patch Status Values

| Field | Values |
|-------|--------|
| `exposure` | `internet`, `corporate`, `dmz`, `isolated`, `air-gapped` |
| `patch_status` | `available`, `scheduled`, `unavailable`, `eol` |
| `purdue_level` | `0`–`5` (supports `3.5` for DMZ) |

## OT Risk Scoring

```
OT Risk Score = CVSS Base × Purdue Weight × Exposure × Patch × KEV
```

| Factor | Multiplier Range |
|--------|-----------------|
| Purdue L0/L1 | ×1.5 |
| Purdue L4/L5 | ×0.8 |
| Internet-facing | ×1.4 |
| Air-gapped | ×0.6 |
| Patch available | ×0.9 |
| No patch / EOL | ×1.3–1.4 |
| In CISA KEV | ×1.5 |

Weights are configurable in `config.py` → `OTRiskWeights`.

## Output

Reports go to `output/` (configurable via `-o`):

- **JSON**: Machine-readable with full finding details, score breakdowns, remediation playbooks
- **HTML**: Dashboard view with severity stats, expandable remediation, NVD links

## API Keys

| Key | Required | Purpose |
|-----|----------|---------|
| `NVD_API_KEY` | Recommended | Higher rate limits (50 vs 5 req/30s) |
| `AZURE_OPENAI_*` | Optional | LLM-powered remediation (falls back to templates) |

## Project Structure

```
├── main.py            # CLI entry point
├── scanner.py         # Pipeline orchestrator
├── config.py          # All configuration & scoring weights
├── models.py          # Data models (Asset, CVE, Finding, ScanResult)
├── inventory.py       # CSV/JSON inventory parser
├── nvd_client.py      # NVD CVE API v2 async client
├── kev_client.py      # CISA KEV catalog client + caching
├── risk_scorer.py     # OT risk scoring engine
├── remediation.py     # LLM + template remediation generator
├── report.py          # JSON & HTML report generation
├── api.py             # FastAPI REST API server
├── dashboard.py       # Streamlit interactive dashboard
├── compliance.py      # IEC 62443 compliance assessment
├── analytics.py       # Vulnerability trend analytics
├── sarif_export.py    # SARIF report export (GitHub Code Scanning)
├── sbom_parser.py     # CycloneDX/SPDX SBOM ingestion
├── scan_diff.py       # Baseline diff for scan comparison
├── alerting.py        # Webhook alerting (Slack, Teams, generic)
├── quality_gate.py    # CI/CD quality gate policy enforcement
├── risk_timeline.py   # Risk posture snapshot & trending
├── network_map.py     # Asset network topology mapping
├── export_mitre.py    # MITRE ATT&CK for ICS export
├── rate_limiter.py    # API rate limiting middleware
├── patch_priority.py  # Patch prioritisation queue calculator
├── validators.py      # CPE and Purdue level validators
├── requirements.txt
├── .env.example
└── sample_inventory.csv
```

## Deployment readiness

See [deployment setup, checks, and rollback](docs/production.md).
