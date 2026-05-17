# Environment Setup Guide

## 1. Create Virtual Environment

```bash
# Navigate to project directory
cd ics-supply-chain-scanner

# Create venv
python -m venv .venv

# Activate
# Linux/macOS:
source .venv/bin/activate

# Windows (PowerShell):
.\.venv\Scripts\Activate.ps1

# Windows (CMD):
.\.venv\Scripts\activate.bat

# Verify
which python    # Should point to .venv/bin/python
python --version
```

## 2. Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

## 3. Configure Environment Variables

```bash
cp .env.example .env
```

Edit `.env` with your keys:

```env
# Required for decent NVD performance (get free key at https://nvd.nist.gov/developers/request-an-api-key)
NVD_API_KEY=your-nvd-api-key

# Optional — enables AI-powered remediation instead of templates
AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com
AZURE_OPENAI_API_KEY=your-key
AZURE_OPENAI_DEPLOYMENT=gpt-4o
```

Without keys, the scanner still works:
- **No NVD key** → Slower rate limit (5 req/30s vs 50 req/30s)
- **No Azure OpenAI** → Template-based remediation (still maps IEC 62443)

## 4. Run

### CLI
```bash
python main.py -i sample_inventory.csv
python main.py -i sample_inventory.csv --no-llm --log-level DEBUG
```

### Streamlit Dashboard
```bash
streamlit run dashboard.py
# Opens at http://localhost:8501
```

### FastAPI
```bash
uvicorn api:app --reload --port 8000
# Docs at http://localhost:8000/docs

# Example API calls:
curl -X POST http://localhost:8000/scan \
  -F "inventory=@sample_inventory.csv"

curl http://localhost:8000/kev/CVE-2023-27997

curl -X POST http://localhost:8000/scan/score \
  -H "Content-Type: application/json" \
  -d '{
    "asset_name": "PLC-01",
    "vendor": "Siemens",
    "model": "S7-1200",
    "firmware_version": "4.5.0",
    "cpe": "cpe:2.3:o:siemens:simatic_s7-1200_firmware:4.5.0:*:*:*:*:*:*:*",
    "purdue_level": 1,
    "exposure": "isolated",
    "patch_status": "available",
    "cve_id": "CVE-2023-12345",
    "cvss_base_score": 8.5
  }'
```

## 5. Deactivate When Done

```bash
deactivate
```

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `pip install` fails on cryptography | `sudo apt install build-essential libffi-dev python3-dev` |
| NVD returns 403 | Rate limited — add `NVD_API_KEY` to `.env` |
| Streamlit blank page | Clear cache: `streamlit cache clear` |
| `ModuleNotFoundError` | Ensure venv is activated: check `which python` |
