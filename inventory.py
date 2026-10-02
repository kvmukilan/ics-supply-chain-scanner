"""Asset inventory parser for CSV and JSON formats."""

from __future__ import annotations

import csv
import json
import logging
from pathlib import Path

from models import Asset
from validators import validate_cpe, validate_purdue_level

logger = logging.getLogger(__name__)

# CSV column name mappings (flexible header matching)
COLUMN_ALIASES = {
    "name": ["name", "device_name", "asset_name", "hostname"],
    "vendor": ["vendor", "manufacturer", "oem"],
    "model": ["model", "product", "device_model"],
    "firmware_version": ["firmware_version", "firmware", "fw_version", "version", "sw_version"],
    "cpe": ["cpe", "cpe_string", "cpe_id"],
    "purdue_level": ["purdue_level", "purdue", "level", "ics_level"],
    "network_zone": ["network_zone", "zone", "network_segment", "segment"],
    "exposure": ["exposure", "network_exposure", "connectivity"],
    "patch_status": ["patch_status", "patching", "patch_availability"],
    "location": ["location", "site", "plant"],
    "asset_id": ["asset_id", "id", "asset_tag"],
    "last_patched": ["last_patched", "last_patch_date", "patched_date"],
    "notes": ["notes", "comments", "description"],
}


def _resolve_column(headers: list[str], field_name: str) -> str | None:
    """Find the actual column header matching a field name."""
    aliases = COLUMN_ALIASES.get(field_name, [field_name])
    normalized = {h.strip().lower().replace(" ", "_"): h for h in headers}
    for alias in aliases:
        if alias in normalized:
            return normalized[alias]
    return None


def parse_csv(filepath: str | Path) -> list[Asset]:
    """Parse asset inventory from CSV file."""
    filepath = Path(filepath)
    if not filepath.exists():
        raise FileNotFoundError(f"Inventory file not found: {filepath}")

    assets = []
    with open(filepath, encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        headers = reader.fieldnames or []
        col_map = {}
        for field_name in COLUMN_ALIASES:
            resolved = _resolve_column(headers, field_name)
            if resolved:
                col_map[field_name] = resolved

        required = ["name", "vendor", "model", "firmware_version", "cpe", "purdue_level"]
        missing = [r for r in required if r not in col_map]
        if missing:
            raise ValueError(
                f"Missing required columns: {missing}. "
                f"Available: {headers}. Accepted aliases: {COLUMN_ALIASES}"
            )

        def cell(row: dict, field_name: str, default: str = "") -> str:
            """Return a stripped cell value, or `default` if the column or value is absent.

            Short rows come back from DictReader with None for the missing cells, and
            optional columns are often left blank; both fall back to the default.
            """
            column = col_map.get(field_name)
            value = row.get(column) if column else None
            if value is None or not value.strip():
                return default
            return value.strip()

        for i, row in enumerate(reader, start=2):
            try:
                for req in required:
                    if not cell(row, req):
                        raise ValueError(f"missing value for required column '{col_map[req]}'")
                asset = Asset(
                    name=cell(row, "name"),
                    vendor=cell(row, "vendor"),
                    model=cell(row, "model"),
                    firmware_version=cell(row, "firmware_version"),
                    cpe=cell(row, "cpe"),
                    purdue_level=float(cell(row, "purdue_level")),
                    network_zone=cell(row, "network_zone", "unknown"),
                    exposure=cell(row, "exposure", "isolated").lower(),
                    patch_status=cell(row, "patch_status", "available").lower(),
                    location=cell(row, "location"),
                    # i is the 1-based file line (header is line 1), so i - 1 is the
                    # data row number; this matches parse_json's ASSET-0001 numbering.
                    asset_id=cell(row, "asset_id", f"ASSET-{i - 1:04d}"),
                    last_patched=cell(row, "last_patched") or None,
                    notes=cell(row, "notes"),
                )
                cpe_valid, cpe_err = validate_cpe(asset.cpe)
                if not cpe_valid:
                    logger.warning(f"Row {i} ({asset.name}): invalid CPE — {cpe_err}")
                purdue_valid, purdue_err = validate_purdue_level(asset.purdue_level)
                if not purdue_valid:
                    logger.warning(f"Row {i} ({asset.name}): {purdue_err}")
                assets.append(asset)
            except (ValueError, KeyError) as e:
                logger.warning(f"Skipping row {i}: {e}")

    logger.info(f"Parsed {len(assets)} assets from {filepath}")
    return assets


def parse_json(filepath: str | Path) -> list[Asset]:
    """Parse asset inventory from JSON file."""
    filepath = Path(filepath)
    if not filepath.exists():
        raise FileNotFoundError(f"Inventory file not found: {filepath}")

    with open(filepath, encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, dict):
        data = data.get("assets", data.get("inventory", []))

    assets = []
    for i, item in enumerate(data):
        try:
            asset = Asset(
                name=item["name"],
                vendor=item["vendor"],
                model=item["model"],
                firmware_version=item["firmware_version"],
                cpe=item["cpe"],
                purdue_level=float(item["purdue_level"]),
                network_zone=item.get("network_zone", "unknown"),
                exposure=item.get("exposure", "isolated"),
                patch_status=item.get("patch_status", "available"),
                location=item.get("location", ""),
                asset_id=item.get("asset_id", f"ASSET-{i+1:04d}"),
                last_patched=item.get("last_patched"),
                notes=item.get("notes", ""),
            )
            assets.append(asset)
        except (ValueError, KeyError) as e:
            logger.warning(f"Skipping entry {i}: {e}")

    logger.info(f"Parsed {len(assets)} assets from {filepath}")
    return assets


def load_inventory(filepath: str | Path) -> list[Asset]:
    """Auto-detect format and load asset inventory.

    Supports CSV, JSON (flat inventory), and SBOM (CycloneDX/SPDX JSON).
    For JSON files, auto-detects whether it's a plain inventory or an SBOM.
    """
    filepath = Path(filepath)
    ext = filepath.suffix.lower()
    if ext == ".csv":
        return parse_csv(filepath)
    elif ext == ".json":
        # Peek to detect SBOM format
        with open(filepath, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict) and ("bomFormat" in data or "spdxVersion" in data):
            from sbom_parser import parse_sbom
            logger.info("Detected SBOM format, using SBOM parser")
            return parse_sbom(filepath)
        return parse_json(filepath)
    else:
        raise ValueError(f"Unsupported inventory format: {ext}. Use .csv or .json")
