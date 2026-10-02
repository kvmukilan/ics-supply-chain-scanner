"""SBOM (Software Bill of Materials) parser for CycloneDX and SPDX formats.

Extracts CPE strings and asset metadata from SBOM files to auto-generate
the scanner's asset inventory. Supports both CycloneDX JSON and SPDX JSON.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from models import Asset

logger = logging.getLogger(__name__)


def parse_sbom(filepath: str | Path) -> list[Asset]:
    """Auto-detect SBOM format and extract assets with CPE data."""
    filepath = Path(filepath)
    if not filepath.exists():
        raise FileNotFoundError(f"SBOM file not found: {filepath}")

    with open(filepath, encoding="utf-8") as f:
        data = json.load(f)

    # Detect format
    if "bomFormat" in data and data["bomFormat"] == "CycloneDX":
        return _parse_cyclonedx(data)
    elif "spdxVersion" in data:
        return _parse_spdx(data)
    else:
        raise ValueError(
            "Unrecognized SBOM format. Supported: CycloneDX JSON, SPDX JSON"
        )


def _parse_cyclonedx(data: dict) -> list[Asset]:
    """Parse CycloneDX SBOM JSON and extract assets with CPE strings.

    CycloneDX components can contain `cpe` fields directly or within
    `externalReferences`. We extract vendor/product/version from the
    component metadata and the CPE from wherever it's found.
    """
    assets = []
    components = data.get("components", [])

    for i, comp in enumerate(components):
        cpe = comp.get("cpe", "")

        # Also check externalReferences for CPE
        if not cpe:
            for ref in comp.get("externalReferences", []):
                url = ref.get("url", "")
                if url.startswith("cpe:"):
                    cpe = url
                    break

        if not cpe:
            # Try to construct a basic CPE from component data
            cpe = _build_cpe_from_component(comp)

        if not cpe:
            logger.debug(f"Skipping component without CPE: {comp.get('name', 'unknown')}")
            continue

        name = comp.get("name", f"component-{i}")
        vendor = comp.get("publisher", comp.get("author", ""))
        if not vendor:
            vendor = comp.get("group", _extract_vendor_from_cpe(cpe))
        version = comp.get("version", "")

        # Extract properties for OT context if available
        properties = {p["name"]: p["value"] for p in comp.get("properties", [])}

        asset = Asset(
            name=name,
            vendor=vendor,
            model=comp.get("description", name),
            firmware_version=version,
            cpe=cpe,
            purdue_level=float(properties.get("purdue_level", properties.get("ics:level", "3"))),
            network_zone=properties.get("network_zone", "unknown"),
            exposure=properties.get("exposure", "isolated"),
            patch_status=properties.get("patch_status", "available"),
            asset_id=comp.get("bom-ref", f"SBOM-{i+1:04d}"),
        )
        assets.append(asset)

    logger.info(f"Parsed {len(assets)} assets from CycloneDX SBOM ({len(components)} total components)")
    return assets


def _parse_spdx(data: dict) -> list[Asset]:
    """Parse SPDX JSON SBOM and extract assets with CPE data.

    SPDX stores CPE in `externalRefs` with referenceType
    `cpe23Type` or `cpe22Type`.
    """
    assets = []
    packages = data.get("packages", [])

    for i, pkg in enumerate(packages):
        cpe = ""

        # Look for CPE in externalRefs
        for ref in pkg.get("externalRefs", []):
            ref_type = ref.get("referenceType", "")
            if ref_type in ("cpe23Type", "cpe22Type"):
                cpe = ref.get("referenceLocator", "")
                break

        if not cpe:
            cpe = _build_cpe_from_spdx_package(pkg)

        if not cpe:
            logger.debug(f"Skipping package without CPE: {pkg.get('name', 'unknown')}")
            continue

        name = pkg.get("name", f"package-{i}")
        vendor = pkg.get("supplier", pkg.get("originator", ""))
        if vendor and vendor.startswith("Organization:"):
            vendor = vendor.replace("Organization:", "").strip()
        if not vendor:
            vendor = _extract_vendor_from_cpe(cpe)

        version = pkg.get("versionInfo", "")

        asset = Asset(
            name=name,
            vendor=vendor,
            model=pkg.get("description", name)[:100] if pkg.get("description") else name,
            firmware_version=version,
            cpe=cpe,
            purdue_level=3.0,  # Default for SPDX (no OT context)
            network_zone="unknown",
            asset_id=pkg.get("SPDXID", f"SBOM-{i+1:04d}"),
        )
        assets.append(asset)

    logger.info(f"Parsed {len(assets)} assets from SPDX SBOM ({len(packages)} total packages)")
    return assets


def _build_cpe_from_component(comp: dict) -> str:
    """Attempt to build a CPE 2.3 string from CycloneDX component metadata."""
    name = comp.get("name", "").lower().replace(" ", "_")
    vendor = comp.get("publisher", comp.get("group", "")).lower().replace(" ", "_")
    version = comp.get("version", "*")

    if not (name and vendor):
        return ""

    comp_type = comp.get("type", "library")
    part = "a" if comp_type in ("library", "application", "framework") else "o"

    return f"cpe:2.3:{part}:{vendor}:{name}:{version}:*:*:*:*:*:*:*"


def _build_cpe_from_spdx_package(pkg: dict) -> str:
    """Attempt to build a CPE 2.3 string from SPDX package metadata."""
    name = pkg.get("name", "").lower().replace(" ", "_")
    version = pkg.get("versionInfo", "*")

    supplier = pkg.get("supplier", pkg.get("originator", ""))
    if supplier and supplier.startswith("Organization:"):
        supplier = supplier.replace("Organization:", "").strip()
    vendor = supplier.lower().replace(" ", "_")

    if not (name and vendor):
        return ""

    return f"cpe:2.3:a:{vendor}:{name}:{version}:*:*:*:*:*:*:*"


def _extract_vendor_from_cpe(cpe: str) -> str:
    """Extract vendor name from a CPE 2.3 string."""
    parts = cpe.split(":")
    if len(parts) >= 4:
        return parts[3].replace("_", " ")
    return "unknown"
