"""Purdue model network topology visualization data generator.

Produces structured data for rendering OT network diagrams with
assets placed at their Purdue levels, color-coded by risk, and
annotated with finding counts and KEV flags.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from models import Finding, ScanResult, Severity

PURDUE_LEVELS = {
    0: "Level 0 — Physical Process (Sensors, Actuators)",
    1: "Level 1 — Basic Control (PLCs, RTUs, Safety Controllers)",
    2: "Level 2 — Area Supervisory (HMI, SCADA, Engineering Workstations)",
    3: "Level 3 — Site Operations (Historian, OPC, App Servers)",
    3.5: "Level 3.5 — DMZ (Firewalls, Jump Servers, Data Diodes)",
    4: "Level 4 — Enterprise IT (ERP, Email, Business Apps)",
    5: "Level 5 — Enterprise Network (Internet, Cloud, VPN)",
}


@dataclass
class AssetNode:
    """A single asset rendered on the network map."""
    name: str
    vendor: str
    model: str
    purdue_level: float
    network_zone: str
    exposure: str
    finding_count: int = 0
    critical_count: int = 0
    max_ot_score: float = 0.0
    has_kev: bool = False
    risk_color: str = "#6b7280"  # gray default


@dataclass
class ZoneConnection:
    """A connection between two network zones."""
    from_zone: str
    to_zone: str
    finding_count: int = 0
    has_critical_path: bool = False


def build_network_map(result: ScanResult) -> dict:
    """Build Purdue-model network map data from scan results.

    Returns structured data for rendering a topology diagram with:
    - Assets grouped by Purdue level
    - Risk-colored nodes
    - Cross-zone connections with risk indicators
    """
    # Gather all assets (from findings + scan metadata)
    asset_findings: dict[str, list[Finding]] = defaultdict(list)
    asset_info: dict[str, Finding] = {}

    for f in result.findings:
        key = f.asset.name
        asset_findings[key].append(f)
        asset_info[key] = f

    # Build asset nodes
    nodes: dict[float, list[AssetNode]] = defaultdict(list)
    for asset_name, findings in asset_findings.items():
        f = asset_info[asset_name]
        critical_count = sum(1 for af in findings if af.ot_severity == Severity.CRITICAL)
        max_score = max(af.ot_risk_score for af in findings)
        has_kev = any(af.in_kev for af in findings)

        node = AssetNode(
            name=asset_name,
            vendor=f.asset.vendor,
            model=f.asset.model,
            purdue_level=f.asset.purdue_level,
            network_zone=f.asset.network_zone,
            exposure=f.asset.exposure.value,
            finding_count=len(findings),
            critical_count=critical_count,
            max_ot_score=round(max_score, 2),
            has_kev=has_kev,
            risk_color=_score_to_color(max_score),
        )
        nodes[f.asset.purdue_level].append(node)

    # Sort nodes within each level by score desc
    for level in nodes:
        nodes[level].sort(key=lambda n: -n.max_ot_score)

    # Detect cross-zone exposure paths
    connections = _detect_connections(result.findings)

    # Build output
    levels = []
    for level in sorted(PURDUE_LEVELS.keys()):
        level_nodes = nodes.get(level, [])
        levels.append({
            "level": level,
            "label": PURDUE_LEVELS[level],
            "asset_count": len(level_nodes),
            "total_findings": sum(n.finding_count for n in level_nodes),
            "critical_count": sum(n.critical_count for n in level_nodes),
            "assets": [
                {
                    "name": n.name,
                    "vendor": n.vendor,
                    "model": n.model,
                    "zone": n.network_zone,
                    "exposure": n.exposure,
                    "findings": n.finding_count,
                    "criticals": n.critical_count,
                    "max_score": n.max_ot_score,
                    "kev": n.has_kev,
                    "color": n.risk_color,
                }
                for n in level_nodes
            ],
        })

    return {
        "total_assets_with_findings": len(asset_findings),
        "levels": levels,
        "connections": [
            {
                "from": c.from_zone,
                "to": c.to_zone,
                "findings": c.finding_count,
                "critical_path": c.has_critical_path,
            }
            for c in connections
        ],
    }


def _score_to_color(score: float) -> str:
    """Map OT risk score to a hex color for visualization."""
    if score >= 8.5:
        return "#dc2626"  # red
    elif score >= 6.5:
        return "#ea580c"  # orange
    elif score >= 4.0:
        return "#ca8a04"  # yellow
    elif score > 0:
        return "#2563eb"  # blue
    return "#6b7280"  # gray


def _detect_connections(findings: list[Finding]) -> list[ZoneConnection]:
    """Detect network zone connections from asset exposure patterns.

    Assets with corporate/internet/dmz exposure imply cross-zone
    data flows that represent attack paths.
    """
    zone_pairs: dict[tuple[str, str], ZoneConnection] = {}

    for f in findings:
        zone = f.asset.network_zone
        exposure = f.asset.exposure.value

        # Internet-exposed assets connect to external
        if exposure == "internet":
            key = ("Internet", zone)
            if key not in zone_pairs:
                zone_pairs[key] = ZoneConnection("Internet", zone)
            zone_pairs[key].finding_count += 1
            if f.ot_severity == Severity.CRITICAL:
                zone_pairs[key].has_critical_path = True

        # Corporate-exposed assets bridge IT-OT
        elif exposure == "corporate":
            key = ("Corporate-IT", zone)
            if key not in zone_pairs:
                zone_pairs[key] = ZoneConnection("Corporate-IT", zone)
            zone_pairs[key].finding_count += 1
            if f.ot_severity == Severity.CRITICAL:
                zone_pairs[key].has_critical_path = True

        # DMZ assets connect zones
        elif exposure == "dmz":
            key = ("DMZ", zone)
            if key not in zone_pairs:
                zone_pairs[key] = ZoneConnection("DMZ", zone)
            zone_pairs[key].finding_count += 1

    return sorted(zone_pairs.values(), key=lambda c: -c.finding_count)
