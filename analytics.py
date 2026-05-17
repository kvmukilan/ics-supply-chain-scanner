"""OT-specific analytics and aggregate metrics from scan results.

Computes executive-level KPIs: risk by Purdue level, most vulnerable
vendors, CVE age analysis, KEV coverage, and per-zone risk heatmap data.
"""

from __future__ import annotations

import statistics
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

from models import Finding, ScanResult, Severity


def compute_analytics(result: ScanResult) -> dict:
    """Compute aggregate analytics from a scan result.

    Returns a dict of KPIs suitable for dashboards and executive reports.
    """
    findings = result.findings
    if not findings:
        return {
            "total_findings": 0,
            "risk_by_purdue_level": {},
            "risk_by_network_zone": {},
            "top_vulnerable_vendors": [],
            "cve_age_stats": {},
            "kev_coverage": {},
            "severity_percentages": {},
            "mean_ot_risk_score": 0.0,
            "findings_above_threshold": {"critical_8_5": 0, "high_6_5": 0},
        }

    return {
        "total_findings": len(findings),
        "risk_by_purdue_level": _risk_by_purdue_level(findings),
        "risk_by_network_zone": _risk_by_network_zone(findings),
        "top_vulnerable_vendors": _top_vulnerable_vendors(findings),
        "cve_age_stats": _cve_age_stats(findings),
        "kev_coverage": _kev_coverage(findings),
        "severity_percentages": _severity_percentages(findings),
        "mean_ot_risk_score": round(
            statistics.mean(f.ot_risk_score for f in findings), 2
        ),
        "findings_above_threshold": {
            "critical_8_5": sum(1 for f in findings if f.ot_risk_score >= 8.5),
            "high_6_5": sum(1 for f in findings if 6.5 <= f.ot_risk_score < 8.5),
        },
    }


def _risk_by_purdue_level(findings: list[Finding]) -> dict:
    """Average and max OT risk score per Purdue level."""
    by_level: dict[float, list[float]] = defaultdict(list)
    for f in findings:
        by_level[f.asset.purdue_level].append(f.ot_risk_score)

    return {
        level: {
            "count": len(scores),
            "avg_score": round(statistics.mean(scores), 2),
            "max_score": round(max(scores), 2),
        }
        for level, scores in sorted(by_level.items())
    }


def _risk_by_network_zone(findings: list[Finding]) -> dict:
    """Average OT risk score per network zone."""
    by_zone: dict[str, list[float]] = defaultdict(list)
    for f in findings:
        by_zone[f.asset.network_zone].append(f.ot_risk_score)

    return {
        zone: {
            "count": len(scores),
            "avg_score": round(statistics.mean(scores), 2),
            "max_score": round(max(scores), 2),
        }
        for zone, scores in sorted(by_zone.items())
    }


def _top_vulnerable_vendors(findings: list[Finding], top_n: int = 5) -> list[dict]:
    """Vendors ranked by total finding count and max risk score."""
    by_vendor: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_vendor[f.asset.vendor].append(f)

    ranked = []
    for vendor, vendor_findings in by_vendor.items():
        ranked.append({
            "vendor": vendor,
            "finding_count": len(vendor_findings),
            "max_ot_score": round(max(f.ot_risk_score for f in vendor_findings), 2),
            "critical_count": sum(
                1 for f in vendor_findings if f.ot_severity == Severity.CRITICAL
            ),
            "kev_count": sum(1 for f in vendor_findings if f.in_kev),
        })

    return sorted(ranked, key=lambda x: (-x["max_ot_score"], -x["finding_count"]))[:top_n]


def _cve_age_stats(findings: list[Finding]) -> dict:
    """Statistics on CVE age (days since publication)."""
    now = datetime.now(timezone.utc)
    ages = []

    for f in findings:
        pub = f.cve.published
        if not pub:
            continue
        try:
            # NVD dates: "2023-11-14T00:00:00" or "2023-11-14T00:00:00.000"
            pub_clean = pub.replace("Z", "+00:00")
            if "+" not in pub_clean and pub_clean.count("T") == 1:
                pub_clean += "+00:00"
            pub_dt = datetime.fromisoformat(pub_clean)
            age_days = (now - pub_dt).days
            if age_days >= 0:
                ages.append(age_days)
        except (ValueError, TypeError):
            continue

    if not ages:
        return {"oldest_days": 0, "newest_days": 0, "median_days": 0, "avg_days": 0}

    return {
        "oldest_days": max(ages),
        "newest_days": min(ages),
        "median_days": round(statistics.median(ages)),
        "avg_days": round(statistics.mean(ages)),
    }


def _kev_coverage(findings: list[Finding]) -> dict:
    """KEV statistics: how many findings are actively exploited."""
    total = len(findings)
    kev_count = sum(1 for f in findings if f.in_kev)
    ransomware_count = sum(
        1 for f in findings
        if f.in_kev and f.kev_entry and f.kev_entry.known_ransomware_use == "Known"
    )

    return {
        "total_in_kev": kev_count,
        "kev_percentage": round(kev_count / total * 100, 1) if total else 0,
        "ransomware_linked": ransomware_count,
    }


def _severity_percentages(findings: list[Finding]) -> dict:
    """Severity distribution as percentages."""
    total = len(findings)
    counts: dict[str, int] = defaultdict(int)
    for f in findings:
        counts[f.ot_severity.value] += 1

    return {
        sev: {
            "count": counts.get(sev, 0),
            "percentage": round(counts.get(sev, 0) / total * 100, 1) if total else 0,
        }
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]
    }
