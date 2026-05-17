"""Patch priority calculator for OT remediation planning.

Groups vulnerabilities by CVE across all affected assets, then ranks
them by a weighted priority score combining OT risk, fleet impact,
KEV status, and compliance weight. Produces an actionable queue for
maintenance window planning.
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field

from models import Finding, ScanResult, Severity


# Compliance-sensitive CWE families get a priority boost
_COMPLIANCE_CWES = {
    "CWE-287", "CWE-306", "CWE-798", "CWE-521",  # Auth (FR1)
    "CWE-269", "CWE-276", "CWE-862",              # Access control (FR2)
    "CWE-120", "CWE-787", "CWE-119",              # Integrity (FR3)
    "CWE-200", "CWE-312", "CWE-319", "CWE-327",   # Confidentiality (FR4)
    "CWE-400", "CWE-770",                          # Availability (FR7)
}


@dataclass
class PatchAction:
    """A single remediation action grouped by CVE."""
    cve_id: str
    description: str
    max_ot_score: float
    affected_assets: list[str] = field(default_factory=list)
    affected_vendors: set[str] = field(default_factory=set)
    purdue_levels: set[float] = field(default_factory=set)
    in_kev: bool = False
    has_compliance_cwe: bool = False
    severity: Severity = Severity.NONE
    priority_score: float = 0.0

    @property
    def asset_count(self) -> int:
        return len(self.affected_assets)


def compute_patch_priority(
    result: ScanResult,
    kev_weight: float = 2.0,
    fleet_weight: float = 1.5,
    compliance_weight: float = 1.3,
    purdue_low_weight: float = 1.2,
) -> list[dict]:
    """Compute ranked patch priority queue from scan results.

    Priority score formula:
        base = max_ot_score
        * kev_weight      (if in CISA KEV)
        * fleet_factor     (1 + log2(asset_count) * fleet_weight_factor)
        * compliance_weight (if CWE maps to IEC 62443 FR)
        * purdue_low_weight (if affects Purdue level 0 or 1)

    Returns a list of patch actions sorted by priority score descending.
    """
    # Group findings by CVE
    by_cve: dict[str, list[Finding]] = defaultdict(list)
    for f in result.findings:
        by_cve[f.cve.cve_id].append(f)

    actions: list[PatchAction] = []

    for cve_id, findings in by_cve.items():
        first = findings[0]
        max_score = max(f.ot_risk_score for f in findings)
        asset_names = sorted({f.asset.name for f in findings})
        vendors = {f.asset.vendor for f in findings}
        levels = {f.asset.purdue_level for f in findings}
        is_kev = any(f.in_kev for f in findings)
        max_sev = max(findings, key=lambda f: f.ot_risk_score).ot_severity

        # Check if any CWE maps to compliance-sensitive categories
        all_cwes = set()
        for f in findings:
            all_cwes.update(f.cve.weaknesses)
        has_compliance = bool(all_cwes & _COMPLIANCE_CWES)

        # Compute priority score
        score = max_score

        if is_kev:
            score *= kev_weight

        # Fleet impact: more affected assets = higher priority
        if len(asset_names) > 1:
            score *= 1 + math.log2(len(asset_names)) * (fleet_weight - 1)

        if has_compliance:
            score *= compliance_weight

        # Assets at Purdue levels 0-1 are safety-critical
        if any(l <= 1 for l in levels):
            score *= purdue_low_weight

        action = PatchAction(
            cve_id=cve_id,
            description=first.cve.description[:200],
            max_ot_score=round(max_score, 2),
            affected_assets=asset_names,
            affected_vendors=vendors,
            purdue_levels=levels,
            in_kev=is_kev,
            has_compliance_cwe=has_compliance,
            severity=max_sev,
            priority_score=round(score, 2),
        )
        actions.append(action)

    # Sort by priority score descending
    actions.sort(key=lambda a: -a.priority_score)

    return [
        {
            "rank": i + 1,
            "cve_id": a.cve_id,
            "priority_score": a.priority_score,
            "max_ot_score": a.max_ot_score,
            "severity": a.severity.value,
            "affected_assets": a.affected_assets,
            "asset_count": a.asset_count,
            "vendors": sorted(a.affected_vendors),
            "purdue_levels": sorted(a.purdue_levels),
            "in_kev": a.in_kev,
            "compliance_relevant": a.has_compliance_cwe,
            "description": a.description,
        }
        for i, a in enumerate(actions)
    ]
