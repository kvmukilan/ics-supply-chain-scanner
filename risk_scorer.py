"""OT-specific risk scoring engine.

Applies Purdue-level, network exposure, patch feasibility,
and CISA KEV multipliers to base CVSS scores.
"""

from __future__ import annotations

import logging

from config import OTRiskWeights
from models import Asset, CVEEntry, Finding, Severity

logger = logging.getLogger(__name__)


class OTRiskScorer:
    """Calculate OT-contextualized risk scores."""

    def __init__(self, weights: OTRiskWeights):
        self.weights = weights

    def score(self, asset: Asset, cve: CVEEntry, in_kev: bool) -> tuple[float, dict]:
        """
        Calculate OT risk score for a finding.

        Returns:
            (final_score, breakdown_dict)
        """
        base = cve.cvss_base_score
        if base == 0.0:
            return 0.0, {"base_cvss": 0.0, "note": "No CVSS score available"}

        # Purdue level weight
        purdue_w = self.weights.purdue_weights.get(
            asset.purdue_level,
            self.weights.purdue_weights.get(int(asset.purdue_level), 1.0),
        )

        # Network exposure weight
        exposure_w = self.weights.exposure_weights.get(asset.exposure.value, 1.0)

        # Patch feasibility weight
        patch_w = self.weights.patch_weights.get(asset.patch_status.value, 1.0)

        # KEV presence
        kev_w = self.weights.kev_multiplier if in_kev else self.weights.no_kev_multiplier

        raw_score = base * purdue_w * exposure_w * patch_w * kev_w
        final_score = min(raw_score, self.weights.max_score)

        breakdown = {
            "base_cvss": base,
            "purdue_level": asset.purdue_level,
            "purdue_weight": purdue_w,
            "exposure": asset.exposure.value,
            "exposure_weight": exposure_w,
            "patch_status": asset.patch_status.value,
            "patch_weight": patch_w,
            "in_kev": in_kev,
            "kev_weight": kev_w,
            "raw_score": round(raw_score, 3),
            "final_score": round(final_score, 2),
            "formula": f"{base} × {purdue_w} × {exposure_w} × {patch_w} × {kev_w} = {round(raw_score, 3)} → capped at {round(final_score, 2)}",
        }

        return final_score, breakdown

    def classify_ot_severity(self, score: float) -> Severity:
        """
        Map OT risk score to severity.

        Thresholds are slightly different from standard CVSS
        because our scoring can exceed base CVSS via multipliers.
        """
        if score >= 8.5:
            return Severity.CRITICAL
        elif score >= 6.5:
            return Severity.HIGH
        elif score >= 4.0:
            return Severity.MEDIUM
        elif score > 0.0:
            return Severity.LOW
        return Severity.NONE

    def score_finding(self, finding: Finding) -> Finding:
        """Score a finding in-place and return it."""
        score, breakdown = self.score(
            finding.asset, finding.cve, finding.in_kev
        )
        finding.ot_risk_score = score
        finding.score_breakdown = breakdown
        finding.ot_severity = self.classify_ot_severity(score)
        return finding
