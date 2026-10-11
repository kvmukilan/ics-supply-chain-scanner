"""Scan comparison — diff two scan results to track vulnerability posture over time.

Identifies new, resolved, and score-changed findings between a baseline
and a current scan. Useful for trending dashboards and compliance reporting.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from models import ScanResult, Severity


@dataclass
class FindingDelta:
    """A single finding that changed between scans."""

    finding_id: str
    cve_id: str
    asset_name: str
    status: str  # "new", "resolved", "score_increased", "score_decreased", "severity_changed"
    old_ot_score: float = 0.0
    new_ot_score: float = 0.0
    old_severity: str = ""
    new_severity: str = ""
    in_kev: bool = False


@dataclass
class ScanDiff:
    """Result of comparing two scans."""

    baseline_scan_id: str
    current_scan_id: str
    new_findings: list[FindingDelta] = field(default_factory=list)
    resolved_findings: list[FindingDelta] = field(default_factory=list)
    score_changes: list[FindingDelta] = field(default_factory=list)
    unchanged_count: int = 0

    @property
    def total_changes(self) -> int:
        return len(self.new_findings) + len(self.resolved_findings) + len(self.score_changes)

    def summary(self) -> dict:
        return {
            "baseline_scan_id": self.baseline_scan_id,
            "current_scan_id": self.current_scan_id,
            "new_findings": len(self.new_findings),
            "resolved_findings": len(self.resolved_findings),
            "score_changes": len(self.score_changes),
            "unchanged": self.unchanged_count,
            "total_changes": self.total_changes,
            "new_critical": sum(1 for f in self.new_findings if f.new_severity == Severity.CRITICAL.value),
            "new_kev": sum(1 for f in self.new_findings if f.in_kev),
        }


def compare_scans(baseline: ScanResult, current: ScanResult, score_threshold: float = 0.5) -> ScanDiff:
    """Compare two scan results and return the diff.

    Args:
        baseline: The previous/older scan result.
        current: The newer scan result.
        score_threshold: Minimum OT score change to count as a delta (avoids noise).

    Returns:
        ScanDiff with new, resolved, and changed findings.
    """
    diff = ScanDiff(
        baseline_scan_id=baseline.scan_id,
        current_scan_id=current.scan_id,
    )

    baseline_map = {f.finding_id: f for f in baseline.findings}
    current_map = {f.finding_id: f for f in current.findings}

    baseline_ids = set(baseline_map.keys())
    current_ids = set(current_map.keys())

    # New findings (in current but not baseline)
    for fid in current_ids - baseline_ids:
        f = current_map[fid]
        diff.new_findings.append(
            FindingDelta(
                finding_id=fid,
                cve_id=f.cve.cve_id,
                asset_name=f.asset.name,
                status="new",
                new_ot_score=round(f.ot_risk_score, 2),
                new_severity=f.ot_severity.value,
                in_kev=f.in_kev,
            )
        )

    # Resolved findings (in baseline but not current)
    for fid in baseline_ids - current_ids:
        f = baseline_map[fid]
        diff.resolved_findings.append(
            FindingDelta(
                finding_id=fid,
                cve_id=f.cve.cve_id,
                asset_name=f.asset.name,
                status="resolved",
                old_ot_score=round(f.ot_risk_score, 2),
                old_severity=f.ot_severity.value,
                in_kev=f.in_kev,
            )
        )

    # Changed findings (in both, but score or severity changed)
    for fid in baseline_ids & current_ids:
        old = baseline_map[fid]
        new = current_map[fid]

        score_delta = abs(new.ot_risk_score - old.ot_risk_score)
        severity_changed = old.ot_severity != new.ot_severity

        if score_delta >= score_threshold or severity_changed:
            if new.ot_risk_score > old.ot_risk_score:
                status = "score_increased"
            elif new.ot_risk_score < old.ot_risk_score:
                status = "score_decreased"
            else:
                status = "severity_changed"

            diff.score_changes.append(
                FindingDelta(
                    finding_id=fid,
                    cve_id=new.cve.cve_id,
                    asset_name=new.asset.name,
                    status=status,
                    old_ot_score=round(old.ot_risk_score, 2),
                    new_ot_score=round(new.ot_risk_score, 2),
                    old_severity=old.ot_severity.value,
                    new_severity=new.ot_severity.value,
                    in_kev=new.in_kev,
                )
            )
        else:
            diff.unchanged_count += 1

    # Sort new findings by severity (critical first)
    severity_order = {s.value: i for i, s in enumerate(Severity)}
    diff.new_findings.sort(key=lambda d: (severity_order.get(d.new_severity, 99), -d.new_ot_score))
    diff.score_changes.sort(key=lambda d: -abs(d.new_ot_score - d.old_ot_score))

    return diff
