"""Risk posture timeline tracker.

Records scan result snapshots over time to enable trending,
regression detection, and compliance reporting of OT risk posture.

Snapshots are stored as append-only JSON lines (.jsonl) for
lightweight persistence without database dependencies.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from pathlib import Path

from models import ScanResult, Severity

logger = logging.getLogger(__name__)

DEFAULT_TIMELINE_PATH = ".cache/risk_timeline.jsonl"


@dataclass
class RiskSnapshot:
    """Point-in-time summary of scan risk posture."""
    scan_id: str
    timestamp: str
    total_assets: int
    total_findings: int
    total_kev: int
    severity_counts: dict[str, int]
    mean_ot_score: float
    max_ot_score: float
    critical_asset_count: int
    compliance_posture: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def capture_snapshot(
    result: ScanResult,
    compliance_posture: str = "",
) -> RiskSnapshot:
    """Capture a risk snapshot from a scan result."""
    severity_counts: dict[str, int] = {}
    scores: list[float] = []
    critical_assets: set[str] = set()

    for f in result.findings:
        sev = f.ot_severity.value
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        scores.append(f.ot_risk_score)
        if f.ot_severity == Severity.CRITICAL:
            critical_assets.add(f.asset.name)

    return RiskSnapshot(
        scan_id=result.scan_id,
        timestamp=result.timestamp,
        total_assets=result.total_assets,
        total_findings=len(result.findings),
        total_kev=result.total_kev_hits,
        severity_counts=severity_counts,
        mean_ot_score=round(sum(scores) / len(scores), 2) if scores else 0.0,
        max_ot_score=round(max(scores), 2) if scores else 0.0,
        critical_asset_count=len(critical_assets),
        compliance_posture=compliance_posture,
    )


def save_snapshot(snapshot: RiskSnapshot, path: str = DEFAULT_TIMELINE_PATH) -> None:
    """Append a snapshot to the timeline file."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a", encoding="utf-8") as f:
        f.write(json.dumps(snapshot.to_dict()) + "\n")
    logger.info(f"Risk snapshot saved to {p}")


def load_timeline(
    path: str = DEFAULT_TIMELINE_PATH,
    limit: int | None = None,
) -> list[RiskSnapshot]:
    """Load snapshots from the timeline file.

    Returns snapshots in chronological order. If limit is set,
    returns only the most recent N snapshots.
    """
    p = Path(path)
    if not p.exists():
        return []

    snapshots: list[RiskSnapshot] = []
    with open(p, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                snapshots.append(RiskSnapshot(**data))
            except (json.JSONDecodeError, TypeError) as e:
                logger.warning(f"Skipping corrupt timeline entry: {e}")

    if limit is not None and limit > 0:
        snapshots = snapshots[-limit:]

    return snapshots


def compute_trend(snapshots: list[RiskSnapshot]) -> dict:
    """Compute risk trend metrics from a timeline.

    Returns trend data including direction, score deltas,
    and finding count changes.
    """
    if len(snapshots) < 2:
        return {
            "data_points": len(snapshots),
            "trend": "insufficient_data",
            "latest": snapshots[-1].to_dict() if snapshots else None,
        }

    latest = snapshots[-1]
    previous = snapshots[-2]
    first = snapshots[0]

    score_delta = round(latest.mean_ot_score - previous.mean_ot_score, 2)
    finding_delta = latest.total_findings - previous.total_findings
    kev_delta = latest.total_kev - previous.total_kev
    critical_delta = latest.critical_asset_count - previous.critical_asset_count

    # Determine overall trend direction
    if score_delta < -0.5:
        trend = "improving"
    elif score_delta > 0.5:
        trend = "worsening"
    else:
        trend = "stable"

    # Long-term trend (first to latest)
    long_score_delta = round(latest.mean_ot_score - first.mean_ot_score, 2)
    if long_score_delta < -1.0:
        long_trend = "improving"
    elif long_score_delta > 1.0:
        long_trend = "worsening"
    else:
        long_trend = "stable"

    return {
        "data_points": len(snapshots),
        "trend": trend,
        "long_term_trend": long_trend,
        "latest": latest.to_dict(),
        "previous": previous.to_dict(),
        "deltas": {
            "mean_ot_score": score_delta,
            "total_findings": finding_delta,
            "total_kev": kev_delta,
            "critical_assets": critical_delta,
        },
        "long_term_deltas": {
            "mean_ot_score": long_score_delta,
            "total_findings": latest.total_findings - first.total_findings,
        },
        "timeline": [
            {
                "scan_id": s.scan_id,
                "timestamp": s.timestamp,
                "mean_ot_score": s.mean_ot_score,
                "total_findings": s.total_findings,
                "critical_asset_count": s.critical_asset_count,
            }
            for s in snapshots
        ],
    }
