"""IEC 62443 compliance posture assessment.

Evaluates scan results against IEC 62443 Security Levels (SL)
and generates a compliance scorecard showing coverage gaps per
Foundational Requirement across Purdue levels.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from models import Finding, ScanResult, Severity

# IEC 62443-3-3 Foundational Requirements and key System Requirements
IEC_62443_FRAMEWORK = {
    "FR1": {
        "name": "Identification and Authentication Control",
        "system_requirements": {
            "SR 1.1": "Human user identification and authentication",
            "SR 1.2": "Software process and device identification and authentication",
            "SR 1.3": "Account management",
            "SR 1.5": "Authenticator management",
            "SR 1.7": "Strength of password-based authentication",
            "SR 1.9": "Strength of public key authentication",
        },
        "related_cwes": ["CWE-287", "CWE-306", "CWE-798", "CWE-521", "CWE-307"],
    },
    "FR2": {
        "name": "Use Control",
        "system_requirements": {
            "SR 2.1": "Authorization enforcement",
            "SR 2.2": "Wireless use control",
            "SR 2.4": "Mobile code",
            "SR 2.5": "Session lock",
            "SR 2.8": "Auditable events",
        },
        "related_cwes": ["CWE-269", "CWE-276", "CWE-732", "CWE-862", "CWE-863"],
    },
    "FR3": {
        "name": "System Integrity",
        "system_requirements": {
            "SR 3.1": "Communication integrity",
            "SR 3.2": "Malicious code protection",
            "SR 3.3": "Security functionality verification",
            "SR 3.4": "Software and information integrity",
            "SR 3.5": "Input validation",
        },
        "related_cwes": ["CWE-120", "CWE-787", "CWE-119", "CWE-20", "CWE-79", "CWE-89"],
    },
    "FR4": {
        "name": "Data Confidentiality",
        "system_requirements": {
            "SR 4.1": "Information confidentiality",
            "SR 4.2": "Information persistence",
            "SR 4.3": "Use of cryptography",
        },
        "related_cwes": ["CWE-200", "CWE-312", "CWE-319", "CWE-327", "CWE-311"],
    },
    "FR5": {
        "name": "Restricted Data Flow",
        "system_requirements": {
            "SR 5.1": "Network segmentation",
            "SR 5.2": "Zone boundary protection",
            "SR 5.3": "General purpose person-to-person communication restrictions",
        },
        "related_cwes": ["CWE-284", "CWE-668"],
    },
    "FR6": {
        "name": "Timely Response to Events",
        "system_requirements": {
            "SR 6.1": "Audit log accessibility",
            "SR 6.2": "Continuous monitoring",
        },
        "related_cwes": ["CWE-778", "CWE-223"],
    },
    "FR7": {
        "name": "Resource Availability",
        "system_requirements": {
            "SR 7.1": "Denial of service protection",
            "SR 7.2": "Resource management",
            "SR 7.3": "Control system backup",
            "SR 7.6": "Network and security configuration settings",
        },
        "related_cwes": ["CWE-400", "CWE-770", "CWE-404"],
    },
}


@dataclass
class FRScore:
    """Score for a single Foundational Requirement."""
    fr_id: str
    fr_name: str
    finding_count: int = 0
    critical_count: int = 0
    max_ot_score: float = 0.0
    affected_assets: int = 0
    status: str = "pass"  # "pass", "at_risk", "fail"


@dataclass
class ComplianceReport:
    """Full IEC 62443 compliance posture report."""
    scan_id: str
    total_findings: int = 0
    fr_scores: dict[str, FRScore] = field(default_factory=dict)
    risk_by_purdue: dict[float, dict] = field(default_factory=dict)
    overall_posture: str = "unknown"  # "compliant", "at_risk", "non_compliant"

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "overall_posture": self.overall_posture,
            "total_findings": self.total_findings,
            "foundational_requirements": {
                fr_id: {
                    "name": score.fr_name,
                    "status": score.status,
                    "finding_count": score.finding_count,
                    "critical_count": score.critical_count,
                    "max_ot_score": score.max_ot_score,
                    "affected_assets": score.affected_assets,
                }
                for fr_id, score in self.fr_scores.items()
            },
            "risk_by_purdue_level": self.risk_by_purdue,
        }


def assess_compliance(result: ScanResult) -> ComplianceReport:
    """Assess IEC 62443 compliance posture from scan results."""
    report = ComplianceReport(
        scan_id=result.scan_id,
        total_findings=len(result.findings),
    )

    # Initialize all FR scores
    for fr_id, fr_data in IEC_62443_FRAMEWORK.items():
        report.fr_scores[fr_id] = FRScore(fr_id=fr_id, fr_name=fr_data["name"])

    # Map findings to FRs via CWE
    _map_findings_to_frs(result.findings, report)

    # Map findings to FRs via explicit IEC 62443 mappings in remediation
    _map_explicit_iec_mappings(result.findings, report)

    # Compute per-Purdue-level risk
    report.risk_by_purdue = _compute_purdue_risk(result.findings)

    # Determine status per FR
    for score in report.fr_scores.values():
        if score.critical_count > 0:
            score.status = "fail"
        elif score.finding_count > 0:
            score.status = "at_risk"
        else:
            score.status = "pass"

    # Overall posture
    statuses = [s.status for s in report.fr_scores.values()]
    if "fail" in statuses:
        report.overall_posture = "non_compliant"
    elif "at_risk" in statuses:
        report.overall_posture = "at_risk"
    else:
        report.overall_posture = "compliant"

    return report


def _map_findings_to_frs(findings: list[Finding], report: ComplianceReport) -> None:
    """Map findings to Foundational Requirements via CWE IDs."""
    for f in findings:
        cwes = set(w.upper() for w in f.cve.weaknesses)
        matched_frs: set[str] = set()

        for fr_id, fr_data in IEC_62443_FRAMEWORK.items():
            related = set(c.upper() for c in fr_data["related_cwes"])
            if cwes & related:
                matched_frs.add(fr_id)

        for fr_id in matched_frs:
            score = report.fr_scores[fr_id]
            score.finding_count += 1
            score.max_ot_score = max(score.max_ot_score, f.ot_risk_score)
            if f.ot_severity == Severity.CRITICAL:
                score.critical_count += 1


def _map_explicit_iec_mappings(findings: list[Finding], report: ComplianceReport) -> None:
    """Map findings via explicit IEC 62443 mapping strings (e.g., 'FR3: ...')."""
    # Count unique affected assets per FR (CWE-derived and explicit mappings)
    fr_assets: dict[str, set[str]] = defaultdict(set)
    for f in findings:
        cwes = set(w.upper() for w in f.cve.weaknesses)
        for fr_id, fr_data in IEC_62443_FRAMEWORK.items():
            related = set(c.upper() for c in fr_data["related_cwes"])
            if cwes & related:
                fr_assets[fr_id].add(f.asset.name)

        for mapping in f.iec_62443_mappings:
            for fr_id in IEC_62443_FRAMEWORK:
                if mapping.upper().startswith(fr_id):
                    fr_assets[fr_id].add(f.asset.name)
                    break

    for fr_id, assets in fr_assets.items():
        report.fr_scores[fr_id].affected_assets = len(assets)


def _compute_purdue_risk(findings: list[Finding]) -> dict[float, dict]:
    """Compute compliance risk summary per Purdue level."""
    by_level: dict[float, list[Finding]] = defaultdict(list)
    for f in findings:
        by_level[f.asset.purdue_level].append(f)

    result = {}
    for level in sorted(by_level):
        level_findings = by_level[level]
        criticals = sum(1 for f in level_findings if f.ot_severity == Severity.CRITICAL)
        kev_hits = sum(1 for f in level_findings if f.in_kev)
        assets = set(f.asset.name for f in level_findings)

        result[level] = {
            "finding_count": len(level_findings),
            "critical_count": criticals,
            "kev_count": kev_hits,
            "affected_assets": len(assets),
            "max_ot_score": round(max(f.ot_risk_score for f in level_findings), 2),
        }

    return result
