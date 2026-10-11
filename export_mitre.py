"""MITRE ATT&CK for ICS mapping.

Maps CWE weaknesses from scan findings to MITRE ATT&CK for ICS
techniques and tactics, enabling threat-informed defense analysis.

Reference: https://attack.mitre.org/techniques/ics/
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from models import ScanResult

# CWE -> ATT&CK for ICS technique mapping
# Based on common vulnerability-to-technique relationships
CWE_TO_ATTCK_ICS = {
    # Authentication / access
    "CWE-287": [("T0859", "Valid Accounts", "TA0001")],
    "CWE-306": [("T0859", "Valid Accounts", "TA0001"), ("T0886", "Remote Services", "TA0001")],
    "CWE-798": [("T0859", "Valid Accounts", "TA0001")],
    "CWE-521": [("T0859", "Valid Accounts", "TA0001")],
    "CWE-307": [("T0811", "Data from Information Repositories", "TA0009")],
    # Authorization / privilege
    "CWE-269": [("T0890", "Exploitation for Privilege Escalation", "TA0008")],
    "CWE-276": [("T0890", "Exploitation for Privilege Escalation", "TA0008")],
    "CWE-732": [("T0890", "Exploitation for Privilege Escalation", "TA0008")],
    "CWE-862": [("T0890", "Exploitation for Privilege Escalation", "TA0008")],
    # Memory corruption / code execution
    "CWE-120": [
        ("T0807", "Command-Line Interface", "TA0002"),
        ("T0831", "Manipulation of Control", "TA0011"),
    ],
    "CWE-787": [
        ("T0807", "Command-Line Interface", "TA0002"),
        ("T0831", "Manipulation of Control", "TA0011"),
    ],
    "CWE-119": [("T0807", "Command-Line Interface", "TA0002")],
    "CWE-20": [("T0855", "Unauthorized Command Message", "TA0011")],
    # Injection
    "CWE-79": [("T0865", "Spearphishing Attachment", "TA0001")],
    "CWE-89": [("T0811", "Data from Information Repositories", "TA0009")],
    # Information disclosure
    "CWE-200": [("T0811", "Data from Information Repositories", "TA0009")],
    "CWE-312": [("T0811", "Data from Information Repositories", "TA0009")],
    "CWE-319": [("T0830", "Man in the Middle", "TA0009")],
    "CWE-327": [("T0830", "Man in the Middle", "TA0009")],
    "CWE-311": [("T0830", "Man in the Middle", "TA0009")],
    # Network
    "CWE-284": [("T0886", "Remote Services", "TA0001")],
    "CWE-668": [("T0886", "Remote Services", "TA0001")],
    # Availability
    "CWE-400": [("T0814", "Denial of Service", "TA0010")],
    "CWE-770": [("T0814", "Denial of Service", "TA0010")],
    "CWE-404": [("T0814", "Denial of Service", "TA0010")],
}

# ATT&CK for ICS tactic metadata
ICS_TACTICS = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Evasion",
    "TA0006": "Discovery",
    "TA0007": "Lateral Movement",
    "TA0008": "Privilege Escalation",
    "TA0009": "Collection",
    "TA0010": "Impact",
    "TA0011": "Impair Process Control",
}


@dataclass
class TechniqueHit:
    """A MITRE ATT&CK technique matched from findings."""

    technique_id: str
    technique_name: str
    tactic_id: str
    tactic_name: str
    finding_count: int = 0
    max_ot_score: float = 0.0
    cve_ids: list[str] = field(default_factory=list)
    affected_assets: set[str] = field(default_factory=set)


def map_to_attck(result: ScanResult) -> dict:
    """Map scan findings to MITRE ATT&CK for ICS techniques.

    Returns a dict with technique hits grouped by tactic.
    """
    hits: dict[str, TechniqueHit] = {}

    for f in result.findings:
        for cwe in f.cve.weaknesses:
            cwe_upper = cwe.upper()
            techniques = CWE_TO_ATTCK_ICS.get(cwe_upper, [])
            for tech_id, tech_name, tactic_id in techniques:
                if tech_id not in hits:
                    hits[tech_id] = TechniqueHit(
                        technique_id=tech_id,
                        technique_name=tech_name,
                        tactic_id=tactic_id,
                        tactic_name=ICS_TACTICS.get(tactic_id, "Unknown"),
                    )
                hit = hits[tech_id]
                hit.finding_count += 1
                hit.max_ot_score = max(hit.max_ot_score, f.ot_risk_score)
                if f.cve.cve_id not in hit.cve_ids:
                    hit.cve_ids.append(f.cve.cve_id)
                hit.affected_assets.add(f.asset.name)

    # Group by tactic
    by_tactic: dict[str, list[dict]] = defaultdict(list)
    for hit in sorted(hits.values(), key=lambda h: -h.max_ot_score):
        by_tactic[f"{hit.tactic_id}: {hit.tactic_name}"].append(
            {
                "technique_id": hit.technique_id,
                "technique_name": hit.technique_name,
                "finding_count": hit.finding_count,
                "max_ot_score": round(hit.max_ot_score, 2),
                "cve_ids": hit.cve_ids,
                "affected_assets": sorted(hit.affected_assets),
            }
        )

    return {
        "total_techniques_matched": len(hits),
        "total_tactics_covered": len(by_tactic),
        "attack_surface": by_tactic,
    }
