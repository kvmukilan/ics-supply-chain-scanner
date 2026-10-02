"""MITRE ATT&CK for ICS mapping.

Maps CWE weaknesses from scan findings to MITRE ATT&CK for ICS
techniques and tactics, enabling threat-informed defense analysis.

Reference: https://attack.mitre.org/techniques/ics/
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from models import ScanResult

# ATT&CK for ICS tactics (the ICS matrix uses TA0100-TA0111, not the Enterprise IDs).
# https://attack.mitre.org/tactics/ics/
ICS_TACTICS = {
    "TA0100": "Collection",
    "TA0101": "Command and Control",
    "TA0102": "Discovery",
    "TA0103": "Evasion",
    "TA0104": "Execution",
    "TA0105": "Impact",
    "TA0106": "Impair Process Control",
    "TA0107": "Inhibit Response Function",
    "TA0108": "Initial Access",
    "TA0109": "Lateral Movement",
    "TA0110": "Persistence",
    "TA0111": "Privilege Escalation",
}

# ATT&CK for ICS techniques used below: (technique name, primary tactic ID).
# Techniques that sit under several tactics are pinned to one so that each
# technique is reported under a single, consistent tactic.
_T = {
    "T0807": ("Command-Line Interface", "TA0104"),
    "T0811": ("Data from Information Repositories", "TA0100"),
    "T0814": ("Denial of Service", "TA0107"),
    "T0830": ("Adversary-in-the-Middle", "TA0100"),
    "T0831": ("Manipulation of Control", "TA0105"),
    "T0855": ("Unauthorized Command Message", "TA0106"),
    "T0859": ("Valid Accounts", "TA0109"),
    "T0865": ("Spearphishing Attachment", "TA0108"),
    "T0886": ("Remote Services", "TA0108"),
    "T0890": ("Exploitation for Privilege Escalation", "TA0111"),
}


def _techs(*technique_ids: str) -> list[tuple[str, str, str]]:
    return [(tid, *_T[tid]) for tid in technique_ids]


# CWE -> ATT&CK for ICS technique mapping
# Based on common vulnerability-to-technique relationships
CWE_TO_ATTCK_ICS = {
    # Authentication / access
    "CWE-287": _techs("T0859"),
    "CWE-306": _techs("T0859", "T0886"),
    "CWE-798": _techs("T0859"),
    "CWE-521": _techs("T0859"),
    "CWE-307": _techs("T0859"),  # brute force -> obtaining valid credentials
    # Authorization / privilege
    "CWE-269": _techs("T0890"),
    "CWE-276": _techs("T0890"),
    "CWE-732": _techs("T0890"),
    "CWE-862": _techs("T0890"),
    # Memory corruption / code execution
    "CWE-120": _techs("T0807", "T0831"),
    "CWE-787": _techs("T0807", "T0831"),
    "CWE-119": _techs("T0807"),
    "CWE-20": _techs("T0855"),
    # Injection
    "CWE-79": _techs("T0865"),
    "CWE-89": _techs("T0811"),
    # Information disclosure
    "CWE-200": _techs("T0811"),
    "CWE-312": _techs("T0811"),
    "CWE-319": _techs("T0830"),
    "CWE-327": _techs("T0830"),
    "CWE-311": _techs("T0830"),
    # Network
    "CWE-284": _techs("T0886"),
    "CWE-668": _techs("T0886"),
    # Availability
    "CWE-400": _techs("T0814"),
    "CWE-770": _techs("T0814"),
    "CWE-404": _techs("T0814"),
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
        by_tactic[f"{hit.tactic_id}: {hit.tactic_name}"].append({
            "technique_id": hit.technique_id,
            "technique_name": hit.technique_name,
            "finding_count": hit.finding_count,
            "max_ot_score": round(hit.max_ot_score, 2),
            "cve_ids": hit.cve_ids,
            "affected_assets": sorted(hit.affected_assets),
        })

    return {
        "total_techniques_matched": len(hits),
        "total_tactics_covered": len(by_tactic),
        "attack_surface": by_tactic,
    }
