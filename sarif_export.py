"""SARIF v2.1.0 export for scan results.

Generates Static Analysis Results Interchange Format (SARIF) output
compatible with GitHub Code Scanning, Azure DevOps, and other
security analysis tools.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from models import Finding, ScanResult, Severity

logger = logging.getLogger(__name__)

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"

SEVERITY_TO_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.NONE: "none",
}


def generate_sarif_report(result: ScanResult, output_path: str) -> str:
    """Generate a SARIF v2.1.0 report from scan results."""
    rules = _build_rules(result.findings)
    results = _build_results(result.findings)

    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ICS Supply Chain Vulnerability Scanner",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/karmukilan/ics-supply-chain-scanner",
                        "rules": rules,
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": len(result.errors) == 0,
                        "toolExecutionNotifications": [
                            {
                                "level": "warning",
                                "message": {"text": err},
                            }
                            for err in result.errors
                        ],
                    }
                ],
                "properties": {
                    "scan_id": result.scan_id,
                    "timestamp": result.timestamp,
                    "total_assets": result.total_assets,
                    "total_cves": result.total_cves,
                    "kev_matches": result.total_kev_hits,
                },
            }
        ],
    }

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(sarif, f, indent=2)

    logger.info(f"SARIF report saved to {path}")
    return str(path)


def _build_rules(findings: list[Finding]) -> list[dict]:
    """Build SARIF rule descriptors from unique CVEs."""
    seen = {}
    rules = []

    for f in findings:
        cve_id = f.cve.cve_id
        if cve_id in seen:
            continue
        seen[cve_id] = True

        rule = {
            "id": cve_id,
            "name": cve_id.replace("-", ""),
            "shortDescription": {
                "text": f"{cve_id} (CVSS {f.cve.cvss_base_score})",
            },
            "fullDescription": {
                "text": f.cve.description,
            },
            "helpUri": f.cve.nvd_url,
            "properties": {
                "tags": _build_tags(f),
                "cvss_base_score": f.cve.cvss_base_score,
                "cvss_vector": f.cve.cvss_vector,
            },
        }

        if f.cve.weaknesses:
            rule["properties"]["cwe"] = f.cve.weaknesses

        rules.append(rule)

    return rules


def _build_results(findings: list[Finding]) -> list[dict]:
    """Build SARIF result entries from findings."""
    results = []

    for f in sorted(findings, key=lambda x: x.ot_risk_score, reverse=True):
        kev_note = ""
        if f.in_kev and f.kev_entry:
            kev_note = (
                f" [CISA KEV: actively exploited, "
                f"due {f.kev_entry.due_date}, "
                f"ransomware: {f.kev_entry.known_ransomware_use}]"
            )

        iec_note = ""
        if f.iec_62443_mappings:
            iec_note = f" IEC 62443: {', '.join(m.split(':')[0] for m in f.iec_62443_mappings)}."

        message = (
            f"{f.cve.cve_id} affects {f.asset.vendor} {f.asset.model} "
            f"({f.asset.name}) at Purdue Level {f.asset.purdue_level}. "
            f"OT Risk Score: {f.ot_risk_score:.2f} "
            f"(CVSS base: {f.cve.cvss_base_score}).{kev_note}{iec_note}"
        )

        entry = {
            "ruleId": f.cve.cve_id,
            "level": SEVERITY_TO_SARIF_LEVEL.get(f.ot_severity, "warning"),
            "message": {"text": message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.asset.cpe,
                            "uriBaseId": "OT_INVENTORY",
                        },
                    },
                    "logicalLocations": [
                        {
                            "name": f.asset.name,
                            "fullyQualifiedName": (
                                f"{f.asset.vendor}/{f.asset.model}/"
                                f"{f.asset.firmware_version}"
                            ),
                            "kind": "asset",
                            "properties": {
                                "purdue_level": f.asset.purdue_level,
                                "network_zone": f.asset.network_zone,
                                "exposure": f.asset.exposure.value,
                                "patch_status": f.asset.patch_status.value,
                            },
                        }
                    ],
                }
            ],
            "properties": {
                "finding_id": f.finding_id,
                "ot_risk_score": round(f.ot_risk_score, 2),
                "ot_severity": f.ot_severity.value,
                "in_kev": f.in_kev,
                "score_breakdown": f.score_breakdown,
                "iec_62443_mappings": f.iec_62443_mappings,
            },
        }

        if f.cve.references:
            entry["relatedLocations"] = [
                {
                    "id": i,
                    "message": {"text": f"Reference: {ref}"},
                    "physicalLocation": {
                        "artifactLocation": {"uri": ref},
                    },
                }
                for i, ref in enumerate(f.cve.references[:3])
            ]

        results.append(entry)

    return results


def _build_tags(finding: Finding) -> list[str]:
    """Build SARIF tags for a finding."""
    tags = ["ics", "ot-security", f"purdue-L{finding.asset.purdue_level}"]

    if finding.in_kev:
        tags.append("cisa-kev")
    if finding.cve.weaknesses:
        tags.extend(finding.cve.weaknesses)
    if finding.ot_severity == Severity.CRITICAL:
        tags.append("critical")

    return tags
