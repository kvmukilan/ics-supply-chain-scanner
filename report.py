"""Report generation for scan results.

Supports JSON, HTML, CSV, and Markdown export formats.
"""

from __future__ import annotations

import csv
import json
import logging
from datetime import datetime
from io import StringIO
from pathlib import Path

from models import Finding, ScanResult, Severity

logger = logging.getLogger(__name__)


def generate_json_report(result: ScanResult, output_path: str) -> str:
    """Generate detailed JSON report."""
    from analytics import compute_analytics
    from compliance import assess_compliance

    report = {
        "metadata": result.summary(),
        "analytics": compute_analytics(result),
        "compliance": assess_compliance(result).to_dict(),
        "findings": [],
    }

    for f in sorted(result.findings, key=lambda x: x.ot_risk_score, reverse=True):
        finding_data = {
            "finding_id": f.finding_id,
            "asset": {
                "name": f.asset.name,
                "vendor": f.asset.vendor,
                "model": f.asset.model,
                "firmware": f.asset.firmware_version,
                "cpe": f.asset.cpe,
                "purdue_level": f.asset.purdue_level,
                "network_zone": f.asset.network_zone,
                "exposure": f.asset.exposure.value,
                "patch_status": f.asset.patch_status.value,
            },
            "vulnerability": {
                "cve_id": f.cve.cve_id,
                "description": f.cve.description,
                "cvss_base": f.cve.cvss_base_score,
                "cvss_vector": f.cve.cvss_vector,
                "severity": f.cve.severity.value,
                "weaknesses": f.cve.weaknesses,
                "references": f.cve.references,
                "nvd_url": f.cve.nvd_url,
            },
            "risk_assessment": {
                "ot_risk_score": round(f.ot_risk_score, 2),
                "ot_severity": f.ot_severity.value,
                "in_kev": f.in_kev,
                "score_breakdown": f.score_breakdown,
            },
            "remediation": json.loads(f.remediation) if f.remediation else {},
            "iec_62443_mappings": f.iec_62443_mappings,
        }
        if f.in_kev and f.kev_entry:
            finding_data["kev_details"] = {
                "date_added": f.kev_entry.date_added,
                "due_date": f.kev_entry.due_date,
                "required_action": f.kev_entry.required_action,
                "ransomware_use": f.kev_entry.known_ransomware_use,
            }
        report["findings"].append(finding_data)

    if result.errors:
        report["errors"] = result.errors

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    logger.info(f"JSON report saved to {path}")
    return str(path)


def _severity_color(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "#dc2626",
        Severity.HIGH: "#ea580c",
        Severity.MEDIUM: "#ca8a04",
        Severity.LOW: "#2563eb",
        Severity.NONE: "#6b7280",
    }.get(severity, "#6b7280")


def _severity_badge(severity: Severity) -> str:
    color = _severity_color(severity)
    return f'<span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:600">{severity.value}</span>'


def generate_html_report(result: ScanResult, output_path: str) -> str:
    """Generate HTML report with dashboard summary."""
    from compliance import assess_compliance

    summary = result.summary()
    sev_dist = summary["severity_distribution"]
    compliance = assess_compliance(result)

    # Build compliance scorecard HTML
    posture_colors = {"compliant": "#16a34a", "at_risk": "#ca8a04", "non_compliant": "#dc2626"}
    posture_color = posture_colors.get(compliance.overall_posture, "#6b7280")
    compliance_html = f'<span style="background:{posture_color};color:#fff;padding:4px 12px;border-radius:6px;font-weight:600;font-size:14px">{compliance.overall_posture.replace("_", " ").upper()}</span>'

    fr_rows = ""
    for fr_id, score in compliance.fr_scores.items():
        status_colors = {"pass": "#16a34a", "at_risk": "#ca8a04", "fail": "#dc2626"}
        sc = status_colors.get(score.status, "#6b7280")
        fr_rows += f'<tr><td style="font-weight:600">{fr_id}</td><td>{score.fr_name}</td><td style="text-align:center"><span style="color:{sc};font-weight:700">{score.status.upper()}</span></td><td style="text-align:center">{score.finding_count}</td><td style="text-align:center">{score.critical_count}</td><td style="text-align:center">{score.affected_assets}</td></tr>'

    findings_html = ""
    for f in sorted(result.findings, key=lambda x: x.ot_risk_score, reverse=True):
        kev_tag = ' <span style="background:#7c3aed;color:#fff;padding:2px 6px;border-radius:4px;font-size:11px">KEV</span>' if f.in_kev else ""

        remediation_data = json.loads(f.remediation) if f.remediation else {}
        actions_html = ""
        for section_key, section_label in [
            ("immediate_actions", "Immediate Actions"),
            ("short_term_remediation", "Short-Term Remediation"),
            ("long_term_remediation", "Long-Term Remediation"),
            ("compensating_controls", "Compensating Controls"),
            ("verification_steps", "Verification"),
        ]:
            items = remediation_data.get(section_key, [])
            if items:
                items_li = "".join(f"<li>{item}</li>" for item in items)
                actions_html += f"<h4 style='margin:8px 0 4px'>{section_label}</h4><ul style='margin:0'>{items_li}</ul>"

        iec_tags = " ".join(
            f'<span style="background:#e0e7ff;color:#3730a3;padding:2px 6px;border-radius:4px;font-size:11px;margin-right:4px">{m.split(":")[0] if ":" in m else m}</span>'
            for m in f.iec_62443_mappings
        )

        findings_html += f"""
        <div style="border:1px solid #e5e7eb;border-left:4px solid {_severity_color(f.ot_severity)};border-radius:8px;padding:16px;margin-bottom:16px;background:#fff">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
                <div>
                    <strong style="font-size:16px">{f.cve.cve_id}</strong>{kev_tag}
                    {_severity_badge(f.ot_severity)}
                    <span style="color:#6b7280;margin-left:8px">OT Score: <strong>{f.ot_risk_score:.2f}</strong> | CVSS: {f.cve.cvss_base_score}</span>
                </div>
            </div>
            <div style="margin-bottom:8px">
                <strong>Asset:</strong> {f.asset.vendor} {f.asset.model} ({f.asset.name}) — Level {f.asset.purdue_level} | {f.asset.network_zone} | {f.asset.exposure.value}
            </div>
            <div style="margin-bottom:8px;color:#374151;font-size:14px">{f.cve.description[:300]}{'...' if len(f.cve.description) > 300 else ''}</div>
            <div style="margin-bottom:8px">{iec_tags}</div>
            <details>
                <summary style="cursor:pointer;color:#2563eb;font-weight:600">Remediation Playbook</summary>
                <div style="padding:8px 0">{actions_html}</div>
                <div style="font-size:12px;color:#6b7280;margin-top:4px">
                    Score: {f.score_breakdown.get('formula', 'N/A')}
                </div>
            </details>
            <div style="margin-top:8px">
                <a href="{f.cve.nvd_url}" target="_blank" style="color:#2563eb;font-size:13px">View on NVD →</a>
            </div>
        </div>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ICS Supply Chain Vulnerability Report</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f3f4f6; color: #111827; padding: 24px; }}
        .container {{ max-width: 1100px; margin: 0 auto; }}
        .header {{ background: linear-gradient(135deg, #1e293b, #334155); color: #fff; padding: 32px; border-radius: 12px; margin-bottom: 24px; }}
        .header h1 {{ font-size: 24px; margin-bottom: 8px; }}
        .header p {{ color: #94a3b8; font-size: 14px; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 24px; }}
        .stat {{ background: #fff; border-radius: 10px; padding: 20px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        .stat .value {{ font-size: 32px; font-weight: 700; }}
        .stat .label {{ font-size: 13px; color: #6b7280; margin-top: 4px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>ICS Supply Chain Vulnerability Report</h1>
            <p>Scan ID: {result.scan_id} | Generated: {result.timestamp} | Assets: {result.total_assets}</p>
        </div>
        <div class="stats">
            <div class="stat">
                <div class="value">{result.total_cves}</div>
                <div class="label">Total CVEs</div>
            </div>
            <div class="stat">
                <div class="value" style="color:#dc2626">{sev_dist.get('CRITICAL', 0)}</div>
                <div class="label">Critical</div>
            </div>
            <div class="stat">
                <div class="value" style="color:#ea580c">{sev_dist.get('HIGH', 0)}</div>
                <div class="label">High</div>
            </div>
            <div class="stat">
                <div class="value" style="color:#ca8a04">{sev_dist.get('MEDIUM', 0)}</div>
                <div class="label">Medium</div>
            </div>
            <div class="stat">
                <div class="value" style="color:#7c3aed">{result.total_kev_hits}</div>
                <div class="label">In CISA KEV</div>
            </div>
        </div>
        <div style="background:#fff;border-radius:10px;padding:20px;margin-bottom:24px;box-shadow:0 1px 3px rgba(0,0,0,0.1)">
            <h2 style="margin:0 0 12px;font-size:20px">IEC 62443 Compliance Posture: {compliance_html}</h2>
            <table style="width:100%;border-collapse:collapse;font-size:14px">
                <thead><tr style="border-bottom:2px solid #e5e7eb">
                    <th style="padding:8px;text-align:left">FR</th>
                    <th style="padding:8px;text-align:left">Requirement</th>
                    <th style="padding:8px;text-align:center">Status</th>
                    <th style="padding:8px;text-align:center">Findings</th>
                    <th style="padding:8px;text-align:center">Critical</th>
                    <th style="padding:8px;text-align:center">Assets</th>
                </tr></thead>
                <tbody>{fr_rows}</tbody>
            </table>
        </div>
        <h2 style="margin-bottom:16px;font-size:20px">Findings (sorted by OT Risk Score)</h2>
        {findings_html}
        {"<div style='background:#fef3c7;border:1px solid #f59e0b;border-radius:8px;padding:16px;margin-top:16px'><strong>Errors during scan:</strong><ul>" + "".join(f"<li>{e}</li>" for e in result.errors) + "</ul></div>" if result.errors else ""}
    </div>
</body>
</html>"""

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)

    logger.info(f"HTML report saved to {path}")
    return str(path)


def generate_csv_report(result: ScanResult, output_path: str) -> str:
    """Generate CSV report for spreadsheet analysis and compliance tracking."""
    fieldnames = [
        "Finding ID", "Asset Name", "Asset ID", "Vendor", "Model",
        "Firmware", "CPE", "Purdue Level", "Network Zone", "Exposure",
        "Patch Status", "CVE ID", "CVSS Base", "CVSS Vector",
        "CVE Severity", "OT Risk Score", "OT Severity",
        "In CISA KEV", "KEV Due Date", "KEV Required Action",
        "IEC 62443 Mappings", "NVD URL",
    ]

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for finding in sorted(result.findings, key=lambda x: x.ot_risk_score, reverse=True):
            kev_due = ""
            kev_action = ""
            if finding.in_kev and finding.kev_entry:
                kev_due = finding.kev_entry.due_date
                kev_action = finding.kev_entry.required_action

            writer.writerow({
                "Finding ID": finding.finding_id,
                "Asset Name": finding.asset.name,
                "Asset ID": finding.asset.asset_id,
                "Vendor": finding.asset.vendor,
                "Model": finding.asset.model,
                "Firmware": finding.asset.firmware_version,
                "CPE": finding.asset.cpe,
                "Purdue Level": finding.asset.purdue_level,
                "Network Zone": finding.asset.network_zone,
                "Exposure": finding.asset.exposure.value,
                "Patch Status": finding.asset.patch_status.value,
                "CVE ID": finding.cve.cve_id,
                "CVSS Base": finding.cve.cvss_base_score,
                "CVSS Vector": finding.cve.cvss_vector,
                "CVE Severity": finding.cve.severity.value,
                "OT Risk Score": round(finding.ot_risk_score, 2),
                "OT Severity": finding.ot_severity.value,
                "In CISA KEV": "Yes" if finding.in_kev else "No",
                "KEV Due Date": kev_due,
                "KEV Required Action": kev_action,
                "IEC 62443 Mappings": " | ".join(finding.iec_62443_mappings),
                "NVD URL": finding.cve.nvd_url,
            })

    logger.info(f"CSV report saved to {path}")
    return str(path)


def generate_markdown_report(result: ScanResult, output_path: str) -> str:
    """Generate Markdown report for GitHub/GitLab/Azure DevOps rendering."""
    from compliance import assess_compliance

    summary = result.summary()
    sev_dist = summary["severity_distribution"]
    compliance = assess_compliance(result)

    posture_emoji = {
        "compliant": "PASS", "at_risk": "WARN", "non_compliant": "FAIL",
    }
    posture_label = posture_emoji.get(compliance.overall_posture, "?")

    lines = [
        f"# ICS Supply Chain Vulnerability Report",
        "",
        f"**Scan ID:** `{result.scan_id}` | "
        f"**Timestamp:** {result.timestamp} | "
        f"**Assets:** {result.total_assets}",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "|--------|------:|",
        f"| Total CVEs | {result.total_cves} |",
        f"| Critical | {sev_dist.get('CRITICAL', 0)} |",
        f"| High | {sev_dist.get('HIGH', 0)} |",
        f"| Medium | {sev_dist.get('MEDIUM', 0)} |",
        f"| Low | {sev_dist.get('LOW', 0)} |",
        f"| CISA KEV Hits | {result.total_kev_hits} |",
        f"| IEC 62443 Posture | **{posture_label}** ({compliance.overall_posture}) |",
        "",
    ]

    # Compliance table
    lines.append("## IEC 62443 Compliance")
    lines.append("")
    lines.append("| FR | Requirement | Status | Findings | Critical | Assets |")
    lines.append("|-----|------------|--------|----------|----------|--------|")
    for fr_id, score in compliance.fr_scores.items():
        status_marker = {"pass": "PASS", "at_risk": "WARN", "fail": "FAIL"}.get(
            score.status, "?"
        )
        lines.append(
            f"| {fr_id} | {score.fr_name} | **{status_marker}** | "
            f"{score.finding_count} | {score.critical_count} | {score.affected_assets} |"
        )
    lines.append("")

    # Findings table
    sorted_findings = sorted(result.findings, key=lambda x: x.ot_risk_score, reverse=True)
    if sorted_findings:
        lines.append("## Findings")
        lines.append("")
        lines.append("| OT Score | Severity | CVE | Asset | Vendor | Level | KEV |")
        lines.append("|----------|----------|-----|-------|--------|-------|-----|")
        for f in sorted_findings:
            kev_mark = "Yes" if f.in_kev else ""
            lines.append(
                f"| {f.ot_risk_score:.2f} | {f.ot_severity.value} | "
                f"[{f.cve.cve_id}]({f.cve.nvd_url}) | "
                f"{f.asset.name} | {f.asset.vendor} | "
                f"{f.asset.purdue_level} | {kev_mark} |"
            )
        lines.append("")

    # Top findings detail
    top = sorted_findings[:10]
    if top:
        lines.append("## Top Findings Detail")
        lines.append("")
        for f in top:
            kev_tag = " `KEV`" if f.in_kev else ""
            lines.append(f"### {f.cve.cve_id}{kev_tag}")
            lines.append("")
            lines.append(
                f"**Asset:** {f.asset.vendor} {f.asset.model} ({f.asset.name}) "
                f"— Level {f.asset.purdue_level} | {f.asset.network_zone} | {f.asset.exposure.value}"
            )
            lines.append(f"**OT Score:** {f.ot_risk_score:.2f} | "
                         f"**CVSS:** {f.cve.cvss_base_score} | "
                         f"**Severity:** {f.ot_severity.value}")
            desc = f.cve.description[:300]
            if len(f.cve.description) > 300:
                desc += "..."
            lines.append(f"\n> {desc}")
            if f.iec_62443_mappings:
                lines.append(f"\n**IEC 62443:** {', '.join(f.iec_62443_mappings)}")
            lines.append("")

    # Errors
    if result.errors:
        lines.append("## Scan Errors")
        lines.append("")
        for e in result.errors:
            lines.append(f"- {e}")
        lines.append("")

    lines.append("---")
    lines.append(f"*Generated by ICS Supply Chain Vulnerability Scanner*")

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    logger.info(f"Markdown report saved to {path}")
    return str(path)
