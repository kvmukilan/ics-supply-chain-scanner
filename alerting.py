"""Webhook alerting for critical scan findings.

Sends notifications to Slack, Microsoft Teams, or generic webhook
endpoints when scan results contain critical findings or KEV hits.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

import httpx

from models import Finding, ScanResult

logger = logging.getLogger(__name__)


@dataclass
class AlertRule:
    """Defines when to fire an alert."""
    min_ot_score: float = 8.5
    severities: list[str] = field(default_factory=lambda: ["CRITICAL"])
    kev_only: bool = False
    max_alerts_per_scan: int = 20


@dataclass
class WebhookConfig:
    """Webhook destination configuration."""
    url: str
    webhook_type: str = "generic"  # "slack", "teams", "generic"
    headers: dict = field(default_factory=dict)
    enabled: bool = True


def filter_alertable_findings(
    findings: list[Finding], rule: AlertRule
) -> list[Finding]:
    """Filter findings that match the alert rule."""
    matched = []
    for f in findings:
        if rule.kev_only and not f.in_kev:
            continue
        if f.ot_risk_score < rule.min_ot_score and f.ot_severity.value not in rule.severities:
            continue
        if f.ot_risk_score >= rule.min_ot_score or f.ot_severity.value in rule.severities:
            matched.append(f)

    matched.sort(key=lambda x: x.ot_risk_score, reverse=True)
    return matched[:rule.max_alerts_per_scan]


def build_alert_payload(
    result: ScanResult,
    findings: list[Finding],
    webhook_type: str = "generic",
) -> dict:
    """Build the webhook payload for alertable findings."""
    if webhook_type == "slack":
        return _build_slack_payload(result, findings)
    elif webhook_type == "teams":
        return _build_teams_payload(result, findings)
    return _build_generic_payload(result, findings)


def _build_generic_payload(result: ScanResult, findings: list[Finding]) -> dict:
    """Generic JSON payload."""
    return {
        "scan_id": result.scan_id,
        "timestamp": result.timestamp,
        "total_assets": result.total_assets,
        "alert_count": len(findings),
        "alerts": [
            {
                "finding_id": f.finding_id,
                "cve_id": f.cve.cve_id,
                "asset": f.asset.name,
                "vendor": f.asset.vendor,
                "ot_risk_score": round(f.ot_risk_score, 2),
                "severity": f.ot_severity.value,
                "in_kev": f.in_kev,
                "purdue_level": f.asset.purdue_level,
                "description": f.cve.description[:200],
            }
            for f in findings
        ],
    }


def _build_slack_payload(result: ScanResult, findings: list[Finding]) -> dict:
    """Slack Block Kit payload."""
    kev_count = sum(1 for f in findings if f.in_kev)

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"ICS Scan Alert: {len(findings)} Critical Finding(s)",
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Scan ID:*\n{result.scan_id}"},
                {"type": "mrkdwn", "text": f"*Assets:*\n{result.total_assets}"},
                {"type": "mrkdwn", "text": f"*Alerts:*\n{len(findings)}"},
                {"type": "mrkdwn", "text": f"*KEV Hits:*\n{kev_count}"},
            ],
        },
        {"type": "divider"},
    ]

    for f in findings[:10]:
        kev_tag = " :rotating_light: *KEV*" if f.in_kev else ""
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*<{f.cve.nvd_url}|{f.cve.cve_id}>*{kev_tag}\n"
                    f"Asset: {f.asset.vendor} {f.asset.model} ({f.asset.name}) "
                    f"| L{f.asset.purdue_level}\n"
                    f"OT Score: *{f.ot_risk_score:.1f}* | CVSS: {f.cve.cvss_base_score}\n"
                    f"{f.cve.description[:150]}"
                ),
            },
        })

    return {"blocks": blocks}


def _build_teams_payload(result: ScanResult, findings: list[Finding]) -> dict:
    """Microsoft Teams Adaptive Card payload."""
    kev_count = sum(1 for f in findings if f.in_kev)

    facts = [
        {"name": "Scan ID", "value": result.scan_id},
        {"name": "Assets Scanned", "value": str(result.total_assets)},
        {"name": "Critical Alerts", "value": str(len(findings))},
        {"name": "KEV Hits", "value": str(kev_count)},
    ]

    finding_rows = ""
    for f in findings[:10]:
        kev_flag = " [KEV]" if f.in_kev else ""
        finding_rows += (
            f"- **{f.cve.cve_id}**{kev_flag} | "
            f"{f.asset.name} | Score: {f.ot_risk_score:.1f}\n"
        )

    return {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": "dc2626",
        "summary": f"ICS Scan Alert: {len(findings)} critical findings",
        "sections": [
            {
                "activityTitle": f"ICS Scan Alert: {len(findings)} Critical Finding(s)",
                "facts": facts,
                "markdown": True,
                "text": finding_rows,
            }
        ],
    }


async def send_alert(
    result: ScanResult,
    webhook: WebhookConfig,
    rule: AlertRule | None = None,
) -> bool:
    """Filter findings by rule, build payload, and POST to webhook.

    Returns True if the alert was sent successfully.
    """
    if not webhook.enabled or not webhook.url:
        logger.debug("Webhook disabled or no URL configured")
        return False

    rule = rule or AlertRule()
    alertable = filter_alertable_findings(result.findings, rule)

    if not alertable:
        logger.info("No findings match alert rule — skipping webhook")
        return False

    payload = build_alert_payload(result, alertable, webhook.webhook_type)

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                webhook.url,
                json=payload,
                headers={"Content-Type": "application/json", **webhook.headers},
                timeout=15,
            )
            response.raise_for_status()
            logger.info(
                f"Alert sent to {webhook.webhook_type} webhook: "
                f"{len(alertable)} findings, status {response.status_code}"
            )
            return True

    except httpx.HTTPError as e:
        logger.error(f"Failed to send alert to {webhook.url}: {e}")
        return False
