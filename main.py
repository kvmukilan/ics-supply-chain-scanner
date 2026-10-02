"""CLI entry point for ICS Supply Chain Vulnerability Scanner."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from pathlib import Path

from config import ScannerConfig
from scanner import ICSScanner


def setup_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="ICS Supply Chain Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -i inventory.csv
  %(prog)s -i inventory.json -o reports/ --log-level DEBUG
  %(prog)s -i assets.csv --no-llm --sarif
  %(prog)s -i bom.json --diff output/SCAN-prev_report.json
  %(prog)s -i assets.csv --webhook https://hooks.slack.com/... --webhook-type slack
        """,
    )
    parser.add_argument(
        "-i", "--inventory",
        required=True,
        help="Path to asset inventory file (CSV, JSON, or SBOM CycloneDX/SPDX JSON)",
    )
    parser.add_argument(
        "-o", "--output",
        default="output",
        help="Output directory for reports (default: output)",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level (default: INFO)",
    )
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Skip LLM remediation, use template-based fallback",
    )
    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Only generate JSON report (skip HTML, CSV, SARIF)",
    )
    parser.add_argument(
        "--csv",
        action="store_true",
        help="Also generate CSV report for spreadsheet analysis",
    )
    parser.add_argument(
        "--sarif",
        action="store_true",
        help="Generate SARIF report for GitHub Code Scanning / Azure DevOps",
    )
    parser.add_argument(
        "--markdown",
        action="store_true",
        help="Generate Markdown report for GitHub/GitLab wiki or PR descriptions",
    )
    parser.add_argument(
        "--diff",
        metavar="BASELINE_JSON",
        help="Path to a previous JSON report to diff against (shows new/resolved findings)",
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Validate inventory file and CPE strings without running a scan",
    )
    parser.add_argument(
        "--gate",
        action="store_true",
        help="Run quality gate check; exit 2 if policy violations found (for CI/CD)",
    )
    parser.add_argument(
        "--gate-max-critical",
        type=int,
        default=0,
        help="Quality gate: max allowed critical findings (default: 0)",
    )
    parser.add_argument(
        "--gate-max-kev",
        type=int,
        default=0,
        help="Quality gate: max allowed KEV findings (default: 0)",
    )
    parser.add_argument(
        "--gate-include-possible",
        action="store_true",
        help="Quality gate: also gate on unverified 'possible' (keyword) findings "
        "(default: off — only version-confirmed findings count toward the gate)",
    )
    parser.add_argument(
        "--webhook",
        metavar="URL",
        default=os.getenv("ALERT_WEBHOOK_URL", ""),
        help="Webhook URL for critical finding alerts (env: ALERT_WEBHOOK_URL)",
    )
    parser.add_argument(
        "--webhook-type",
        choices=["slack", "teams", "generic"],
        default=os.getenv("ALERT_WEBHOOK_TYPE", "generic"),
        help="Webhook format: slack, teams, or generic (default: generic)",
    )
    return parser.parse_args()


async def main() -> int:
    args = parse_args()
    setup_logging(args.log_level)

    logger = logging.getLogger("main")
    logger.info("ICS Supply Chain Vulnerability Scanner v1.0")

    # Validate inventory file
    inventory_path = Path(args.inventory)
    if not inventory_path.exists():
        logger.error(f"Inventory file not found: {inventory_path}")
        return 1

    # Build config
    config = ScannerConfig()
    config.output_dir = args.output
    config.log_level = args.log_level

    if args.no_llm:
        config.llm.endpoint = ""
        config.llm.api_key = ""

    # Validate-only mode
    if args.validate:
        return _validate_inventory(str(inventory_path), logger)

    # Run scan
    scanner = ICSScanner(config)
    result = await scanner.scan(str(inventory_path))

    # Generate reports
    from datetime import datetime, timezone

    from report import (
        generate_csv_report,
        generate_html_report,
        generate_json_report,
        generate_markdown_report,
    )

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    prefix = f"{args.output}/{result.scan_id}_{timestamp}"
    Path(args.output).mkdir(parents=True, exist_ok=True)

    json_path = generate_json_report(result, f"{prefix}_report.json")
    logger.info(f"JSON report: {json_path}")

    if not args.json_only:
        html_path = generate_html_report(result, f"{prefix}_report.html")
        logger.info(f"HTML report: {html_path}")

    if args.csv or not args.json_only:
        csv_path = generate_csv_report(result, f"{prefix}_report.csv")
        logger.info(f"CSV report: {csv_path}")

    if args.sarif or not args.json_only:
        from sarif_export import generate_sarif_report
        sarif_path = generate_sarif_report(result, f"{prefix}_report.sarif")
        logger.info(f"SARIF report: {sarif_path}")

    if args.markdown:
        md_path = generate_markdown_report(result, f"{prefix}_report.md")
        logger.info(f"Markdown report: {md_path}")

    # Diff against baseline
    if args.diff:
        _run_diff(args.diff, result, logger)

    # Webhook alerting
    if args.webhook:
        await _send_webhook_alert(args.webhook, args.webhook_type, result, logger)

    # Risk timeline snapshot
    if result.findings:
        from risk_timeline import capture_snapshot, save_snapshot
        posture = ""
        if result.findings:
            from compliance import assess_compliance as _assess
            posture = _assess(result).overall_posture
        snap = capture_snapshot(result, compliance_posture=posture)
        save_snapshot(snap)

    # Quality gate
    gate_exit = 0
    if args.gate:
        from quality_gate import GatePolicy
        from quality_gate import evaluate as gate_evaluate
        gate_policy = GatePolicy(
            max_critical=args.gate_max_critical,
            max_kev=args.gate_max_kev,
        )
        posture_str = ""
        if result.findings:
            from compliance import assess_compliance as _assess_comp
            posture_str = _assess_comp(result).overall_posture
        gate_result = gate_evaluate(
            result,
            gate_policy,
            compliance_posture=posture_str,
            include_possible=args.gate_include_possible,
        )
        if not gate_result.passed:
            logger.warning(f"Quality gate FAILED: {gate_result.summary}")
            gate_exit = 2

    # Print summary
    summary = result.summary()
    print("\n" + "=" * 60)
    print(f"SCAN COMPLETE: {result.scan_id}")
    print("=" * 60)
    print(f"Assets scanned:  {summary['total_assets']}")
    print(f"Findings found:  {summary['total_cves_found']}")
    print(f"  Confirmed:     {summary['confirmed_findings']} (CPE applicability, version-checked)")
    print(f"  Possible:      {summary['possible_findings']} (keyword/unverified — version unconfirmed)")
    print(f"CISA KEV hits:   {summary['kev_matches']} ({summary['kev_matches_confirmed']} confirmed)")
    print(f"Severity dist:   {json.dumps(summary['severity_distribution'])}")
    if summary["top_risk_findings"]:
        print("\nTop findings by OT Risk Score:")
        for f in summary["top_risk_findings"][:5]:
            kev_flag = " [KEV]" if f["in_kev"] else ""
            print(f"  {f['ot_risk_score']:6.2f}  {f['cve']}{kev_flag}  ->  {f['asset']}")
    if result.errors:
        print(f"\nWarnings/Errors: {len(result.errors)}")

    # IEC 62443 compliance posture
    if result.findings:
        from compliance import assess_compliance
        compliance = assess_compliance(result)
        posture_icon = {"compliant": "[OK]", "at_risk": "[!!]", "non_compliant": "[XX]"}
        icon = posture_icon.get(compliance.overall_posture, "?")
        print(f"\nIEC 62443 Posture: {icon} {compliance.overall_posture.upper()}")
        failing = [fr for fr, s in compliance.fr_scores.items() if s.status == "fail"]
        at_risk = [fr for fr, s in compliance.fr_scores.items() if s.status == "at_risk"]
        if failing:
            print(f"  FAIL:    {', '.join(failing)}")
        if at_risk:
            print(f"  AT RISK: {', '.join(at_risk)}")

    # Quality gate result
    if args.gate:
        if gate_result.passed:
            print("\nQuality Gate: PASSED")
        else:
            print("\nQuality Gate: FAILED")
            for v in gate_result.violations:
                print(f"  VIOLATION: {v.message}")
        for w in gate_result.warnings:
            print(f"  NOTE: {w}")

    print("=" * 60)

    return gate_exit if args.gate else 0


def _validate_inventory(inventory_path: str, logger) -> int:
    """Validate inventory file format, CPEs, and Purdue levels without scanning."""
    from inventory import load_inventory
    from validators import validate_cpe, validate_purdue_level

    try:
        assets = load_inventory(inventory_path)
    except (FileNotFoundError, ValueError) as e:
        print(f"INVALID: {e}")
        return 1

    errors = 0
    warnings = 0

    print(f"\nValidating {len(assets)} assets from {inventory_path}")
    print("-" * 50)

    for asset in assets:
        cpe_ok, cpe_err = validate_cpe(asset.cpe)
        if not cpe_ok:
            print(f"  ERROR  {asset.name}: CPE — {cpe_err}")
            errors += 1

        pl_ok, pl_err = validate_purdue_level(asset.purdue_level)
        if not pl_ok:
            print(f"  WARN   {asset.name}: {pl_err}")
            warnings += 1

        if not asset.vendor.strip():
            print(f"  WARN   {asset.name}: empty vendor field")
            warnings += 1

        if not asset.firmware_version.strip():
            print(f"  WARN   {asset.name}: empty firmware version")
            warnings += 1

    print("-" * 50)
    if errors == 0 and warnings == 0:
        print(f"VALID: {len(assets)} assets, no issues found")
    else:
        print(f"Done: {len(assets)} assets, {errors} error(s), {warnings} warning(s)")

    return 1 if errors > 0 else 0


def _run_diff(baseline_path: str, current_result, logger) -> None:
    """Compare current scan against a previous JSON report."""
    from scan_diff import compare_scans, load_report

    baseline_file = Path(baseline_path)
    if not baseline_file.exists():
        logger.warning(f"Diff baseline not found: {baseline_file}")
        return

    try:
        baseline = load_report(baseline_file)
        diff = compare_scans(baseline, current_result)
        summary = diff.summary()

        print(f"\n{'─' * 60}")
        print(f"DIFF vs {baseline.scan_id}")
        print(f"{'─' * 60}")
        print(f"  New findings:      {summary['new_findings']}")
        print(f"  Resolved findings: {summary['resolved_findings']}")
        print(f"  Score changes:     {summary['score_changes']}")
        print(f"  Unchanged:         {summary['unchanged']}")
        if summary["new_critical"] > 0:
            print(f"  !! New CRITICAL:   {summary['new_critical']}")
        if summary["new_kev"] > 0:
            print(f"  !! New KEV hits:   {summary['new_kev']}")

        if diff.new_findings:
            print("\n  New findings:")
            for d in diff.new_findings[:5]:
                kev = " [KEV]" if d.in_kev else ""
                print(f"    + {d.cve_id}{kev}  {d.new_severity}  {d.new_ot_score}  {d.asset_name}")

        if diff.resolved_findings:
            print("\n  Resolved:")
            for d in diff.resolved_findings[:5]:
                print(f"    - {d.cve_id}  {d.asset_name}")

        print(f"{'─' * 60}")

    except (json.JSONDecodeError, KeyError, ValueError) as e:
        logger.error(f"Failed to parse baseline for diff: {e}")


async def _send_webhook_alert(url: str, webhook_type: str, result, logger) -> None:
    """Send webhook alert for critical findings."""
    from alerting import AlertRule, WebhookConfig, send_alert

    webhook = WebhookConfig(url=url, webhook_type=webhook_type)
    rule = AlertRule()

    sent = await send_alert(result, webhook, rule)
    if sent:
        logger.info(f"Alert sent to {webhook_type} webhook")
    else:
        logger.debug("No alert sent (no critical findings or webhook failed)")


def cli() -> None:
    sys.exit(asyncio.run(main()))


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
