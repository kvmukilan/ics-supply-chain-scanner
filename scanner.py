"""Main scanner orchestrator.

Coordinates the full pipeline:
Inventory → NVD Query → KEV Cross-Reference → OT Risk Scoring → LLM Remediation → Report
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone

from config import ScannerConfig
from inventory import load_inventory
from kev_client import KEVClient
from models import Asset, Finding, ScanResult
from nvd_client import NVDClient, query_all_assets
from remediation import RemediationGenerator
from report import generate_html_report, generate_json_report
from risk_scorer import OTRiskScorer

logger = logging.getLogger(__name__)


class ICSScanner:
    """ICS Supply Chain Vulnerability Scanner."""

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.nvd_client = NVDClient(config.nvd)
        self.kev_client = KEVClient(config.kev)
        self.risk_scorer = OTRiskScorer(config.risk)
        self.remediation_gen = RemediationGenerator(config.llm)

    async def scan(self, inventory_path: str) -> ScanResult:
        """Run the full vulnerability scan pipeline."""
        scan_id = f"SCAN-{uuid.uuid4().hex[:8].upper()}"
        logger.info(f"Starting scan {scan_id}")

        result = ScanResult(scan_id=scan_id)

        # Step 1: Load asset inventory
        logger.info("Step 1/5: Loading asset inventory...")
        try:
            assets = load_inventory(inventory_path)
            result.total_assets = len(assets)
            logger.info(f"Loaded {len(assets)} assets")
        except Exception as e:
            logger.error(f"Failed to load inventory: {e}")
            result.errors.append(f"Inventory load failed: {e}")
            return result

        if not assets:
            logger.warning("No assets in inventory")
            return result

        # Step 2: Query NVD for CVEs
        logger.info("Step 2/5: Querying NVD for CVEs...")
        cpe_list = [a.cpe for a in assets]
        try:
            cve_results = await query_all_assets(cpe_list, self.config.nvd)
        except Exception as e:
            logger.error(f"NVD query failed: {e}")
            result.errors.append(f"NVD query failed: {e}")
            cve_results = {}

        # Step 3: Load and cross-reference CISA KEV
        logger.info("Step 3/5: Cross-referencing CISA KEV catalog...")
        try:
            await self.kev_client.load_catalog()
            logger.info(f"KEV catalog: {self.kev_client.catalog_size} entries")
        except Exception as e:
            logger.error(f"KEV load failed: {e}")
            result.errors.append(f"KEV load failed: {e}")

        # Step 4: Build findings and score
        logger.info("Step 4/5: Calculating OT risk scores...")
        findings: list[Finding] = []
        for asset in assets:
            asset_cves = cve_results.get(asset.cpe, [])
            for cve in asset_cves:
                kev_entry = self.kev_client.lookup(cve.cve_id)
                finding = Finding(
                    asset=asset,
                    cve=cve,
                    in_kev=kev_entry is not None,
                    kev_entry=kev_entry,
                )
                self.risk_scorer.score_finding(finding)
                findings.append(finding)

        result.findings = findings
        result.total_cves = len(findings)
        result.total_kev_hits = sum(1 for f in findings if f.in_kev)

        logger.info(
            f"Scored {len(findings)} findings "
            f"({result.total_kev_hits} in KEV)"
        )

        # Step 5: Generate remediation
        logger.info("Step 5/5: Generating remediation playbooks...")
        try:
            result.findings = await self.remediation_gen.generate_batch(
                findings,
                max_concurrent=self.config.max_concurrent_queries,
            )
        except Exception as e:
            logger.error(f"Remediation generation failed: {e}")
            result.errors.append(f"Remediation generation error: {e}")

        logger.info(f"Scan {scan_id} complete: {len(findings)} findings across {len(assets)} assets")
        return result

    def generate_reports(self, result: ScanResult, output_dir: str = None) -> dict[str, str]:
        """Generate JSON and HTML reports."""
        output_dir = output_dir or self.config.output_dir
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        prefix = f"{output_dir}/{result.scan_id}_{timestamp}"

        paths = {}
        paths["json"] = generate_json_report(result, f"{prefix}_report.json")
        paths["html"] = generate_html_report(result, f"{prefix}_report.html")

        return paths


async def run_scan(inventory_path: str, config: ScannerConfig = None) -> ScanResult:
    """Convenience function to run a scan."""
    config = config or ScannerConfig()
    scanner = ICSScanner(config)
    result = await scanner.scan(inventory_path)
    scanner.generate_reports(result)
    return result
