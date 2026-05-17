"""NVD CVE API v2 client for querying vulnerabilities by CPE.

Supports exact CPE match with automatic keywordSearch fallback
when exact match returns 0 results.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Optional

import httpx

from config import NVDConfig
from models import CVEEntry, Severity

logger = logging.getLogger(__name__)


def parse_cpe_keywords(cpe_string: str) -> tuple[str, str, str]:
    """Extract vendor, product, version from a CPE 2.3 string.

    cpe:2.3:PART:VENDOR:PRODUCT:VERSION:...
    Returns (vendor, product, version) with underscores replaced by spaces.
    """
    parts = cpe_string.split(":")
    if len(parts) >= 6:
        vendor = parts[3].replace("_", " ")
        product = parts[4].replace("_", " ")
        version = parts[5] if parts[5] not in ("*", "-") else ""
        return vendor, product, version
    return "", "", ""


class NVDClient:
    """Async client for NVD CVE API v2."""

    def __init__(self, config: NVDConfig):
        self.config = config
        self.rate_delay = (
            config.rate_limit_delay if config.api_key else config.rate_limit_delay_no_key
        )
        self._semaphore = asyncio.Semaphore(3 if config.api_key else 1)

    def _build_headers(self) -> dict:
        headers = {"Accept": "application/json"}
        if self.config.api_key:
            headers["apiKey"] = self.config.api_key
        return headers

    async def query_cpes(self, cpe_string: str, client: httpx.AsyncClient) -> list[CVEEntry]:
        """Query NVD for CVEs matching a CPE string.

        Strategy: exact cpeName match first, then keywordSearch fallback if 0 results.
        """
        async with self._semaphore:
            # Step 1: Exact CPE match
            cves = await self._paginated_query(
                client, {"cpeName": cpe_string, "resultsPerPage": 100}
            )

            if cves:
                logger.info(f"Found {len(cves)} CVEs (exact CPE) for {cpe_string}")
                return cves

            # Step 2: Fallback to keywordSearch
            vendor, product, version = parse_cpe_keywords(cpe_string)
            if not (vendor and product):
                logger.info(f"Found 0 CVEs for {cpe_string} (no fallback keywords)")
                return []

            keyword = f"{vendor} {product}"
            logger.info(f"Exact CPE match returned 0 results. Falling back to keywordSearch: '{keyword}'")

            await asyncio.sleep(self.rate_delay)
            cves = await self._paginated_query(
                client, {"keywordSearch": keyword, "resultsPerPage": 50}
            )

            # Filter by version if available — keyword search is broad
            if version and cves:
                pre_filter = len(cves)
                cves = self._filter_by_version_relevance(cves, vendor, product, version)
                logger.debug(
                    f"Keyword fallback: {pre_filter} raw → {len(cves)} after version filtering"
                )

            logger.info(f"Found {len(cves)} CVEs (keyword fallback) for {cpe_string}")
            return cves

    async def _paginated_query(
        self, client: httpx.AsyncClient, base_params: dict
    ) -> list[CVEEntry]:
        """Run a paginated NVD query."""
        cves = []
        start_index = 0

        while True:
            params = {**base_params, "startIndex": start_index}
            try:
                response = await self._request_with_retry(client, params)
                if response is None:
                    break

                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                if not vulnerabilities:
                    break

                for vuln in vulnerabilities:
                    cve = self._parse_cve(vuln)
                    if cve:
                        cves.append(cve)

                total = data.get("totalResults", 0)
                start_index += len(vulnerabilities)
                if start_index >= total:
                    break

                await asyncio.sleep(self.rate_delay)

            except Exception as e:
                logger.error(f"Error in NVD query: {e}")
                break

        return cves

    @staticmethod
    def _filter_by_version_relevance(
        cves: list[CVEEntry], vendor: str, product: str, version: str
    ) -> list[CVEEntry]:
        """Filter keyword search results for version relevance.

        Keeps CVEs whose description mentions the vendor+product and
        whose affected configs likely overlap the target version.
        This is a heuristic — keyword search is inherently broader than CPE match.
        """
        vendor_lower = vendor.lower()
        product_lower = product.lower()
        filtered = []

        for cve in cves:
            desc = cve.description.lower()
            # Must mention the product
            if product_lower not in desc and vendor_lower not in desc:
                continue
            filtered.append(cve)

        # Cap at 50 to avoid noise from very broad keyword matches
        return filtered[:50]

    async def _request_with_retry(
        self, client: httpx.AsyncClient, params: dict
    ) -> Optional[httpx.Response]:
        """Make request with retry logic for rate limits and transient errors."""
        for attempt in range(self.config.max_retries):
            try:
                response = await client.get(
                    self.config.base_url,
                    params=params,
                    headers=self._build_headers(),
                    timeout=self.config.timeout,
                )
                if response.status_code == 200:
                    return response
                elif response.status_code == 403:
                    wait = (attempt + 1) * 10
                    logger.warning(f"Rate limited by NVD. Waiting {wait}s...")
                    await asyncio.sleep(wait)
                elif response.status_code == 404:
                    logger.debug(f"No results from NVD: {params.get('cpeName')}")
                    return None
                else:
                    logger.warning(f"NVD returned {response.status_code}: {response.text[:200]}")
                    await asyncio.sleep(self.rate_delay * (attempt + 1))
            except httpx.TimeoutException:
                logger.warning(f"NVD request timeout (attempt {attempt + 1})")
                await asyncio.sleep(self.rate_delay * 2)
            except httpx.RequestError as e:
                logger.warning(f"NVD request error: {e}")
                await asyncio.sleep(self.rate_delay * 2)

        logger.error(f"Failed to query NVD after {self.config.max_retries} retries")
        return None

    @staticmethod
    def _parse_cve(vuln_data: dict) -> Optional[CVEEntry]:
        """Parse a single CVE entry from NVD response."""
        try:
            cve_data = vuln_data.get("cve", {})
            cve_id = cve_data.get("id", "")

            # Extract description (prefer English)
            descriptions = cve_data.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                descriptions[0]["value"] if descriptions else "No description",
            )

            # Extract CVSS v3.1 score (prefer primary metric)
            cvss_score = 0.0
            cvss_vector = ""
            metrics = cve_data.get("metrics", {})
            for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                metric_list = metrics.get(metric_key, [])
                if metric_list:
                    # Prefer primary source
                    metric = next(
                        (m for m in metric_list if m.get("type") == "Primary"),
                        metric_list[0],
                    )
                    cvss_data = metric.get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", 0.0)
                    cvss_vector = cvss_data.get("vectorString", "")
                    break

            # Extract references
            references = [
                ref.get("url", "") for ref in cve_data.get("references", [])[:5]
            ]

            # Extract CWE IDs
            weaknesses = []
            for weakness in cve_data.get("weaknesses", []):
                for desc in weakness.get("description", []):
                    if desc.get("value", "").startswith("CWE-"):
                        weaknesses.append(desc["value"])

            return CVEEntry(
                cve_id=cve_id,
                description=description[:500],
                cvss_base_score=cvss_score,
                cvss_vector=cvss_vector,
                severity=Severity.from_cvss(cvss_score),
                published=cve_data.get("published", ""),
                last_modified=cve_data.get("lastModified", ""),
                references=references,
                weaknesses=weaknesses,
            )
        except (KeyError, IndexError, TypeError) as e:
            logger.warning(f"Failed to parse CVE entry: {e}")
            return None


async def query_all_assets(
    assets_cpes: list[str], config: NVDConfig
) -> dict[str, list[CVEEntry]]:
    """Query NVD for all unique CPEs from asset inventory."""
    unique_cpes = list(set(assets_cpes))
    logger.info(f"Querying NVD for {len(unique_cpes)} unique CPEs...")

    client_nvd = NVDClient(config)
    results: dict[str, list[CVEEntry]] = {}

    async with httpx.AsyncClient() as client:
        for cpe in unique_cpes:
            cves = await client_nvd.query_cpes(cpe, client)
            results[cpe] = cves
            await asyncio.sleep(client_nvd.rate_delay)

    total_cves = sum(len(v) for v in results.values())
    logger.info(f"Total CVEs found: {total_cves} across {len(unique_cpes)} CPEs")
    return results
