"""CISA Known Exploited Vulnerabilities (KEV) catalog client."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

import httpx

from config import CISAKEVConfig
from models import KEVEntry

logger = logging.getLogger(__name__)


class KEVClient:
    """Client for CISA's Known Exploited Vulnerabilities catalog."""

    def __init__(self, config: CISAKEVConfig):
        self.config = config
        self._catalog: dict[str, KEVEntry] = {}
        self._loaded = False

    async def load_catalog(self) -> None:
        """Load KEV catalog from cache or remote."""
        cached = self._load_from_cache()
        if cached:
            self._catalog = cached
            self._loaded = True
            logger.info(f"Loaded {len(self._catalog)} KEV entries from cache")
            return

        await self._fetch_remote()

    def _load_from_cache(self) -> dict[str, KEVEntry] | None:
        """Load catalog from local cache if fresh enough."""
        cache_path = Path(self.config.cache_path)
        if not cache_path.exists():
            return None

        cache_age = time.time() - cache_path.stat().st_mtime
        max_age = self.config.cache_ttl_hours * 3600
        if cache_age > max_age:
            logger.info("KEV cache expired, will refresh")
            return None

        try:
            with open(cache_path, encoding="utf-8") as f:
                data = json.load(f)
            return self._parse_catalog(data)
        except (json.JSONDecodeError, KeyError) as e:
            logger.warning(f"Invalid KEV cache: {e}")
            return None

    async def _fetch_remote(self) -> None:
        """Fetch KEV catalog from CISA."""
        logger.info("Fetching KEV catalog from CISA...")
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    self.config.catalog_url,
                    timeout=30,
                    follow_redirects=True,
                )
                response.raise_for_status()
                data = response.json()

            self._catalog = self._parse_catalog(data)
            self._loaded = True
            self._save_to_cache(data)
            logger.info(f"Loaded {len(self._catalog)} KEV entries from CISA")

        except httpx.HTTPError as e:
            logger.error(f"Failed to fetch KEV catalog: {e}")
            # Try loading stale cache as fallback
            cache_path = Path(self.config.cache_path)
            if cache_path.exists():
                logger.info("Using stale KEV cache as fallback")
                with open(cache_path, encoding="utf-8") as f:
                    data = json.load(f)
                self._catalog = self._parse_catalog(data)
                self._loaded = True

    def _save_to_cache(self, data: dict) -> None:
        """Save raw catalog to local cache."""
        cache_path = Path(self.config.cache_path)
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(data, f)
        logger.debug(f"KEV catalog cached at {cache_path}")

    @staticmethod
    def _parse_catalog(data: dict) -> dict[str, KEVEntry]:
        """Parse raw CISA KEV JSON into lookup dict."""
        catalog = {}
        vulnerabilities = data.get("vulnerabilities", [])
        for v in vulnerabilities:
            cve_id = v.get("cveID", "")
            if cve_id:
                catalog[cve_id] = KEVEntry(
                    cve_id=cve_id,
                    vendor=v.get("vendorProject", ""),
                    product=v.get("product", ""),
                    vulnerability_name=v.get("vulnerabilityName", ""),
                    date_added=v.get("dateAdded", ""),
                    due_date=v.get("dueDate", ""),
                    required_action=v.get("requiredAction", ""),
                    known_ransomware_use=v.get("knownRansomwareCampaignUse", "Unknown"),
                )
        return catalog

    def lookup(self, cve_id: str) -> KEVEntry | None:
        """Check if a CVE is in the KEV catalog."""
        if not self._loaded:
            logger.warning("KEV catalog not loaded. Call load_catalog() first.")
            return None
        return self._catalog.get(cve_id)

    def batch_lookup(self, cve_ids: list[str]) -> dict[str, KEVEntry]:
        """Check multiple CVEs against KEV catalog."""
        return {
            cve_id: entry
            for cve_id in cve_ids
            if (entry := self.lookup(cve_id)) is not None
        }

    @property
    def catalog_size(self) -> int:
        return len(self._catalog)

    @property
    def is_loaded(self) -> bool:
        return self._loaded
