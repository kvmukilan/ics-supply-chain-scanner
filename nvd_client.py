"""NVD CVE API v2 client for querying vulnerabilities by CPE.

Supports exact CPE match with automatic keywordSearch fallback
when exact match returns 0 results.
"""

from __future__ import annotations

import asyncio
import logging
import re

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


def _normalize(text: str) -> str:
    """Lower-case and drop everything but letters/digits ("ControlLogix 5580" -> "controllogix5580")."""
    return re.sub(r"[^a-z0-9]", "", text.lower())


def _version_tokens(version: str) -> tuple:
    """Split a version into comparable tokens, e.g. "7.0.5" -> ((1,7,''),(1,0,''),(1,5,'')).

    Numeric runs compare as integers (so 7.0.9 < 7.0.10), alphabetic runs as strings,
    and a numeric token always sorts above an alphabetic one at the same position (so a
    release sorts above its pre-releases). Handles mixed tokens like "7.0.5a".
    """
    tokens: list[tuple[int, int, str]] = []
    for chunk in re.split(r"[._\-+~]", version.strip()):
        for part in re.findall(r"\d+|[A-Za-z]+", chunk):
            if part.isdigit():
                tokens.append((1, int(part), ""))
            else:
                tokens.append((0, 0, part.lower()))
    return tuple(tokens)


def compare_versions(a: str, b: str) -> int:
    """Compare two dotted version strings numerically. Returns -1, 0, or 1."""
    ta, tb = _version_tokens(a), _version_tokens(b)
    return (ta > tb) - (ta < tb)


def build_keyword_query(product: str) -> str:
    """Build an NVD keywordSearch string for a CPE product.

    NVD ANDs every keyword against the CVE description. CPE vendor tokens are
    concatenated identifiers ("rockwellautomation", "schneiderelectric") that
    never appear in prose, and the "_firmware" suffix on firmware CPEs is
    rarely in the text either, so including them makes the fallback return
    nothing. Search on the product words alone and filter results afterwards.
    """
    return " ".join(w for w in product.split() if w.lower() != "firmware")


def build_keyword_queries(vendor: str, product: str) -> list[str]:
    """Keyword searches to try, most specific first.

    "<vendor> <product>" works when the vendor token is a real word ("siemens",
    "osisoft"); concatenated tokens ("rockwellautomation") never match, so fall
    back to the product words alone.
    """
    product_kw = build_keyword_query(product)
    queries = [f"{vendor} {product_kw}".strip(), product_kw]
    return [q for i, q in enumerate(queries) if q and q not in queries[:i]]


# Keyword search can match thousands of CVEs ("pi server"); don't page through them all.
KEYWORD_MAX_RESULTS = 100


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
        """Query NVD for CVEs affecting a CPE, version-checked client-side.

        Strategy: exact cpeName match first, then keywordSearch fallback if 0 results.
        Every returned CVE is version-checked against its NVD CPE applicability data
        (configurations). Right-product/wrong-version hits are dropped; matches that
        couldn't be version-verified are labelled match_method="keyword" (or an
        unverified "cpe") with version_checked=False so callers can treat them as
        "possible" rather than confirmed.
        """
        async with self._semaphore:
            vendor, product, version = parse_cpe_keywords(cpe_string)

            # Step 1: Exact CPE match (NVD resolves the CPE and its version ranges).
            cves = await self._paginated_query(
                client, {"cpeName": cpe_string, "resultsPerPage": 100}
            )

            if cves:
                cves = self._apply_version_matching(
                    cves, vendor, product, version, from_keyword=False
                )
                confirmed = sum(1 for c in cves if c.version_checked)
                logger.info(
                    f"Found {len(cves)} CVEs (exact CPE) for {cpe_string} "
                    f"[{confirmed} version-confirmed]"
                )
                return cves

            # Exact match returned nothing: the CPE could not be resolved against NVD's
            # dictionary (e.g. sample uses fortinet:fortigate_firmware but NVD indexes
            # fortinet:fortios). Warn and fall back to a broad keyword search — those hits
            # are "possible" unless applicability data lets us confirm the version.
            logger.warning(
                f"CPE not resolved in NVD dictionary: {cpe_string} "
                f"(exact cpeName match returned 0 results). Falling back to keyword search; "
                f"hits are reported as 'possible' unless CPE applicability confirms the version."
            )

            # Step 2: Fallback to keywordSearch
            if not (vendor and product):
                logger.info(f"Found 0 CVEs for {cpe_string} (no fallback keywords)")
                return []

            cves = []
            for keyword in build_keyword_queries(vendor, product):
                logger.info(f"Keyword fallback for {cpe_string}: '{keyword}'")
                await asyncio.sleep(self.rate_delay)
                cves = await self._paginated_query(
                    client,
                    {"keywordSearch": keyword, "resultsPerPage": 50},
                    max_results=KEYWORD_MAX_RESULTS,
                )
                if cves:
                    break

            cves = self._apply_version_matching(
                cves, vendor, product, version, from_keyword=True
            )
            confirmed = sum(1 for c in cves if c.version_checked)
            logger.info(
                f"Found {len(cves)} CVEs (keyword fallback) for {cpe_string} "
                f"[{confirmed} version-confirmed, {len(cves) - confirmed} possible]"
            )
            return cves

    async def _paginated_query(
        self, client: httpx.AsyncClient, base_params: dict, max_results: int | None = None
    ) -> list[CVEEntry]:
        """Run a paginated NVD query, stopping early once max_results CVEs are collected."""
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
                if max_results is not None and len(cves) >= max_results:
                    # Don't silently drop the rest: say so, since a version-relevant CVE
                    # could be beyond the cap and would then be missed.
                    search = base_params.get("keywordSearch") or base_params.get("cpeName") or "?"
                    logger.warning(
                        f"NVD results truncated at {max_results} of {total} for "
                        f"'{search}'; some affected versions may be missing from this scan."
                    )
                    break

                await asyncio.sleep(self.rate_delay)

            except Exception as e:
                logger.error(f"Error in NVD query: {e}")
                break

        return cves

    # Version applicability verdicts (see _version_verdict).
    VERSION_IN_RANGE = "in_range"
    VERSION_OUT_OF_RANGE = "out_of_range"
    VERSION_UNDETERMINED = "undetermined"

    def _apply_version_matching(
        self,
        cves: list[CVEEntry],
        vendor: str,
        product: str,
        version: str,
        *,
        from_keyword: bool,
    ) -> list[CVEEntry]:
        """Version-check candidate CVEs and annotate each with how it matched.

        - IN_RANGE  -> confirmed CPE-applicability match (match_method="cpe",
          version_checked=True).
        - OUT_OF_RANGE -> dropped: right product, but the asset's version is outside
          every vulnerable range (a version-blind false positive).
        - UNDETERMINED -> no usable applicability data. Kept as unverified:
          match_method="keyword" (keyword fallback, and only if the description names
          the product) or an unverified "cpe" (exact query with no configurations).
        """
        product_kw = build_keyword_query(product)
        kept: list[CVEEntry] = []
        dropped = 0

        for cve in cves:
            verdict = self._version_verdict(cve, vendor, product, version)
            if verdict == self.VERSION_IN_RANGE:
                cve.match_method = "cpe"
                cve.version_checked = True
                kept.append(cve)
            elif verdict == self.VERSION_OUT_OF_RANGE:
                dropped += 1
            elif from_keyword:
                # Tightened post-filter: require the PRODUCT token in the description.
                # A vendor-only mention is too loose and lets every product from a
                # vendor through, which is what inflated the false-positive count.
                if self._mentions_product(cve, product_kw):
                    cve.match_method = "keyword"
                    cve.version_checked = False
                    kept.append(cve)
            else:
                # Exact cpeName query associated this CVE with the CPE, but the response
                # carried no applicability data we could version-check client-side.
                cve.match_method = "cpe"
                cve.version_checked = False
                kept.append(cve)

        if dropped:
            logger.info(
                f"Dropped {dropped} version-irrelevant CVE(s) for {product_kw} {version} "
                f"(product matched but version out of range)."
            )
        return kept[:KEYWORD_MAX_RESULTS]

    @staticmethod
    def _mentions_product(cve: CVEEntry, product_kw: str) -> bool:
        """True if the CVE description names every token of the product keyword.

        Compared with spacing/punctuation removed so "ControlLogix 5580" in prose
        matches the "controllogix 5580" product token.
        """
        desc = _normalize(cve.description)
        words = [_normalize(w) for w in product_kw.split() if w.strip()]
        return bool(words) and all(w and w in desc for w in words)

    @classmethod
    def _version_verdict(
        cls, cve: CVEEntry, vendor: str, product: str, version: str
    ) -> str:
        """Decide whether `version` of vendor/product is affected, using CPE applicability.

        Walks the CVE's configurations[].nodes[].cpeMatch[] for entries whose criteria
        name the same product (and vendor, when both are known) and checks the asset's
        version against versionStart/End bounds (or an explicit version). Returns
        VERSION_IN_RANGE, VERSION_OUT_OF_RANGE, or VERSION_UNDETERMINED.
        """
        product_norm = _normalize(product)
        vendor_norm = _normalize(vendor)
        matched_product = False
        compared = False

        for match in cls._iter_cpe_matches(cve.configurations):
            if not match.get("vulnerable", False):
                continue
            c_vendor, c_product, c_version = parse_cpe_keywords(match.get("criteria", ""))
            if not product_norm or _normalize(c_product) != product_norm:
                continue
            c_vendor_norm = _normalize(c_vendor)
            if vendor_norm and c_vendor_norm and c_vendor_norm != vendor_norm:
                continue
            matched_product = True
            if not version:
                continue  # product matches but we have no asset version to compare

            explicit = c_version if c_version not in ("", "*", "-") else None
            if explicit is not None:
                compared = True
                if compare_versions(version, explicit) == 0:
                    return cls.VERSION_IN_RANGE
                continue

            start_incl = match.get("versionStartIncluding")
            start_excl = match.get("versionStartExcluding")
            end_incl = match.get("versionEndIncluding")
            end_excl = match.get("versionEndExcluding")
            if any(b is not None for b in (start_incl, start_excl, end_incl, end_excl)):
                compared = True
                if cls._version_in_bounds(version, start_incl, start_excl, end_incl, end_excl):
                    return cls.VERSION_IN_RANGE
            else:
                # Product matches with an unbounded "*" version: NVD marks every version
                # of this product vulnerable, so the asset is affected regardless.
                return cls.VERSION_IN_RANGE

        if matched_product and compared:
            return cls.VERSION_OUT_OF_RANGE
        return cls.VERSION_UNDETERMINED

    @staticmethod
    def _version_in_bounds(
        version: str,
        start_incl: str | None,
        start_excl: str | None,
        end_incl: str | None,
        end_excl: str | None,
    ) -> bool:
        """True if `version` falls within the (possibly open-ended) NVD version range."""
        if start_incl is not None and compare_versions(version, start_incl) < 0:
            return False
        if start_excl is not None and compare_versions(version, start_excl) <= 0:
            return False
        if end_incl is not None and compare_versions(version, end_incl) > 0:
            return False
        if end_excl is not None and compare_versions(version, end_excl) >= 0:
            return False
        return True

    @staticmethod
    def _iter_cpe_matches(configurations: list):
        """Yield every cpeMatch dict in an NVD 2.0 configurations tree (incl. children)."""
        def walk(node: dict):
            yield from node.get("cpeMatch", [])
            for child in node.get("children", []):
                yield from walk(child)

        for config in configurations or []:
            for node in config.get("nodes", []):
                yield from walk(node)

    @staticmethod
    def _filter_by_version_relevance(
        cves: list[CVEEntry], vendor: str, product: str, version: str
    ) -> list[CVEEntry]:
        """Keyword post-filter: keep only CVEs whose description names the PRODUCT.

        This used to keep any CVE that mentioned the vendor OR the product, so a
        vendor-only mention let every product from that vendor through — the loose
        filter behind the false positives. It now requires the product token; real
        version checking happens in query_cpes via CPE applicability (_version_verdict).
        """
        product_kw = build_keyword_query(product)
        return [cve for cve in cves if NVDClient._mentions_product(cve, product_kw)][:50]

    async def _request_with_retry(
        self, client: httpx.AsyncClient, params: dict
    ) -> httpx.Response | None:
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
    def _parse_cve(vuln_data: dict) -> CVEEntry | None:
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

            # Extract CWE IDs. NVD often lists the same CWE twice (Primary from NVD,
            # Secondary from the CNA), so de-duplicate while keeping order.
            weaknesses = []
            for weakness in cve_data.get("weaknesses", []):
                for desc in weakness.get("description", []):
                    value = desc.get("value", "")
                    if value.startswith("CWE-") and value not in weaknesses:
                        weaknesses.append(value)

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
                # Keep NVD 2.0 CPE applicability so matches can be version-checked.
                configurations=cve_data.get("configurations", []),
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
