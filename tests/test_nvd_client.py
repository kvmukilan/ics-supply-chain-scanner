"""NVD CVE API 2.0 client, against recorded NVD responses."""

from __future__ import annotations

import httpx
import pytest
from conftest import load_fixture

import nvd_client
from config import NVDConfig
from models import Severity
from nvd_client import NVDClient, build_keyword_query, parse_cpe_keywords, query_all_assets

CONTROLLOGIX_CPE = "cpe:2.3:o:rockwellautomation:controllogix_5580_firmware:33.011:*:*:*:*:*:*:*"


@pytest.fixture
def nvd_config() -> NVDConfig:
    return NVDConfig(api_key="", rate_limit_delay=0.0, rate_limit_delay_no_key=0.0)


@pytest.fixture
def no_sleep(monkeypatch):
    slept: list[float] = []

    async def fake_sleep(seconds):
        slept.append(seconds)

    monkeypatch.setattr(nvd_client.asyncio, "sleep", fake_sleep)
    return slept


def parse(fixture: str, index: int = 0):
    return NVDClient._parse_cve(load_fixture(fixture)["vulnerabilities"][index])


def test_parse_prefers_nvd_primary_cvss_over_cna_secondary():
    # CVE-2022-1161: CNA (Secondary) scored 10.0, NVD (Primary) scored 9.8
    cves = {c.cve_id: c for c in (NVDClient._parse_cve(v) for v in
                                  load_fixture("nvd_cpe_controllogix_5580.json")["vulnerabilities"])}

    cve = cves["CVE-2022-1161"]
    assert cve.cvss_base_score == 9.8
    assert cve.cvss_vector.startswith("CVSS:3.1/")
    assert cve.severity is Severity.CRITICAL
    assert cve.weaknesses == ["CWE-829"]
    assert cve.nvd_url == "https://nvd.nist.gov/vuln/detail/CVE-2022-1161"
    # Primary is preferred even when it's the lower of the two (7.2 vs CNA's 7.7)
    assert cves["CVE-2022-1159"].cvss_base_score == 7.2


def test_parse_deduplicates_cwes_listed_by_both_nvd_and_cna():
    # Regression: NVD lists CWE-352 twice for CVE-2017-7926 (Primary + Secondary); we
    # used to keep both, double-counting the finding in ATT&CK/IEC 62443 mappings.
    cve = parse("nvd_cve_2017_7926.json")

    assert cve.weaknesses == ["CWE-352"]
    assert cve.cvss_vector.startswith("CVSS:3.0/")  # v3.0 used when v3.1 is absent


def test_parse_falls_back_to_cvss_v2_and_drops_non_cwe_placeholders():
    cve = parse("nvd_cve_2014_2251.json")

    assert cve.cve_id == "CVE-2014-2251"
    assert cve.cvss_base_score == 8.3
    assert "/" in cve.cvss_vector and not cve.cvss_vector.startswith("CVSS:3")
    assert cve.weaknesses == []  # "NVD-CWE-Other" is not a CWE id
    assert cve.description.startswith("The random-number generator on Siemens SIMATIC S7-1500")


def test_parse_caps_description_and_references():
    cve = parse("nvd_cve_2021_22681.json")

    assert len(cve.description) <= 500
    assert 0 < len(cve.references) <= 5
    assert cve.weaknesses == ["CWE-522"]


def test_parse_cpe_keywords():
    assert parse_cpe_keywords(CONTROLLOGIX_CPE) == (
        "rockwellautomation", "controllogix 5580 firmware", "33.011")
    assert parse_cpe_keywords("cpe:2.3:a:osisoft:pi_server:*:*:*:*:*:*:*:*") == ("osisoft", "pi server", "")
    assert parse_cpe_keywords("cpe:2.3:a") == ("", "", "")


def test_keyword_query_drops_firmware_suffix():
    assert build_keyword_query("controllogix 5580 firmware") == "controllogix 5580"
    assert build_keyword_query("pi server") == "pi server"


async def test_exact_cpe_match_is_used_when_nvd_has_results(fake_api, nvd_config):
    fake_api.nvd_by_cpe[CONTROLLOGIX_CPE] = "nvd_cpe_controllogix_5580.json"

    async with httpx.AsyncClient(transport=httpx.MockTransport(fake_api.handler)) as client:
        cves = await NVDClient(nvd_config).query_cpes(CONTROLLOGIX_CPE, client)

    assert len(cves) == 7
    assert "CVE-2022-1161" in {c.cve_id for c in cves}
    [call] = fake_api.nvd_calls()
    assert call.url.params["cpeName"] == CONTROLLOGIX_CPE
    assert "apiKey" not in call.headers  # no key configured -> none sent


async def test_api_key_is_sent_as_header_when_configured(fake_api):
    config = NVDConfig(api_key="test-key", rate_limit_delay=0.0)

    async with httpx.AsyncClient(transport=httpx.MockTransport(fake_api.handler)) as client:
        await NVDClient(config).query_cpes(CONTROLLOGIX_CPE, client)

    assert all(c.headers["apiKey"] == "test-key" for c in fake_api.nvd_calls())


async def test_keyword_fallback_finds_cves_when_exact_cpe_has_none(fake_api, nvd_config):
    # Regression: the fallback used to search "rockwellautomation controllogix 5580 firmware".
    # NVD ANDs keywords against the description, and "rockwellautomation" never appears
    # in prose, so the live API returned 0 results. It also post-filtered on the raw CPE
    # tokens, which would have discarded every hit anyway.
    fake_api.nvd_by_keyword["controllogix 5580"] = "nvd_keyword_controllogix_5580.json"

    async with httpx.AsyncClient(transport=httpx.MockTransport(fake_api.handler)) as client:
        cves = await NVDClient(nvd_config).query_cpes(CONTROLLOGIX_CPE, client)

    calls = fake_api.nvd_calls()
    assert [c.url.params.get("cpeName") for c in calls] == [CONTROLLOGIX_CPE, None]
    assert calls[1].url.params["keywordSearch"] == "controllogix 5580"
    ids = {c.cve_id for c in cves}
    assert {"CVE-2017-6024", "CVE-2021-22681"} <= ids


def test_version_relevance_filter_matches_vendor_names_written_with_spaces():
    keyword_hits = [NVDClient._parse_cve(v) for v in
                    load_fixture("nvd_keyword_controllogix_5580.json")["vulnerabilities"]]
    unrelated = parse("nvd_cve_2014_2251.json")  # Siemens: mentions neither vendor nor product

    kept = NVDClient._filter_by_version_relevance(
        [*keyword_hits, unrelated], "rockwellautomation", "controllogix 5580 firmware", "33.011"
    )

    assert unrelated not in kept
    assert len(kept) == len(keyword_hits)


async def test_pagination_follows_total_results(nvd_config):
    page = load_fixture("nvd_cpe_controllogix_5580.json")
    vulns = page["vulnerabilities"]
    seen_start = []

    def handler(request):
        start = int(request.url.params["startIndex"])
        seen_start.append(start)
        chunk = vulns[start:start + 3]
        return httpx.Response(200, json={"totalResults": len(vulns), "startIndex": start,
                                         "resultsPerPage": len(chunk), "vulnerabilities": chunk})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        cves = await NVDClient(nvd_config).query_cpes(CONTROLLOGIX_CPE, client)

    assert seen_start == [0, 3, 6]
    assert [c.cve_id for c in cves] == [v["cve"]["id"] for v in vulns]


async def test_rate_limit_403_is_retried_with_backoff(nvd_config, no_sleep):
    responses = iter([httpx.Response(403), httpx.Response(200, json=load_fixture("nvd_cve_2021_22681.json"))])

    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: next(responses))) as client:
        cves = await NVDClient(nvd_config)._paginated_query(client, {"cveId": "CVE-2021-22681"})

    assert [c.cve_id for c in cves] == ["CVE-2021-22681"]
    assert 10 in no_sleep  # first 403 backs off 10s


async def test_gives_up_after_max_retries(nvd_config, no_sleep):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(503, text="Service Unavailable")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        cves = await NVDClient(nvd_config).query_cpes(CONTROLLOGIX_CPE, client)

    assert cves == []
    # exact query exhausts its retries; the keyword fallback then does the same
    assert len(calls) == 2 * nvd_config.max_retries


async def test_query_all_assets_queries_each_unique_cpe_once(fake_api, nvd_config):
    fake_api.nvd_by_cpe[CONTROLLOGIX_CPE] = "nvd_cpe_controllogix_5580.json"
    other = "cpe:2.3:a:vendor:no_such_product:1.0:*:*:*:*:*:*:*"

    results = await query_all_assets([CONTROLLOGIX_CPE, other, CONTROLLOGIX_CPE], nvd_config)

    assert set(results) == {CONTROLLOGIX_CPE, other}
    assert len(results[CONTROLLOGIX_CPE]) == 7
    assert results[other] == []
    exact_calls = [c for c in fake_api.nvd_calls() if c.url.params.get("cpeName") == CONTROLLOGIX_CPE]
    assert len(exact_calls) == 1
