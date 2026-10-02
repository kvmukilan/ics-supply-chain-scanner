"""Shared pytest fixtures.

The whole suite runs offline. NVD and CISA KEV traffic is served from
responses recorded from the live APIs (trimmed to the fields the scanner
reads) in tests/fixtures/, through httpx.MockTransport. Any attempt to open a
real non-loopback connection fails the test.
"""

from __future__ import annotations

import functools
import json
import socket
from pathlib import Path

import httpx
import pytest

from config import CISAKEVConfig, NVDConfig, OTRiskWeights, ScannerConfig
from models import Asset, CVEEntry, Finding, KEVEntry, Severity

FIXTURES = Path(__file__).parent / "fixtures"
REPO_ROOT = Path(__file__).parent.parent

NVD_URL = NVDConfig().base_url
KEV_URL = CISAKEVConfig().catalog_url


def load_fixture(name: str) -> dict:
    with open(FIXTURES / name, encoding="utf-8") as f:
        return json.load(f)


# --------------------------------------------------------------------------- #
# Network guard
# --------------------------------------------------------------------------- #

_LOOPBACK = {"127.0.0.1", "::1", "localhost"}
_real_connect = socket.socket.connect


def _guarded_connect(self, address):
    host = address[0] if isinstance(address, tuple) else address
    if host not in _LOOPBACK:
        raise RuntimeError(f"Test attempted a real network connection to {address!r}")
    return _real_connect(self, address)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    # Loopback stays allowed: asyncio's Windows event loop uses a local socketpair.
    monkeypatch.setattr(socket.socket, "connect", _guarded_connect)


# --------------------------------------------------------------------------- #
# Fake NVD / KEV HTTP layer
# --------------------------------------------------------------------------- #

class FakeAPI:
    """Routes NVD/KEV requests to recorded fixtures and records every call."""

    def __init__(self):
        self.calls: list[httpx.Request] = []
        # cpeName -> fixture name (unknown CPEs get an empty result page)
        self.nvd_by_cpe: dict[str, str] = {}
        # keywordSearch -> fixture name
        self.nvd_by_keyword: dict[str, str] = {}
        self.kev_fixture: str | None = "kev_catalog_subset.json"
        self.kev_status = 200

    @staticmethod
    def empty_page() -> dict:
        return {"resultsPerPage": 0, "startIndex": 0, "totalResults": 0,
                "format": "NVD_CVE", "version": "2.0", "vulnerabilities": []}

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        url = str(request.url.copy_with(query=None))
        if url == NVD_URL:
            params = request.url.params
            name = None
            if "cpeName" in params:
                name = self.nvd_by_cpe.get(params["cpeName"])
            elif "keywordSearch" in params:
                name = self.nvd_by_keyword.get(params["keywordSearch"])
            body = load_fixture(name) if name else self.empty_page()
            return httpx.Response(200, json=body)
        if url == KEV_URL:
            if self.kev_status != 200 or self.kev_fixture is None:
                return httpx.Response(self.kev_status)
            return httpx.Response(200, json=load_fixture(self.kev_fixture))
        return httpx.Response(404)

    def nvd_calls(self) -> list[httpx.Request]:
        return [c for c in self.calls if str(c.url).startswith(NVD_URL)]

    def kev_calls(self) -> list[httpx.Request]:
        return [c for c in self.calls if str(c.url).startswith(KEV_URL)]


@pytest.fixture
def fake_api(monkeypatch) -> FakeAPI:
    """Patch httpx.AsyncClient in the NVD and KEV clients to use recorded fixtures."""
    import kev_client
    import nvd_client

    api = FakeAPI()
    patched = functools.partial(httpx.AsyncClient, transport=httpx.MockTransport(api.handler))
    monkeypatch.setattr(nvd_client.httpx, "AsyncClient", patched)
    monkeypatch.setattr(kev_client.httpx, "AsyncClient", patched)
    return api


@pytest.fixture
def scanner_config(tmp_path) -> ScannerConfig:
    """A ScannerConfig with no API keys, no rate-limit sleeps and a temp KEV cache."""
    cfg = ScannerConfig()
    cfg.nvd.api_key = ""
    cfg.nvd.rate_limit_delay = 0.0
    cfg.nvd.rate_limit_delay_no_key = 0.0
    cfg.kev.cache_path = str(tmp_path / "kev_cache.json")
    cfg.llm.endpoint = ""
    cfg.llm.api_key = ""
    cfg.output_dir = str(tmp_path / "output")
    return cfg


# --------------------------------------------------------------------------- #
# Model factories
# --------------------------------------------------------------------------- #

def make_asset(**overrides) -> Asset:
    fields = {
        "name": "PLC-01",
        "vendor": "Rockwell Automation",
        "model": "ControlLogix 5580",
        "firmware_version": "33.011",
        "cpe": "cpe:2.3:o:rockwellautomation:controllogix_5580_firmware:33.011:*:*:*:*:*:*:*",
        "purdue_level": 1,
        "network_zone": "OT-Zone1",
        "exposure": "isolated",
        "patch_status": "available",
        "asset_id": "ASSET-0001",
    }
    fields.update(overrides)
    return Asset(**fields)


def make_cve(cve_id: str = "CVE-2022-1161", score: float = 9.8, **overrides) -> CVEEntry:
    fields = {
        "cve_id": cve_id,
        "description": "Test vulnerability",
        "cvss_base_score": score,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": Severity.from_cvss(score),
        "published": "2022-04-01T00:00:00.000",
        "last_modified": "2022-04-01T00:00:00.000",
    }
    fields.update(overrides)
    return CVEEntry(**fields)


def make_kev(cve_id: str = "CVE-2021-22681") -> KEVEntry:
    return KEVEntry(
        cve_id=cve_id,
        vendor="Rockwell",
        product="Multiple Products",
        vulnerability_name="Rockwell Multiple Products Insufficient Protected Credentials Vulnerability",
        date_added="2026-03-05",
        due_date="2026-03-26",
        required_action="Apply mitigations per vendor instructions.",
        known_ransomware_use="Unknown",
    )


def make_finding(asset: Asset | None = None, cve: CVEEntry | None = None, *,
                 in_kev: bool = False, score: float | None = None,
                 severity: Severity | None = None) -> Finding:
    asset = asset or make_asset()
    cve = cve or make_cve()
    finding = Finding(asset=asset, cve=cve, in_kev=in_kev,
                      kev_entry=make_kev(cve.cve_id) if in_kev else None)
    if score is None:
        from risk_scorer import OTRiskScorer
        OTRiskScorer(OTRiskWeights()).score_finding(finding)
    else:
        finding.ot_risk_score = score
        finding.ot_severity = severity or Severity.from_cvss(score)
    return finding
