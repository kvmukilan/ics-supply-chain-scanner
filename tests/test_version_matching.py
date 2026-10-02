"""Version-aware CVE matching (regression tests for the version-blind false positives).

Covers the fix for the keyword fallback that used to keep every CVE mentioning a
product/vendor regardless of the asset's version. Everything runs offline against
recorded NVD responses served through httpx.MockTransport (see conftest.FakeAPI).
"""

from __future__ import annotations

import httpx
import pytest
from conftest import make_finding

import quality_gate
from models import ScanResult, Severity
from nvd_client import NVDClient, compare_versions
from scanner import ICSScanner

# FortiGate 60F running FortiOS 7.0.5 — the acceptance-test asset.
FORTIOS_CPE = "cpe:2.3:o:fortinet:fortios:7.0.5:*:*:*:*:*:*:*"
# OSIsoft PI Server — CPE not in NVD's dictionary, so it exercises the keyword fallback.
PI_SERVER_CPE = "cpe:2.3:a:osisoft:pi_server:2018:*:*:*:*:*:*:*"


@pytest.fixture
def nvd_config():
    from config import NVDConfig

    return NVDConfig(api_key="", rate_limit_delay=0.0, rate_limit_delay_no_key=0.0)


def _version_end_excluding(cve) -> list[str]:
    """All versionEndExcluding bounds declared in a CVE's CPE applicability."""
    return [
        m["versionEndExcluding"]
        for m in NVDClient._iter_cpe_matches(cve.configurations)
        if m.get("versionEndExcluding")
    ]


# --------------------------------------------------------------------------- #
# Version comparison
# --------------------------------------------------------------------------- #

def test_version_comparison_is_numeric_not_lexical():
    assert compare_versions("7.0.5", "7.0.6") == -1
    assert compare_versions("7.0.9", "7.0.10") == -1  # 9 < 10, not "9" > "1"
    assert compare_versions("7.0.5", "7.0.5") == 0
    assert compare_versions("33.011", "34.0") == -1
    assert compare_versions("2.9.2", "1.5.0") == 1


# --------------------------------------------------------------------------- #
# Acceptance test: FortiGate 7.0.5
# --------------------------------------------------------------------------- #

async def test_fortigate_7_0_5_excludes_cves_fixed_at_or_before_that_version(fake_api, nvd_config):
    """A FortiGate at 7.0.5 must NOT list any CVE whose versionEndExcluding <= 7.0.5."""
    fake_api.nvd_by_cpe[FORTIOS_CPE] = "nvd_cpe_fortios_7_0_5.json"

    async with httpx.AsyncClient(transport=httpx.MockTransport(fake_api.handler)) as client:
        cves = await NVDClient(nvd_config).query_cpes(FORTIOS_CPE, client)

    ids = {c.cve_id for c in cves}
    # Patched at or before 7.0.5, so a 7.0.5 box is not affected — must be absent.
    assert "CVE-2022-40001" not in ids  # versionEndExcluding == 7.0.5 (boundary)
    assert "CVE-2022-40002" not in ids  # versionEndExcluding 7.0.3
    assert "CVE-2022-40005" not in ids  # affects 7.2.x; 7.0.5 is below the range
    # Still within an affected range — kept.
    assert ids == {"CVE-2022-40003", "CVE-2022-40004"}

    # The general invariant the acceptance criterion states, checked structurally.
    for cve in cves:
        assert all(compare_versions(ee, "7.0.5") > 0 for ee in _version_end_excluding(cve)), (
            f"{cve.cve_id} has versionEndExcluding <= 7.0.5 but was kept"
        )


async def test_confirmed_fortios_findings_are_version_checked_cpe_matches(fake_api, nvd_config):
    fake_api.nvd_by_cpe[FORTIOS_CPE] = "nvd_cpe_fortios_7_0_5.json"

    async with httpx.AsyncClient(transport=httpx.MockTransport(fake_api.handler)) as client:
        cves = await NVDClient(nvd_config).query_cpes(FORTIOS_CPE, client)

    assert cves  # sanity
    for cve in cves:
        assert cve.match_method == "cpe"
        assert cve.version_checked is True


# --------------------------------------------------------------------------- #
# Keyword fallback is labelled as unverified / "possible"
# --------------------------------------------------------------------------- #

async def test_keyword_fallback_findings_are_labelled_possible(fake_api, nvd_config):
    # CPE not in NVD's dictionary -> exact match is empty -> keyword fallback runs.
    fake_api.nvd_by_keyword["osisoft pi server"] = "nvd_keyword_pi_server.json"
    fake_api.nvd_by_keyword["pi server"] = "nvd_keyword_pi_server.json"

    async with httpx.AsyncClient(transport=httpx.MockTransport(fake_api.handler)) as client:
        cves = await NVDClient(nvd_config).query_cpes(PI_SERVER_CPE, client)

    ids = {c.cve_id for c in cves}
    assert ids == {"CVE-2020-50001"}  # names the product "PI Server"
    for cve in cves:
        assert cve.match_method == "keyword"
        assert cve.version_checked is False


async def test_vendor_or_wrong_product_keyword_hit_is_dropped(fake_api, nvd_config):
    """Tightened post-filter: a hit that names the vendor/another product, not the
    product token, is dropped (vendor-only mentions were too loose)."""
    fake_api.nvd_by_keyword["osisoft pi server"] = "nvd_keyword_pi_server.json"
    fake_api.nvd_by_keyword["pi server"] = "nvd_keyword_pi_server.json"

    async with httpx.AsyncClient(transport=httpx.MockTransport(fake_api.handler)) as client:
        cves = await NVDClient(nvd_config).query_cpes(PI_SERVER_CPE, client)

    # CVE-2020-50002 mentions OSIsoft PI Vision (not "PI Server") and must not be kept.
    assert "CVE-2020-50002" not in {c.cve_id for c in cves}


# --------------------------------------------------------------------------- #
# End-to-end: confirmed vs possible flow through the scanner and summary
# --------------------------------------------------------------------------- #

@pytest.fixture
def mixed_inventory(tmp_path):
    path = tmp_path / "plant.csv"
    path.write_text(
        "asset_id,name,vendor,model,firmware_version,cpe,purdue_level,network_zone,exposure,patch_status\n"
        f"FW1,FW-OT-01,Fortinet,FortiGate 60F,7.0.5,{FORTIOS_CPE},3.5,OT-DMZ,dmz,available\n"
        f"HS1,HISTORIAN-01,OSIsoft,PI Server,2018,{PI_SERVER_CPE},3,OT-DMZ,dmz,eol\n",
        encoding="utf-8",
    )
    return path


async def test_scan_separates_confirmed_from_possible(fake_api, scanner_config, mixed_inventory):
    fake_api.nvd_by_cpe[FORTIOS_CPE] = "nvd_cpe_fortios_7_0_5.json"
    fake_api.nvd_by_keyword["osisoft pi server"] = "nvd_keyword_pi_server.json"
    fake_api.nvd_by_keyword["pi server"] = "nvd_keyword_pi_server.json"

    result = await ICSScanner(scanner_config).scan(str(mixed_inventory))

    assert result.errors == []
    # 2 version-confirmed FortiOS CVEs + 1 unverified PI Server keyword hit.
    assert len(result.confirmed_findings) == 2
    assert len(result.possible_findings) == 1

    (possible,) = result.possible_findings
    assert possible.cve.cve_id == "CVE-2020-50001"
    assert possible.match_method == "keyword"
    assert possible.version_checked is False

    for f in result.confirmed_findings:
        assert f.match_method == "cpe"
        assert f.version_checked is True

    summary = result.summary()
    assert summary["confirmed_findings"] == 2
    assert summary["possible_findings"] == 1


# --------------------------------------------------------------------------- #
# Quality gate excludes "possible" findings by default
# --------------------------------------------------------------------------- #

def _result_with(finding):
    return ScanResult(scan_id="SCAN-TEST", findings=[finding])


def test_gate_ignores_possible_findings_by_default():
    possible = make_finding(score=9.0, severity=Severity.CRITICAL)  # version_checked defaults False
    assert possible.version_checked is False
    result = _result_with(possible)

    assert quality_gate.evaluate(result).passed  # excluded -> nothing to fail on
    assert not quality_gate.evaluate(result, include_possible=True).passed  # now counted


def test_gate_fails_on_confirmed_finding():
    confirmed = make_finding(score=9.0, severity=Severity.CRITICAL)
    confirmed.version_checked = True
    result = _result_with(confirmed)

    gate = quality_gate.evaluate(result)
    assert not gate.passed
    assert any(v.rule == "max_critical" for v in gate.violations)
