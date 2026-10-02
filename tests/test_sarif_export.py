"""SARIF 2.1.0 export (GitHub code scanning / Azure DevOps)."""

from __future__ import annotations

import json

import pytest
from conftest import make_asset, make_cve, make_finding

from models import ScanResult, Severity
from sarif_export import generate_sarif_report


@pytest.fixture
def scan() -> ScanResult:
    plc = make_asset(name="PLC-01", asset_id="A1", purdue_level=1, exposure="internet")
    hist = make_asset(name="HIST-01", asset_id="A2", purdue_level=3, exposure="dmz",
                      vendor="OSIsoft", model="PI Server",
                      cpe="cpe:2.3:a:osisoft:pi_server:2018:*:*:*:*:*:*:*")
    kev_cve = make_cve("CVE-2021-22681", 9.8, weaknesses=["CWE-522"],
                       references=["https://a.example/1", "https://a.example/2", "https://a.example/3",
                                   "https://a.example/4"])
    low_cve = make_cve("CVE-2017-7926", 3.1, weaknesses=["CWE-352"])
    findings = [
        make_finding(plc, low_cve),
        make_finding(plc, kev_cve, in_kev=True),
        make_finding(hist, kev_cve, in_kev=True),  # same CVE on a second asset
    ]
    findings[1].iec_62443_mappings = ["FR1: Identification and Authentication Control (SR 1.1)"]
    return ScanResult(scan_id="SCAN-TEST", findings=findings, total_assets=2, total_cves=3,
                      total_kev_hits=2, errors=["NVD query failed for one CPE"])


@pytest.fixture
def sarif(scan, tmp_path) -> dict:
    path = generate_sarif_report(scan, str(tmp_path / "nested" / "report.sarif"))
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def test_document_envelope(sarif):
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"].endswith("sarif-schema-2.1.0.json")
    [run] = sarif["runs"]
    driver = run["tool"]["driver"]
    assert driver["name"] == "ICS Supply Chain Vulnerability Scanner"
    assert driver["informationUri"] == "https://github.com/kvmukilan/ics-supply-chain-scanner"
    assert run["properties"]["scan_id"] == "SCAN-TEST"
    assert run["properties"]["kev_matches"] == 2


def test_one_rule_per_cve_and_every_result_references_a_rule(sarif):
    [run] = sarif["runs"]
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]

    assert sorted(rule_ids) == ["CVE-2017-7926", "CVE-2021-22681"]
    assert len(run["results"]) == 3
    assert {r["ruleId"] for r in run["results"]} <= set(rule_ids)


def test_rules_carry_github_security_severity_and_cwe(sarif):
    rules = {r["id"]: r for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    kev_rule = rules["CVE-2021-22681"]

    assert kev_rule["properties"]["security-severity"] == "9.8"
    assert kev_rule["properties"]["cwe"] == ["CWE-522"]
    assert "cisa-kev" in kev_rule["properties"]["tags"]
    assert kev_rule["helpUri"] == "https://nvd.nist.gov/vuln/detail/CVE-2021-22681"


def test_results_sorted_by_ot_risk_with_levels_from_ot_severity(sarif, scan):
    results = sarif["runs"][0]["results"]
    scores = [r["properties"]["ot_risk_score"] for r in results]

    assert scores == sorted(scores, reverse=True)
    expected_level = {Severity.CRITICAL: "error", Severity.HIGH: "error",
                      Severity.MEDIUM: "warning", Severity.LOW: "note"}
    for r in results:
        assert r["level"] == expected_level[Severity(r["properties"]["ot_severity"])]


def test_result_locates_the_asset_and_explains_the_kev_hit(sarif):
    top = sarif["runs"][0]["results"][0]
    loc = top["locations"][0]

    assert top["ruleId"] == "CVE-2021-22681"
    assert loc["physicalLocation"]["artifactLocation"]["uri"].startswith("cpe:2.3:")
    logical = loc["logicalLocations"][0]
    assert logical["kind"] == "asset"
    assert logical["properties"]["purdue_level"] in (1.0, 3.0)
    assert "CISA KEV: actively exploited" in top["message"]["text"]
    assert top["properties"]["in_kev"] is True
    assert top["properties"]["score_breakdown"]["kev_weight"] == 1.5
    assert len(top["relatedLocations"]) == 3  # capped at 3 references


def test_scan_errors_mark_the_invocation_unsuccessful(sarif):
    [invocation] = sarif["runs"][0]["invocations"]

    assert invocation["executionSuccessful"] is False
    assert invocation["toolExecutionNotifications"][0]["message"]["text"] == "NVD query failed for one CPE"


def test_empty_scan_produces_valid_empty_run(tmp_path):
    path = generate_sarif_report(ScanResult(scan_id="EMPTY"), str(tmp_path / "e.sarif"))
    with open(path, encoding="utf-8") as f:
        run = json.load(f)["runs"][0]

    assert run["results"] == []
    assert run["tool"]["driver"]["rules"] == []
    assert run["invocations"][0]["executionSuccessful"] is True
