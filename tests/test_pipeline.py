"""End-to-end scans (scanner pipeline and CLI) with NVD and KEV served from recorded fixtures."""

from __future__ import annotations

import json
import sys

import pytest
from conftest import REPO_ROOT

import main as cli
from models import Severity
from scanner import ICSScanner

CONTROLLOGIX = "cpe:2.3:o:rockwellautomation:controllogix_5580_firmware:33.011:*:*:*:*:*:*:*"
S7_1500 = "cpe:2.3:o:siemens:simatic_s7-1500_firmware:2.9.2:*:*:*:*:*:*:*"


@pytest.fixture
def inventory(tmp_path):
    path = tmp_path / "plant.csv"
    path.write_text(
        "asset_id,name,vendor,model,firmware_version,cpe,purdue_level,network_zone,exposure,patch_status\n"
        f"A1,PLC-SAFETY-01,Rockwell,ControlLogix 5580,33.011,{CONTROLLOGIX},1,OT-Zone1,internet,unavailable\n"
        f"A2,PLC-AUX-02,Siemens,S7-1500,2.9.2,{S7_1500},1,OT-Zone1,air-gapped,available\n",
        encoding="utf-8",
    )
    return path


async def test_scan_scores_nvd_findings_and_flags_kev(fake_api, scanner_config, inventory):
    # ControlLogix has no exact-CPE results here, so the keyword fallback runs and finds
    # CVE-2021-22681, which is in CISA KEV. The S7-1500 exact match returns CVE-2014-2251.
    fake_api.nvd_by_keyword["controllogix 5580"] = "nvd_keyword_controllogix_5580.json"
    fake_api.nvd_by_cpe[S7_1500] = "nvd_cve_2014_2251.json"

    result = await ICSScanner(scanner_config).scan(str(inventory))

    assert result.errors == []
    assert result.total_assets == 2
    by_id = {f.finding_id: f for f in result.findings}
    assert "A2_CVE-2014-2251" in by_id

    kev = by_id["A1_CVE-2021-22681"]
    assert kev.in_kev and kev.kev_entry.vendor == "Rockwell"
    assert kev.ot_risk_score == 10.0  # 9.8 x L1 x internet x no patch x KEV, capped
    assert kev.ot_severity is Severity.CRITICAL
    assert result.total_kev_hits == 1

    s7 = by_id["A2_CVE-2014-2251"]
    assert s7.ot_risk_score == pytest.approx(8.3 * 1.5 * 0.6 * 0.9)  # air-gapped, patch available
    assert s7.ot_risk_score < s7.cve.cvss_base_score  # air gap de-rates it below raw CVSS
    assert s7.ot_severity is Severity.HIGH

    # Template remediation ran (no LLM configured) and attached IEC 62443 mappings
    remediation = json.loads(kev.remediation)
    assert remediation["immediate_actions"][0].startswith("URGENT: CISA KEV deadline")
    assert any(m.startswith("FR5") for m in kev.iec_62443_mappings)


async def test_scan_reports_unreadable_inventory_as_error(scanner_config, tmp_path):
    bad = tmp_path / "bad.csv"
    bad.write_text("name,vendor\nx,y\n", encoding="utf-8")

    result = await ICSScanner(scanner_config).scan(str(bad))

    assert result.findings == []
    assert result.errors and "Missing required columns" in result.errors[0]


def run_cli(monkeypatch, *args) -> int:
    monkeypatch.setattr(sys, "argv", ["main.py", *args])
    with pytest.raises(SystemExit) as exc:
        cli.cli()
    return exc.value.code


@pytest.fixture
def cli_env(monkeypatch, tmp_path, fake_api, scanner_config):
    """Run the CLI in a temp dir with no API keys and no rate-limit delays."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "ScannerConfig", lambda: scanner_config)
    fake_api.nvd_by_keyword["controllogix 5580"] = "nvd_keyword_controllogix_5580.json"
    fake_api.nvd_by_cpe[S7_1500] = "nvd_cve_2014_2251.json"
    return tmp_path


def test_cli_writes_all_report_formats(monkeypatch, cli_env, inventory, capsys):
    out = cli_env / "reports"

    code = run_cli(monkeypatch, "-i", str(inventory), "-o", str(out), "--no-llm", "--sarif", "--markdown")

    assert code == 0
    suffixes = sorted(p.name.split("_report")[1] for p in out.iterdir())
    assert suffixes == [".csv", ".html", ".json", ".md", ".sarif"]
    sarif = json.loads(next(out.glob("*.sarif")).read_text(encoding="utf-8"))
    assert len(sarif["runs"][0]["results"]) > 0
    stdout = capsys.readouterr().out
    assert "SCAN COMPLETE" in stdout and "[KEV]" in stdout


def test_cli_quality_gate_fails_build_on_kev_finding(monkeypatch, cli_env, inventory, capsys):
    code = run_cli(monkeypatch, "-i", str(inventory), "-o", "out", "--no-llm", "--json-only", "--gate")

    assert code == 2
    assert "Quality Gate: FAILED" in capsys.readouterr().out


def test_cli_diff_against_previous_report_shows_no_spurious_changes(monkeypatch, cli_env, inventory, capsys):
    assert run_cli(monkeypatch, "-i", str(inventory), "-o", "first", "--no-llm", "--json-only") == 0
    [baseline] = (cli_env / "first").glob("*_report.json")
    capsys.readouterr()

    code = run_cli(monkeypatch, "-i", str(inventory), "-o", "second", "--no-llm", "--json-only",
                   "--diff", str(baseline))

    assert code == 0
    out = capsys.readouterr().out
    assert "New findings:      0" in out
    assert "Resolved findings: 0" in out


@pytest.mark.parametrize("sample", ["sample_inventory.csv", "sample_sbom_cyclonedx.json"])
def test_cli_validate_checks_samples_without_calling_apis(monkeypatch, cli_env, fake_api, sample, capsys):
    code = run_cli(monkeypatch, "-i", str(REPO_ROOT / sample), "--validate")

    assert code == 0
    assert "VALID:" in capsys.readouterr().out
    assert fake_api.calls == []


def test_cli_validate_fails_on_inventory_with_bad_cpe(monkeypatch, cli_env, tmp_path):
    bad = tmp_path / "bad.csv"
    bad.write_text("name,vendor,model,firmware_version,cpe,purdue_level\n"
                   "PLC,Siemens,S7,1.0,cpe:/o:siemens:s7:1.0,1\n", encoding="utf-8")

    assert run_cli(monkeypatch, "-i", str(bad), "--validate") == 1
