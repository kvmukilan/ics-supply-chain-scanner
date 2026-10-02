"""Baseline diffing between two scans, including diffing against a saved JSON report."""

from __future__ import annotations

import json

import pytest
from conftest import make_asset, make_cve, make_finding

from models import ScanResult, Severity
from report import generate_json_report
from scan_diff import compare_scans, load_report, report_to_scan_result

PLC = dict(name="PLC-MAIN-01", asset_id="ASSET-0001")
HMI = dict(name="HMI-01", asset_id="ASSET-0003", purdue_level=2)


def scan(scan_id, *findings) -> ScanResult:
    return ScanResult(scan_id=scan_id, findings=list(findings))


def f(asset_kw, cve_id, score, severity=None, in_kev=False):
    return make_finding(make_asset(**asset_kw), make_cve(cve_id, 7.0), in_kev=in_kev,
                        score=score, severity=severity)


def test_new_resolved_changed_and_unchanged_are_classified():
    baseline = scan("OLD",
                    f(PLC, "CVE-2022-1161", 9.0, Severity.CRITICAL),
                    f(PLC, "CVE-2022-1159", 6.0, Severity.MEDIUM),
                    f(HMI, "CVE-2019-10929", 5.0, Severity.MEDIUM))
    current = scan("NEW",
                   f(PLC, "CVE-2022-1161", 9.1, Severity.CRITICAL),     # +0.1: below threshold
                   f(PLC, "CVE-2022-1159", 8.0, Severity.HIGH),         # +2.0: changed
                   f(PLC, "CVE-2021-22681", 10.0, Severity.CRITICAL, in_kev=True))  # new

    diff = compare_scans(baseline, current)

    assert [d.cve_id for d in diff.new_findings] == ["CVE-2021-22681"]
    assert [d.cve_id for d in diff.resolved_findings] == ["CVE-2019-10929"]
    assert diff.resolved_findings[0].asset_name == "HMI-01"
    [change] = diff.score_changes
    assert (change.cve_id, change.status, change.old_ot_score, change.new_ot_score) == \
        ("CVE-2022-1159", "score_increased", 6.0, 8.0)
    assert (change.old_severity, change.new_severity) == ("MEDIUM", "HIGH")
    assert diff.unchanged_count == 1

    summary = diff.summary()
    assert summary["total_changes"] == 3
    assert summary["new_critical"] == 1
    assert summary["new_kev"] == 1
    assert (summary["baseline_scan_id"], summary["current_scan_id"]) == ("OLD", "NEW")


def test_same_cve_on_a_different_asset_is_a_new_finding():
    diff = compare_scans(scan("A", f(PLC, "CVE-2022-1161", 9.0)),
                         scan("B", f(PLC, "CVE-2022-1161", 9.0), f(HMI, "CVE-2022-1161", 9.0)))

    assert [d.asset_name for d in diff.new_findings] == ["HMI-01"]
    assert diff.unchanged_count == 1


def test_severity_change_below_score_threshold_is_still_reported():
    diff = compare_scans(scan("A", f(PLC, "CVE-1", 8.45, Severity.HIGH)),
                         scan("B", f(PLC, "CVE-1", 8.55, Severity.CRITICAL)))

    [change] = diff.score_changes
    assert change.status == "score_increased"
    assert change.new_severity == "CRITICAL"


def test_score_decrease_and_custom_threshold():
    base = scan("A", f(PLC, "CVE-1", 8.0))
    cur = scan("B", f(PLC, "CVE-1", 7.8))  # both HIGH, delta 0.2

    assert compare_scans(base, cur).score_changes == []
    [change] = compare_scans(base, cur, score_threshold=0.1).score_changes
    assert change.status == "score_decreased"


def test_new_findings_are_ordered_critical_first_then_by_score():
    diff = compare_scans(scan("A"), scan("B",
                                         f(PLC, "CVE-LOW", 2.0, Severity.LOW),
                                         f(PLC, "CVE-CRIT-A", 9.0, Severity.CRITICAL),
                                         f(HMI, "CVE-HIGH", 7.0, Severity.HIGH),
                                         f(HMI, "CVE-CRIT-B", 9.9, Severity.CRITICAL)))

    assert [d.cve_id for d in diff.new_findings] == ["CVE-CRIT-B", "CVE-CRIT-A", "CVE-HIGH", "CVE-LOW"]


def test_identical_scans_have_no_changes():
    findings = [f(PLC, "CVE-1", 9.0), f(HMI, "CVE-2", 4.0)]
    diff = compare_scans(scan("A", *findings), scan("B", *findings))

    assert diff.total_changes == 0
    assert diff.unchanged_count == 2


def test_diff_against_saved_json_report_matches_findings_by_asset_id(tmp_path):
    # Regression: `main.py --diff` rebuilt the baseline with asset_id = asset *name*,
    # so finding ids ("PLC-MAIN-01_CVE-…") never matched the live scan's ("ASSET-0001_CVE-…").
    # Every finding showed up as both new and resolved.
    findings = [f(PLC, "CVE-2022-1161", 9.0, Severity.CRITICAL, in_kev=True),
                f(HMI, "CVE-2019-10929", 5.0, Severity.MEDIUM)]
    original = scan("SCAN-OLD", *findings)
    report_path = generate_json_report(original, str(tmp_path / "old_report.json"))

    baseline = load_report(report_path)
    diff = compare_scans(baseline, scan("SCAN-NEW", *findings))

    assert baseline.scan_id == "SCAN-OLD"
    assert {x.finding_id for x in baseline.findings} == {x.finding_id for x in findings}
    assert diff.new_findings == [] and diff.resolved_findings == []
    assert diff.unchanged_count == 2
    restored = {x.cve.cve_id: x for x in baseline.findings}["CVE-2022-1161"]
    assert restored.in_kev is True
    assert restored.ot_severity is Severity.CRITICAL
    assert restored.asset.purdue_level == 1.0


def test_reports_written_before_asset_id_was_stored_still_diff_correctly(tmp_path):
    finding = f(PLC, "CVE-2022-1161", 9.0, Severity.CRITICAL)
    path = generate_json_report(scan("OLD", finding), str(tmp_path / "r.json"))
    with open(path, encoding="utf-8") as fh:
        report = json.load(fh)
    del report["findings"][0]["asset"]["asset_id"]  # simulate an older report

    baseline = report_to_scan_result(report)

    assert baseline.findings[0].finding_id == "ASSET-0001_CVE-2022-1161"


def test_unknown_severity_in_report_raises_value_error():
    # main._run_diff catches ValueError and reports the baseline as unparseable
    with pytest.raises(ValueError):
        report_to_scan_result({"findings": [{"risk_assessment": {"ot_severity": "SEVERE"}}]})
