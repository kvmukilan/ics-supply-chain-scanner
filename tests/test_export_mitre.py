"""CWE -> MITRE ATT&CK for ICS mapping."""

from __future__ import annotations

from conftest import make_asset, make_cve, make_finding

from export_mitre import CWE_TO_ATTCK_ICS, ICS_TACTICS, map_to_attck
from models import ScanResult


def test_mapping_uses_ics_matrix_tactic_ids():
    # Regression: tactics used Enterprise ATT&CK ids (TA0001-TA0011), and two ids were
    # both labelled "Privilege Escalation". The ICS matrix uses TA0100-TA0111.
    assert set(ICS_TACTICS) == {f"TA01{n:02d}" for n in range(12)}
    assert len(set(ICS_TACTICS.values())) == len(ICS_TACTICS)
    for techniques in CWE_TO_ATTCK_ICS.values():
        for tech_id, _, tactic_id in techniques:
            assert tech_id.startswith("T08"), tech_id
            assert tactic_id in ICS_TACTICS


def test_each_technique_has_one_name_and_tactic():
    seen: dict[str, tuple[str, str]] = {}
    for techniques in CWE_TO_ATTCK_ICS.values():
        for tech_id, name, tactic in techniques:
            assert seen.setdefault(tech_id, (name, tactic)) == (name, tactic)

    assert seen["T0814"] == ("Denial of Service", "TA0107")  # Inhibit Response Function
    assert seen["T0855"] == ("Unauthorized Command Message", "TA0106")  # Impair Process Control
    assert seen["T0830"][0] == "Adversary-in-the-Middle"


def test_findings_are_grouped_by_tactic_with_asset_and_cve_rollup():
    plc = make_asset(name="PLC-01", asset_id="A1")
    hmi = make_asset(name="HMI-01", asset_id="A2", purdue_level=2)
    result = ScanResult(scan_id="S", findings=[
        make_finding(plc, make_cve("CVE-A", 9.8, weaknesses=["CWE-306"])),
        make_finding(hmi, make_cve("CVE-B", 5.0, weaknesses=["cwe-798"])),  # case-insensitive
        make_finding(hmi, make_cve("CVE-C", 7.5, weaknesses=["CWE-400"])),
        make_finding(hmi, make_cve("CVE-D", 7.5, weaknesses=["CWE-9999"])),  # unmapped
    ])

    out = map_to_attck(result)
    surface = out["attack_surface"]

    assert out["total_techniques_matched"] == 3  # T0859, T0886, T0814
    assert set(surface) == {"TA0109: Lateral Movement", "TA0108: Initial Access",
                            "TA0107: Inhibit Response Function"}
    [valid_accounts] = surface["TA0109: Lateral Movement"]
    assert valid_accounts["technique_id"] == "T0859"
    assert valid_accounts["cve_ids"] == ["CVE-A", "CVE-B"]
    assert valid_accounts["affected_assets"] == ["HMI-01", "PLC-01"]
    assert valid_accounts["finding_count"] == 2
