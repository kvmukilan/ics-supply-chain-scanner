"""Asset inventory parsing (CSV and flat JSON)."""

from __future__ import annotations

import json
import logging

import pytest
from conftest import REPO_ROOT

from inventory import load_inventory, parse_csv, parse_json
from models import NetworkExposure, PatchStatus

HEADER = "asset_id,name,vendor,model,firmware_version,cpe,purdue_level,network_zone,exposure,patch_status\n"
CPE = "cpe:2.3:o:siemens:simatic_s7-1200_firmware:4.5.0:*:*:*:*:*:*:*"


def write(tmp_path, text, name="inv.csv"):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_sample_inventory_parses_every_asset_with_ot_context():
    assets = parse_csv(REPO_ROOT / "sample_inventory.csv")

    assert len(assets) == 10
    by_id = {a.asset_id: a for a in assets}

    plc = by_id["ASSET-0001"]
    assert plc.name == "PLC-MAIN-01"
    assert plc.vendor == "Siemens"
    assert plc.cpe == CPE
    assert plc.purdue_level == 1.0
    assert plc.exposure is NetworkExposure.ISOLATED

    # Purdue 3.5 (OT DMZ) must survive as a float, not be truncated to 3
    firewall = by_id["ASSET-0008"]
    assert firewall.purdue_level == 3.5
    assert firewall.exposure is NetworkExposure.DMZ

    assert by_id["ASSET-0004"].exposure is NetworkExposure.AIR_GAPPED
    assert by_id["ASSET-0004"].patch_status is PatchStatus.UNAVAILABLE
    assert by_id["ASSET-0007"].patch_status is PatchStatus.EOL
    assert by_id["ASSET-0010"].exposure is NetworkExposure.INTERNET


def test_header_aliases_and_case_are_resolved(tmp_path):
    path = write(tmp_path,
                 "Hostname,Manufacturer,Product,FW Version,CPE String,ICS Level,Connectivity\n"
                 f"rtu-7,Schneider Electric,Modicon M340,3.20,{CPE},1,Internet\n")

    [asset] = parse_csv(path)

    assert asset.name == "rtu-7"
    assert asset.vendor == "Schneider Electric"
    assert asset.firmware_version == "3.20"
    assert asset.exposure is NetworkExposure.INTERNET  # value is lower-cased


def test_missing_required_column_is_rejected(tmp_path):
    path = write(tmp_path, "name,vendor,model,firmware_version,purdue_level\nx,y,z,1,1\n")

    with pytest.raises(ValueError, match="cpe"):
        parse_csv(path)


def test_blank_optional_cells_fall_back_to_defaults(tmp_path):
    # Regression: a blank exposure cell used to raise ValueError("'' is not a valid
    # NetworkExposure") and silently drop the asset.
    path = write(tmp_path, HEADER + f",PLC-1,Siemens,S7-1200,4.5.0,{CPE},1,,,\n")

    [asset] = parse_csv(path)

    assert asset.exposure is NetworkExposure.ISOLATED
    assert asset.patch_status is PatchStatus.AVAILABLE
    assert asset.network_zone == "unknown"
    assert asset.asset_id == "ASSET-0001"  # generated, numbered like parse_json


def test_short_row_is_skipped_without_aborting_the_file(tmp_path, caplog):
    # Regression: a truncated row made DictReader return None cells, and
    # None.strip() raised AttributeError, aborting the whole inventory load.
    path = write(tmp_path, HEADER
                 + "A1,PLC-1,Siemens\n"
                 + f"A2,PLC-2,Siemens,S7-1200,4.5.0,{CPE},1,Z1,dmz,eol\n")

    with caplog.at_level(logging.WARNING):
        assets = parse_csv(path)

    assert [a.asset_id for a in assets] == ["A2"]
    assert "Skipping row 2" in caplog.text


def test_invalid_enum_value_skips_only_that_row(tmp_path):
    path = write(tmp_path, HEADER
                 + f"A1,PLC-1,Siemens,S7-1200,4.5.0,{CPE},1,Z1,wifi,available\n"
                 + f"A2,PLC-2,Siemens,S7-1200,4.5.0,{CPE},1,Z1,corporate,scheduled\n")

    assets = parse_csv(path)

    assert [a.asset_id for a in assets] == ["A2"]
    assert assets[0].patch_status is PatchStatus.SCHEDULED


def test_invalid_cpe_and_purdue_level_are_kept_but_warned(tmp_path, caplog):
    path = write(tmp_path, HEADER + "A1,PLC-1,Siemens,S7-1200,4.5.0,not-a-cpe,7,Z1,dmz,available\n")

    with caplog.at_level(logging.WARNING):
        [asset] = parse_csv(path)

    assert asset.cpe == "not-a-cpe"
    assert "invalid CPE" in caplog.text
    assert "Purdue level must be between 0 and 5" in caplog.text


def test_utf8_bom_from_excel_is_handled(tmp_path):
    path = tmp_path / "excel.csv"
    path.write_bytes(("﻿" + HEADER + f"A1,PLC-ü,Siemens,S7,4.5.0,{CPE},1,Z,dmz,eol\n").encode("utf-8"))

    [asset] = parse_csv(path)

    assert asset.asset_id == "A1"  # header not mangled into "﻿asset_id"
    assert asset.name == "PLC-ü"


def test_parse_json_accepts_wrapped_and_bare_lists(tmp_path):
    entry = {"name": "HMI-1", "vendor": "Siemens", "model": "WinCC", "firmware_version": "16.0",
             "cpe": CPE, "purdue_level": 2, "exposure": "corporate"}
    wrapped = write(tmp_path, json.dumps({"assets": [entry]}), "wrapped.json")
    bare = write(tmp_path, json.dumps([entry, {"name": "incomplete"}]), "bare.json")

    [a] = parse_json(wrapped)
    assert a.asset_id == "ASSET-0001"
    assert a.exposure is NetworkExposure.CORPORATE
    assert a.purdue_level == 2.0

    # The incomplete entry (missing vendor/cpe/...) is skipped, not fatal
    assert [x.name for x in parse_json(bare)] == ["HMI-1"]


def test_load_inventory_dispatches_on_content(tmp_path):
    assert len(load_inventory(REPO_ROOT / "sample_inventory.csv")) == 10
    # A .json file that is really a CycloneDX SBOM goes to the SBOM parser
    sbom_assets = load_inventory(REPO_ROOT / "sample_sbom_cyclonedx.json")
    assert sbom_assets and all(a.asset_id for a in sbom_assets)

    with pytest.raises(ValueError, match="Unsupported inventory format"):
        load_inventory(write(tmp_path, "x", "inv.xlsx"))
    with pytest.raises(FileNotFoundError):
        parse_csv(tmp_path / "missing.csv")
