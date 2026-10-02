"""CycloneDX / SPDX SBOM ingestion."""

from __future__ import annotations

import json

import pytest
from conftest import REPO_ROOT

from models import NetworkExposure, PatchStatus
from sbom_parser import parse_sbom


def write_sbom(tmp_path, doc: dict):
    path = tmp_path / "bom.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def cyclonedx(*components) -> dict:
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": list(components)}


def test_sample_cyclonedx_sbom_carries_ot_properties():
    assets = parse_sbom(REPO_ROOT / "sample_sbom_cyclonedx.json")
    by_ref = {a.asset_id: a for a in assets}

    assert set(by_ref) == {"FW-S7-1200", "FW-S7-1500", "APP-WINCC", "FW-M340", "FW-FORTI", "FW-MOXA"}

    s7 = by_ref["FW-S7-1200"]
    assert s7.vendor == "Siemens"
    assert s7.firmware_version == "4.5.0"
    assert s7.cpe == "cpe:2.3:o:siemens:simatic_s7-1200_firmware:4.5.0:*:*:*:*:*:*:*"
    assert s7.purdue_level == 1.0
    assert s7.network_zone == "OT-Zone1"

    assert by_ref["FW-M340"].exposure is NetworkExposure.AIR_GAPPED
    assert by_ref["FW-M340"].patch_status is PatchStatus.UNAVAILABLE
    assert by_ref["FW-MOXA"].exposure is NetworkExposure.INTERNET
    assert by_ref["FW-FORTI"].purdue_level == 3.5
    # Missing patch_status property falls back to the default
    assert by_ref["APP-WINCC"].patch_status is PatchStatus.AVAILABLE


def test_cpe_is_taken_from_external_references(tmp_path):
    cpe = "cpe:2.3:o:moxa:edr-g9010_firmware:1.0:*:*:*:*:*:*:*"
    path = write_sbom(tmp_path, cyclonedx({
        "type": "firmware", "name": "EDR-G9010", "version": "1.0", "bom-ref": "moxa",
        "externalReferences": [
            {"type": "website", "url": "https://www.moxa.com"},
            {"type": "other", "url": cpe},
        ],
    }))

    [asset] = parse_sbom(path)

    assert asset.cpe == cpe
    assert asset.vendor == "moxa"  # no publisher -> vendor recovered from the CPE
    assert asset.purdue_level == 3.0  # no OT properties -> Level 3 default


def test_cpe_is_synthesised_from_publisher_name_and_version(tmp_path):
    path = write_sbom(tmp_path, cyclonedx(
        {"type": "firmware", "name": "Modicon M580", "version": "4.10", "publisher": "Schneider Electric"},
        {"type": "library", "name": "openssl", "version": "1.1.1k", "publisher": "OpenSSL"},
        # No publisher/group and no CPE: cannot be looked up, so it is skipped
        {"type": "library", "name": "anonymous-lib", "version": "0.1"},
    ))

    assets = parse_sbom(path)

    assert [a.cpe for a in assets] == [
        "cpe:2.3:o:schneider_electric:modicon_m580:4.10:*:*:*:*:*:*:*",  # firmware -> part "o"
        "cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*",  # library -> part "a"
    ]
    assert [a.asset_id for a in assets] == ["SBOM-0001", "SBOM-0002"]


def test_ics_level_property_alias_is_honoured(tmp_path):
    path = write_sbom(tmp_path, cyclonedx({
        "name": "RTU", "publisher": "ABB", "version": "1",
        "cpe": "cpe:2.3:o:abb:rtu560_firmware:1:*:*:*:*:*:*:*",
        "properties": [{"name": "ics:level", "value": "0"}],
    }))

    [asset] = parse_sbom(path)

    assert asset.purdue_level == 0.0


def test_one_bad_component_does_not_drop_the_whole_sbom(tmp_path):
    # Regression: an invalid exposure value (or a property without "value", which
    # CycloneDX allows) used to raise out of parse_sbom and lose every asset.
    path = write_sbom(tmp_path, cyclonedx(
        {"name": "bad", "publisher": "X", "version": "1", "cpe": "cpe:2.3:a:x:bad:1:*:*:*:*:*:*:*",
         "properties": [{"name": "exposure", "value": "internet-facing"}]},
        {"name": "valueless", "publisher": "X", "version": "1",
         "cpe": "cpe:2.3:a:x:valueless:1:*:*:*:*:*:*:*",
         "properties": [{"name": "note"}]},
        {"name": "good", "publisher": "X", "version": "1", "cpe": "cpe:2.3:a:x:good:1:*:*:*:*:*:*:*",
         "properties": [{"name": "exposure", "value": "dmz"}]},
    ))

    assets = parse_sbom(path)

    assert [a.name for a in assets] == ["valueless", "good"]
    assert assets[1].exposure is NetworkExposure.DMZ


def test_spdx_external_ref_cpe_and_supplier_prefix(tmp_path):
    cpe = "cpe:2.3:a:osisoft:pi_server:2018:*:*:*:*:*:*:*"
    path = write_sbom(tmp_path, {
        "spdxVersion": "SPDX-2.3",
        "packages": [
            {"SPDXID": "SPDXRef-pi", "name": "PI Server", "versionInfo": "2018",
             "supplier": "Organization: OSIsoft",
             "externalRefs": [{"referenceCategory": "SECURITY", "referenceType": "cpe23Type",
                               "referenceLocator": cpe}]},
        ],
    })

    [asset] = parse_sbom(path)

    assert asset.cpe == cpe
    assert asset.vendor == "OSIsoft"
    assert asset.asset_id == "SPDXRef-pi"
    assert asset.purdue_level == 3.0


def test_unknown_document_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="Unrecognized SBOM format"):
        parse_sbom(write_sbom(tmp_path, {"bomFormat": "SomethingElse"}))
