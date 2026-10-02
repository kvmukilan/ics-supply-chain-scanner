"""Input validators for CPE strings, CVE ids and Purdue levels."""

from __future__ import annotations

import pytest
from conftest import REPO_ROOT

from inventory import parse_csv
from validators import validate_cpe, validate_cve_id, validate_purdue_level


def test_every_cpe_in_the_sample_inventory_is_valid():
    for asset in parse_csv(REPO_ROOT / "sample_inventory.csv"):
        assert validate_cpe(asset.cpe) == (True, ""), asset.cpe


@pytest.mark.parametrize("cpe", [
    "cpe:2.3:o:siemens:simatic_s7-1200_firmware:4.5.0:*:*:*:*:*:*:*",
    "cpe:2.3:h:siemens:simatic_s7-1200:-:*:*:*:*:*:*:*",
    "cpe:2.3:a:osisoft:pi_server:2018",  # trailing fields are optional
])
def test_valid_cpes(cpe):
    assert validate_cpe(cpe) == (True, "")


@pytest.mark.parametrize(("cpe", "reason"), [
    ("", "empty"),
    ("cpe:/o:siemens:simatic_s7-1200_firmware:4.5.0", "must start with 'cpe:2.3:'"),  # CPE 2.2 URI
    ("cpe:2.3:o:siemens:s7", "at least 6"),
    ("cpe:2.3:o:a:b:c:d:e:f:g:h:i:j:k", "too many fields"),
    ("cpe:2.3:x:siemens:s7:1.0", "Invalid CPE part 'x'"),
    ("cpe:2.3:o::s7:1.0", "vendor field is empty"),
    ("cpe:2.3:o:siemens::1.0", "product field is empty"),
])
def test_invalid_cpes_explain_why(cpe, reason):
    ok, message = validate_cpe(cpe)

    assert not ok
    assert reason in message


@pytest.mark.parametrize(("cve_id", "ok"), [
    ("CVE-2021-22681", True),
    ("CVE-2024-123456", True),   # 5+ digit sequence numbers are valid since 2014
    ("CVE-2021-123", False),
    ("cve-2021-22681", False),
    ("CVE-21-22681", False),
    ("", False),
])
def test_cve_id(cve_id, ok):
    assert validate_cve_id(cve_id)[0] is ok


@pytest.mark.parametrize(("level", "ok", "reason"), [
    (0, True, ""), (1, True, ""), (3.5, True, ""), (5, True, ""),
    (-1, False, "between 0 and 5"),
    (6, False, "between 0 and 5"),
    (2.7, False, "Non-standard Purdue level"),
])
def test_purdue_level(level, ok, reason):
    valid, message = validate_purdue_level(level)

    assert valid is ok
    assert reason in message
