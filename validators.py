"""Input validation utilities for the ICS Supply Chain Scanner.

Validates CPE strings, inventory data, and API inputs to catch
malformed data early before wasting NVD API calls.
"""

from __future__ import annotations

import re

# CPE 2.3 format: cpe:2.3:PART:VENDOR:PRODUCT:VERSION:UPDATE:EDITION:LANG:SW_EDITION:TARGET_SW:TARGET_HW:OTHER
CPE_23_PATTERN = re.compile(
    r"^cpe:2\.3:[aho\*\-]:"  # part: a=application, h=hardware, o=OS
    r"[a-zA-Z0-9\._\-\*\\]+"  # vendor
    r":[a-zA-Z0-9\._\-\*\\]+"  # product
    r":[a-zA-Z0-9\._\-\*\\]+"  # version
    r"(:[a-zA-Z0-9\._\-\*\\]*){0,7}$"  # remaining optional fields
)

CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")


def validate_cpe(cpe: str) -> tuple[bool, str]:
    """Validate a CPE 2.3 string format.

    Returns (is_valid, error_message).
    """
    if not cpe:
        return False, "CPE string is empty"

    if not cpe.startswith("cpe:2.3:"):
        return False, f"CPE must start with 'cpe:2.3:', got: {cpe[:20]}"

    parts = cpe.split(":")
    if len(parts) < 6:
        return (
            False,
            f"CPE must have at least 6 colon-separated fields "
            f"(part:vendor:product:version), got {len(parts)}",
        )

    if len(parts) > 13:
        return False, f"CPE has too many fields ({len(parts)}), expected at most 13"

    part = parts[2]
    if part not in ("a", "h", "o", "*", "-"):
        return False, f"Invalid CPE part '{part}', must be a (application), h (hardware), or o (OS)"

    vendor = parts[3]
    product = parts[4]
    if not vendor or vendor.isspace():
        return False, "CPE vendor field is empty"
    if not product or product.isspace():
        return False, "CPE product field is empty"

    return True, ""


def validate_cve_id(cve_id: str) -> tuple[bool, str]:
    """Validate a CVE ID format (CVE-YYYY-NNNNN)."""
    if not cve_id:
        return False, "CVE ID is empty"

    if not CVE_ID_PATTERN.match(cve_id):
        return False, f"Invalid CVE ID format '{cve_id}', expected CVE-YYYY-NNNN+"

    return True, ""


def validate_purdue_level(level: float) -> tuple[bool, str]:
    """Validate Purdue model level (0-5, including 3.5 for DMZ)."""
    valid_levels = {0, 0.5, 1, 1.5, 2, 2.5, 3, 3.5, 4, 4.5, 5}
    if level < 0 or level > 5:
        return False, f"Purdue level must be between 0 and 5, got {level}"
    if level not in valid_levels:
        return False, f"Non-standard Purdue level {level}. Standard levels: 0, 1, 2, 3, 3.5, 4, 5"
    return True, ""
