"""Data models for the ICS Supply Chain Vulnerability Scanner."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"

    @classmethod
    def from_cvss(cls, score: float) -> Severity:
        if score >= 9.0:
            return cls.CRITICAL
        elif score >= 7.0:
            return cls.HIGH
        elif score >= 4.0:
            return cls.MEDIUM
        elif score > 0.0:
            return cls.LOW
        return cls.NONE


class NetworkExposure(str, Enum):
    INTERNET = "internet"
    CORPORATE = "corporate"
    DMZ = "dmz"
    ISOLATED = "isolated"
    AIR_GAPPED = "air-gapped"


class PatchStatus(str, Enum):
    AVAILABLE = "available"
    SCHEDULED = "scheduled"
    UNAVAILABLE = "unavailable"
    EOL = "eol"


@dataclass
class Asset:
    """Represents an OT asset in the inventory."""

    name: str
    vendor: str
    model: str
    firmware_version: str
    cpe: str
    purdue_level: float
    network_zone: str
    exposure: NetworkExposure = NetworkExposure.ISOLATED
    patch_status: PatchStatus = PatchStatus.AVAILABLE
    location: str = ""
    asset_id: str = ""
    last_patched: str | None = None
    notes: str = ""

    def __post_init__(self):
        if isinstance(self.exposure, str):
            self.exposure = NetworkExposure(self.exposure.lower())
        if isinstance(self.patch_status, str):
            self.patch_status = PatchStatus(self.patch_status.lower())
        self.purdue_level = float(self.purdue_level)


@dataclass
class CVEEntry:
    """A CVE record from NVD."""

    cve_id: str
    description: str
    cvss_base_score: float
    cvss_vector: str
    severity: Severity
    published: str
    last_modified: str
    affected_versions: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    weaknesses: list[str] = field(default_factory=list)  # CWE IDs

    @property
    def nvd_url(self) -> str:
        return f"https://nvd.nist.gov/vuln/detail/{self.cve_id}"


@dataclass
class KEVEntry:
    """CISA Known Exploited Vulnerability entry."""

    cve_id: str
    vendor: str
    product: str
    vulnerability_name: str
    date_added: str
    due_date: str
    required_action: str
    known_ransomware_use: str = "Unknown"


@dataclass
class Finding:
    """A vulnerability finding tied to a specific asset."""

    asset: Asset
    cve: CVEEntry
    in_kev: bool = False
    kev_entry: KEVEntry | None = None
    ot_risk_score: float = 0.0
    ot_severity: Severity = Severity.NONE
    remediation: str = ""
    iec_62443_mappings: list[str] = field(default_factory=list)
    score_breakdown: dict = field(default_factory=dict)

    @property
    def finding_id(self) -> str:
        return f"{self.asset.asset_id or self.asset.name}_{self.cve.cve_id}"


@dataclass
class ScanResult:
    """Complete scan result for an inventory."""

    scan_id: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    total_assets: int = 0
    total_cves: int = 0
    total_kev_hits: int = 0
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def critical_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.ot_severity == Severity.CRITICAL]

    @property
    def high_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.ot_severity == Severity.HIGH]

    def summary(self) -> dict:
        severity_counts = {}
        for f in self.findings:
            sev = f.ot_severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        return {
            "scan_id": self.scan_id,
            "timestamp": self.timestamp,
            "total_assets": self.total_assets,
            "total_cves_found": self.total_cves,
            "kev_matches": self.total_kev_hits,
            "severity_distribution": severity_counts,
            "top_risk_findings": [
                {
                    "asset": f.asset.name,
                    "cve": f.cve.cve_id,
                    "ot_risk_score": round(f.ot_risk_score, 2),
                    "in_kev": f.in_kev,
                }
                for f in sorted(self.findings, key=lambda x: x.ot_risk_score, reverse=True)[:10]
            ],
        }
