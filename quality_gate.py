"""Quality gate for CI/CD pipeline integration.

Evaluates scan results against configurable security thresholds
and returns pass/fail status with violation details. Designed for
use in GitHub Actions, Azure DevOps, or any CI pipeline to block
deployments that don't meet OT security standards.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from models import ScanResult, Severity


@dataclass
class GatePolicy:
    """Configurable security thresholds for the quality gate."""
    max_critical: int = 0
    max_high: int = 5
    max_kev: int = 0
    max_mean_ot_score: float = 7.0
    max_single_ot_score: float = 9.5
    min_compliance_posture: str = "at_risk"  # compliant, at_risk, non_compliant
    fail_on_kev: bool = True


@dataclass
class GateViolation:
    """A single quality gate violation."""
    rule: str
    message: str
    actual: str
    threshold: str


@dataclass
class GateResult:
    """Outcome of a quality gate evaluation."""
    passed: bool
    violations: list[GateViolation] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "passed": self.passed,
            "summary": self.summary,
            "violation_count": len(self.violations),
            "violations": [
                {
                    "rule": v.rule,
                    "message": v.message,
                    "actual": v.actual,
                    "threshold": v.threshold,
                }
                for v in self.violations
            ],
            "warnings": self.warnings,
        }


# Compliance posture ranking (higher = stricter)
_POSTURE_RANK = {"compliant": 3, "at_risk": 2, "non_compliant": 1}


def evaluate(
    result: ScanResult,
    policy: Optional[GatePolicy] = None,
    compliance_posture: str = "",
) -> GateResult:
    """Evaluate scan results against a quality gate policy.

    Args:
        result: The scan result to evaluate.
        policy: Security thresholds. Uses defaults if not provided.
        compliance_posture: IEC 62443 compliance posture string
            (from compliance.assess_compliance). Empty string skips
            the compliance check.

    Returns:
        GateResult with pass/fail status and violation details.
    """
    if policy is None:
        policy = GatePolicy()

    violations: list[GateViolation] = []
    warnings: list[str] = []

    # Count severities
    critical_count = sum(
        1 for f in result.findings if f.ot_severity == Severity.CRITICAL
    )
    high_count = sum(
        1 for f in result.findings if f.ot_severity == Severity.HIGH
    )
    kev_count = sum(1 for f in result.findings if f.in_kev)
    scores = [f.ot_risk_score for f in result.findings]
    mean_score = round(sum(scores) / len(scores), 2) if scores else 0.0
    max_score = round(max(scores), 2) if scores else 0.0

    # Check critical findings
    if critical_count > policy.max_critical:
        violations.append(GateViolation(
            rule="max_critical",
            message=f"{critical_count} critical findings exceed threshold of {policy.max_critical}",
            actual=str(critical_count),
            threshold=str(policy.max_critical),
        ))

    # Check high findings
    if high_count > policy.max_high:
        violations.append(GateViolation(
            rule="max_high",
            message=f"{high_count} high findings exceed threshold of {policy.max_high}",
            actual=str(high_count),
            threshold=str(policy.max_high),
        ))

    # Check KEV findings
    if policy.fail_on_kev and kev_count > policy.max_kev:
        violations.append(GateViolation(
            rule="max_kev",
            message=f"{kev_count} CISA KEV findings exceed threshold of {policy.max_kev}",
            actual=str(kev_count),
            threshold=str(policy.max_kev),
        ))

    # Check mean OT score
    if scores and mean_score > policy.max_mean_ot_score:
        violations.append(GateViolation(
            rule="max_mean_ot_score",
            message=f"Mean OT risk score {mean_score} exceeds threshold of {policy.max_mean_ot_score}",
            actual=str(mean_score),
            threshold=str(policy.max_mean_ot_score),
        ))

    # Check single highest score
    if scores and max_score > policy.max_single_ot_score:
        violations.append(GateViolation(
            rule="max_single_ot_score",
            message=f"Highest OT risk score {max_score} exceeds threshold of {policy.max_single_ot_score}",
            actual=str(max_score),
            threshold=str(policy.max_single_ot_score),
        ))

    # Check compliance posture
    if compliance_posture:
        required_rank = _POSTURE_RANK.get(policy.min_compliance_posture, 0)
        actual_rank = _POSTURE_RANK.get(compliance_posture, 0)
        if actual_rank < required_rank:
            violations.append(GateViolation(
                rule="min_compliance_posture",
                message=f"Compliance posture '{compliance_posture}' does not meet minimum '{policy.min_compliance_posture}'",
                actual=compliance_posture,
                threshold=policy.min_compliance_posture,
            ))

    # Warnings (informational, don't fail the gate)
    if result.errors:
        warnings.append(f"{len(result.errors)} scan error(s) encountered")
    if not result.findings:
        warnings.append("No findings in scan results — verify inventory is correct")

    passed = len(violations) == 0
    summary = (
        f"PASSED — {len(result.findings)} findings within policy"
        if passed
        else f"FAILED — {len(violations)} violation(s): {', '.join(v.rule for v in violations)}"
    )

    return GateResult(
        passed=passed,
        violations=violations,
        warnings=warnings,
        summary=summary,
    )
