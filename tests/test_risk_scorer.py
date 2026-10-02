"""OT risk scoring: CVSS base adjusted for Purdue level, exposure, patchability and KEV."""

from __future__ import annotations

import pytest
from conftest import make_asset, make_cve, make_finding

from config import OTRiskWeights
from models import Severity
from risk_scorer import OTRiskScorer


@pytest.fixture
def scorer() -> OTRiskScorer:
    return OTRiskScorer(OTRiskWeights())


def test_same_cve_scores_higher_on_a_level_1_plc_than_on_an_enterprise_host(scorer):
    cve = make_cve(score=6.0)

    plc, _ = scorer.score(make_asset(purdue_level=1, exposure="dmz", patch_status="scheduled"), cve, False)
    erp, _ = scorer.score(make_asset(purdue_level=4, exposure="dmz", patch_status="scheduled"), cve, False)

    assert plc == pytest.approx(6.0 * 1.5)
    assert erp == pytest.approx(6.0 * 0.8)


@pytest.mark.parametrize(
    ("purdue", "exposure", "patch", "in_kev", "expected"),
    [
        # 5.0 x Purdue x exposure x patch x KEV
        (1, "air-gapped", "available", False, 5.0 * 1.5 * 0.6 * 0.9),
        (2, "corporate", "unavailable", False, 5.0 * 1.2 * 1.1 * 1.3),
        (3, "dmz", "scheduled", False, 5.0),
        (3.5, "dmz", "scheduled", False, 5.0 * 0.9),  # OT DMZ weight
        (3, "isolated", "eol", True, 5.0 * 0.7 * 1.4 * 1.5),
    ],
)
def test_multipliers_compose(scorer, purdue, exposure, patch, in_kev, expected):
    asset = make_asset(purdue_level=purdue, exposure=exposure, patch_status=patch)

    score, breakdown = scorer.score(asset, make_cve(score=5.0), in_kev)

    assert score == pytest.approx(expected)
    assert breakdown["raw_score"] == pytest.approx(round(expected, 3))
    assert breakdown["in_kev"] is in_kev


def test_kev_listing_raises_the_score_by_the_kev_multiplier(scorer):
    asset = make_asset(purdue_level=3, exposure="dmz", patch_status="scheduled")
    cve = make_cve(score=4.0)

    without, _ = scorer.score(asset, cve, False)
    with_kev, breakdown = scorer.score(asset, cve, True)

    assert with_kev == pytest.approx(without * 1.5)
    assert breakdown["kev_weight"] == 1.5


def test_score_is_capped_at_ten_and_breakdown_says_so(scorer):
    asset = make_asset(purdue_level=0, exposure="internet", patch_status="eol")

    score, breakdown = scorer.score(asset, make_cve(score=9.8), True)

    assert breakdown["raw_score"] == pytest.approx(9.8 * 1.5 * 1.4 * 1.4 * 1.5, abs=1e-3)
    assert score == 10.0
    assert "capped at 10.0" in breakdown["formula"]


def test_uncapped_formula_does_not_claim_a_cap(scorer):
    _, breakdown = scorer.score(make_asset(purdue_level=3, exposure="dmz"), make_cve(score=5.0), False)

    assert "capped" not in breakdown["formula"]


def test_non_standard_purdue_level_falls_back_to_its_integer_level(scorer):
    # Level 1.5 is not in the weight table; it should use Level 1's weight, not 1.0
    score, breakdown = scorer.score(
        make_asset(purdue_level=1.5, exposure="dmz", patch_status="scheduled"), make_cve(score=5.0), False
    )

    assert breakdown["purdue_weight"] == 1.5
    assert score == pytest.approx(7.5)


def test_cve_without_cvss_is_not_scored(scorer):
    score, breakdown = scorer.score(make_asset(), make_cve(score=0.0), True)

    assert score == 0.0
    assert breakdown["note"] == "No CVSS score available"


@pytest.mark.parametrize(
    ("score", "severity"),
    [(10.0, Severity.CRITICAL), (8.5, Severity.CRITICAL), (8.49, Severity.HIGH), (6.5, Severity.HIGH),
     (6.49, Severity.MEDIUM), (4.0, Severity.MEDIUM), (3.99, Severity.LOW), (0.1, Severity.LOW),
     (0.0, Severity.NONE)],
)
def test_ot_severity_thresholds(scorer, score, severity):
    assert scorer.classify_ot_severity(score) is severity


def test_medium_cvss_on_exposed_unpatchable_plc_becomes_critical(scorer):
    """The point of OT scoring: a CVSS 6.5 'medium' is critical on an internet-exposed L1 PLC."""
    asset = make_asset(purdue_level=1, exposure="internet", patch_status="unavailable")
    finding = make_finding(asset=asset, cve=make_cve(score=6.5))

    assert finding.cve.severity is Severity.MEDIUM
    assert finding.ot_severity is Severity.CRITICAL
    assert finding.score_breakdown["exposure"] == "internet"


def test_custom_weights_are_respected():
    weights = OTRiskWeights(kev_multiplier=2.0, max_score=12.0)
    scorer = OTRiskScorer(weights)

    score, _ = scorer.score(make_asset(purdue_level=3, exposure="dmz", patch_status="scheduled"),
                            make_cve(score=7.0), True)

    assert score == pytest.approx(12.0)  # 14.0 raw, capped at the custom max
