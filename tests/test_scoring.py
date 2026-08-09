"""
Tests for Composite Risk Scoring (epic #4, ticket #27).

Covers the acceptance criteria: every row gets a composite score, the formula
runs on a full merged dataset without errors, and the headline property holds —
a "medium" CVSS can out-score a "critical" one once likelihood, KEV status, and
asset importance are folded in.
"""
import pandas as pd
import pytest

import scoring


# ---------------------------------------------------------------------------
# ScoringWeights — the tunable knobs (#28/#29 build on these)
# ---------------------------------------------------------------------------
class TestScoringWeights:
    def test_default_weights_sum_to_one(self):
        w = scoring.DEFAULT_WEIGHTS
        assert w.cvss + w.epss + w.kev + w.importance == pytest.approx(1.0)

    def test_rejects_weights_that_do_not_sum_to_one(self):
        with pytest.raises(ValueError):
            scoring.ScoringWeights(cvss=0.5, epss=0.5, kev=0.5, importance=0.5)

    def test_rejects_negative_weight(self):
        # A negative KEV weight would let KEV *lower* a score, breaking the
        # KEV-never-lower invariant (#30) once weighting (#28) is tunable.
        with pytest.raises(ValueError):
            scoring.ScoringWeights(cvss=0.5, epss=0.4, kev=-0.2, importance=0.3)

    def test_with_weights_returns_validated_copy(self):
        w = scoring.DEFAULT_WEIGHTS.with_weights(cvss=0.4, importance=0.1)
        assert w.cvss == 0.4 and w.importance == 0.1
        # original untouched (frozen dataclass)
        assert scoring.DEFAULT_WEIGHTS.cvss == 0.25

    def test_with_weights_still_validates_the_sum(self):
        with pytest.raises(ValueError):
            scoring.DEFAULT_WEIGHTS.with_weights(cvss=0.9)


# ---------------------------------------------------------------------------
# compute_score — the formula itself
# ---------------------------------------------------------------------------
class TestComputeScore:
    def test_all_max_inputs_score_100(self):
        score = scoring.compute_score(10.0, 1.0, True, "critical")
        assert score == pytest.approx(100.0)

    def test_min_inputs_hit_the_low_tier_floor_not_zero(self):
        score = scoring.compute_score(0.0, 0.0, False, "low")
        # Even a wholly-benign CVE keeps a small floor: it still sits on *some*
        # asset. low tier contributes 0.25 importance weight * 0.25 tier * 100.
        assert score == pytest.approx(6.25)

    def test_score_is_on_zero_to_100_scale(self):
        score = scoring.compute_score(7.5, 0.4, True, "high")
        assert 0.0 <= score <= 100.0

    def test_kev_flag_moves_the_score(self):
        without = scoring.compute_score(5.0, 0.1, False, "medium")
        with_kev = scoring.compute_score(5.0, 0.1, True, "medium")
        # KEV carries 0.20 weight => +20 points
        assert with_kev - without == pytest.approx(20.0)

    def test_medium_cvss_can_outrank_critical_cvss(self):
        # The headline claim: a modest CVSS on an important, actively-exploited
        # asset beats a severe CVSS that is unlikely and peripheral.
        modest_but_dangerous = scoring.compute_score(
            cvss_score=5.5, epss_score=0.90, kev_flag=True, importance_tier="critical"
        )
        severe_but_remote = scoring.compute_score(
            cvss_score=9.8, epss_score=0.01, kev_flag=False, importance_tier="low"
        )
        assert modest_but_dangerous > severe_but_remote

    def test_missing_cvss_and_epss_count_as_zero(self):
        score = scoring.compute_score(None, None, False, "low")
        assert score == pytest.approx(6.25)

    def test_nan_inputs_do_not_crash(self):
        score = scoring.compute_score(float("nan"), float("nan"), False, "high")
        # only the importance term survives: 0.25 * 0.75 * 100
        assert score == pytest.approx(18.75)

    def test_tier_is_case_insensitive(self):
        assert scoring.compute_score(5.0, 0.2, False, "Critical") == scoring.compute_score(
            5.0, 0.2, False, "critical"
        )

    def test_unknown_tier_raises(self):
        with pytest.raises(ValueError):
            scoring.compute_score(5.0, 0.2, False, "platinum")

    def test_out_of_range_cvss_is_clamped(self):
        assert scoring.compute_score(99.0, 0.0, False, "low") == scoring.compute_score(
            10.0, 0.0, False, "low"
        )


# ---------------------------------------------------------------------------
# score_dataframe — runs on the full merged dataset
# ---------------------------------------------------------------------------
def _sample_merged_frame() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {"cve_id": "CVE-A", "cvss_score": 9.8, "epss_score": 0.02, "kev_flag": False, "importance_tier": "low"},
            {"cve_id": "CVE-B", "cvss_score": 5.5, "epss_score": 0.90, "kev_flag": True, "importance_tier": "critical"},
            {"cve_id": "CVE-C", "cvss_score": 7.0, "epss_score": 0.30, "kev_flag": False, "importance_tier": "high"},
            {"cve_id": "CVE-D", "cvss_score": None, "epss_score": None, "kev_flag": False, "importance_tier": "medium"},
        ]
    )


class TestScoreDataframe:
    def test_every_row_gets_a_score(self):
        scored = scoring.score_dataframe(_sample_merged_frame())
        assert "composite_score" in scored.columns
        assert scored["composite_score"].notna().all()
        assert len(scored) == 4

    def test_output_is_sorted_highest_risk_first(self):
        scored = scoring.score_dataframe(_sample_merged_frame())
        scores = scored["composite_score"].tolist()
        assert scores == sorted(scores, reverse=True)
        # CVE-B (dangerous medium) should top CVE-A (remote critical)
        assert scored.iloc[0]["cve_id"] == "CVE-B"

    def test_does_not_mutate_input(self):
        frame = _sample_merged_frame()
        scoring.score_dataframe(frame)
        assert "composite_score" not in frame.columns

    def test_missing_required_column_raises(self):
        frame = _sample_merged_frame().drop(columns=["kev_flag"])
        with pytest.raises(KeyError):
            scoring.score_dataframe(frame)

    def test_custom_weights_change_the_ranking(self):
        # Weight importance to zero and CVSS heavily: the remote critical wins.
        cvss_heavy = scoring.ScoringWeights(cvss=0.9, epss=0.1, kev=0.0, importance=0.0)
        scored = scoring.score_dataframe(_sample_merged_frame(), weights=cvss_heavy)
        assert scored.iloc[0]["cve_id"] == "CVE-A"


# ---------------------------------------------------------------------------
# #28 — Adjustable weighting: weights are parameters, tuned to a company's appetite
# ---------------------------------------------------------------------------
class TestAdjustableWeighting:
    def test_defaults_reproduce_the_base_formula(self):
        # Passing the default weights explicitly must equal the no-args call, so
        # the tuning knobs never silently change the shipped formula (#28 AC).
        explicit = scoring.compute_score(6.0, 0.5, True, "high", scoring.DEFAULT_WEIGHTS)
        implicit = scoring.compute_score(6.0, 0.5, True, "high")
        assert explicit == implicit

    def test_weighting_exploitability_over_severity(self):
        # "Exploitability matters more to us than severity": crank EPSS weight up
        # and CVSS down, and a high-EPSS/low-CVSS CVE overtakes the reverse.
        appetite = scoring.ScoringWeights(cvss=0.10, epss=0.65, kev=0.0, importance=0.25)
        exploitable = scoring.compute_score(4.0, 0.95, False, "medium", appetite)
        severe = scoring.compute_score(9.5, 0.05, False, "medium", appetite)
        assert exploitable > severe

    def test_changing_any_single_weight_changes_the_score(self):
        base = scoring.compute_score(7.0, 0.4, True, "high")
        for change in ({"cvss": 0.4, "importance": 0.1}, {"epss": 0.4, "cvss": 0.15}):
            tuned = scoring.compute_score(
                7.0, 0.4, True, "high", scoring.DEFAULT_WEIGHTS.with_weights(**change)
            )
            assert tuned != base


# ---------------------------------------------------------------------------
# #30 — Scoring invariants against sample vulnerabilities
# ---------------------------------------------------------------------------
class TestScoringInvariants:
    @pytest.mark.parametrize("cvss", [0.0, 3.5, 7.0, 9.8])
    @pytest.mark.parametrize("epss", [0.0, 0.5, 1.0])
    @pytest.mark.parametrize("tier", ["critical", "high", "medium", "low"])
    def test_kev_never_scores_lower_than_identical_non_kev(self, cvss, epss, tier):
        # The headline invariant: flipping KEV on can only raise (never lower)
        # the score of an otherwise-identical vulnerability.
        non_kev = scoring.compute_score(cvss, epss, False, tier)
        kev = scoring.compute_score(cvss, epss, True, tier)
        assert kev >= non_kev

    def test_higher_severity_scores_higher_all_else_equal(self):
        low = scoring.compute_score(2.0, 0.3, False, "high")
        high = scoring.compute_score(9.0, 0.3, False, "high")
        assert high > low

    def test_more_important_asset_scores_higher_all_else_equal(self):
        peripheral = scoring.compute_score(6.0, 0.3, False, "low")
        crown = scoring.compute_score(6.0, 0.3, False, "critical")
        assert crown > peripheral
