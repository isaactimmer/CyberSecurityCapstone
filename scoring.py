"""
Composite Risk Scoring (epic #4, ticket #27)

The core IP of the project: collapse four independent signals into a single
prioritization number per vulnerability, so a "medium" CVSS on a crown-jewel-
adjacent asset can out-rank a "critical" CVSS sitting on the network edge.

Inputs (one vulnerability row = one asset-affecting CVE):
    cvss_score       float 0-10   CVSS base score (severity of the flaw itself)
    epss_score       float 0-1    EPSS probability the CVE is exploited in the wild
    kev_flag         bool         True if the CVE is on CISA's KEV catalog
    importance_tier  str          asset importance from the graph (#17):
                                  critical / high / medium / low

Each input is normalized to 0-1, combined as a weighted sum, then scaled to a
0-100 composite so the output reads like a familiar risk score.

    composite = 100 * (
          w_cvss       * (cvss_score / 10)
        + w_epss       * epss_score
        + w_kev        * (1.0 if kev_flag else 0.0)
        + w_importance * TIER_WEIGHTS[importance_tier]
    )

Default component weights (sum to 1.0) and tier weights live in DEFAULT_WEIGHTS
below and are documented alongside the ticket. They are deliberately exposed as
a `ScoringWeights` object so the adjustable-weighting (#28) and security-lead
override (#29) stories can tune them without touching the formula.

Run:
    python scoring.py merged_vulnerabilities_with_tiers.csv
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field, replace
from pathlib import Path

import pandas as pd

# Missing CVSS/EPSS values contribute nothing rather than crashing the formula;
# a CVE we know nothing about should not inflate its own score.
_MISSING = 0.0

# How much each asset importance tier counts toward the score, normalized 0-1.
# critical (crown jewel / one hop away) fully weighted; low barely registers.
DEFAULT_TIER_WEIGHTS: dict[str, float] = {
    "critical": 1.0,
    "high": 0.75,
    "medium": 0.5,
    "low": 0.25,
}


@dataclass(frozen=True)
class ScoringWeights:
    """
    Component and tier weights for the composite formula.

    The four component weights (cvss, epss, kev, importance) must sum to 1.0 so
    the composite stays on a clean 0-100 scale. `tier_weights` maps each
    importance tier to its normalized 0-1 contribution.
    """

    cvss: float = 0.25
    epss: float = 0.30
    kev: float = 0.20
    importance: float = 0.25
    tier_weights: dict[str, float] = field(
        default_factory=lambda: dict(DEFAULT_TIER_WEIGHTS)
    )

    def __post_init__(self) -> None:
        components = {
            "cvss": self.cvss,
            "epss": self.epss,
            "kev": self.kev,
            "importance": self.importance,
        }
        negatives = {name: w for name, w in components.items() if w < 0}
        if negatives:
            # A negative weight would invert a signal — e.g. a negative KEV
            # weight makes an actively-exploited CVE score *lower*, breaking the
            # invariant that KEV never reduces risk (ticket #30).
            raise ValueError(f"Component weights must be non-negative, got {negatives}")

        total = sum(components.values())
        if abs(total - 1.0) > 1e-9:
            raise ValueError(
                f"Component weights must sum to 1.0, got {total:.4f} ({components})"
            )

    def with_weights(self, **changes: float) -> "ScoringWeights":
        """Return a copy with some component weights overridden (for #28/#29)."""
        return replace(self, **changes)


DEFAULT_WEIGHTS = ScoringWeights()


def _normalize_cvss(cvss_score: float | None) -> float:
    if cvss_score is None or pd.isna(cvss_score):
        return _MISSING
    return max(0.0, min(float(cvss_score), 10.0)) / 10.0


def _normalize_epss(epss_score: float | None) -> float:
    if epss_score is None or pd.isna(epss_score):
        return _MISSING
    return max(0.0, min(float(epss_score), 1.0))


def _normalize_tier(importance_tier: str | None, tier_weights: dict[str, float]) -> float:
    if importance_tier is None or (isinstance(importance_tier, float) and pd.isna(importance_tier)):
        return _MISSING
    key = str(importance_tier).strip().lower()
    if key not in tier_weights:
        raise ValueError(
            f"Unknown importance tier {importance_tier!r}; "
            f"expected one of {sorted(tier_weights)}"
        )
    return tier_weights[key]


def compute_score(
    cvss_score: float | None,
    epss_score: float | None,
    kev_flag: bool,
    importance_tier: str | None,
    weights: ScoringWeights = DEFAULT_WEIGHTS,
) -> float:
    """
    Composite risk score for a single vulnerability, on a 0-100 scale.

    See the module docstring for the formula. Missing CVSS/EPSS values count as
    zero; an unrecognized importance tier raises rather than scoring silently.
    """
    cvss_norm = _normalize_cvss(cvss_score)
    epss_norm = _normalize_epss(epss_score)
    kev_norm = 1.0 if bool(kev_flag) else 0.0
    tier_norm = _normalize_tier(importance_tier, weights.tier_weights)

    composite = (
        weights.cvss * cvss_norm
        + weights.epss * epss_norm
        + weights.kev * kev_norm
        + weights.importance * tier_norm
    )
    return round(100.0 * composite, 2)


def score_dataframe(
    df: pd.DataFrame,
    weights: ScoringWeights = DEFAULT_WEIGHTS,
    score_column: str = "composite_score",
) -> pd.DataFrame:
    """
    Add a composite-score column to a merged vulnerability DataFrame.

    Expects the columns produced upstream: `cvss_score`, `epss_score`,
    `kev_flag`, and `importance_tier` (the asset tier joined onto each CVE).
    Returns a new DataFrame sorted by composite score, highest risk first.
    """
    required = {"cvss_score", "epss_score", "kev_flag", "importance_tier"}
    missing = required - set(df.columns)
    if missing:
        raise KeyError(
            f"DataFrame is missing required column(s) for scoring: {sorted(missing)}"
        )

    scored = df.copy()
    scored[score_column] = scored.apply(
        lambda row: compute_score(
            row["cvss_score"],
            row["epss_score"],
            row["kev_flag"],
            row["importance_tier"],
            weights,
        ),
        axis=1,
    )
    return scored.sort_values(score_column, ascending=False).reset_index(drop=True)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compute composite risk scores for a merged vulnerability CSV."
    )
    parser.add_argument(
        "input",
        help="CSV with cvss_score, epss_score, kev_flag, importance_tier columns.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Optional CSV path to write the scored table to.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    frame = pd.read_csv(args.input)
    scored = score_dataframe(frame)

    print(f"Scored {len(scored)} vulnerabilities. Top 10 by composite risk:\n")
    preview_cols = [
        c
        for c in ("cve_id", "cvss_score", "epss_score", "kev_flag", "importance_tier", "composite_score")
        if c in scored.columns
    ]
    print(scored[preview_cols].head(10).to_string(index=False))

    if args.output:
        scored.to_csv(args.output, index=False)
        print(f"\nSaved scored table to {args.output}")
