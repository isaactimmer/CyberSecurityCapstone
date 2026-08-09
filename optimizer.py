"""
Capacity-Aware Optimizer (epic #5, tickets #32/#33/#34)

Given the scored vulnerabilities (#27) and the team's capacity pools (#31), this
module answers the proposal's core question: *given our limited time, what order
of fixes gives the most risk reduction?*

Three pieces, all working over the same scored dataset and the same pools so
their outputs are directly comparable:

    greedy_optimize   (#32)  fill each pool by best risk-reduction/effort ratio
    severity_baseline (#33)  the "before" picture: fill by CVSS severity only
    improvement_metric(#34)  headline % extra risk reduction of optimizer/baseline

Each plan is a `RemediationPlan`: the ordered list of chosen fixes, the total
risk it removes, and how much of each pool it consumed.

"Risk reduction" is a fix's composite score — fixing the CVE removes that much
risk. Both plans measure risk removed with the *same* composite metric; they
differ only in the order they pick fixes. That is what makes the comparison
apples-to-apples: the baseline is not penalised on the metric, only on strategy.

Why the optimizer can never do worse than the baseline (the #34 invariant):
effort is constant within each pool (see `capacity`). So inside a pool, ranking
by ratio is the same as ranking by composite score, and a pool that holds k
fixes takes the k highest-scoring ones. The sum of the k largest scores is
>= any other k-subset the baseline could pick from that pool, so per pool — and
therefore overall — the optimizer's total risk reduction dominates the
baseline's. With variable per-item effort this guarantee weakens to a heuristic;
that gap is exactly what the ILP stretch ticket (#35) measures.

Run:
    python optimizer.py merged_vulnerabilities_with_scores.csv
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass

import pandas as pd

from capacity import CapacityPool, assign_remediation_effort, default_pools

SCORE_COLUMN = "composite_score"
SEVERITY_COLUMN = "cvss_score"
POOL_COLUMN = "pool"
EFFORT_COLUMN = "effort"


@dataclass
class RemediationPlan:
    """
    The output of a fill strategy over the capacity pools.

    items                 selected fixes, in the order the strategy chose them
    total_risk_reduction  sum of the selected fixes' composite scores
    consumed              effort used per pool name
    pools                 the pools the plan was built against (for the caps)
    """

    items: pd.DataFrame
    total_risk_reduction: float
    consumed: dict[str, float]
    pools: dict[str, CapacityPool]


def validate_optimizer_input(df: pd.DataFrame, order_column: str) -> None:
    """Raise KeyError unless `df` has the columns a fill strategy needs. Public
    so the ILP stretch module (#35) can reuse it without importing internals."""
    required = {order_column, SCORE_COLUMN, POOL_COLUMN, EFFORT_COLUMN}
    missing = required - set(df.columns)
    if missing:
        raise KeyError(
            f"Optimizer input is missing required column(s): {sorted(missing)}"
        )


def _order_by(
    df: pd.DataFrame, sort_cols: list[str], ascending: list[bool]
) -> pd.DataFrame:
    """Sort by `sort_cols`, always tie-breaking on `cve_id` (ascending) when
    present so a strategy's ordering is deterministic across runs."""
    cols = list(sort_cols)
    asc = list(ascending)
    if "cve_id" in df.columns:
        cols.append("cve_id")
        asc.append(True)
    return df.sort_values(cols, ascending=asc)


def _fill_pools(
    df: pd.DataFrame,
    pools: dict[str, CapacityPool],
    order: pd.DataFrame,
) -> RemediationPlan:
    """
    Walk `order` (already sorted by a strategy) and greedily take each fix if its
    pool still has room, never exceeding any pool's capacity.
    """
    remaining = {name: float(pool.capacity) for name, pool in pools.items()}
    consumed = {name: 0.0 for name in pools}
    chosen_index: list = []  # DataFrame index labels of the selected fixes

    for idx, row in order.iterrows():
        pool_name = row[POOL_COLUMN]
        if pool_name not in remaining:
            # A fix whose pool the team does not staff cannot be scheduled.
            continue
        effort = float(row[EFFORT_COLUMN])
        if effort <= remaining[pool_name] + 1e-9:
            remaining[pool_name] -= effort
            consumed[pool_name] += effort
            chosen_index.append(idx)

    items = df.loc[chosen_index].reset_index(drop=True)
    total = float(items[SCORE_COLUMN].sum()) if len(items) else 0.0
    return RemediationPlan(
        items=items, total_risk_reduction=total, consumed=consumed, pools=pools
    )


def greedy_optimize(
    df: pd.DataFrame,
    pools: dict[str, CapacityPool] | None = None,
) -> RemediationPlan:
    """
    Build the capacity-aware plan (#32).

    Orders every fix by risk-reduction-per-effort ratio (composite / effort),
    highest first, and fills each pool until adding the next fix would exceed its
    capacity. Ties break by higher raw score, then by cve_id for determinism.
    """
    pools = pools if pools is not None else default_pools()
    validate_optimizer_input(df, order_column=SCORE_COLUMN)

    work = df.copy()
    work["_ratio"] = work[SCORE_COLUMN] / work[EFFORT_COLUMN]
    order = _order_by(work, ["_ratio", SCORE_COLUMN], [False, False])

    return _fill_pools(df, pools, order)


def severity_baseline(
    df: pd.DataFrame,
    pools: dict[str, CapacityPool] | None = None,
) -> RemediationPlan:
    """
    Build the naive "before" plan (#33): fill the same pools by CVSS severity
    only — no EPSS, KEV, importance, or composite signal in the ordering.

    The risk it removes is still measured with the composite metric, so the plan
    is directly comparable to the optimizer's.
    """
    pools = pools if pools is not None else default_pools()
    validate_optimizer_input(df, order_column=SEVERITY_COLUMN)

    order = _order_by(df.copy(), [SEVERITY_COLUMN], [False])

    return _fill_pools(df, pools, order)


def improvement_metric(
    optimized: RemediationPlan,
    baseline: RemediationPlan,
) -> float:
    """
    Headline result (#34): percent extra risk reduction the optimizer buys over
    the baseline, from both plans' actual totals.

        (optimizer_total - baseline_total) / baseline_total * 100

    Returns 0.0 when the baseline removed no risk (nothing to improve on).
    """
    base = baseline.total_risk_reduction
    opt = optimized.total_risk_reduction
    if base <= 0.0:
        return 0.0
    return (opt - base) / base * 100.0


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the capacity-aware optimizer vs. the severity baseline."
    )
    parser.add_argument(
        "input",
        help="CSV of scored vulnerabilities (needs composite_score, cvss_score).",
    )
    return parser.parse_args()


def load_ready_frame(path: str) -> pd.DataFrame:
    """Read a scored CSV and ensure pool/effort columns exist (stand-in join)."""
    frame = pd.read_csv(path)
    if POOL_COLUMN not in frame.columns or EFFORT_COLUMN not in frame.columns:
        frame = assign_remediation_effort(frame)
    return frame


if __name__ == "__main__":
    args = _parse_args()
    data = load_ready_frame(args.input)
    pools = default_pools()

    optimized = greedy_optimize(data, pools)
    baseline = severity_baseline(data, pools)
    lift = improvement_metric(optimized, baseline)

    print("Capacity pools:")
    for name, pool in pools.items():
        print(f"  {name:<14} {pool.capacity:g} {pool.unit}")
    print()
    print(f"Optimizer  : {len(optimized.items):>4} fixes, "
          f"risk reduced {optimized.total_risk_reduction:,.1f}")
    print(f"Baseline   : {len(baseline.items):>4} fixes, "
          f"risk reduced {baseline.total_risk_reduction:,.1f}")
    print(f"\nOptimizer buys {lift:.1f}% more risk reduction than the "
          f"severity-first baseline.")
