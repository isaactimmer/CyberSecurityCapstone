"""
ILP Optimal Comparison (epic #5, ticket #35 — STRETCH)

The greedy optimizer (#32) is fast and, with constant-within-pool effort,
provably at least as good as the severity baseline — but it is still a heuristic
in the general (variable-effort) case. This module computes the *mathematically
optimal* plan with Integer Linear Programming (PuLP) so we can measure exactly
how much, if anything, greedy leaves on the table.

The problem is a 0/1 multi-knapsack: choose a subset of fixes maximising total
composite risk reduction, subject to each pool's total effort staying within its
capacity. Each fix belongs to exactly one pool, so the pool constraints are
independent — the ILP just solves them jointly and optimally.

PuLP is an optional dependency (it is a *stretch* ticket): importing this module
raises if PuLP is not installed, and its tests skip in that case. Nothing in the
required Sprint-2 path imports it.

Run:
    python optimizer_ilp.py merged_vulnerabilities_with_scores.csv
"""
from __future__ import annotations

import argparse

import pandas as pd

try:
    import pulp
except ImportError as exc:  # pragma: no cover - exercised only without pulp
    raise ImportError(
        "optimizer_ilp requires the optional 'pulp' package. "
        "Install it with `py -m pip install pulp` to run the ILP comparison (#35)."
    ) from exc

from capacity import CapacityPool, default_pools
from optimizer import (
    EFFORT_COLUMN,
    POOL_COLUMN,
    SCORE_COLUMN,
    RemediationPlan,
    validate_optimizer_input,
)


def ilp_optimize(
    df: pd.DataFrame,
    pools: dict[str, CapacityPool] | None = None,
) -> RemediationPlan:
    """
    The mathematically optimal capacity-aware plan via ILP.

    Maximises total composite risk reduction subject to each pool's effort not
    exceeding its capacity. Returns the same `RemediationPlan` shape as the
    greedy optimizer so the two are directly comparable.
    """
    pools = pools if pools is not None else default_pools()
    validate_optimizer_input(df, order_column=SCORE_COLUMN)

    work = df.reset_index(drop=True)
    problem = pulp.LpProblem("capacity_aware_remediation", pulp.LpMaximize)

    # One binary decision per fix: schedule it (1) or not (0).
    take = {
        i: pulp.LpVariable(f"take_{i}", cat="Binary")
        for i in work.index
        # A fix whose pool the team does not staff can never be scheduled.
        if work.at[i, POOL_COLUMN] in pools
    }

    problem += pulp.lpSum(
        float(work.at[i, SCORE_COLUMN]) * take[i] for i in take
    ), "total_risk_reduction"

    for name, pool in pools.items():
        members = [i for i in take if work.at[i, POOL_COLUMN] == name]
        problem += (
            pulp.lpSum(float(work.at[i, EFFORT_COLUMN]) * take[i] for i in members)
            <= float(pool.capacity),
            f"capacity_{name}",
        )

    problem.solve(pulp.PULP_CBC_CMD(msg=0))

    chosen = [i for i in take if take[i].value() is not None and take[i].value() > 0.5]
    items = (
        work.loc[chosen]
        .sort_values(SCORE_COLUMN, ascending=False)
        .reset_index(drop=True)
    )
    total = float(items[SCORE_COLUMN].sum()) if len(items) else 0.0
    consumed = {
        name: float(
            items.loc[items[POOL_COLUMN] == name, EFFORT_COLUMN].sum()
        )
        for name in pools
    }
    return RemediationPlan(
        items=items, total_risk_reduction=total, consumed=consumed, pools=pools
    )


def greedy_gap(greedy: RemediationPlan, optimal: RemediationPlan) -> float:
    """
    Percent of the optimal risk reduction that greedy captures short of optimal:

        (optimal_total - greedy_total) / optimal_total * 100

    0.0 means greedy matched the optimum; a small positive number quantifies the
    heuristic's cost. Returns 0.0 when the optimal plan removed no risk.
    """
    opt = optimal.total_risk_reduction
    if opt <= 0.0:
        return 0.0
    return (opt - greedy.total_risk_reduction) / opt * 100.0


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare the greedy optimizer against the ILP optimum (#35)."
    )
    parser.add_argument("input", help="CSV of scored vulnerabilities.")
    return parser.parse_args()


if __name__ == "__main__":
    from optimizer import greedy_optimize, load_ready_frame

    args = _parse_args()
    data = load_ready_frame(args.input)
    pools = default_pools()

    greedy = greedy_optimize(data, pools)
    optimal = ilp_optimize(data, pools)
    gap = greedy_gap(greedy, optimal)

    print(f"Greedy   : risk reduced {greedy.total_risk_reduction:,.1f}")
    print(f"ILP optim: risk reduced {optimal.total_risk_reduction:,.1f}")
    print(f"\nGreedy is within {gap:.2f}% of the mathematical optimum.")
