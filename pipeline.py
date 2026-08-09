"""
Fulcrum pipeline — end-to-end wiring (epic #47, story #52)

Ties the real seams together into one runnable flow, on live/cached data instead
of the old stand-ins:

    asset graph (assets.csv, #49)
      -> CVE->asset join by vendor keyword (cve_asset_map, #50)
      -> composite scoring (scoring, epic #4)
      -> capacity pool/effort by asset role (capacity, #51)
      -> capacity-aware optimizer vs. severity baseline (optimizer, epic #5)

`build_plan` is pure — a fixture DataFrame in, plans out — so it is the primary
test seam. `scan_environment` is the only I/O (it pulls each asset vendor's CVEs,
cached to disk). `run` is scan + plan for the CLI and the dashboard.

Run:
    python pipeline.py                 # scan assets.csv, print optimizer vs baseline
    python pipeline.py --max-results 500
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass

import pandas as pd

import capacity
import cve_asset_map
import optimizer
import scoring
from optimizer import RemediationPlan
from scoring import ScoringWeights


@dataclass
class PlanResult:
    """The full output of a planning run — everything the dashboard reads."""

    scored: pd.DataFrame          # every CVE with composite_score, pool, effort
    optimized: RemediationPlan    # capacity-aware plan
    baseline: RemediationPlan     # naive severity-first plan
    improvement: float            # headline % extra risk the optimizer removes


def build_plan(
    env_vulns: pd.DataFrame,
    *,
    weights: ScoringWeights = scoring.DEFAULT_WEIGHTS,
    pools: dict[str, capacity.CapacityPool] | None = None,
    pool_effort: dict[str, float] | None = None,
) -> PlanResult:
    """
    Score an environment's vulnerabilities and build both plans. Pure: no I/O.

    `env_vulns` needs the four scoring inputs (cvss_score, epss_score, kev_flag,
    importance_tier) plus `cve_id`; a `vendor` column drives asset-role pool
    assignment (otherwise the stand-in hash is used).
    """
    pools = pools if pools is not None else capacity.default_pools()

    scored = scoring.score_dataframe(env_vulns, weights)
    ready = capacity.assign_remediation_effort(scored, pools, pool_effort=pool_effort)

    optimized = optimizer.greedy_optimize(ready, pools)
    baseline = optimizer.severity_baseline(ready, pools)
    improvement = optimizer.improvement_metric(optimized, baseline)

    return PlanResult(
        scored=ready, optimized=optimized, baseline=baseline, improvement=improvement
    )


def scan_environment(
    asset_table: pd.DataFrame | None = None,
    *,
    asset_csv: str = "assets.csv",
    max_results: int = 200,
    use_cache: bool = True,
    fetch=None,
) -> pd.DataFrame:
    """
    Pull every asset vendor's CVEs and join importance tiers — the one I/O step.

    Pass `asset_table` to skip loading the CSV; inject `fetch` to avoid the
    network in tests.
    """
    if asset_table is None:
        import asset_graph

        asset_table = asset_graph.build_asset_table(asset_csv)

    return cve_asset_map.build_environment_vulnerabilities(
        asset_table, fetch=fetch, max_results=max_results, use_cache=use_cache
    )


def run(
    *,
    asset_csv: str = "assets.csv",
    max_results: int = 200,
    use_cache: bool = True,
    weights: ScoringWeights = scoring.DEFAULT_WEIGHTS,
    pools: dict[str, capacity.CapacityPool] | None = None,
) -> PlanResult:
    """Scan the environment and build the plan — the full flow for CLI/dashboard."""
    env = scan_environment(
        asset_csv=asset_csv, max_results=max_results, use_cache=use_cache
    )
    return build_plan(env, weights=weights, pools=pools)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the full Fulcrum pipeline on the asset environment."
    )
    parser.add_argument("--assets", default="assets.csv", help="Path to the asset CSV.")
    parser.add_argument(
        "--max-results", type=int, default=200,
        help="Max CVEs to pull per vendor from NVD.",
    )
    parser.add_argument(
        "--no-cache", action="store_true", help="Bypass the on-disk pull cache."
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    pools = capacity.default_pools()

    print(f"Scanning environment from {args.assets} ...")
    result = run(asset_csv=args.assets, max_results=args.max_results,
                 use_cache=not args.no_cache, pools=pools)

    print(f"\nScored {len(result.scored)} vulnerabilities across the environment.")
    print("Capacity pools:")
    for name, pool in pools.items():
        print(f"  {name:<14} {pool.capacity:g} {pool.unit}")
    print()
    print(f"Optimizer  : {len(result.optimized.items):>4} fixes, "
          f"risk reduced {result.optimized.total_risk_reduction:,.1f}")
    print(f"Baseline   : {len(result.baseline.items):>4} fixes, "
          f"risk reduced {result.baseline.total_risk_reduction:,.1f}")
    print(f"\nOptimizer buys {result.improvement:.1f}% more risk reduction than the "
          f"severity-first baseline.")
    print("\nNOTE: the asset environment is a modelled mid-sized company (assets.csv); "
          "NVD/EPSS/KEV data is real. See the POC-assumptions ADR.")
