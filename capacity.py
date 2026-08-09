"""
Capacity Pools (epic #5, ticket #31)

A security team does not have one generic pool of "hours available" — it has
several *distinct* kinds of work-time, and a given remediation can only draw
from the right one:

    patching        general/patching hours (routine OS & package updates)
    appsec          application-security hours (code fixes, dependency bumps)
    change_window   scheduled change-window slots (reboots, prod-impacting work)

Modelling these separately is what makes the remediation plan "capacity-aware"
instead of just a sorted list: the plan has to fit inside each pool, not spend
one big undifferentiated budget. The greedy optimizer (#32) and the naive
baseline (#33) both fill these same pools so their plans are comparable (#34).

Each pool holds a numeric `capacity` in its own `unit` of effort. A remediation
is described by two columns joined onto each scored CVE:

    pool     str    which pool the fix draws from
    effort   float  how much of that pool the fix consumes

Where a CVE's remediation truly lands (pool + effort) is a separate, not-yet-
built mapping — the same gap as the CVE->asset join. `assign_remediation_effort`
is a deterministic *stand-in* so the optimizer can run end-to-end; treat the
specific pool a CVE lands in as placeholder, not ground truth.

Effort is deliberately kept *constant within each pool*: this is what lets the
greedy optimizer guarantee it never does worse than the severity baseline (#34).
See `optimizer.greedy_optimize` for why.
"""
from __future__ import annotations

from dataclasses import dataclass

import pandas as pd

# Canonical pool names, referenced by the optimizer and its tests.
POOL_PATCHING = "patching"
POOL_APPSEC = "appsec"
POOL_CHANGE_WINDOW = "change_window"


@dataclass(frozen=True)
class CapacityPool:
    """
    One distinct kind of team work-time and how much of it is available.

    `capacity` is a numeric amount in `unit` (e.g. 40 hours, 8 slots). It is the
    hard ceiling a remediation plan may consume from this pool.
    """

    name: str
    capacity: float
    unit: str = "hours"

    def __post_init__(self) -> None:
        if self.capacity < 0:
            # A pool cannot hold less than zero work-time; a negative ceiling
            # would let the optimizer "spend" capacity it does not have.
            raise ValueError(
                f"Pool {self.name!r} capacity must be non-negative, got {self.capacity}"
            )


# Default capacities for a representative sprint. These are illustrative team
# budgets a security lead would tune per organisation; the units differ on
# purpose to show capacity is several separate pools, not one number.
DEFAULT_POOL_CAPACITY: dict[str, tuple[float, str]] = {
    POOL_PATCHING: (40.0, "hours"),
    POOL_APPSEC: (16.0, "hours"),
    POOL_CHANGE_WINDOW: (8.0, "slots"),
}

# Effort a single remediation consumes, held *constant within each pool*. A
# change-window fix (reboot in a scheduled slot) costs more of its scarcer pool
# than a routine patch costs of the plentiful patching pool.
DEFAULT_POOL_EFFORT: dict[str, float] = {
    POOL_PATCHING: 1.0,
    POOL_APPSEC: 2.0,
    POOL_CHANGE_WINDOW: 1.0,
}


def default_pools() -> dict[str, CapacityPool]:
    """The three distinct pools a security team actually works out of."""
    return {
        name: CapacityPool(name=name, capacity=cap, unit=unit)
        for name, (cap, unit) in DEFAULT_POOL_CAPACITY.items()
    }


def _pool_for_cve(cve_id: object, pool_names: list[str]) -> str:
    """
    Deterministically map a CVE id to one pool.

    STAND-IN: the real "which team fixes this, in which pool" mapping is a
    separate ticket. We hash the id so the assignment is stable across runs but
    make no claim it is the true pool for that CVE.
    """
    # Python's built-in hash is salted per-process, so use a stable digest.
    text = str(cve_id)
    digest = 0
    for ch in text:
        digest = (digest * 31 + ord(ch)) & 0xFFFFFFFF
    return pool_names[digest % len(pool_names)]


def assign_remediation_effort(
    df: pd.DataFrame,
    pools: dict[str, CapacityPool] | None = None,
    *,
    pool_effort: dict[str, float] | None = None,
) -> pd.DataFrame:
    """
    Join a `pool` and `effort` column onto each scored CVE (stand-in).

    Returns a new DataFrame; the input is not mutated. Effort is looked up per
    pool from `pool_effort`, so it is constant within a pool by construction.
    """
    if "cve_id" not in df.columns:
        raise KeyError("assign_remediation_effort requires a 'cve_id' column")

    pools = pools if pools is not None else default_pools()
    pool_effort = pool_effort if pool_effort is not None else dict(DEFAULT_POOL_EFFORT)

    pool_names = list(pools)
    missing_effort = [name for name in pool_names if name not in pool_effort]
    if missing_effort:
        raise KeyError(f"No effort defined for pool(s): {sorted(missing_effort)}")

    out = df.copy()
    out["pool"] = out["cve_id"].map(lambda c: _pool_for_cve(c, pool_names))
    out["effort"] = out["pool"].map(pool_effort).astype(float)
    return out
