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

Which pool a fix draws from is derived from the *kind* of software it affects —
the asset's `vendor` (#49/#51): network/security/DB/storage/mail infra needs a
scheduled change window, apps/web/dev work is AppSec, and the rest is routine
patching. See `pool_for_vendor`. Rows with no vendor fall back to a deterministic
hash stand-in (`_pool_for_cve`). The vendor->pool rules are a documented
modelling heuristic (POC-assumptions ADR, #54), not a per-CVE ground truth.

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


# Which work-pool a fix draws from, derived from the *kind* of software (its
# vendor/product), which is a real signal from the asset graph (#49/#51):
#   - network gear, security appliances, databases, storage, mail/DNS infra ->
#     change_window: prod-impacting, reboot-y work that needs a scheduled slot.
#   - applications, web servers, dev/CI, containers, libraries -> appsec: code,
#     dependency, and config fixes owned by application security.
#   - everything else (OS, endpoints) -> patching: routine package/OS updates.
# Checked in priority order; first match wins, default is patching. This is a
# documented modelling heuristic (see the POC-assumptions ADR, #54), not a claim
# about any individual CVE's true remediation path.
_POOL_VENDOR_KEYWORDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        POOL_CHANGE_WINDOW,
        (
            "cisco", "fortinet", "palo alto", "f5", "haproxy", "aruba", "juniper",
            "oracle database", "netapp", "veeam", "sap", "exchange", "isc bind",
            "bind", "dhcp", "firewall", "router", "storage", "vmware",
        ),
    ),
    (
        POOL_APPSEC,
        (
            "apache", "tomcat", "nginx", "kong", "kubernetes", "docker", "jenkins",
            "jira", "confluence", "atlassian", "elasticsearch", "grafana", "splunk",
            "sharepoint", "mosquitto", "wordpress", "openssl", "http server", "web",
        ),
    ),
)


def pool_for_vendor(vendor: object) -> str:
    """
    Map an asset's vendor/product to the capacity pool its fixes draw from.

    Keyword-matched in priority order (change_window, then appsec), defaulting to
    patching. Case-insensitive and deterministic, so the assignment is explainable
    from the software rather than a hash.
    """
    text = str(vendor).strip().lower()
    for pool, keywords in _POOL_VENDOR_KEYWORDS:
        if any(kw in text for kw in keywords):
            return pool
    return POOL_PATCHING


def _pool_for_cve(cve_id: object, pool_names: list[str]) -> str:
    """
    Deterministically map a CVE id to one pool.

    STAND-IN fallback for rows with no `vendor` (asset) signal. We hash the id so
    the assignment is stable across runs but make no claim it is the true pool.
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
    has_vendor = "vendor" in out.columns

    def _assign_pool(row: pd.Series) -> str:
        # Prefer the real asset-role signal (the software's vendor); fall back to
        # the deterministic hash stand-in when a row carries no vendor.
        if has_vendor and pd.notna(row["vendor"]):
            pool = pool_for_vendor(row["vendor"])
            if pool in pool_effort:
                return pool
        return _pool_for_cve(row["cve_id"], pool_names)

    out["pool"] = out.apply(_assign_pool, axis=1)
    out["effort"] = out["pool"].map(pool_effort).astype(float)
    return out
