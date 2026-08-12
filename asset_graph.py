"""
Asset Graph Setup (epic #2)
Turns the hand-authored asset map (assets.csv) into a networkx graph, computes
each asset's hop-distance to the crown jewel, and buckets that distance into
importance tiers that feed the risk-scoring formula.

Pipeline:
    assets.csv
      -> load_assets()          # clean DataFrame                (#14 schema)
      -> load_asset_graph()     # networkx.Graph                 (#15)
      -> compute_hop_distances()# {asset_id: hops-to-crown-jewel}(#16)
      -> assign_importance_tiers()  # {asset_id: tier}           (#17)
    build_asset_table() runs the whole chain into one DataFrame.

Run:
    python asset_graph.py                 # prints the asset table
    python asset_graph.py --output asset_importance.csv
"""
from __future__ import annotations

import argparse
from pathlib import Path

import networkx as nx
import pandas as pd

DEFAULT_ASSET_CSV = "assets.csv"
CONNECTION_SEP = "|"

# Default hop-distance -> importance tier boundaries (inclusive upper bounds).
# 0-1 = critical, 2-3 = high, 4-5 = medium, 6+ = low. Cutoffs are adjustable:
# pass a different ordered tuple to assign_importance_tiers / tier_for_distance
# so a security lead can override the graph's read.
DEFAULT_TIER_CUTOFFS: tuple[tuple[int, str], ...] = (
    (1, "critical"),
    (3, "high"),
    (5, "medium"),
)
DEFAULT_TIER_LABEL = "low"


def parse_connections(raw: object) -> list[str]:
    """Split a pipe-separated connections cell into a clean list of asset ids."""
    if raw is None or (isinstance(raw, float) and pd.isna(raw)):
        return []
    return [part.strip() for part in str(raw).split(CONNECTION_SEP) if part.strip()]


# Back-compat alias: the parser was private before the dashboard needed it (the
# view/logic split — see dashboard.asset_map_data). Keep the old name working.
_parse_connections = parse_connections


# ---------------------------------------------------------------------------
# #14 — read the hand-authored asset CSV into a clean DataFrame
# ---------------------------------------------------------------------------
def load_assets(csv_path: str | Path = DEFAULT_ASSET_CSV) -> pd.DataFrame:
    """
    Load assets.csv into a DataFrame with a normalized schema:
    asset_id (str), name (str), criticality (str), crown_jewel (bool),
    connections (list[str]).
    """
    df = pd.read_csv(csv_path, dtype=str).fillna("")
    df["asset_id"] = df["asset_id"].str.strip()
    df["crown_jewel"] = (
        df["crown_jewel"].str.strip().str.lower().isin(("true", "1", "yes"))
    )
    df["connections"] = df["connections"].apply(parse_connections)
    return df


# ---------------------------------------------------------------------------
# #15 — build the networkx graph from the asset DataFrame
# ---------------------------------------------------------------------------
def build_graph(df: pd.DataFrame) -> nx.Graph:
    """
    Build an undirected graph: nodes = assets (carrying name/criticality/
    crown_jewel attributes), edges = connections. Undirected edges listed on
    both endpoints collapse to a single edge.

    Raises ValueError on referential-integrity problems (a connection to an
    unknown asset) or if the CSV does not contain exactly one crown jewel.
    """
    graph = nx.Graph()
    ids = set(df["asset_id"])

    if df["asset_id"].duplicated().any():
        dupes = sorted(df.loc[df["asset_id"].duplicated(), "asset_id"])
        raise ValueError(f"Duplicate asset_id(s) in CSV: {dupes}")

    for _, row in df.iterrows():
        graph.add_node(
            row["asset_id"],
            name=row["name"],
            criticality=row["criticality"],
            crown_jewel=bool(row["crown_jewel"]),
        )

    for _, row in df.iterrows():
        for neighbor in row["connections"]:
            if neighbor not in ids:
                raise ValueError(
                    f"Asset '{row['asset_id']}' connects to unknown asset '{neighbor}'"
                )
            graph.add_edge(row["asset_id"], neighbor)

    find_crown_jewel(graph)  # validates exactly one crown jewel, or raises

    return graph


def load_asset_graph(csv_path: str | Path = DEFAULT_ASSET_CSV) -> nx.Graph:
    """Convenience: load the CSV and build the graph in one call."""
    return build_graph(load_assets(csv_path))


def find_crown_jewel(graph: nx.Graph) -> str:
    """Return the id of the single crown-jewel node."""
    crown_jewels = [n for n, d in graph.nodes(data=True) if d.get("crown_jewel")]
    if len(crown_jewels) != 1:
        raise ValueError(
            f"Expected exactly one crown jewel, found {len(crown_jewels)}: {crown_jewels}"
        )
    return crown_jewels[0]


# ---------------------------------------------------------------------------
# #16 — shortest-path hop-distance from every asset to the crown jewel
# ---------------------------------------------------------------------------
def compute_hop_distances(
    graph: nx.Graph, crown_jewel: str | None = None
) -> dict[str, int]:
    """
    Return {asset_id: hops-to-crown-jewel} using BFS shortest paths. Every node
    must be reachable from the crown jewel; a disconnected asset would get no
    (null) distance, so we raise instead of returning a silently incomplete map.
    """
    if crown_jewel is None:
        crown_jewel = find_crown_jewel(graph)

    distances = nx.single_source_shortest_path_length(graph, crown_jewel)

    unreachable = set(graph.nodes) - set(distances)
    if unreachable:
        raise ValueError(
            "These assets have no path to the crown jewel "
            f"'{crown_jewel}': {sorted(unreachable)}"
        )
    return distances


# ---------------------------------------------------------------------------
# #17 — bucket hop-distance into importance tiers
# ---------------------------------------------------------------------------
def tier_for_distance(
    distance: int,
    cutoffs: tuple[tuple[int, str], ...] = DEFAULT_TIER_CUTOFFS,
    default_label: str = DEFAULT_TIER_LABEL,
) -> str:
    """
    Map a single hop-distance to a tier label. `cutoffs` is an ordered sequence
    of (inclusive-max-distance, label); the first bucket the distance falls into
    wins, and anything beyond the last cutoff gets `default_label`.
    """
    for max_distance, label in cutoffs:
        if distance <= max_distance:
            return label
    return default_label


def assign_importance_tiers(
    distances: dict[str, int],
    cutoffs: tuple[tuple[int, str], ...] = DEFAULT_TIER_CUTOFFS,
    default_label: str = DEFAULT_TIER_LABEL,
) -> dict[str, str]:
    """Map every asset's hop-distance to its importance tier."""
    return {
        asset_id: tier_for_distance(distance, cutoffs, default_label)
        for asset_id, distance in distances.items()
    }


# ---------------------------------------------------------------------------
# Full pipeline — one table with distances and tiers attached
# ---------------------------------------------------------------------------
def build_asset_table(
    csv_path: str | Path = DEFAULT_ASSET_CSV,
    cutoffs: tuple[tuple[int, str], ...] = DEFAULT_TIER_CUTOFFS,
    default_label: str = DEFAULT_TIER_LABEL,
) -> pd.DataFrame:
    """
    Run the whole chain and return a DataFrame with one row per asset plus
    computed `hop_distance` and `importance_tier` columns, sorted crown-jewel
    outward (closest/most-important first).
    """
    df = load_assets(csv_path)
    graph = build_graph(df)
    distances = compute_hop_distances(graph)
    tiers = assign_importance_tiers(distances, cutoffs, default_label)

    table = df.copy()
    table["hop_distance"] = table["asset_id"].map(distances)
    table["importance_tier"] = table["asset_id"].map(tiers)
    table["connections"] = table["connections"].apply(CONNECTION_SEP.join)
    return table.sort_values(["hop_distance", "asset_id"]).reset_index(drop=True)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build the asset graph and compute hop-distance importance tiers."
    )
    parser.add_argument(
        "--assets", default=DEFAULT_ASSET_CSV, help="Path to the asset CSV."
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Optional CSV path to write the asset importance table to.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    table = build_asset_table(args.assets)

    crown_jewel = find_crown_jewel(load_asset_graph(args.assets))
    print(f"Crown jewel: {crown_jewel}")
    print(f"{len(table)} assets loaded\n")
    print(
        table[
            ["asset_id", "criticality", "hop_distance", "importance_tier"]
        ].to_string(index=False)
    )

    if args.output:
        table.to_csv(args.output, index=False)
        print(f"\nSaved asset importance table to {args.output}")
