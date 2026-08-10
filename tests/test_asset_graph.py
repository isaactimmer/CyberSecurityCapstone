"""
Tests for the Asset Graph (epic #2): CSV integrity (#14), networkx loader (#15),
hop-distance calculation (#16), and importance-tier mapping (#17).
"""
from pathlib import Path

import networkx as nx
import pytest

import asset_graph as ag

ASSET_CSV = Path(__file__).resolve().parent.parent / "assets.csv"


# ---------------------------------------------------------------------------
# #14 — Author the asset CSV
# ---------------------------------------------------------------------------
class TestAssetCsv:
    def test_asset_count_in_range(self):
        df = ag.load_assets(ASSET_CSV)
        # Mid-sized company environment (#49): ~35-40 assets.
        assert 30 <= len(df) <= 45, "Mid-sized environment expects ~35-40 assets"

    def test_exactly_one_crown_jewel(self):
        df = ag.load_assets(ASSET_CSV)
        assert int(df["crown_jewel"].sum()) == 1, "Exactly one crown jewel required"

    def test_every_asset_has_criticality_and_connections(self):
        df = ag.load_assets(ASSET_CSV)
        assert df["criticality"].notna().all()
        assert (df["criticality"].str.len() > 0).all()
        # Every asset participates in at least one connection.
        assert df["connections"].apply(lambda c: len(c) > 0).all()

    def test_connections_are_referentially_valid(self):
        df = ag.load_assets(ASSET_CSV)
        ids = set(df["asset_id"])
        for _, row in df.iterrows():
            for neighbor in row["connections"]:
                assert neighbor in ids, f"{row['asset_id']} points at unknown '{neighbor}'"

    def test_connections_are_bidirectional(self):
        df = ag.load_assets(ASSET_CSV).set_index("asset_id")
        for asset_id, row in df.iterrows():
            for neighbor in row["connections"]:
                assert asset_id in df.loc[neighbor, "connections"], (
                    f"{asset_id}->{neighbor} listed, but reverse edge is missing"
                )


# ---------------------------------------------------------------------------
# #15 — Build networkx graph loader
# ---------------------------------------------------------------------------
class TestGraphLoader:
    def test_returns_graph(self):
        assert isinstance(ag.load_asset_graph(ASSET_CSV), nx.Graph)

    def test_node_count_matches_csv(self):
        df = ag.load_assets(ASSET_CSV)
        graph = ag.load_asset_graph(ASSET_CSV)
        assert graph.number_of_nodes() == len(df)

    def test_edge_count_matches_unique_connections(self):
        df = ag.load_assets(ASSET_CSV)
        expected_edges = {
            frozenset((row["asset_id"], neighbor))
            for _, row in df.iterrows()
            for neighbor in row["connections"]
        }
        graph = ag.load_asset_graph(ASSET_CSV)
        assert graph.number_of_edges() == len(expected_edges)

    def test_nodes_carry_attributes(self):
        graph = ag.load_asset_graph(ASSET_CSV)
        for _, data in graph.nodes(data=True):
            assert "name" in data
            assert "criticality" in data
            assert "crown_jewel" in data

    def test_graph_is_connected(self):
        # Required so every asset has a finite hop-distance (#16).
        assert nx.is_connected(ag.load_asset_graph(ASSET_CSV))

    def test_rejects_unknown_connection(self, tmp_path):
        bad = tmp_path / "bad.csv"
        bad.write_text(
            "asset_id,name,criticality,crown_jewel,connections\n"
            "a,A,High,true,ghost\n",
            encoding="utf-8",
        )
        with pytest.raises(ValueError):
            ag.load_asset_graph(bad)

    def test_rejects_multiple_crown_jewels(self, tmp_path):
        bad = tmp_path / "bad.csv"
        bad.write_text(
            "asset_id,name,criticality,crown_jewel,connections\n"
            "a,A,High,true,b\n"
            "b,B,High,true,a\n",
            encoding="utf-8",
        )
        with pytest.raises(ValueError):
            ag.load_asset_graph(bad)


# ---------------------------------------------------------------------------
# #16 — Implement hop-distance calculation
# ---------------------------------------------------------------------------
class TestHopDistance:
    def test_every_asset_has_non_null_distance(self):
        graph = ag.load_asset_graph(ASSET_CSV)
        distances = ag.compute_hop_distances(graph)
        assert set(distances) == set(graph.nodes)
        assert all(d is not None for d in distances.values())

    def test_crown_jewel_distance_is_zero(self):
        graph = ag.load_asset_graph(ASSET_CSV)
        distances = ag.compute_hop_distances(graph)
        assert distances[ag.find_crown_jewel(graph)] == 0

    @pytest.mark.parametrize(
        "asset_id, expected",
        [
            ("customer-database", 0),
            ("app-server", 1),
            ("api-gateway", 2),
            ("domain-controller", 3),
            ("reverse-proxy", 3),
            ("waf", 4),
            ("dmz-firewall", 4),
            ("load-balancer", 5),
            ("edge-router", 5),
            ("guest-wifi", 6),
        ],
    )
    def test_spot_check_distances(self, asset_id, expected):
        graph = ag.load_asset_graph(ASSET_CSV)
        distances = ag.compute_hop_distances(graph)
        assert distances[asset_id] == expected

    def test_raises_when_crown_jewel_unreachable(self):
        graph = nx.Graph()
        graph.add_node("cj", crown_jewel=True)
        graph.add_node("island", crown_jewel=False)
        with pytest.raises(ValueError):
            ag.compute_hop_distances(graph)


# ---------------------------------------------------------------------------
# #17 — Map hop-distance into importance tiers
# ---------------------------------------------------------------------------
class TestImportanceTiers:
    def test_every_asset_lands_in_exactly_one_tier(self):
        graph = ag.load_asset_graph(ASSET_CSV)
        distances = ag.compute_hop_distances(graph)
        tiers = ag.assign_importance_tiers(distances)
        assert set(tiers) == set(distances)
        valid = {"critical", "high", "medium", "low"}
        assert all(t in valid for t in tiers.values())

    @pytest.mark.parametrize(
        "distance, expected",
        [
            (0, "critical"),
            (1, "critical"),
            (2, "high"),
            (3, "high"),
            (4, "medium"),
            (5, "medium"),
            (6, "low"),
            (9, "low"),
        ],
    )
    def test_default_tier_boundaries(self, distance, expected):
        assert ag.tier_for_distance(distance) == expected

    def test_cutoffs_are_adjustable(self):
        # A stricter security-lead view: only the crown jewel is "critical".
        cutoffs = ((0, "critical"), (2, "high"), (4, "medium"))
        assert ag.tier_for_distance(0, cutoffs) == "critical"
        assert ag.tier_for_distance(1, cutoffs) == "high"
        assert ag.tier_for_distance(5, cutoffs) == "low"

    def test_full_pipeline_table(self):
        table = ag.build_asset_table(ASSET_CSV)
        for col in ("asset_id", "name", "criticality", "hop_distance", "importance_tier"):
            assert col in table.columns
        assert table["hop_distance"].notna().all()
        assert table["importance_tier"].notna().all()
        assert len(table) == len(ag.load_assets(ASSET_CSV))
