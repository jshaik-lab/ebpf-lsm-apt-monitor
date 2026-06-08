"""Tests for sentinel.provenance_ml (scorer and fusion)."""
from __future__ import annotations

import networkx as nx

from sentinel.ipg import IPGMeta, IPGBuilder
from sentinel.provenance_ml import provenance_score, fuse_scores


def test_scorer_monotonicity():
    # Base meta (completely benign)
    meta_benign = IPGMeta(
        n_nodes=3, n_edges=3, outbound_ext=0, exec_after_net=False,
        unusual_comm=False, sensitive_reads=0, tmp_exec=False, external_connect=False
    )
    G = nx.MultiDiGraph()
    
    score_benign = provenance_score(meta_benign, G)
    assert score_benign == 0.0

    # Add sensitive read
    meta_sens = IPGMeta(
        n_nodes=3, n_edges=3, outbound_ext=0, exec_after_net=False,
        unusual_comm=False, sensitive_reads=1, tmp_exec=False, external_connect=False
    )
    score_sens = provenance_score(meta_sens, G)
    assert score_sens > score_benign

    # Add tmp_exec
    meta_tmp = IPGMeta(
        n_nodes=3, n_edges=3, outbound_ext=0, exec_after_net=False,
        unusual_comm=False, sensitive_reads=0, tmp_exec=True, external_connect=False
    )
    score_tmp = provenance_score(meta_tmp, G)
    assert score_tmp >= 0.70

    # Max score is 1.0
    meta_extreme = IPGMeta(
        n_nodes=10, n_edges=20, outbound_ext=5, exec_after_net=True,
        unusual_comm=True, sensitive_reads=10, tmp_exec=True, external_connect=True
    )
    # Mock graph with connects
    G_ext = nx.MultiDiGraph()
    u = nx.utils.groups # placeholder comm
    class MockNode:
        comm = "bad_process"
    n0 = MockNode()
    G_ext.add_node(n0)
    G_ext.add_edge(n0, n0, sc_label="connect", resource="8.8.8.8:80")
    
    score_extreme = provenance_score(meta_extreme, G_ext)
    assert score_extreme == 1.0


def test_fusion_logic():
    # 1. Base case: all benign
    label, conf = fuse_scores(0.1, "BENIGN", 0.05, 0.0, 0.0)
    assert label == "BENIGN"
    assert conf == 0.1

    # 2. PCABP consensus override
    label, conf = fuse_scores(0.1, "BENIGN", 0.05, 0.0, 0.65)
    assert label == "MALICIOUS"
    assert conf == 0.65

    # 3. LTL safety floor
    label, conf = fuse_scores(0.1, "BENIGN", 0.05, 0.85, 0.0)
    assert label == "MALICIOUS"
    assert conf == 0.85

    # 4. LLM escalation
    label, conf = fuse_scores(0.1, "MALICIOUS", 0.75, 0.0, 0.0)
    assert label == "MALICIOUS"
    assert conf == 0.75

    # 5. CoVe grounding cap
    label, conf = fuse_scores(0.1, "MALICIOUS", 0.90, 0.0, 0.0, cove_cap=0.29)
    assert label == "BENIGN"
    assert conf == 0.29
