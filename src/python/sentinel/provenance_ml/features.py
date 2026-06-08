"""Feature extraction for SENTINEL IPG graphs."""
from __future__ import annotations

import math
from collections import Counter
from typing import Dict

import networkx as nx

from sentinel.ipg import IPGMeta, _is_external_routable, IPGBuilder


def extract_features(meta: IPGMeta, G: nx.MultiDiGraph) -> Dict[str, float]:
    """Extract a topological and behavioral feature vector from an IPG graph.
    
    Returns a dict mapping feature names to float values.
    """
    features: Dict[str, float] = {}

    # Core IPGMeta fields
    features["n_nodes"] = float(meta.n_nodes)
    features["n_edges"] = float(meta.n_edges)
    features["outbound_ext"] = float(meta.outbound_ext)
    features["exec_after_net"] = 1.0 if meta.exec_after_net else 0.0
    features["unusual_comm"] = 1.0 if meta.unusual_comm else 0.0
    features["sensitive_reads"] = float(meta.sensitive_reads)
    features["tmp_exec"] = 1.0 if meta.tmp_exec else 0.0
    features["external_connect"] = 1.0 if meta.external_connect else 0.0

    # Structural Entropy of Edge Labels (Proxy for behavioral complexity)
    features["structural_entropy"] = IPGBuilder.structural_entropy(G)

    # Path-specific counts
    openat_r_tmp = 0
    openat_w_tmp = 0
    openat_r_var_log = 0
    openat_w_var_log = 0
    openat_r_etc_shadow = 0
    execve_tmp = 0
    execve_var_log = 0
    execve_cache = 0
    ext_outbound_edges = 0

    for _, _, data in G.edges(data=True):
        sc = data.get("sc_label", "")
        res = data.get("resource", "")

        # Openat checks
        if sc == "openat(R)":
            if res.startswith("/tmp/"):
                openat_r_tmp += 1
            elif res.startswith("/var/log/"):
                openat_r_var_log += 1
            elif res == "/etc/shadow":
                openat_r_etc_shadow += 1
        elif sc == "openat(W)":
            if res.startswith("/tmp/"):
                openat_w_tmp += 1
            elif res.startswith("/var/log/"):
                openat_w_var_log += 1

        # Execve checks
        elif sc == "execve":
            if res.startswith("/tmp/"):
                execve_tmp += 1
            elif res.startswith("/var/log/"):
                execve_var_log += 1
            elif res.startswith("/home/admin/cache"):
                execve_cache += 1

        # Connect checks
        elif sc == "connect" and _is_external_routable(res):
            ext_outbound_edges += 1

    features["openat_r_tmp"] = float(openat_r_tmp)
    features["openat_w_tmp"] = float(openat_w_tmp)
    features["openat_r_var_log"] = float(openat_r_var_log)
    features["openat_w_var_log"] = float(openat_w_var_log)
    features["openat_r_etc_shadow"] = float(openat_r_etc_shadow)
    features["execve_tmp"] = float(execve_tmp)
    features["execve_var_log"] = float(execve_var_log)
    features["execve_cache"] = float(execve_cache)
    features["ext_outbound_edges"] = float(ext_outbound_edges)

    # Process name (comm) entropy
    comms = [n.comm for n in G.nodes()]
    comm_counts = Counter(comms)
    total_comms = len(comms)
    if total_comms > 0:
        features["comm_entropy"] = -sum(
            (c / total_comms) * math.log2(c / total_comms)
            for c in comm_counts.values()
        )
    else:
        features["comm_entropy"] = 0.0

    # Max parallel edges between any node pair
    max_parallel = 0
    for u, v in G.edges():
        count = G.number_of_edges(u, v)
        if count > max_parallel:
            max_parallel = count
    features["max_parallel_edges"] = float(max_parallel)

    return features
