"""Deterministic Provenance Scorer for Option A."""
from __future__ import annotations

import networkx as nx

from sentinel.ipg import IPGMeta, _is_external_routable, _KNOWN_DAEMONS

_SERVER_DAEMONS = {
    "nginx", "sshd", "apache2", "httpd", "mysqld", "postgres", "postgresql", "redis-server",
    "bash", "sh", "dash", "zsh", "python", "python3"
}


def provenance_score(meta: IPGMeta, G: nx.MultiDiGraph) -> float:
    """Assign a deterministic score ∈ [0, 1] to an IPG based on anomalous behaviors.
    
    This matches Option A's primary detector thesis.
    """
    score = 0.0

    # 1. Spawning executable from world-writable paths (tmp_exec)
    if meta.tmp_exec:
        score += 0.75

    # 2. Outbound connections to external public IPs (excluding port 53 DNS)
    if meta.outbound_ext > 0:
        has_suspicious_outbound = False
        for u, v, data in G.edges(data=True):
            sc = data.get("sc_label", "")
            res = data.get("resource", "")
            if sc == "connect" and _is_external_routable(res):
                port = res.split(":")[-1] if ":" in res else ""
                if port != "53":
                    comm = u.comm.lower()
                    if comm in _SERVER_DAEMONS or comm not in _KNOWN_DAEMONS:
                        has_suspicious_outbound = True
                        break
        if has_suspicious_outbound:
            score += 0.80

    # 3. Reading sensitive credential files
    if meta.sensitive_reads > 0:
        score += min(0.20 * meta.sensitive_reads, 0.45)

    # 4. Temporal execution after network activity
    if meta.exec_after_net:
        score += 0.30

    # 5. Non-standard daemon process name
    if meta.unusual_comm:
        score += 0.15

    return min(score, 1.0)
