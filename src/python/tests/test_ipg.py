"""Tests for sentinel.ipg — IPG builder (Algorithm 1)."""

from sentinel.ipg import IPGBuilder, ResourceType, _is_external_routable, infer_resource_type
from sentinel.models import KernelEvent, SyscallType


# ── Helper ────────────────────────────────────────────────────────────────────

def _evt(ms, comm, sc, res, pid=1):
    return KernelEvent(ts_ns=ms * 1_000_000, pid=pid, ppid=pid - 1, uid=0,
                       comm=comm, sc_type=int(sc), resource=res)


def test_build_node_edge_counts(ipg, attack_window):
    G = ipg.build(attack_window)
    assert G.number_of_nodes() >= 2
    assert G.number_of_edges() >= 1


def test_sensitive_file_flagged(ipg, attack_window):
    G = ipg.build(attack_window)
    sensitive_edges = [
        d for _, _, d in G.edges(data=True) if d.get("sensitive")
    ]
    assert len(sensitive_edges) >= 1, "/etc/shadow should be flagged as SENSITIVE"


def test_edge_deduplication(ipg):
    """Two identical openat(R) on the same resource should merge into one edge."""
    def e(ms, comm, sc, res):
        return KernelEvent(ts_ns=ms * 1_000_000, pid=1, ppid=0, uid=0,
                           comm=comm, sc_type=int(sc), resource=res)
    E = SyscallType
    window = [
        e(0, "bash", E.EXEC,   "/bin/bash"),
        e(1, "bash", E.FILE_R, "/etc/passwd"),
        e(2, "bash", E.FILE_R, "/etc/passwd"),   # duplicate
    ]
    G = ipg.build(window)
    # There should be at most 2 distinct edge labels between the same node pair
    edge_labels = set()
    for u, v, d in G.edges(data=True):
        edge_labels.add(d.get("sc_label"))
    assert len(edge_labels) <= 2


def test_edge_summary_surfaces_slow_instance(ipg):
    """Audit fix #5: a slow (malicious) instance of a transition must not be
    masked by a fast (benign) instance of the same edge.  The merged edge
    keeps count + min + max, and serialize() surfaces n / dt_max_ms."""
    E = SyscallType
    win = [
        _evt(0,    "svc", E.FILE_R, "/var/cache/x"),
        _evt(1,    "svc", E.FILE_R, "/var/cache/x"),   # +1 ms    (fast)
        _evt(2,    "svc", E.FILE_R, "/var/cache/x"),   # +1 ms    (fast)
        _evt(5002, "svc", E.FILE_R, "/var/cache/x"),   # +5000 ms (slow burst)
    ]
    G = ipg.build(win)
    edges = [d for _, _, d in G.edges(data=True)]
    assert len(edges) == 1
    d = edges[0]
    assert d["count"] == 3
    assert d["min_dt_ms"] <= 1.0
    assert d["max_dt_ms"] >= 5000.0
    assert d["first_idx"] == 1   # edge is born on the 2nd event (needs a pred.)

    txt = ipg.serialize(G)
    assert "dt_ms: 1.0" in txt          # fast (min) still reported
    assert "n: 3" in txt                # occurrence count surfaced
    assert "dt_max_ms: 5000.0" in txt   # slow instance no longer hidden

    # Single-shot edges stay token-cheap (no n:/dt_max_ms noise).
    G2  = ipg.build([_evt(0, "svc", E.FILE_R, "/a"),
                     _evt(1, "svc", E.FILE_W, "/a")])
    assert ", n: " not in ipg.serialize(G2)


def test_structural_entropy_positive(ipg, attack_window):
    G = ipg.build(attack_window)
    H = IPGBuilder.structural_entropy(G)
    assert H > 0.0, "Mixed syscall types should yield positive entropy"


def test_structural_entropy_zero_for_uniform(ipg):
    """Graph with only one syscall type has zero entropy."""
    def e(ms):
        return KernelEvent(ts_ns=ms * 1_000_000, pid=1, ppid=0, uid=0,
                           comm="test", sc_type=int(SyscallType.FILE_R),
                           resource="/tmp/x")
    G = ipg.build([e(i) for i in range(5)])
    H = IPGBuilder.structural_entropy(G)
    assert H == 0.0


def test_serialize_contains_graph_header(ipg, attack_window):
    G   = ipg.build(attack_window)
    txt = ipg.serialize(G)
    assert "# Intent Provenance Graph" in txt
    assert "meta:" in txt
    assert "edges:" in txt
    assert "procs:" in txt


def test_fingerprint_deterministic(ipg, attack_window):
    G   = ipg.build(attack_window)
    fp1 = IPGBuilder.fingerprint(G)
    fp2 = IPGBuilder.fingerprint(G)
    assert fp1 == fp2
    assert len(fp1) == 64   # SHA-256 hex digest


def test_infer_resource_type_net():
    assert infer_resource_type(int(SyscallType.NET_CON), "") == ResourceType.NET


def test_infer_resource_type_mem():
    assert infer_resource_type(int(SyscallType.MMAP), "") == ResourceType.MEM


def test_compression_ratio(ipg, attack_window):
    G       = ipg.build(attack_window)
    txt     = ipg.serialize(G)
    raw_est = len(attack_window) * 42
    ratio   = IPGBuilder.compression_ratio(raw_est, txt)
    assert 0 < ratio < 1.0


# ── Behavioral meta field tests ───────────────────────────────────────────────

def test_serialize_behavioral_meta_absent_for_benign_nginx(ipg):
    """For a benign nginx window, behavioral meta signals are absent from meta: line.

    Only positive signals appear — omitting them avoids zero-anchoring bias in the LLM.
    """
    E = SyscallType
    window = [
        _evt(0, "nginx", E.NET_LIS, "0.0.0.0:80"),
        _evt(1, "nginx", E.FILE_R,  "/var/www/html/index.html"),
    ]
    G = ipg.build(window)
    txt = ipg.serialize(G)
    # Positive-only design: zero/false signals are omitted
    assert "outbound_ext:" not in txt
    assert "exec_after_net:" not in txt
    assert "unusual_comm:" not in txt


def test_serialize_outbound_ext_counts_external_ips(ipg):
    """outbound_ext counts distinct connect edges to routable external IPs.

    Two connects from different source nodes produce two separate edges (no dedup),
    so outbound_ext=2. A private IP from the same node merges with another connect
    if it shares sc_label — but private IPs don't increment the counter anyway.
    """
    E = SyscallType
    # nginx→nginx connect (external): one edge
    # nginx→vUgefal connect (external): different dst node, second edge
    window = [
        _evt(0, "nginx",   E.NET_CON, "10.0.0.1:80"),        # private — not counted
        _evt(1, "nginx",   E.NET_CON, "81.49.200.166:80"),    # external, nginx→nginx
        _evt(2, "vUgefal", E.NET_CON, "200.36.109.214:443"),  # external, nginx→vUgefal
    ]
    G = ipg.build(window)
    txt = ipg.serialize(G)
    assert "outbound_ext: 2" in txt


def test_serialize_exec_after_net_true(ipg):
    """exec_after_net is true when an execve EDGE follows a connect EDGE.

    The first event creates no edge (prev_node is None), so the connect must
    not be the first event in the window for the connect edge to exist.
    """
    E = SyscallType
    window = [
        _evt(0, "nginx", E.NET_LIS, "0.0.0.0:80"),         # establishes prev_node
        _evt(1, "nginx", E.NET_CON, "81.49.200.166:80"),    # creates connect edge
        _evt(2, "nginx", E.EXEC,    "/tmp/payload"),         # creates execve edge
    ]
    G = ipg.build(window)
    txt = ipg.serialize(G)
    assert "exec_after_net: true" in txt


def test_serialize_exec_after_net_absent_no_net(ipg):
    """exec_after_net is omitted when there is no prior connect edge (positive-only design)."""
    E = SyscallType
    window = [
        _evt(0, "nginx", E.FILE_R, "/var/www/html/index.html"),
        _evt(1, "nginx", E.EXEC,   "/usr/bin/openssl"),
    ]
    G = ipg.build(window)
    txt = ipg.serialize(G)
    assert "exec_after_net:" not in txt


def test_serialize_unusual_comm_flagged(ipg):
    """unusual_comm is true for non-daemon process names."""
    E = SyscallType
    window = [
        _evt(0, "vUgefal", E.NET_CON, "200.36.109.214:80"),
    ]
    G = ipg.build(window)
    txt = ipg.serialize(G)
    assert "unusual_comm: true" in txt


def test_serialize_known_comm_not_unusual(ipg):
    """unusual_comm is absent when all comms are known system daemons (positive-only design)."""
    E = SyscallType
    window = [
        _evt(0, "nginx", E.NET_LIS, "0.0.0.0:80"),
        _evt(1, "nginx", E.FILE_R,  "/var/www/html/index.html"),
    ]
    G = ipg.build(window)
    txt = ipg.serialize(G)
    assert "unusual_comm:" not in txt


def test_serialize_edge_anomaly_for_external_ip(ipg):
    """connect to external routable IP gets anomaly: ext_outbound tag on the edge."""
    E = SyscallType
    window = [
        _evt(0, "nginx", E.NET_CON, "81.49.200.166:80"),
        _evt(1, "nginx", E.NET_CON, "81.49.200.166:80"),  # duplicate merges
    ]
    G = ipg.build(window)
    txt = ipg.serialize(G)
    assert "anomaly: ext_outbound" in txt


def test_serialize_private_ip_no_anomaly_tag(ipg):
    """connect to RFC-1918 address must NOT get anomaly: ext_outbound."""
    E = SyscallType
    window = [
        _evt(0, "nginx", E.NET_CON, "192.168.1.10:8080"),
        _evt(1, "nginx", E.NET_CON, "10.0.0.1:80"),
    ]
    G = ipg.build(window)
    txt = ipg.serialize(G)
    assert "anomaly: ext_outbound" not in txt
    assert "outbound_ext:" not in txt  # zero outbound_ext is omitted (positive-only design)


def test_is_external_routable_private():
    assert _is_external_routable("10.0.0.1:80")     is False
    assert _is_external_routable("192.168.1.1:443") is False
    assert _is_external_routable("172.16.0.1:8080") is False
    assert _is_external_routable("127.0.0.1:80")    is False


def test_is_external_routable_public():
    assert _is_external_routable("81.49.200.166:80")     is True
    assert _is_external_routable("200.36.109.214:80")    is True
    assert _is_external_routable("104.21.43.12:4444")    is True


def test_is_external_routable_hostname():
    """Hostnames (not raw IPs) should not be flagged."""
    assert _is_external_routable("example.com:443")   is False
    assert _is_external_routable("api.openai.com:443") is False
