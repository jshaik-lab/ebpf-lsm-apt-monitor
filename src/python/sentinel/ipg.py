"""Intent Provenance Graph (IPG) builder — Algorithm 1 from the SENTINEL paper.

Converts a sliding window of KernelEvents into a compact directed multigraph
whose serialised text form is consumed by the LLM classifier tier.

Measured token reduction vs. raw strace text (tiktoken cl100k_base, n=6 traces):
  window=20 events : 59.8% reduction (range 54–78%, avg 441 tokens)
  full trace       : 84.5% reduction (range 82–89%, avg 774 tokens)
  (Lower than the prior 64.1%/86.7%: merged edges now carry a bounded
   (count, min, max) summary instead of min-Δt-only — audit fix #5, which
   closes a fast-instance-masks-slow-instance temporal evasion.)
The reduction grows with window size as deduplication of repeated syscall/resource
patterns amortises the fixed YAML header overhead.
"""
from __future__ import annotations

import hashlib
import ipaddress
import math
from dataclasses import dataclass
from enum import IntEnum
from typing import Dict, List, Optional

import networkx as nx

from sentinel.models import KernelEvent, SyscallType


# ── Behavioral analysis helpers ───────────────────────────────────────────────

_KNOWN_DAEMONS = frozenset({
    "nginx", "sshd", "apache2", "httpd", "mysqld", "postgres", "postgresql",
    "redis-server", "mongod", "memcached", "systemd", "init", "cron", "rsyslogd",
    "dockerd", "containerd", "kubelet", "java", "python3", "python", "ruby",
    "node", "php", "php-fpm", "bash", "sh", "dash", "zsh", "fish", "sudo",
    "su", "ssh", "curl", "wget", "cat", "ls", "find", "grep", "awk", "sed",
    "apt", "dpkg", "yum", "dnf", "pip", "git", "tar", "gzip", "bzip2",
    "openssl", "strace", "tcpdump", "which", "env", "id", "whoami", "ps",
    "top", "netstat", "ss", "ip", "ifconfig", "route", "hostname", "uname",
})


def _is_external_routable(resource: str) -> bool:
    """Return True if resource encodes a non-private, non-loopback IPv4/IPv6 address."""
    host = resource.split(":")[0]
    try:
        ip = ipaddress.ip_address(host)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local
                    or ip.is_multicast or ip.is_reserved)
    except ValueError:
        return False  # hostname or empty — not flagged as external IP


class ResourceType(IntEnum):
    EXEC = 0
    FILE = 1
    NET  = 2
    PIPE = 3
    MEM  = 4
    SYS  = 5
    LLM  = 6   # TLS-intercepted LLM API intent (SSL_read/SSL_write uprobes)
    UNK  = 15


_SYSCALL_LABELS: Dict[int, str] = {
    SyscallType.EXEC:    "execve",
    SyscallType.FILE_R:  "openat(R)",
    SyscallType.FILE_W:  "openat(W)",
    SyscallType.NET_CON: "connect",
    SyscallType.NET_LIS: "listen",
    SyscallType.FORK:    "fork",
    SyscallType.CLONE:   "clone",
    SyscallType.SETUID:  "setuid",
    SyscallType.MMAP:    "mmap",
    SyscallType.PTRACE:  "ptrace",
    SyscallType.OTHER:   "syscall",
}

_RTYPE_LABELS: Dict[ResourceType, str] = {
    ResourceType.EXEC: "EXEC",
    ResourceType.FILE: "FILE",
    ResourceType.NET:  "NET",
    ResourceType.PIPE: "PIPE",
    ResourceType.MEM:  "MEM",
    ResourceType.SYS:  "SYS",
    ResourceType.LLM:  "LLM",
    ResourceType.UNK:  "UNK",
}

_SENSITIVE_FILE_PREFIXES = (
    "/etc/shadow", "/etc/passwd", "/etc/sudoers",
    "/root/", "/proc/", "/sys/", "/dev/mem",
    "/.ssh/", "/tmp/", ".aws/credentials", "id_rsa", "ssl/private",
)


@dataclass
class IPGNode:
    comm:  str
    rtype: ResourceType

    def __hash__(self) -> int:
        return hash((self.comm, self.rtype))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, IPGNode):
            return False
        return self.comm == other.comm and self.rtype == other.rtype

    def label(self) -> str:
        return f"PROC[{self.comm}/{_RTYPE_LABELS[self.rtype]}]"


def infer_resource_type(sc_type: int, resource: str) -> ResourceType:
    sc = SyscallType(sc_type) if sc_type in SyscallType._value2member_map_ else SyscallType.OTHER
    if sc == SyscallType.EXEC:
        return ResourceType.EXEC
    if sc in (SyscallType.FILE_R, SyscallType.FILE_W):
        return ResourceType.FILE
    if sc in (SyscallType.NET_CON, SyscallType.NET_LIS):
        return ResourceType.NET
    if sc in (SyscallType.FORK, SyscallType.CLONE):
        return ResourceType.EXEC
    if sc == SyscallType.MMAP:
        return ResourceType.MEM
    if sc == SyscallType.SETUID:
        return ResourceType.SYS
    if sc == SyscallType.PTRACE:
        return ResourceType.MEM
    return ResourceType.UNK


class IPGBuilder:
    """Builds Intent Provenance Graphs (Algorithm 1) from kernel event windows."""

    def __init__(self, sensitive_file_highlight: bool = True):
        self._sensitive = sensitive_file_highlight

    def build(self, window: List[KernelEvent]) -> nx.MultiDiGraph:
        """Algorithm 1: construct IPG from a window of kernel events."""
        G: nx.MultiDiGraph = nx.MultiDiGraph()
        prev_node: Optional[IPGNode] = None
        prev_ts:   Optional[int]     = None

        for idx, evt in enumerate(window):
            rtype = infer_resource_type(evt.sc_type, evt.resource)
            node  = IPGNode(comm=evt.comm, rtype=rtype)

            if not G.has_node(node):
                G.add_node(node, label=node.label(), pid=evt.pid)

            if prev_node is not None and prev_ts is not None:
                dt_ms     = (evt.ts_ns - prev_ts) / 1e6
                sc_label  = _SYSCALL_LABELS.get(evt.sc_type, "syscall")
                sensitive = any(evt.resource.startswith(p) for p in _SENSITIVE_FILE_PREFIXES)

                # Merge parallel edges with the same syscall label.  We keep a
                # bounded summary (count, min, max) rather than min Δt alone:
                # min-only biased the edge toward the *fastest* observed
                # transition, which a slow-burn attacker exploited by ensuring
                # a fast benign instance of the same (src,dst,syscall) existed
                # to mask a slow malicious one (theoretical-audit item #5).
                # Surfacing max Δt and the occurrence count makes the slow
                # instance visible to the LLM; first_idx preserves chronology.
                dt_r   = round(dt_ms, 2)
                merged = False
                if G.has_edge(prev_node, node):
                    for _key, data in G[prev_node][node].items():
                        if data.get("sc_label") == sc_label:
                            data["min_dt_ms"] = min(data["min_dt_ms"], dt_r)
                            data["max_dt_ms"] = max(
                                data.get("max_dt_ms", data["min_dt_ms"]), dt_r)
                            data["count"] = data.get("count", 1) + 1
                            merged = True
                            break

                if not merged:
                    # Attach semantic annotation at build time (Core Novelty 2)
                    semantic_hint = ""
                    try:
                        from sentinel.semantic import SemanticLabeler
                        lbl = SemanticLabeler().label(evt)
                        if lbl.attack_relevance or lbl.risk_level in ("HIGH", "CRITICAL"):
                            semantic_hint = lbl.compact()
                    except Exception:
                        pass

                    G.add_edge(
                        prev_node, node,
                        sc_label=sc_label,
                        min_dt_ms=dt_r,
                        max_dt_ms=dt_r,
                        count=1,
                        first_idx=idx,
                        sensitive=sensitive,
                        resource=evt.resource[:64],
                        semantic=semantic_hint,
                    )

            prev_node = node
            prev_ts   = evt.ts_ns

        return G

    def serialize(self, G: nx.MultiDiGraph) -> str:
        """YAML-structured IPG (~441 tokens avg at window=20; 60% reduction vs raw strace)."""
        node_list  = list(G.nodes())
        node_index = {n: f"n{i}" for i, n in enumerate(node_list)}

        # ── Behavioral analysis: pre-scan edges for anomaly signals ──────────
        outbound_ext   = 0
        net_con_seen   = False
        exec_after_net = False
        for _, _, data in G.edges(data=True):
            sc  = data.get("sc_label", "")
            res = data.get("resource", "")
            if sc == "connect":
                net_con_seen = True
                if _is_external_routable(res):
                    outbound_ext += 1
            elif sc == "execve" and net_con_seen:
                exec_after_net = True
        unusual_comm = any(
            n.comm.lower() not in _KNOWN_DAEMONS for n in G.nodes()
        )

        # Build meta line — only emit signals when positive (avoid zero-anchoring:
        # explicit zero/false values cause LLMs to infer benign from absence of signal)
        meta = f"{{nodes: {G.number_of_nodes()}, edges: {G.number_of_edges()}"
        if outbound_ext:
            meta += f", outbound_ext: {outbound_ext}"
        if exec_after_net:
            meta += ", exec_after_net: true"
        if unusual_comm:
            meta += ", unusual_comm: true"
        meta += "}"

        lines: List[str] = [
            "# Intent Provenance Graph -- SENTINEL v1.0",
            f"meta: {meta}",
            "nodes:",
        ]
        for n, nid in node_index.items():
            lines.append(
                f"  - {{id: {nid}, comm: {n.comm}, rtype: {_RTYPE_LABELS[n.rtype]}}}"
            )

        lines.append("edges:")
        for u, v, data in G.edges(data=True):
            sc  = data.get("sc_label", "syscall")
            dt  = data.get("min_dt_ms", 0.0)
            res = data.get("resource", "")
            entry = (
                f"  - {{src: {node_index[u]}, dst: {node_index[v]},"
                f" syscall: {sc}, dt_ms: {dt:.1f}"
            )
            # For merged edges surface occurrence count and the SLOWEST Δt
            # (audit fix #5): a min-only summary let a fast benign instance
            # mask a slow malicious one of the same transition.  Emitted only
            # when count>1 so single-shot edges stay token-cheap and the LLM
            # is not zero-anchored by uniform "n: 1" noise.
            cnt = data.get("count", 1)
            if cnt > 1:
                entry += f", n: {cnt}, dt_max_ms: {data.get('max_dt_ms', dt):.1f}"
            if res:
                # For TLS intent edges include the captured payload as 'intent'
                field_name = "intent" if sc == "tls_read" else "res"
                entry += f", {field_name}: {res}"
            if data.get("sensitive"):
                entry += ", sensitive: true"
            # Flag outbound connections to external routable IPs
            if sc == "connect" and _is_external_routable(res):
                entry += ", anomaly: ext_outbound"
            # Inject semantic annotation when present (Core Novelty 2)
            sem = data.get("semantic", "")
            if sem:
                entry += f", semantic: \"{sem}\""
            entry += "}"
            lines.append(entry)

        comms = sorted({n.comm for n in G.nodes()})
        lines.append(f"procs: [{', '.join(comms)}]")
        return "\n".join(lines)

    def inject_tls_intent(
        self,
        G:       nx.MultiDiGraph,
        comm:    str,
        payload: str,
    ) -> None:
        """Item 2 — inject a TLS-captured LLM intent node into an existing IPG.

        Creates an LLM-rtype node for *comm* and connects it from the
        process's NET node (the API connection) via a synthetic 'tls_read'
        edge that carries the intercepted plaintext payload snippet.
        This surfaces prompt-injection content directly in the IPG that the
        LLM classifier receives, enabling detection without MITM proxies.
        """
        llm_node = IPGNode(comm=comm, rtype=ResourceType.LLM)
        if not G.has_node(llm_node):
            G.add_node(llm_node, label=f"LLM_INTENT[{comm}]")

        # Connect from the existing NET node for this comm, if one exists
        src_node: Optional[IPGNode] = None
        for n in G.nodes():
            if n.comm == comm and n.rtype == ResourceType.NET:
                src_node = n
                break

        # If no NET node found, connect from any node of this comm
        if src_node is None:
            for n in G.nodes():
                if n.comm == comm:
                    src_node = n
                    break

        if src_node is not None:
            G.add_edge(
                src_node, llm_node,
                sc_label="tls_read",
                min_dt_ms=0.0,
                sensitive=True,
                resource=payload[:128],
            )

    def inject_parent_events(
        self,
        window:       List[KernelEvent],
        parent_window: List[KernelEvent],
        max_parent:   int = 5,
    ) -> List[KernelEvent]:
        """Item 4 — prepend parent-process events for cross-PID provenance.

        When a child PID inherits suspicious context from its parent (e.g.,
        bash spawned by a web server that just received a payload), standard
        per-PID IPGs miss that causal chain.  This method prepends the last
        *max_parent* events from the parent's sliding window so the IPG
        captures the full fork→exec→action provenance chain.
        """
        prefix = list(parent_window)[-max_parent:]
        return prefix + list(window)

    @staticmethod
    def structural_entropy(G: nx.MultiDiGraph) -> float:
        """Shannon entropy over edge-label distribution — proxy for behavioral complexity."""
        counts: Dict[str, int] = {}
        for _, _, d in G.edges(data=True):
            lbl = d.get("sc_label", "syscall")
            counts[lbl] = counts.get(lbl, 0) + 1
        total = sum(counts.values())
        if total == 0:
            return 0.0
        return -sum((c / total) * math.log2(c / total) for c in counts.values() if c > 0)

    @staticmethod
    def fingerprint(G: nx.MultiDiGraph) -> str:
        """SHA-256 of sorted edge list — used for bloom-filter dedup."""
        edges = sorted(
            (u.label(), v.label(), d.get("sc_label", ""))
            for u, v, d in G.edges(data=True)
        )
        return hashlib.sha256(str(edges).encode()).hexdigest()

    @staticmethod
    def compression_ratio(raw_token_count: int, ipg_text: str) -> float:
        ipg_tokens = len(ipg_text.split())
        return 1.0 - (ipg_tokens / max(raw_token_count, 1))
