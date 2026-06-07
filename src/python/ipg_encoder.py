"""
ipg_encoder.py — Intent Provenance Graph (IPG) Builder

Implements Algorithm 1 from the SENTINEL paper.  Takes a list of raw kernel
events (structs populated by the ring-buffer reader) and produces a compact
directed multigraph whose serialised text form is consumed by the LLM
classifier tier.

The IPG is the primary novelty of SENTINEL:
  - Nodes:  (comm, resource_type) pairs — deduplicated across PIDs in window
  - Edges:  (src_node, dst_node, syscall_label, min_delta_t_ms)
  - Dedup:  parallel edges with the same label are merged; minimum Δt kept
  - Text:   compact natural-language narrative (~228 tokens avg for 20 events)
"""

from __future__ import annotations

import math
import hashlib
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional, Tuple

import networkx as nx


# ── Enumerations ──────────────────────────────────────────────────────────────

class SyscallType(IntEnum):
    EXEC      = 0
    FILE_R    = 1
    FILE_W    = 2
    NET_CON   = 3
    NET_LIS   = 4
    FORK      = 5
    CLONE     = 6
    SETUID    = 7
    MMAP      = 8
    PTRACE    = 9
    OTHER     = 15

class ResourceType(IntEnum):
    EXEC  = 0   # binary / script being executed
    FILE  = 1   # regular file path
    NET   = 2   # network endpoint (ip:port)
    PIPE  = 3   # anonymous / named pipe
    MEM   = 4   # memory region (mmap / ptrace)
    SYS   = 5   # system identity (uid change)
    UNK   = 15


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
    ResourceType.EXEC:  "EXEC",
    ResourceType.FILE:  "FILE",
    ResourceType.NET:   "NET",
    ResourceType.PIPE:  "PIPE",
    ResourceType.MEM:   "MEM",
    ResourceType.SYS:   "SYS",
    ResourceType.UNK:   "UNK",
}


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class KernelEvent:
    ts_ns:    int
    pid:      int
    ppid:     int
    uid:      int
    comm:     str
    sc_type:  int
    resource: str
    flags:    int = 0
    net_port: int = 0
    net_ip4:  int = 0


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


@dataclass
class IPGEdge:
    src:       IPGNode
    dst:       IPGNode
    sc_label:  str
    min_dt_ms: float   # minimum observed Δt in milliseconds


# ── Resource-type inference ───────────────────────────────────────────────────

_SENSITIVE_FILE_PREFIXES = (
    "/etc/shadow", "/etc/passwd", "/etc/sudoers",
    "/root/", "/proc/", "/sys/", "/dev/mem",
    "/.ssh/", "/tmp/",
)

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


# ── Main IPG builder ──────────────────────────────────────────────────────────

class IPGBuilder:
    """Constructs an Intent Provenance Graph from a window of kernel events."""

    def __init__(self, sensitive_file_highlight: bool = True):
        self._sensitive = sensitive_file_highlight

    # ── Algorithm 1 implementation ────────────────────────────────────────────

    def build(self, window: List[KernelEvent]) -> nx.MultiDiGraph:
        """
        Implements IPG Construction (Algorithm 1 in the paper).

        Returns a NetworkX MultiDiGraph with node attribute 'label' and
        edge attributes 'sc_label', 'min_dt_ms', 'sensitive'.
        """
        G: nx.MultiDiGraph = nx.MultiDiGraph()

        prev_node: Optional[IPGNode] = None
        prev_ts:   Optional[int]     = None

        for evt in window:
            rtype = infer_resource_type(evt.sc_type, evt.resource)
            node  = IPGNode(comm=evt.comm, rtype=rtype)

            if not G.has_node(node):
                G.add_node(node, label=node.label(), pid=evt.pid)

            if prev_node is not None and prev_ts is not None:
                dt_ms      = (evt.ts_ns - prev_ts) / 1e6
                sc_label   = _SYSCALL_LABELS.get(evt.sc_type, "syscall")
                sensitive  = any(evt.resource.startswith(p)
                                 for p in _SENSITIVE_FILE_PREFIXES)

                # Deduplication: merge parallel edges with same syscall label
                # (keep minimum Δt — line 9-10 of Algorithm 1)
                merged = False
                if G.has_edge(prev_node, node):
                    for key, data in G[prev_node][node].items():
                        if data.get("sc_label") == sc_label:
                            if dt_ms < data["min_dt_ms"]:
                                data["min_dt_ms"] = dt_ms
                            merged = True
                            break

                if not merged:
                    G.add_edge(prev_node, node,
                               sc_label=sc_label,
                               min_dt_ms=round(dt_ms, 2),
                               sensitive=sensitive,
                               resource=evt.resource[:64])

            prev_node = node
            prev_ts   = evt.ts_ns

        return G

    # ── Serialisation ─────────────────────────────────────────────────────────

    def serialize(self, G: nx.MultiDiGraph) -> str:
        """
        Converts an IPG to a compact natural-language narrative for LLM input.
        Produces approximately 228 tokens on average for 20-event windows
        (vs. ~847 tokens for raw narrative encoding).
        """
        lines: List[str] = []
        n_nodes = G.number_of_nodes()
        n_edges = G.number_of_edges()
        lines.append(f"Behavioral graph ({n_nodes} nodes, {n_edges} edges):")

        for u, v, data in G.edges(data=True):
            sc      = data.get("sc_label", "syscall")
            dt      = data.get("min_dt_ms", 0.0)
            sens    = " [SENSITIVE]" if data.get("sensitive") else ""
            # Include resource path for FILE/NET edges so the LLM has full context
            res     = data.get("resource", "")
            res_tag = f" path={res}" if res and v.rtype.name in ("FILE", "NET") else ""
            lines.append(
                f"  {u.label()} --[{sc}, dt={dt:.1f}ms]--> {v.label()}{sens}{res_tag}"
            )

        # Append a one-line process inventory
        comms = sorted({n.comm for n in G.nodes()})
        lines.append(f"Processes involved: {', '.join(comms)}")
        return "\n".join(lines)

    # ── Compression statistics ────────────────────────────────────────────────

    @staticmethod
    def compression_ratio(raw_token_count: int, ipg_text: str) -> float:
        """Estimates compression ratio using whitespace-split token count."""
        ipg_tokens = len(ipg_text.split())
        return 1.0 - (ipg_tokens / max(raw_token_count, 1))

    # ── Information-preservation fingerprint ──────────────────────────────────

    @staticmethod
    def fingerprint(G: nx.MultiDiGraph) -> str:
        """SHA-256 digest of the sorted edge list — used for bloom-filter dedup."""
        edges = sorted(
            (u.label(), v.label(), d.get("sc_label", ""))
            for u, v, d in G.edges(data=True)
        )
        h = hashlib.sha256(str(edges).encode()).hexdigest()
        return h

    # ── Entropy of IPG structure (structural novelty score) ───────────────────

    @staticmethod
    def structural_entropy(G: nx.MultiDiGraph) -> float:
        """
        Shannon entropy over edge-label distribution in the IPG.
        High entropy = many distinct syscall types = more suspicious context.
        """
        counts: Dict[str, int] = {}
        for _, _, d in G.edges(data=True):
            lbl = d.get("sc_label", "syscall")
            counts[lbl] = counts.get(lbl, 0) + 1

        total = sum(counts.values())
        if total == 0:
            return 0.0
        return -sum((c / total) * math.log2(c / total)
                    for c in counts.values() if c > 0)
