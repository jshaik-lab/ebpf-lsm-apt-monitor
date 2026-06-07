"""Shared data models for the SENTINEL pipeline."""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import IntEnum
from typing import List


class SyscallType(IntEnum):
    EXEC    = 0
    FILE_R  = 1
    FILE_W  = 2
    NET_CON = 3
    NET_LIS = 4
    FORK    = 5
    CLONE   = 6
    SETUID  = 7
    MMAP    = 8
    PTRACE  = 9
    PRCTL   = 10   # comm masquerading via PR_SET_NAME
    OTHER   = 15


def _new_event_id() -> str:
    return str(uuid.uuid4())


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
    # User-space instruction pointer captured by eBPF bpf_get_stack().
    # 0 = not captured (simulation / CDM18 data). Non-zero = PCABP eligible.
    # Used by PCABP static layer to check whether the syscall caller is inside
    # the process binary (.text) or in heap/stack-injected shellcode.
    ip:       int = 0
    # Unique event ID — enables forensic linking between eBPF trace and LLM claims.
    # Every event gets a stable UUID so CoVe can cite "eBPF event EVT-<id>" in proofs.
    event_id: str = field(default_factory=_new_event_id)


@dataclass
class TLSEvent:
    """Plaintext payload captured by eBPF uprobes on SSL_read / SSL_write."""
    ts_ns:     int
    pid:       int
    uid:       int
    comm:      str
    direction: int    # 0 = SSL_read (inbound), 1 = SSL_write (outbound)
    data_len:  int
    payload:   str    # captured plaintext (may be truncated to TLS_BUF_LEN)
    truncated: bool = False


@dataclass
class ThreatDecision:
    label:           str           # "BENIGN" | "MALICIOUS"
    confidence:      float
    reasoning:       str
    mitre_ttps:      List[str] = field(default_factory=list)
    chain_of_thought: str = ""    # step-by-step LLM reasoning (CoT)
    model_used:      str = "unknown"
    latency_ms:      float = 0.0
    ts_ns:           int = field(default_factory=time.time_ns)
    # Structured evidence references (Core Novelty 1 — verifiable trace reasoning)
    # Each ref: {"event_desc": str, "supports": str, "confidence_contribution": float}
    evidence_refs:   List[dict] = field(default_factory=list)


class EnforcementTier(IntEnum):
    LOG_ONLY   = 0
    PAUSE      = 1
    KILL       = 2
    QUARANTINE = 3
    ISOLATE    = 4


TIER_LABELS: dict[EnforcementTier, str] = {
    EnforcementTier.LOG_ONLY:   "LOG_ONLY",
    EnforcementTier.PAUSE:      "PAUSE",
    EnforcementTier.KILL:       "KILL",
    EnforcementTier.QUARANTINE: "QUARANTINE",
    EnforcementTier.ISOLATE:    "ISOLATE",
}


@dataclass
class EnforcementRecord:
    pid:        int
    comm:       str
    confidence: float
    tier:       EnforcementTier
    label:      str
    reasoning:  str
    mitre_ttps: List[str]
    ts_ns:      int = field(default_factory=time.time_ns)
    latency_us: float = 0.0
