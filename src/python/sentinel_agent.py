"""
sentinel_agent.py — SENTINEL Main Orchestrator

Entry point for the SENTINEL zero-trust kernel anomaly detection agent.
Orchestrates the full pipeline:
  1. Load and attach the eBPF kernel component (sentinel.bpf.o)
  2. Poll the ring buffer for kernel events
  3. Maintain per-PID event windows and compute sliding entropy
  4. Run the dual-tier LLM inference pipeline via DualTierClassifier
  5. Execute enforcement decisions via CWAEEngine

Usage:
  sudo python3 sentinel_agent.py \
      --draft-model /opt/models/Llama-3-1B-Instruct.Q4_K_M.gguf \
      --full-model  /opt/models/Llama-3-8B-Instruct.Q4_K_M.gguf \
      --window-size 20 \
      --entropy-low 1.2 \
      --entropy-high 3.8 \
      [--dry-run]

Requires: root privileges, Linux >= 5.8, BCC or libbpf-python.
"""

from __future__ import annotations

import argparse
import ctypes
import logging
import math
import os
import signal
import struct
import sys
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Deque, Dict, List, Optional, Tuple

from ipg_encoder import KernelEvent, IPGBuilder, SyscallType
from agents.pipeline import SentinelPipeline
from enforcement import CWAEEngine

logger = logging.getLogger("sentinel")


# ── Constants ─────────────────────────────────────────────────────────────────

ENTROPY_WINDOW = 64          # must match sentinel.c ENTROPY_WINDOW
SC_TYPES       = 16          # must match sentinel.c SC_TYPES

# Event struct layout (must match sentinel.c struct event_t)
EVENT_FORMAT = "=QIIIIBBHIcc"   # simplified — actual uses char arrays
EVENT_STRUCT_SIZE = 180          # sizeof(struct event_t)


class EventStruct(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("ts_ns",    ctypes.c_uint64),
        ("pid",      ctypes.c_uint32),
        ("ppid",     ctypes.c_uint32),
        ("uid",      ctypes.c_uint32),
        ("gid",      ctypes.c_uint32),
        ("sc_type",  ctypes.c_uint8),
        ("flags",    ctypes.c_uint8),
        ("net_port", ctypes.c_uint16),
        ("net_ip4",  ctypes.c_uint32),
        ("comm",     ctypes.c_char * 16),
        ("resource", ctypes.c_char * 128),
    ]


# ── Entropy computation (user-space mirror of BPF entropy map) ────────────────

class EntropyTracker:
    """
    Mirrors the kernel-side entropy histogram for user-space pre-check.
    Also implements the novel-edge bloom-filter bypass trigger.
    """

    def __init__(self, window_size: int = ENTROPY_WINDOW,
                 low: float = 1.2, high: float = 3.8):
        self._w    = window_size
        self._low  = low
        self._high = high
        self._hists: Dict[int, List[int]] = defaultdict(lambda: [0] * SC_TYPES)
        self._wins:  Dict[int, Deque[int]] = defaultdict(lambda: deque(maxlen=window_size))
        self._seen_edges = set()  # (comm, rtype) pairs seen so far

    def update(self, pid: int, sc_type: int) -> None:
        hist = self._hists[pid]
        win  = self._wins[pid]
        if len(win) == self._w:
            evicted = win[0]
            if evicted < SC_TYPES:
                hist[evicted] = max(0, hist[evicted] - 1)
        win.append(sc_type)
        if sc_type < SC_TYPES:
            hist[sc_type] += 1

    def entropy(self, pid: int) -> float:
        hist  = self._hists[pid]
        total = sum(hist)
        if total == 0:
            return 0.0
        return -sum((c / total) * math.log2(c / total)
                    for c in hist if c > 0)

    def should_invoke_llm(self, pid: int, comm: str, rtype: int) -> Tuple[bool, float]:
        """
        Returns (should_invoke, entropy_value).
        Bypasses entropy gate if a novel (comm, rtype) pair is seen.
        """
        H = self.entropy(pid)
        edge_key = (comm, rtype)
        novel_edge = edge_key not in self._seen_edges
        self._seen_edges.add(edge_key)

        if H < self._low and not novel_edge:
            return False, H
        return True, H


# ── BCC-based loader (fallback: mock loader for CI) ───────────────────────────

class BPFLoader:
    """Loads the eBPF object file and attaches tracepoints."""

    def __init__(self, bpf_obj_path: str):
        self._path = bpf_obj_path
        self._bpf  = None
        self._rb   = None

    def load(self) -> bool:
        try:
            from bcc import BPF
            self._bpf = BPF(src_file=self._path)
            logger.info("eBPF object loaded: %s", self._path)
            return True
        except ImportError:
            logger.warning("BCC not available; falling back to mock loader.")
            return False
        except Exception as exc:
            logger.error("Failed to load eBPF: %s", exc)
            return False

    def get_ringbuf_fd(self) -> int:
        if self._bpf is None:
            return -1
        try:
            return self._bpf["events"].map_fd
        except Exception:
            return -1

    def get_enforce_map_fd(self) -> int:
        if self._bpf is None:
            return -1
        try:
            return self._bpf["enforce_map"].map_fd
        except Exception:
            return -1

    def get_xdp_quarantine_fd(self) -> int:
        if self._bpf is None:
            return -1
        try:
            return self._bpf["xdp_quarantine_map"].map_fd
        except Exception:
            return -1

    def poll(self, callback, timeout_ms: int = 50) -> None:
        if self._bpf is None:
            return
        try:
            self._bpf["events"].open_ring_buffer(callback)
            self._bpf.ring_buffer_poll(timeout_ms)
        except Exception as exc:
            logger.debug("Ring buffer poll error: %s", exc)


# ── Main pipeline ─────────────────────────────────────────────────────────────

class SentinelAgent:
    """
    Orchestrates the complete SENTINEL pipeline:
      eBPF telemetry → entropy gate → IPG encoder → LLM classifier → CWAE
    """

    def __init__(
        self,
        draft_model:    str,
        full_model:     str,
        window_size:    int   = 20,
        entropy_low:    float = 1.2,
        entropy_high:   float = 3.8,
        draft_threshold: float = 0.90,
        n_threads:      int   = 8,
        dry_run:        bool  = False,
        bpf_obj:        str   = "sentinel.bpf.o",
    ):
        self._window_size = window_size
        self._entropy     = EntropyTracker(ENTROPY_WINDOW, entropy_low, entropy_high)
        self._ipg         = IPGBuilder()
        self._pipeline    = SentinelPipeline(model_name="llama3.1")
        self._loader      = BPFLoader(bpf_obj)
        self._windows:    Dict[int, Deque[KernelEvent]] = \
            defaultdict(lambda: deque(maxlen=window_size))
        self._stats       = {"events": 0, "llm_invoked": 0, "enforced": 0}
        self._running     = False

        # Deferred init of CWAE (needs BPF map FDs from loader)
        self._cwae: Optional[CWAEEngine] = None
        self._dry_run = dry_run

    # ── Ring-buffer callback ───────────────────────────────────────────────────

    def _on_event(self, cpu: int, data: ctypes.c_void_p, size: int) -> None:
        raw = ctypes.cast(data, ctypes.POINTER(EventStruct)).contents
        evt = KernelEvent(
            ts_ns    = raw.ts_ns,
            pid      = raw.pid,
            ppid     = raw.ppid,
            uid      = raw.uid,
            comm     = raw.comm.decode("utf-8", errors="replace").rstrip("\x00"),
            sc_type  = raw.sc_type,
            resource = raw.resource.decode("utf-8", errors="replace").rstrip("\x00"),
            flags    = raw.flags,
            net_port = raw.net_port,
            net_ip4  = raw.net_ip4,
        )

        self._stats["events"] += 1
        self._entropy.update(evt.pid, evt.sc_type)

        win = self._windows[evt.pid]
        win.append(evt)

        if len(win) < self._window_size:
            return  # accumulate more events first

        should_invoke, H = self._entropy.should_invoke_llm(
            evt.pid, evt.comm, evt.sc_type)

        if not should_invoke:
            return  # Tier-1 gate: skip LLM for this window

        self._stats["llm_invoked"] += 1
        self._run_inference(evt.pid, evt.comm, list(win), H)

    # ── Inference + enforcement ────────────────────────────────────────────────

    def _run_inference(
        self,
        pid: int,
        comm: str,
        window: List[KernelEvent],
        entropy: float,
    ) -> None:
        # Convert window of KernelEvent to raw dicts for LangGraph state
        raw_events = [vars(evt) for evt in window]
        
        try:
            state = self._pipeline.invoke(pid=pid, comm=comm, raw_events=raw_events)
            decision = state.get("final_decision")
            
            if decision and decision["label"] == "MALICIOUS" and state.get("is_verified", False):
                self._stats["enforced"] += 1
                assert self._cwae is not None
                self._cwae.enforce(
                    pid=pid, comm=comm,
                    label=decision["label"],
                    confidence=decision["confidence"],
                    reasoning=decision["reasoning"],
                    mitre_ttps=decision["mitre_ttps"],
                )
            else:
                conf = decision["confidence"] if decision else 0.0
                logger.debug("PID %d (%s) BENIGN (conf=%.3f)",
                             pid, comm, conf)
        except Exception as e:
            logger.error(f"Pipeline error for PID {pid}: {e}")

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> None:
        if os.geteuid() != 0 and not self._dry_run:
            logger.error("SENTINEL requires root privileges.")
            sys.exit(1)

        self._loader.load()
        self._cwae = CWAEEngine(
            enforce_map_fd=self._loader.get_enforce_map_fd(),
            xdp_quarantine_fd=self._loader.get_xdp_quarantine_fd(),
            dry_run=self._dry_run,
        )

        logger.info("SENTINEL started. Window=%d, EntropyLow=%.2f, EntropyHigh=%.2f",
                    self._window_size,
                    self._entropy._low,
                    self._entropy._high)

        self._running = True
        signal.signal(signal.SIGINT,  self._shutdown)
        signal.signal(signal.SIGTERM, self._shutdown)

        while self._running:
            self._loader.poll(self._on_event, timeout_ms=50)
            self._log_stats()

    def _shutdown(self, signum: int, frame) -> None:
        self._running = False
        logger.info("Shutting down. Final stats: %s", self._stats)
        if self._cwae:
            logger.info("Enforcement stats: %s", self._cwae.enforcement_stats)
        logger.info("LLM invocation reduction: %.1f%%",
                    self._classifier.invocation_reduction_rate * 100)

    def _log_stats(self) -> None:
        if self._stats["events"] % 10000 == 0 and self._stats["events"] > 0:
            logger.info("Stats: events=%d llm_invoked=%d enforced=%d",
                        self._stats["events"],
                        self._stats["llm_invoked"],
                        self._stats["enforced"])


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    parser = argparse.ArgumentParser(
        description="SENTINEL: eBPF+LLM Intent-Based Zero-Trust Agent")
    parser.add_argument("--draft-model", required=True,
                        help="Path to Llama-3-1B-Instruct GGUF model")
    parser.add_argument("--full-model",  required=True,
                        help="Path to Llama-3-8B-Instruct GGUF model")
    parser.add_argument("--bpf-obj", default="sentinel.bpf.o",
                        help="Path to compiled eBPF object (default: sentinel.bpf.o)")
    parser.add_argument("--window-size",  type=int,   default=20,
                        help="Syscall window size (default: 20)")
    parser.add_argument("--entropy-low",  type=float, default=1.2,
                        help="Low entropy threshold — skip LLM (default: 1.2 bits)")
    parser.add_argument("--entropy-high", type=float, default=3.8,
                        help="High entropy threshold — skip draft model (default: 3.8 bits)")
    parser.add_argument("--draft-threshold", type=float, default=0.90,
                        help="Draft confidence threshold (default: 0.90)")
    parser.add_argument("--threads",      type=int,   default=8,
                        help="LLM inference threads (default: 8)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Log enforcement actions without executing them")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    agent = SentinelAgent(
        draft_model=args.draft_model,
        full_model=args.full_model,
        window_size=args.window_size,
        entropy_low=args.entropy_low,
        entropy_high=args.entropy_high,
        draft_threshold=args.draft_threshold,
        n_threads=args.threads,
        dry_run=args.dry_run,
        bpf_obj=args.bpf_obj,
    )
    agent.start()


if __name__ == "__main__":
    main()
