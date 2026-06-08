"""DetectorAgent — Stage 1 of the agentic pipeline.

Responsibility: fast triage of every kernel event.

Decision logic (in order of precedence):
  1. Hard-trigger bypass: sensitive resource → ALWAYS_ANALYZE
  2. Flagged-parent bypass: child of MALICIOUS PID → ALWAYS_ANALYZE
  3. Window minimum: fewer than window_size events → SKIP
  4. Order-aware entropy gate (Algorithm 2 Tier-1): SKIP only when the
     marginal Shannon entropy AND the first-order Markov entropy rate are
     both below low_threshold AND no novel (comm,syscall) unigram or
     (comm,prev→cur) transition bigram appeared.  Marginal entropy alone is
     permutation-invariant, so a single malicious syscall interleaved into a
     repetitive benign loop barely shifts it and evades the gate (theoretical
     -audit item #2).  The conditional Markov term plus transition-novelty
     close that order-blindness hole.
  5. Otherwise: ANALYZE

Output: DetectionSignal pushed to the analyzer queue.
Latency target: < 0.1 ms per event (pure Python, no I/O).

The DetectorAgent is intentionally stateless between PIDs — all state
is carried in the DetectionSignal so the AnalyzerAgent can be swapped
or scaled horizontally.
"""
from __future__ import annotations

import asyncio
import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional

import structlog

from sentinel.triggers import HARD_TRIGGER_RESOURCES, FLAGGED_PID_TTL_SECONDS
from sentinel.models import KernelEvent

try:
    from sentinel.pcabp.call_site_map import ValidCallSiteMap
    _PCABP_AVAILABLE = True
except ImportError:
    _PCABP_AVAILABLE = False

logger = structlog.get_logger(__name__)

SC_TYPES = 16


@dataclass
class DetectionSignal:
    """Output of DetectorAgent — input to AnalyzerAgent."""
    pid:         int
    comm:        str
    window:      List[KernelEvent]
    entropy:     float          # marginal Shannon entropy (legacy Eq. 3)
    trigger:     str   # hard_trigger|flagged_parent|entropy|novel_edge|novel_transition|markov
    markov_entropy: float = 0.0  # first-order Markov entropy rate H(s_t|s_{t-1})
    ts_ns:       int   = field(default_factory=lambda: time.time_ns())
    detector_ms: float = 0.0   # DetectorAgent processing latency


class DetectorAgent:
    """Stage 1: fast triage, no LLM, no I/O.

    Consumes KernelEvents from an input queue and pushes DetectionSignals
    to the analyzer queue whenever a PID warrants deeper inspection.
    """

    def __init__(
        self,
        out_queue:        asyncio.Queue,
        window_size:      int   = 20,
        entropy_low:      float = 1.2,
        entropy_high:     float = 3.8,
        entropy_window:   int   = 64,
        call_site_map:    Optional["ValidCallSiteMap"] = None,
        markov_gate:      bool  = True,
    ):
        self._out       = out_queue
        self._win_size  = window_size
        self._ent_low   = entropy_low
        self._ent_high  = entropy_high
        self._ent_win   = entropy_window
        # Order-aware gate (audit fix #2). False = legacy marginal-only gate
        # (kept for the before/after ablation in entropy_evasion_eval.py).
        self._markov_gate = markov_gate
        # PCABP static call-site map (None = disabled; no impact on existing behaviour)
        self._csm: Optional["ValidCallSiteMap"] = call_site_map if _PCABP_AVAILABLE else None

        # Per-PID state
        self._windows: Dict[int, Deque[KernelEvent]] = defaultdict(
            lambda: deque(maxlen=window_size)
        )
        self._hists:   Dict[int, List[int]] = defaultdict(lambda: [0] * SC_TYPES)
        self._ent_wins: Dict[int, Deque[int]] = defaultdict(
            lambda: deque(maxlen=entropy_window)
        )
        # First-order transition state (order-aware gate, audit fix #2).
        # _trans_wins: sliding window of consecutive (prev_sc, cur_sc) bigrams;
        # _trans_hist: live bigram→count over that window (O(1) per event,
        # bounded by entropy_window — same memory class as _hists).
        self._trans_wins: Dict[int, Deque[tuple]] = defaultdict(
            lambda: deque(maxlen=entropy_window)
        )
        self._trans_hist: Dict[int, Dict[tuple, int]] = defaultdict(dict)
        self._prev_sc:    Dict[int, int]  = {}             # pid → last sc_type
        self._last_trans: Dict[int, Optional[tuple]] = {}  # pid → current bigram
        self._ppid_map: Dict[int, int] = {}
        self._flagged:  Dict[int, float] = {}   # pid → expiry
        self._seen_edges: set = set()
        # Global first-occurrence set of (comm, prev_sc, cur_sc) transitions —
        # mirrors _seen_edges' unigram philosophy at the bigram level.
        self._seen_transitions: set = set()
        # PID activity tracking for TTL eviction — pid → global event count at last seen
        self._pid_last_seen: Dict[int, int] = {}
        # Evict PIDs inactive for more than this many global events (~50k events ≈ minutes)
        self._pid_evict_ttl: int = 50_000
        self._pid_evict_interval: int = 10_000  # check every N events

        self._stats = {"events": 0, "signals": 0, "skipped": 0, "pids_evicted": 0}

    # ── Public API ─────────────────────────────────────────────────────────────

    async def handle(self, event: KernelEvent) -> None:
        t0 = time.perf_counter()
        self._stats["events"] += 1

        if event.ppid > 1:
            self._ppid_map[event.pid] = event.ppid

        self._pid_last_seen[event.pid] = self._stats["events"]
        self._update_entropy(event)
        self._windows[event.pid].append(event)

        trigger = self._triage(event)
        if trigger is None:
            self._stats["skipped"] += 1
            self._maybe_evict_pids()
            return

        sig = DetectionSignal(
            pid=event.pid,
            comm=event.comm,
            window=list(self._windows[event.pid]),
            entropy=self._entropy(event.pid),
            markov_entropy=self._markov_entropy(event.pid),
            trigger=trigger,
            detector_ms=round((time.perf_counter() - t0) * 1000, 3),
        )
        self._stats["signals"] += 1

        # Warn when queue is near saturation — signals back-pressure under high LLM latency
        qsize = self._out.qsize()
        if self._out.maxsize > 0 and qsize >= int(self._out.maxsize * 0.8):
            logger.warning(
                "detector_queue_pressure",
                qsize=qsize,
                maxsize=self._out.maxsize,
                utilization_pct=round(100 * qsize / self._out.maxsize),
            )

        await self._out.put(sig)
        self._maybe_evict_pids()
        logger.debug("detection_signal", pid=event.pid, trigger=trigger,
                     entropy=round(sig.entropy, 3))

    def flag_pid(self, pid: int) -> None:
        """Called by AuditorAgent when a MALICIOUS verdict is confirmed."""
        self._flagged[pid] = time.monotonic() + FLAGGED_PID_TTL_SECONDS

    def _maybe_evict_pids(self) -> None:
        """Evict per-PID state for processes inactive for _pid_evict_ttl events."""
        n = self._stats["events"]
        if n % self._pid_evict_interval != 0:
            return
        threshold = n - self._pid_evict_ttl
        dead = [p for p, seen in self._pid_last_seen.items() if seen < threshold]
        for p in dead:
            self._windows.pop(p, None)
            self._hists.pop(p, None)
            self._ent_wins.pop(p, None)
            self._trans_wins.pop(p, None)
            self._trans_hist.pop(p, None)
            self._prev_sc.pop(p, None)
            self._last_trans.pop(p, None)
            self._ppid_map.pop(p, None)
            self._pid_last_seen.pop(p, None)
        if dead:
            self._stats["pids_evicted"] += len(dead)
            logger.debug("pid_eviction", evicted=len(dead), remaining=len(self._windows))

    @property
    def stats(self) -> dict:
        return dict(**self._stats, active_pids=len(self._windows))

    # ── Internal triage logic ──────────────────────────────────────────────────

    def _triage(self, event: KernelEvent) -> Optional[str]:
        """Return trigger name if this event should be analyzed, else None."""
        # Layer 0: PCABP static violation — IP outside binary call-site bloom filter.
        # Fires before entropy gate so novel heap-injected syscalls are never suppressed.
        if self._csm is not None and event.ip != 0:
            is_valid, _ = self._csm.check(event.ip)
            if not is_valid:
                logger.info(
                    "pcabp_static_violation",
                    pid=event.pid, comm=event.comm,
                    ip=hex(event.ip),
                    region=self._csm.region(event.ip),
                )
                return "pcabp_static_violation"

        # Layer 1: hard-trigger (sensitive resource)
        if any(p in event.resource for p in HARD_TRIGGER_RESOURCES):
            return "hard_trigger"

        # Layer 2: flagged-parent bypass
        now = time.monotonic()
        self._flagged = {p: e for p, e in self._flagged.items() if e > now}
        pid_flagged   = event.pid in self._flagged
        ppid_flagged  = self._ppid_map.get(event.pid) in self._flagged
        if pid_flagged or ppid_flagged:
            return "flagged_parent"

        # Layer 3: minimum window guard
        win = self._windows[event.pid]
        if len(win) < self._win_size:
            return None

        # Layer 4: order-aware entropy gate (audit fix #2).
        H        = self._entropy(event.pid)            # marginal Shannon (Eq. 3)
        edge_key = (event.comm, event.sc_type)
        novel    = edge_key not in self._seen_edges
        self._seen_edges.add(edge_key)

        if not self._markov_gate:
            # Legacy permutation-invariant gate (kept for the ablation only).
            if H < self._ent_low and not novel:
                return None
            return "entropy" if not novel else "novel_edge"

        Hm    = self._markov_entropy(event.pid)        # H(s_t | s_{t-1})
        trans = self._last_trans.get(event.pid)
        novel_trans = False
        if trans is not None:
            tkey = (event.comm, trans[0], trans[1])
            novel_trans = tkey not in self._seen_transitions
            self._seen_transitions.add(tkey)

        # Skip ONLY when the window is repetitive by BOTH the marginal and the
        # order-aware (conditional) measure AND introduced no unseen unigram or
        # transition.  A malicious syscall interleaved into a benign loop holds
        # the marginal flat but produces a novel/low-probability transition,
        # so it can no longer slip the gate.
        if H < self._ent_low and Hm < self._ent_low and not novel and not novel_trans:
            return None
        if novel_trans:
            return "novel_transition"
        if novel:
            return "novel_edge"
        return "markov" if H < self._ent_low else "entropy"

    def _update_entropy(self, event: KernelEvent) -> None:
        pid = event.pid
        sc  = event.sc_type
        hist = self._hists[pid]
        win  = self._ent_wins[pid]
        if len(win) == self._ent_win and win:
            evicted = win[0]
            if evicted < SC_TYPES:
                hist[evicted] = max(0, hist[evicted] - 1)
        win.append(sc)
        if sc < SC_TYPES:
            hist[sc] += 1

        # First-order transition bookkeeping (mirrors the marginal histogram
        # eviction so the bigram counts track the same sliding window).
        prev = self._prev_sc.get(pid)
        if prev is None:
            self._last_trans[pid] = None
        else:
            bigram = (prev, sc)
            twin = self._trans_wins[pid]
            thist = self._trans_hist[pid]
            if len(twin) == self._ent_win and twin:
                old = twin[0]
                if thist.get(old, 0) <= 1:
                    thist.pop(old, None)
                else:
                    thist[old] -= 1
            twin.append(bigram)
            thist[bigram] = thist.get(bigram, 0) + 1
            self._last_trans[pid] = bigram
        self._prev_sc[pid] = sc

    def _markov_entropy(self, pid: int) -> float:
        """First-order Markov entropy rate H(s_t | s_{t-1}) over the window.

        H = -Σ_{i,j} p(i,j) log2 p(j|i),  p(j|i) = n_ij / Σ_j n_ij.

        Unlike the marginal Shannon entropy (Eq. 3), this is *not*
        permutation-invariant: reordering syscalls changes the transition
        distribution, so an off-pattern interleaved event raises H even when
        the per-type frequencies are unchanged.
        """
        thist = self._trans_hist.get(pid)
        if not thist:
            return 0.0
        total = sum(thist.values())
        if total == 0:
            return 0.0
        row_tot: Dict[int, int] = {}
        for (i, _j), c in thist.items():
            row_tot[i] = row_tot.get(i, 0) + c
        H = 0.0
        for (i, _j), n_ij in thist.items():
            if n_ij <= 0:
                continue
            p_ij = n_ij / total
            p_j_given_i = n_ij / row_tot[i]
            H -= p_ij * math.log2(p_j_given_i)
        return H

    def _entropy(self, pid: int) -> float:
        hist  = self._hists[pid]
        total = sum(hist)
        if total == 0:
            return 0.0
        return -sum((c / total) * math.log2(c / total) for c in hist if c > 0)
