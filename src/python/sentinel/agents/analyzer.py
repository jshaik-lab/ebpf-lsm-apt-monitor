"""AnalyzerAgent — Stage 2 of the agentic pipeline.

Responsibility: full contextual reasoning on a PID window.

Processing steps:
  1. Build IPG from event window (Algorithm 1) — with semantic annotations
  2. Optionally stitch parent-PID events for cross-PID provenance
  3. Run DualTierClassifier (Algorithm 2): draft → full model
  4. Return AnalysisResult containing ThreatDecision + raw IPG text

Latency: dominated by LLM inference (p50 ~3.6s Ollama HTTP, ~80ms llama.cpp native).
Concurrency: controlled by asyncio.Semaphore(max_concurrent_llm).
"""
from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict

import structlog

from sentinel.agents.detector import DetectionSignal
from sentinel.ipg import IPGBuilder
from sentinel.llm.base import DualTierClassifier
from sentinel.models import KernelEvent, ThreatDecision

try:
    from sentinel.pcabp.behavioral_encoder import BehavioralEncoder
    from sentinel.pcabp.call_site_map import ValidCallSiteMap
    _PCABP_AVAILABLE = True
except ImportError:
    _PCABP_AVAILABLE = False

logger = structlog.get_logger(__name__)

# Non-maskable floor for a confirmed static call-site violation.
#
# A static violation (syscall IP outside the binary's valid call-site Bloom
# filter) is a *deterministic* indicator of process injection / shellcode
# execution.  The original consensus `0.4·static + 0.6·ai` was a convex blend:
# a payload whose syscall sequence mimics the host (ai_divergence ≈ 0) dragged
# the score to exactly 0.40, which maps to the PAUSE tier (SIGSTOP) rather than
# KILL.  That let a low AI score numerically mask a deterministic compromise.
#
# Fix (theoretical-audit item #4): the static term is now a non-maskable lower
# bound.  When static_violation == 1.0 the consensus score can never fall below
# the KILL band (0.50 ≤ conf < 0.70); ai_divergence may only *raise* severity
# (toward QUARANTINE/ISOLATE), never lower it.  The AI-only path
# (static_violation == 0) is unchanged: pcabp_score == 0.6·ai_divergence.
_STATIC_VIOLATION_FLOOR = 0.55  # KILL tier (see EnforcementTier.TIERS)


@dataclass
class AnalysisResult:
    """Output of AnalyzerAgent — input to AuditorAgent."""
    signal:           DetectionSignal
    decision:         ThreatDecision
    ipg_text:         str
    ipg_nodes:        int
    ipg_edges:        int
    analyzer_ms:      float = 0.0   # AnalyzerAgent processing latency (excl. LLM)
    llm_ms:           float = 0.0   # LLM inference latency
    # PCABP scores (0.0 if PCABP disabled or no IPs captured)
    pcabp_static:     float = 0.0   # 1.0 if ≥1 IP outside call-site bloom filter
    pcabp_ai:         float = 0.0   # BehavioralEncoder divergence ∈ [0, 1]
    pcabp_score:      float = 0.0   # max(0.4*static+0.6*ai, 0.55*static)
    graph_score:      float = 0.0   # Option A deterministic graph anomaly score


class AnalyzerAgent:
    """Stage 2: IPG construction + LLM classification.

    Pulls DetectionSignals from the detector queue, runs the full
    IPG + LLM pipeline, and pushes AnalysisResults to the auditor queue.
    """

    def __init__(
        self,
        in_queue:           asyncio.Queue,
        out_queue:          asyncio.Queue,
        classifier:         DualTierClassifier,
        max_concurrent_llm: int = 4,
        call_site_map:      "Optional[ValidCallSiteMap]" = None,
        behavioral_encoder: "Optional[BehavioralEncoder]" = None,
    ):
        self._in         = in_queue
        self._out        = out_queue
        self._clf        = classifier
        self._sem        = asyncio.Semaphore(max_concurrent_llm)
        self._ipg        = IPGBuilder()
        # PCABP components (None = disabled gracefully)
        self._csm        = call_site_map      if _PCABP_AVAILABLE else None
        self._encoder    = behavioral_encoder if _PCABP_AVAILABLE else None
        # Parent-window cache: pid → recent events for provenance stitching
        self._parent_cache: Dict[int, Deque[KernelEvent]] = defaultdict(
            lambda: deque(maxlen=10)
        )
        # Activity tracking for TTL eviction of parent_cache entries
        self._cache_last_seen: Dict[int, int] = {}
        self._cache_evict_ttl: int = 5_000      # analyses before eviction
        self._cache_evict_interval: int = 1_000  # check every N analyses

        self._stats = {"analyzed": 0, "llm_invocations": 0, "pids_evicted": 0}

    async def run(self) -> None:
        """Consume signals forever — run as asyncio.Task."""
        while True:
            signal: DetectionSignal = await self._in.get()
            asyncio.create_task(self._analyze(signal))

    async def _analyze(self, signal: DetectionSignal) -> None:
        t0 = time.perf_counter()
        async with self._sem:
            window = signal.window

            # Cross-PID provenance: prepend parent events if cached
            ppid = signal.window[0].ppid if signal.window else None
            if ppid and ppid in self._parent_cache and self._parent_cache[ppid]:
                window = self._ipg.inject_parent_events(
                    window, list(self._parent_cache[ppid]), max_parent=5
                )

            G        = self._ipg.build(window)
            meta     = self._ipg.analyze(G)
            ipg_text = self._ipg.serialize(G, meta)
            H        = signal.entropy

            from sentinel.provenance_ml import provenance_score
            graph_score = provenance_score(meta, G)

            t1       = time.perf_counter()
            llm_ms   = 0.0
            
            # Gray-zone model escalation (Option A hybrid mode)
            # High/Low zones skip LLM for labeling, Gray zone escalates to LLM
            if graph_score >= 0.55:
                decision = ThreatDecision(
                    label="MALICIOUS",
                    confidence=graph_score,
                    reasoning=f"Option A Graph-First Detector: high provenance anomaly score ({graph_score:.2f})",
                    mitre_ttps=[],
                    chain_of_thought="Deterministic graph-first detection triggered.",
                    model_used="graph-scorer",
                )
            elif graph_score <= 0.15:
                decision = ThreatDecision(
                    label="BENIGN",
                    confidence=1.0 - graph_score,
                    reasoning="Option A Graph-First Detector: low provenance anomaly score",
                    mitre_ttps=[],
                    chain_of_thought="Deterministic graph-first benign classification.",
                    model_used="graph-scorer",
                )
            else:
                decision = await self._clf.classify(ipg_text, H)
                llm_ms   = (time.perf_counter() - t1) * 1000

            # ── PCABP scoring (runs in thread to avoid blocking event loop) ──
            pcabp_static = 0.0
            pcabp_ai     = 0.0
            pcabp_score  = 0.0
            if self._csm is not None or self._encoder is not None:
                pcabp_static, pcabp_ai, pcabp_score = await asyncio.to_thread(
                    self._compute_pcabp, window
                )

            # Update parent cache so children can stitch
            pid = signal.pid
            for evt in signal.window:
                self._parent_cache[pid].append(evt)
            self._cache_last_seen[pid] = self._stats["analyzed"]

            self._stats["analyzed"] += 1
            self._stats["llm_invocations"] += 1
            self._maybe_evict_cache()

            result = AnalysisResult(
                signal=signal,
                decision=decision,
                ipg_text=ipg_text,
                ipg_nodes=G.number_of_nodes(),
                ipg_edges=G.number_of_edges(),
                analyzer_ms=round((time.perf_counter() - t0) * 1000, 2),
                llm_ms=round(llm_ms, 2),
                pcabp_static=round(pcabp_static, 4),
                pcabp_ai=round(pcabp_ai, 4),
                pcabp_score=round(pcabp_score, 4),
                graph_score=round(graph_score, 4),
            )
            logger.debug(
                "analysis_complete",
                pid=signal.pid, label=decision.label,
                conf=round(decision.confidence, 3),
                trigger=signal.trigger, llm_ms=round(llm_ms, 1),
            )
            await self._out.put(result)

    def _maybe_evict_cache(self) -> None:
        """Evict parent_cache entries for PIDs inactive for _cache_evict_ttl analyses."""
        n = self._stats["analyzed"]
        if n % self._cache_evict_interval != 0:
            return
        threshold = n - self._cache_evict_ttl
        dead = [p for p, seen in self._cache_last_seen.items() if seen < threshold]
        for p in dead:
            self._parent_cache.pop(p, None)
            self._cache_last_seen.pop(p, None)
        if dead:
            self._stats["pids_evicted"] += len(dead)

    def _compute_pcabp(
        self, window: list
    ) -> tuple[float, float, float]:
        """Synchronous PCABP scoring — run in a thread via asyncio.to_thread.

        Returns (static_violation, ai_divergence, pcabp_score).
        """
        # Static violation: 1.0 if ANY event's IP is outside bloom filter
        static_violation = 0.0
        offset_deltas    = []
        if self._csm is not None:
            for evt in window:
                if evt.ip != 0:
                    is_valid, delta = self._csm.check(evt.ip)
                    if not is_valid:
                        static_violation = 1.0
                    offset_deltas.append(delta)
                else:
                    offset_deltas.append(0)

        # AI divergence from contrastive encoder
        ai_divergence = 0.0
        if self._encoder is not None:
            ai_divergence = self._encoder.score(window, offset_deltas or None)

        # Consensus with a non-maskable static floor (audit fix #4).
        # Convex blend keeps the published 0.4/0.6 weighting for the mixed
        # case, but a confirmed static violation cannot be dragged below the
        # KILL tier by a low AI divergence — the deterministic IoC dominates.
        blended = 0.4 * static_violation + 0.6 * ai_divergence
        pcabp_score = max(blended, _STATIC_VIOLATION_FLOOR * static_violation)
        return static_violation, ai_divergence, pcabp_score

    @property
    def stats(self) -> dict:
        return dict(**self._stats, llm_tier=self._clf.stats)
