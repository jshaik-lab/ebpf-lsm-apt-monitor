"""SENTINEL main async orchestrator.

Event flow (AgentPipeline — Option A):
  SimulationSource / BPFSource
    → DetectorAgent (entropy + PCABP static triage)
    → AnalyzerAgent (IPG + provenance_score + gray-zone LLM + PCABP)
    → AuditorAgent (CoVe + LTL + fuse_scores + CWAE)
"""
from __future__ import annotations

import asyncio
import ctypes
import math
import signal
import time
from collections import defaultdict, deque
from typing import Deque, Dict, List, Optional

import structlog
import uvicorn

from sentinel import metrics as m
from sentinel.api import app as fastapi_app, register_agent
from sentinel.bpf import BPFLoader, EventStruct
from sentinel.config import SentinelConfig
from sentinel.agents.pipeline import AgentPipeline
from sentinel.models import KernelEvent

logger = structlog.get_logger(__name__)

ENTROPY_WINDOW = 64
SC_TYPES       = 16

from sentinel.triggers import HARD_TRIGGER_RESOURCES, FLAGGED_PID_TTL_SECONDS

# Back-compat aliases for tests importing from sentinel.agent
_HARD_TRIGGER_RESOURCES = HARD_TRIGGER_RESOURCES
_FLAGGED_PID_TTL_SECONDS = FLAGGED_PID_TTL_SECONDS


class EntropyTracker:
    """User-space mirror of the BPF entropy histogram with novel-edge bypass."""

    def __init__(self, window_size: int, low: float, high: float,
                 markov_gate: bool = True):
        self._w    = window_size
        self._low  = low
        self._high = high
        self._markov_gate = markov_gate
        self._hists: Dict[int, List[int]] = defaultdict(lambda: [0] * SC_TYPES)
        self._wins:  Dict[int, Deque[int]] = defaultdict(lambda: deque(maxlen=window_size))
        self._seen_edges: set = set()
        # Order-aware transition state (audit fix #2) — mirrors DetectorAgent.
        self._twins: Dict[int, Deque[tuple]] = defaultdict(lambda: deque(maxlen=window_size))
        self._thist: Dict[int, Dict[tuple, int]] = defaultdict(dict)
        self._prev_sc:    Dict[int, int] = {}
        self._last_trans: Dict[int, tuple] = {}
        self._seen_transitions: set = set()

    def update(self, pid: int, sc_type: int) -> None:
        hist = self._hists[pid]
        win  = self._wins[pid]
        if len(win) == self._w and win:
            evicted = win[0]
            if evicted < SC_TYPES:
                hist[evicted] = max(0, hist[evicted] - 1)
        win.append(sc_type)
        if sc_type < SC_TYPES:
            hist[sc_type] += 1

        prev = self._prev_sc.get(pid)
        if prev is None:
            self._last_trans.pop(pid, None)
        else:
            bigram = (prev, sc_type)
            twin, thist = self._twins[pid], self._thist[pid]
            if len(twin) == self._w and twin:
                old = twin[0]
                if thist.get(old, 0) <= 1:
                    thist.pop(old, None)
                else:
                    thist[old] -= 1
            twin.append(bigram)
            thist[bigram] = thist.get(bigram, 0) + 1
            self._last_trans[pid] = bigram
        self._prev_sc[pid] = sc_type

    def entropy(self, pid: int) -> float:
        hist  = self._hists[pid]
        total = sum(hist)
        if total == 0:
            return 0.0
        return -sum((c / total) * math.log2(c / total) for c in hist if c > 0)

    def markov_entropy(self, pid: int) -> float:
        """First-order Markov entropy rate H(s_t | s_{t-1}); see DetectorAgent."""
        thist = self._thist.get(pid)
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
            H -= (n_ij / total) * math.log2(n_ij / row_tot[i])
        return H

    def should_invoke_llm(self, pid: int, comm: str, rtype: int) -> tuple[bool, float]:
        H = self.entropy(pid)
        edge_key  = (comm, rtype)
        novel     = edge_key not in self._seen_edges
        self._seen_edges.add(edge_key)

        if not self._markov_gate:
            if H < self._low and not novel:
                return False, H
            return True, H

        Hm = self.markov_entropy(pid)
        trans = self._last_trans.get(pid)
        novel_trans = False
        if trans is not None:
            tkey = (comm, trans[0], trans[1])
            novel_trans = tkey not in self._seen_transitions
            self._seen_transitions.add(tkey)
        if H < self._low and Hm < self._low and not novel and not novel_trans:
            return False, H
        return True, H

    def clear_pid(self, pid: int) -> None:
        self._hists.pop(pid, None)
        self._wins.pop(pid, None)
        self._twins.pop(pid, None)
        self._thist.pop(pid, None)
        self._prev_sc.pop(pid, None)
        self._last_trans.pop(pid, None)


class SentinelAgent:
    """Async main orchestrator — ties together all SENTINEL subsystems."""

    def __init__(self, config: SentinelConfig):
        self.config     = config
        self._loader    = BPFLoader(
            obj_path=config.bpf.obj_path,
            poll_interval_ms=config.bpf.poll_interval_ms,
        )
        self._pipeline: Optional[AgentPipeline] = None
        # Kept for unit tests (test_evasion_fixes.py) — runtime uses DetectorAgent.
        self._ppid_map: Dict[int, int] = {}
        self._flagged_pids: Dict[int, float] = {}
        self._recent: Deque[Dict] = deque(maxlen=200)
        self._stats = {
            "events": 0,
            "start_time": time.time(),
        }
        self.is_running = False

    # ── Public API for /status and /decisions ──────────────────────────────────

    def get_stats(self) -> Dict:
        out: Dict = {
            **self._stats,
            "uptime_s":    round(time.time() - self._stats["start_time"]),
            "mode":        self.config.mode,
            "llm_backend": self.config.llm.backend,
            "dry_run":     self.config.enforcement.dry_run,
            "pipeline":    "AgentPipeline",
            "llm_invoked": 0,
            "enforced":    0,
            "active_pids": 0,
            "llm_tier":    {},
            "enforcement": {},
        }
        if self._pipeline is not None:
            ps = self._pipeline.stats()
            out["llm_invoked"] = ps["analyzer"].get("llm_invocations", 0)
            out["enforced"]    = ps["auditor"].get("enforced", 0)
            out["active_pids"] = ps["detector"].get("active_pids", 0)
            out["llm_tier"]    = ps.get("classifier", {})
            out["pipeline_stats"] = ps
        return out

    def get_recent_decisions(self, limit: int = 100) -> List[Dict]:
        items = list(self._recent)
        return items[-limit:]

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    async def run(self) -> None:
        self._pipeline = AgentPipeline.from_config(
            self.config,
            enforce_map_fd=self._loader.get_enforce_map_fd(),
            xdp_fd=self._loader.get_xdp_quarantine_fd(),
            on_audit_entry=self._record_decision,
        )
        register_agent(self)

        if self.config.metrics.enabled:
            m.start_metrics_server(self.config.metrics.port)
            logger.info("metrics_server_started", port=self.config.metrics.port)

        self.is_running = True
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(signal.SIGINT,  self._request_shutdown)
        loop.add_signal_handler(signal.SIGTERM, self._request_shutdown)

        logger.info(
            "sentinel_started",
            mode=self.config.mode,
            llm_backend=self.config.llm.backend,
            dry_run=self.config.enforcement.dry_run,
            pipeline="AgentPipeline",
        )

        try:
            async with self._pipeline:
                async with asyncio.TaskGroup() as tg:
                    tg.create_task(self._event_loop(), name="event-loop")
                    tg.create_task(self._api_server(), name="api-server")
                    tg.create_task(self._stats_reporter(), name="stats-reporter")
        except asyncio.CancelledError:
            pass
        finally:
            self.is_running = False
            logger.info("sentinel_stopped", stats=self.get_stats())

    def _request_shutdown(self) -> None:
        logger.info("shutdown_requested")
        for task in asyncio.all_tasks():
            task.cancel()

    # ── Event loop ─────────────────────────────────────────────────────────────

    async def _event_loop(self) -> None:
        if self.config.mode == "live":
            await self._live_loop()
        else:
            await self._simulation_loop()

    async def _simulation_loop(self) -> None:
        from sentinel.simulation import SimulationSource
        source = SimulationSource(self.config.simulation)
        async for event in source.events():
            await self._handle_event(event)

    async def _live_loop(self) -> None:
        loaded = self._loader.load()
        if not loaded:
            logger.warning("ebpf_load_failed_falling_back_to_simulation")
            await self._simulation_loop()
            return

        logger.info("ebpf_live_mode_active")
        queue: asyncio.Queue[KernelEvent] = asyncio.Queue(maxsize=50_000)

        def _bpf_callback(cpu: int, data: ctypes.c_void_p, size: int) -> None:
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
                ip       = raw.user_ip,   # PCABP: user-space call-site IP
            )
            try:
                queue.put_nowait(evt)
            except asyncio.QueueFull:
                pass  # drop when backpressure builds

        # BPF poll runs in a thread — ring buffer is synchronous
        async def _poll_thread() -> None:
            while self.is_running:
                await asyncio.to_thread(self._loader.poll, _bpf_callback)

        async def _drain_queue() -> None:
            while self.is_running:
                event = await queue.get()
                m.queue_depth.set(queue.qsize())
                await self._handle_event(event)

        await asyncio.gather(_poll_thread(), _drain_queue())

    # ── Hard-trigger and flagged-PID helpers ───────────────────────────────────

    def _is_hard_trigger(self, event: KernelEvent) -> bool:
        """True when the event touches a resource that always demands LLM review.

        Bypasses both the minimum-window-size guard and the entropy gate so that
        an attacker who issues only FILE_R syscalls (entropy=0, EVASION-01) or
        spaces out one attack syscall per window (EVASION-03) is still caught on
        the first sensitive-resource access.

        prctl(PR_SET_NAME) events (EVASION-08) are always hard-triggered:
        any comm rename is immediately suspicious and must be analyzed.
        """
        from sentinel.models import SyscallType
        if event.sc_type == int(SyscallType.PRCTL):
            return True
        return any(p in event.resource for p in HARD_TRIGGER_RESOURCES)

    def _is_flagged_pid(self, pid: int) -> bool:
        """True when this PID (or its parent) was recently labelled MALICIOUS.

        Clears expired entries on read. Enables cross-PID kill-chain detection:
        once PID 23000 is flagged, child PID 23001 bypasses the entropy gate on
        its next event (fixes EVASION-04).
        """
        now = time.monotonic()
        expired = [p for p, exp in self._flagged_pids.items() if exp < now]
        for p in expired:
            del self._flagged_pids[p]
        if pid in self._flagged_pids:
            return True
        # Check if parent is flagged
        ppid = self._ppid_map.get(pid)
        return ppid is not None and ppid in self._flagged_pids

    def _flag_pid(self, pid: int) -> None:
        expiry = time.monotonic() + FLAGGED_PID_TTL_SECONDS
        self._flagged_pids[pid] = expiry

    # ── Main event handler ─────────────────────────────────────────────────────

    async def _handle_event(self, event: KernelEvent) -> None:
        self._stats["events"] += 1
        m.events_total.inc()

        if event.ppid > 1:
            self._ppid_map[event.pid] = event.ppid

        if self._pipeline is not None:
            await self._pipeline.push_event(event)
            m.active_pids.set(
                self._pipeline.stats()["detector"].get("active_pids", 0)
            )

    def _record_decision(self, entry: dict) -> None:
        """Callback from AuditorAgent — feeds /decisions API and Prometheus."""
        self._recent.append({
            "ts":         entry.get("ts"),
            "pid":        entry.get("pid"),
            "comm":       entry.get("comm"),
            "label":      entry.get("label"),
            "confidence": entry.get("confidence"),
            "reasoning":  entry.get("reasoning"),
            "mitre_ttps": entry.get("mitre_ttps", []),
            "model_used": entry.get("cove", {}).get("draft_label", "pipeline"),
            "latency_ms": entry.get("latency", {}).get("total_ms"),
            "tier":       entry.get("tier"),
        })
        llm_ms = entry.get("latency", {}).get("llm_ms", 0)
        if llm_ms and llm_ms > 0:
            m.llm_latency_seconds.observe(llm_ms / 1000.0)
        if entry.get("label") == "MALICIOUS":
            for ttp in entry.get("mitre_ttps", []):
                m.threats_total.labels(ttp=ttp).inc()
            tier = entry.get("tier", "LOG_ONLY")
            m.enforcement_total.labels(action=tier).inc()

    # ── Background tasks ───────────────────────────────────────────────────────

    async def _api_server(self) -> None:
        if not self.config.api.enabled:
            return
        uv_config = uvicorn.Config(
            fastapi_app,
            host=self.config.api.host,
            port=self.config.api.port,
            log_level="warning",
            access_log=False,
        )
        server = uvicorn.Server(uv_config)
        logger.info("api_server_started", host=self.config.api.host, port=self.config.api.port)
        await server.serve()

    async def _stats_reporter(self) -> None:
        while self.is_running:
            await asyncio.sleep(30)
            s = self.get_stats()
            logger.info(
                "stats",
                events=s["events"],
                llm_invoked=s.get("llm_invoked", 0),
                enforced=s.get("enforced", 0),
            )
