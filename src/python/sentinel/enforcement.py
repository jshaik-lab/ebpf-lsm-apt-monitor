"""Confidence-Weighted Adaptive Enforcement (CWAE) Engine — Algorithm 3.

Enforcement tiers (Equation 3 from the paper):
  c < 0.30  → LOG_ONLY
  c < 0.50  → SIGSTOP  + alert
  c < 0.70  → SIGKILL  + audit dump
  c < 0.85  → SIGKILL  + XDP quarantine
  c >= 0.85 → SIGKILL  + XDP + cgroup freeze + incident report
"""
from __future__ import annotations

import asyncio
import bisect
import ctypes
import json
import os
import signal
import time
from collections import deque
from pathlib import Path
from typing import Dict, List

import structlog

from typing import Optional

from sentinel.models import EnforcementRecord, EnforcementTier, ThreatDecision, TIER_LABELS

logger = structlog.get_logger(__name__)

# eBPF enforce_map action codes (must match sentinel.c)
_ENF_NONE       = 0
_ENF_SIGSTOP    = 1
_ENF_SIGKILL    = 2
_ENF_QUARANTINE = 3

_BPF_MAP_UPDATE_ELEM = 2
_BPF_ANY             = 0


class _LatencyTracker:
    """Rolling percentile tracker for enforcement latency measurements.

    Maintains a fixed-size sorted buffer. Percentiles are computed exactly
    over the last `maxlen` samples — suitable for paper Section V-C reporting.
    """

    def __init__(self, maxlen: int = 10_000):
        self._buf: deque = deque(maxlen=maxlen)
        self._sorted: List[float] = []   # maintained sorted for O(log n) insert

    def record(self, latency_us: float) -> None:
        if len(self._buf) == self._buf.maxlen:
            # Evict oldest — remove from sorted list
            oldest = self._buf[0]
            idx = bisect.bisect_left(self._sorted, oldest)
            if idx < len(self._sorted) and self._sorted[idx] == oldest:
                self._sorted.pop(idx)
        self._buf.append(latency_us)
        bisect.insort(self._sorted, latency_us)

    def percentile(self, p: float) -> float:
        """Return the p-th percentile (p ∈ [0, 100]) from recorded samples."""
        if not self._sorted:
            return 0.0
        idx = max(0, int(len(self._sorted) * p / 100) - 1)
        return round(self._sorted[idx], 3)

    @property
    def stats(self) -> Dict[str, float]:
        return {
            "count":   len(self._sorted),
            "p50_us":  self.percentile(50),
            "p95_us":  self.percentile(95),
            "p99_us":  self.percentile(99),
            "min_us":  round(self._sorted[0],  3) if self._sorted else 0.0,
            "max_us":  round(self._sorted[-1], 3) if self._sorted else 0.0,
        }


def _bpf_map_update(map_fd: int, key: int, value: int) -> bool:
    """Write key→value into a BPF hash map via the bpf() syscall."""
    try:
        class _MapElem(ctypes.Structure):
            _fields_ = [
                ("map_fd", ctypes.c_uint),
                ("key",    ctypes.c_uint64),
                ("value",  ctypes.c_uint64),
                ("flags",  ctypes.c_uint64),
            ]
        key_buf   = ctypes.c_uint32(key)
        value_buf = ctypes.c_uint8(value)
        attr = _MapElem()
        attr.map_fd = map_fd
        attr.key    = ctypes.addressof(key_buf)
        attr.value  = ctypes.addressof(value_buf)
        attr.flags  = _BPF_ANY
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        ret  = libc.syscall(321, _BPF_MAP_UPDATE_ELEM, ctypes.addressof(attr), ctypes.sizeof(attr))
        return ret == 0
    except Exception as exc:
        logger.debug("bpf_map_update_failed", error=str(exc))
        return False


class CWAEEngine:
    """Confidence-Weighted Adaptive Enforcement — Algorithm 3."""

    TIERS = [
        (0.30, EnforcementTier.LOG_ONLY),
        (0.50, EnforcementTier.PAUSE),
        (0.70, EnforcementTier.KILL),
        (0.85, EnforcementTier.QUARANTINE),
        (1.01, EnforcementTier.ISOLATE),
    ]

    def __init__(
        self,
        enforce_map_fd:    int  = -1,
        xdp_quarantine_fd: int  = -1,
        audit_log_path:    str  = "/var/log/sentinel/audit.jsonl",
        incident_log_path: str  = "/var/log/sentinel/incidents.jsonl",
        dry_run:           bool = True,
    ):
        self._enforce_fd    = enforce_map_fd
        self._xdp_fd        = xdp_quarantine_fd
        self._audit_path    = Path(audit_log_path)
        self._incident_path = Path(incident_log_path)
        self._dry_run       = dry_run
        self._records:      List[EnforcementRecord] = []
        self._latency       = _LatencyTracker(maxlen=10_000)

        # Ensure log dirs exist
        self._audit_path.parent.mkdir(parents=True, exist_ok=True)
        self._incident_path.parent.mkdir(parents=True, exist_ok=True)

    def compute_tier(self, decision: ThreatDecision) -> EnforcementTier:
        """Preview what tier CWAE would assign without executing any action.

        Used by EGTE to get T_cwae before applying gates and calibration.
        """
        if decision.label == "BENIGN":
            return EnforcementTier.LOG_ONLY
        for threshold, candidate in self.TIERS:
            if decision.confidence < threshold:
                return candidate
        return EnforcementTier.ISOLATE

    async def enforce(
        self,
        pid:          int,
        comm:         str,
        decision:     ThreatDecision,
        max_tier:     Optional[EnforcementTier] = None,
        pcabp_score:  float = 0.0,
    ) -> EnforcementRecord:
        """Algorithm 3: map confidence → enforcement tier, execute action.

        Parameters
        ----------
        max_tier    : optional upper bound from EGTE (min(cwae_tier, max_tier)).
        pcabp_score : PCABP consensus score ∈ [0, 1].
            pcabp_score = max(0.4·static + 0.6·AI, 0.55·static), so a
            confirmed static call-site violation is non-maskable and floors
            at the KILL tier regardless of AI divergence (audit fix #4).
            When non-zero, the effective confidence is:
              effective_conf = max(llm_confidence, pcabp_score)
            This ensures that high-confidence PCABP violations escalate the
            enforcement tier even when the LLM is uncertain (e.g. novel attack
            that behaviorally looks like normal nginx but IPs are from heap).
        """
        t0 = time.perf_counter()

        # PCABP consensus: take the higher of LLM confidence and PCABP score.
        # If pcabp_score > llm_confidence the attack evaded the LLM but was
        # caught by the static/AI layer — still warrant enforcement.
        effective_conf = max(decision.confidence, pcabp_score)
        if pcabp_score > 0 and pcabp_score > decision.confidence:
            logger.info(
                "pcabp_confidence_override",
                pid=pid, comm=comm,
                llm_conf=round(decision.confidence, 3),
                pcabp_score=round(pcabp_score, 3),
                effective_conf=round(effective_conf, 3),
            )

        if decision.label == "BENIGN" and pcabp_score < 0.40:
            tier = EnforcementTier.LOG_ONLY
        else:
            # Default to ISOLATE (most restrictive) so any confidence > 1.01
            # (invalid but defensive) does not silently fall through to LOG_ONLY.
            tier = EnforcementTier.ISOLATE
            for threshold, candidate in self.TIERS:
                if effective_conf < threshold:
                    tier = candidate
                    break

        # Apply EGTE max_tier constraint (backward-compatible: None = no change)
        if max_tier is not None:
            tier = min(tier, max_tier)

        await asyncio.to_thread(self._dispatch, pid, comm, tier)

        latency_us = (time.perf_counter() - t0) * 1e6
        self._latency.record(latency_us)
        rec = EnforcementRecord(
            pid=pid, comm=comm,
            confidence=decision.confidence,
            tier=tier, label=decision.label,
            reasoning=decision.reasoning,
            mitre_ttps=decision.mitre_ttps,
            latency_us=latency_us,
        )
        self._records.append(rec)
        await asyncio.to_thread(self._write_audit, rec)
        if tier == EnforcementTier.ISOLATE:
            await asyncio.to_thread(self._write_incident, rec)

        logger.info(
            "cwae_decision",
            pid=pid, comm=comm,
            label=decision.label,
            confidence=round(decision.confidence, 4),
            tier=TIER_LABELS[tier],
            latency_us=round(latency_us, 2),
            mitre_ttps=decision.mitre_ttps,
            dry_run=self._dry_run,
        )
        return rec

    def _dispatch(self, pid: int, comm: str, tier: EnforcementTier) -> None:
        if tier == EnforcementTier.LOG_ONLY:
            return
        if tier == EnforcementTier.PAUSE:
            self._send_signal(pid, signal.SIGSTOP, comm)
            self._bpf_mark(pid, _ENF_SIGSTOP)
            logger.warning("enforcement_pause", pid=pid, comm=comm)
            return
        if tier in (EnforcementTier.KILL, EnforcementTier.QUARANTINE, EnforcementTier.ISOLATE):
            self._send_signal(pid, signal.SIGKILL, comm)
            self._bpf_mark(pid, _ENF_SIGKILL)
            self._dump_proc(pid)
        if tier in (EnforcementTier.QUARANTINE, EnforcementTier.ISOLATE):
            self._xdp_quarantine(pid)
        if tier == EnforcementTier.ISOLATE:
            self._cgroup_freeze(pid)

    def _send_signal(self, pid: int, sig: int, comm: str) -> None:
        if self._dry_run:
            logger.warning("enforcement_signal_dryrun", pid=pid, comm=comm, signal=sig)
            return
        try:
            os.kill(pid, sig)
            logger.warning("enforcement_signal_sent", pid=pid, comm=comm, signal=sig)
        except ProcessLookupError:
            logger.debug("enforcement_pid_already_exited", pid=pid)
        except PermissionError:
            logger.error("enforcement_permission_denied", pid=pid)

    def _bpf_mark(self, pid: int, action: int) -> None:
        if self._enforce_fd > 0:
            _bpf_map_update(self._enforce_fd, pid, action)

    def _xdp_quarantine(self, pid: int) -> None:
        try:
            cookie = os.stat(f"/proc/{pid}/ns/net").st_ino
            if self._xdp_fd > 0 and not self._dry_run:
                _bpf_map_update(self._xdp_fd, cookie, 1)
                logger.warning("enforcement_xdp_quarantine", pid=pid, netns_ino=cookie)
            else:
                logger.warning("enforcement_xdp_dryrun", pid=pid, netns_ino=cookie)
        except Exception:
            pass

    def _cgroup_freeze(self, pid: int) -> None:
        if self._dry_run:
            logger.warning("enforcement_cgroup_freeze_dryrun", pid=pid)
            return
        try:
            for line in Path(f"/proc/{pid}/cgroup").read_text().splitlines():
                if "0::" in line:
                    cg = line.split("::")[1].strip()
                    freeze = Path(f"/sys/fs/cgroup{cg}/cgroup.freeze")
                    if freeze.exists():
                        freeze.write_text("1")
                        logger.warning("enforcement_cgroup_frozen", pid=pid, cgroup=cg)
                    return
        except Exception as exc:
            logger.debug("enforcement_cgroup_freeze_failed", pid=pid, error=str(exc))

    def _dump_proc(self, pid: int) -> None:
        dump = self._audit_path.parent / f"memdump_{pid}_{int(time.time())}.txt"
        try:
            dump.write_text(Path(f"/proc/{pid}/maps").read_text())
            logger.info("enforcement_memdump_written", pid=pid, path=str(dump))
        except Exception:
            pass

    def _write_audit(self, rec: EnforcementRecord) -> None:
        row = {
            "ts": rec.ts_ns, "pid": rec.pid, "comm": rec.comm,
            "label": rec.label, "confidence": round(rec.confidence, 4),
            "tier": TIER_LABELS[rec.tier], "latency_us": round(rec.latency_us, 2),
            "mitre_ttps": rec.mitre_ttps, "reasoning": rec.reasoning,
        }
        try:
            with self._audit_path.open("a") as f:
                f.write(json.dumps(row) + "\n")
        except Exception as exc:
            logger.debug("audit_write_failed", error=str(exc))

    def _write_incident(self, rec: EnforcementRecord) -> None:
        row = {
            "incident_ts": rec.ts_ns, "pid": rec.pid, "comm": rec.comm,
            "confidence": round(rec.confidence, 4), "severity": "CRITICAL",
            "mitre_ttps": rec.mitre_ttps, "reasoning": rec.reasoning,
        }
        try:
            with self._incident_path.open("a") as f:
                f.write(json.dumps(row) + "\n")
        except Exception as exc:
            logger.debug("incident_write_failed", error=str(exc))

    @property
    def enforcement_stats(self) -> dict:
        stats: Dict[str, int] = {v: 0 for v in TIER_LABELS.values()}
        for r in self._records:
            stats[TIER_LABELS[r.tier]] += 1
        stats["latency"] = self._latency.stats
        return stats
