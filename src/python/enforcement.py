"""
enforcement.py — SENTINEL Confidence-Weighted Adaptive Enforcement (CWAE) Engine

Implements Algorithm 3 from the SENTINEL paper.

Enforcement tiers (Equation 3):
  c < 0.30   → LOG_ONLY
  c < 0.50   → SIGSTOP  + alert
  c < 0.70   → SIGKILL  + audit dump
  c < 0.85   → SIGKILL  + XDP quarantine
  c >= 0.85  → SIGKILL  + XDP quarantine + cgroup freeze + incident report

Communication with the eBPF enforcement map is done via ctypes + bpf syscall.
XDP quarantine is applied by writing the process's netns cookie to xdp_quarantine_map.
"""

from __future__ import annotations

import os
import ctypes
import signal
import struct
import logging
import json
import time
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


# ── Enforcement tiers ─────────────────────────────────────────────────────────

class EnforcementTier(IntEnum):
    LOG_ONLY    = 0
    PAUSE       = 1   # SIGSTOP + human alert
    KILL        = 2   # SIGKILL + audit
    QUARANTINE  = 3   # SIGKILL + XDP packet-drop
    ISOLATE     = 4   # SIGKILL + XDP + cgroup freeze + incident report

TIER_LABELS = {
    EnforcementTier.LOG_ONLY:   "LOG_ONLY",
    EnforcementTier.PAUSE:      "PAUSE",
    EnforcementTier.KILL:       "KILL",
    EnforcementTier.QUARANTINE: "QUARANTINE",
    EnforcementTier.ISOLATE:    "ISOLATE",
}

# eBPF enforce_map action codes (must match sentinel.c)
ENF_NONE      = 0
ENF_SIGSTOP   = 1
ENF_SIGKILL   = 2
ENF_QUARANTINE = 3


@dataclass
class EnforcementRecord:
    pid:        int
    comm:       str
    confidence: float
    tier:       EnforcementTier
    label:      str
    reasoning:  str
    mitre_ttps: List[str]
    ts_ns:      int = field(default_factory=lambda: time.time_ns())
    latency_us: float = 0.0


# ── BPF map interface ─────────────────────────────────────────────────────────

_BPF_MAP_UPDATE_ELEM = 2
_BPF_ANY = 0

class _BpfAttr(ctypes.Union):
    class _MapElem(ctypes.Structure):
        _fields_ = [
            ("map_fd",    ctypes.c_uint),
            ("key",       ctypes.c_uint64),
            ("value",     ctypes.c_uint64),
            ("flags",     ctypes.c_uint64),
        ]
    _fields_ = [("map_elem", _MapElem)]


def _bpf_map_update(map_fd: int, key: int, value: int) -> bool:
    """Write key→value into a BPF hash map via the bpf() syscall."""
    try:
        key_buf   = ctypes.c_uint32(key)
        value_buf = ctypes.c_uint8(value)
        attr = _BpfAttr()
        attr.map_elem.map_fd = map_fd
        attr.map_elem.key    = ctypes.addressof(key_buf)
        attr.map_elem.value  = ctypes.addressof(value_buf)
        attr.map_elem.flags  = _BPF_ANY
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        ret  = libc.syscall(321, _BPF_MAP_UPDATE_ELEM,
                            ctypes.addressof(attr), ctypes.sizeof(attr))
        return ret == 0
    except Exception as exc:
        logger.debug("BPF map update failed: %s", exc)
        return False


# ── CWAE Engine ───────────────────────────────────────────────────────────────

class CWAEEngine:
    """
    Confidence-Weighted Adaptive Enforcement engine.

    Args:
        enforce_map_fd:      File descriptor of the eBPF enforce_map.
        xdp_quarantine_fd:   File descriptor of the eBPF xdp_quarantine_map.
        audit_log_path:      Path to write JSON audit records.
        incident_log_path:   Path to write incident reports.
        dry_run:             If True, log actions but do not execute them.
    """

    TIERS = [
        (0.30, EnforcementTier.LOG_ONLY),
        (0.50, EnforcementTier.PAUSE),
        (0.70, EnforcementTier.KILL),
        (0.85, EnforcementTier.QUARANTINE),
        (1.01, EnforcementTier.ISOLATE),
    ]

    def __init__(
        self,
        enforce_map_fd:    int = -1,
        xdp_quarantine_fd: int = -1,
        audit_log_path:    str = "/var/log/sentinel_audit.jsonl",
        incident_log_path: str = "/var/log/sentinel_incidents.jsonl",
        dry_run:           bool = False,
    ):
        self._enforce_fd   = enforce_map_fd
        self._xdp_fd       = xdp_quarantine_fd
        self._audit_path   = Path(audit_log_path)
        self._incident_path = Path(incident_log_path)
        self._dry_run      = dry_run
        self._records: List[EnforcementRecord] = []

    # ── Algorithm 3 ───────────────────────────────────────────────────────────

    def enforce(
        self,
        pid:        int,
        comm:       str,
        label:      str,
        confidence: float,
        reasoning:  str,
        mitre_ttps: List[str],
    ) -> EnforcementRecord:
        """
        Implements Algorithm 3 (CWAE) from the SENTINEL paper.

        Maps confidence ∈ [0,1] to a graduated enforcement tier and executes
        the corresponding kernel action.
        """
        t0 = time.perf_counter()

        if label == "BENIGN":
            tier = EnforcementTier.LOG_ONLY
        else:
            tier = EnforcementTier.LOG_ONLY
            for threshold, candidate_tier in self.TIERS:
                if confidence < threshold:
                    tier = candidate_tier
                    break

        action = self._dispatch(pid, comm, tier)

        latency_us = (time.perf_counter() - t0) * 1e6
        rec = EnforcementRecord(
            pid=pid, comm=comm, confidence=confidence,
            tier=tier, label=label, reasoning=reasoning,
            mitre_ttps=mitre_ttps, latency_us=latency_us,
        )
        self._records.append(rec)
        self._write_audit(rec)

        if tier == EnforcementTier.ISOLATE:
            self._write_incident(rec)

        logger.info(
            "CWAE: pid=%d comm=%s label=%s conf=%.3f tier=%s latency=%.1fµs",
            pid, comm, label, confidence, TIER_LABELS[tier], latency_us,
        )
        return rec

    def _dispatch(self, pid: int, comm: str, tier: EnforcementTier) -> str:
        if tier == EnforcementTier.LOG_ONLY:
            return "logged"

        if tier == EnforcementTier.PAUSE:
            self._send_signal(pid, signal.SIGSTOP, comm)
            self._bpf_mark(pid, ENF_SIGSTOP)
            self._alert(pid, comm, "PAUSED")
            return "paused"

        if tier == EnforcementTier.KILL:
            self._send_signal(pid, signal.SIGKILL, comm)
            self._bpf_mark(pid, ENF_SIGKILL)
            self._dump_proc(pid)
            return "killed"

        if tier == EnforcementTier.QUARANTINE:
            self._send_signal(pid, signal.SIGKILL, comm)
            self._bpf_mark(pid, ENF_SIGKILL)
            self._xdp_quarantine(pid)
            return "quarantined"

        # ISOLATE
        self._send_signal(pid, signal.SIGKILL, comm)
        self._bpf_mark(pid, ENF_SIGKILL)
        self._xdp_quarantine(pid)
        self._cgroup_freeze(pid)
        return "isolated"

    def _send_signal(self, pid: int, sig: int, comm: str) -> None:
        if self._dry_run:
            logger.warning("[DRY-RUN] Would send signal %d to PID %d (%s)", sig, pid, comm)
            return
        try:
            os.kill(pid, sig)
            logger.warning("Sent signal %d to PID %d (%s)", sig, pid, comm)
        except ProcessLookupError:
            logger.debug("PID %d already exited before enforcement.", pid)
        except PermissionError:
            logger.error("Insufficient privileges to signal PID %d.", pid)

    def _bpf_mark(self, pid: int, action: int) -> None:
        if self._enforce_fd > 0:
            ok = _bpf_map_update(self._enforce_fd, pid, action)
            if not ok:
                logger.debug("BPF enforce_map update failed for PID %d", pid)

    def _xdp_quarantine(self, pid: int) -> None:
        netns_cookie = self._get_netns_cookie(pid)
        if netns_cookie and self._xdp_fd > 0 and not self._dry_run:
            _bpf_map_update(self._xdp_fd, netns_cookie, 1)
            logger.warning("XDP quarantine applied for PID %d (netns %d)", pid, netns_cookie)
        else:
            logger.warning("[DRY-RUN/NA] XDP quarantine for PID %d", pid)

    def _get_netns_cookie(self, pid: int) -> Optional[int]:
        try:
            netns_path = f"/proc/{pid}/ns/net"
            stat = os.stat(netns_path)
            return stat.st_ino
        except Exception:
            return None

    def _cgroup_freeze(self, pid: int) -> None:
        if self._dry_run:
            logger.warning("[DRY-RUN] Would freeze cgroup for PID %d", pid)
            return
        try:
            cgroup_path = Path(f"/proc/{pid}/cgroup").read_text().splitlines()
            for line in cgroup_path:
                if "0::" in line:
                    cg = line.split("::")[1].strip()
                    freeze_file = Path(f"/sys/fs/cgroup{cg}/cgroup.freeze")
                    if freeze_file.exists():
                        freeze_file.write_text("1")
                        logger.warning("Frozen cgroup %s for PID %d", cg, pid)
                    return
        except Exception as exc:
            logger.debug("Cgroup freeze failed for PID %d: %s", pid, exc)

    def _dump_proc(self, pid: int) -> None:
        dump_path = Path(f"/var/log/sentinel_memdump_{pid}_{int(time.time())}.txt")
        try:
            maps = Path(f"/proc/{pid}/maps").read_text()
            dump_path.write_text(maps)
            logger.info("Memory map dumped to %s", dump_path)
        except Exception as exc:
            logger.debug("Proc dump failed for PID %d: %s", pid, exc)

    def _alert(self, pid: int, comm: str, action: str) -> None:
        logger.warning("SENTINEL ALERT: PID=%d COMM=%s ACTION=%s", pid, comm, action)

    def _write_audit(self, rec: EnforcementRecord) -> None:
        record = {
            "ts": rec.ts_ns, "pid": rec.pid, "comm": rec.comm,
            "label": rec.label, "confidence": round(rec.confidence, 4),
            "tier": TIER_LABELS[rec.tier], "latency_us": round(rec.latency_us, 2),
            "mitre_ttps": rec.mitre_ttps, "reasoning": rec.reasoning,
        }
        try:
            with self._audit_path.open("a") as f:
                f.write(json.dumps(record) + "\n")
        except Exception as exc:
            logger.debug("Audit write failed: %s", exc)

    def _write_incident(self, rec: EnforcementRecord) -> None:
        report = {
            "incident_ts": rec.ts_ns, "pid": rec.pid, "comm": rec.comm,
            "confidence": round(rec.confidence, 4),
            "mitre_ttps": rec.mitre_ttps, "reasoning": rec.reasoning,
            "severity": "CRITICAL",
        }
        try:
            with self._incident_path.open("a") as f:
                f.write(json.dumps(report) + "\n")
        except Exception as exc:
            logger.debug("Incident write failed: %s", exc)

    @property
    def enforcement_stats(self) -> Dict[str, int]:
        stats: Dict[str, int] = {t: 0 for t in TIER_LABELS.values()}
        for r in self._records:
            stats[TIER_LABELS[r.tier]] += 1
        return stats
