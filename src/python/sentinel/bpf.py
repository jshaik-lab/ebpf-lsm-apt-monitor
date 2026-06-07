"""eBPF program loader — wraps BCC with a graceful no-BCC fallback.

In live mode the BPFLoader attaches sentinel.bpf.o to the kernel ring buffer.
When BCC is unavailable (macOS, missing kernel headers) it logs a warning and
returns available=False; SentinelAgent then switches to SimulationSource.
"""
from __future__ import annotations

import ctypes
import logging
from pathlib import Path
from typing import Callable, Optional

logger = logging.getLogger(__name__)


class EventStruct(ctypes.Structure):
    """Mirrors struct event_t in sentinel.c — pack=1 for exact layout match.

    Layout (packed, 224 bytes total):
      offset 0:   ts_ns          u64
      offset 8:   pid            u32
      offset 12:  ppid           u32
      offset 16:  uid            u32
      offset 20:  gid            u32
      offset 24:  sc_type        u8
      offset 25:  flags          u8
      offset 26:  net_port       u16
      offset 28:  net_ip4        u32
      offset 32:  arm64_regs[3]  u64[3]  (24 bytes)
      offset 56:  comm           char[16]
      offset 72:  resource       char[128]
      offset 200: original_comm  char[16]
      offset 216: user_ip        u64      ← PCABP call-site IP
    """
    _pack_ = 1
    _fields_ = [
        ("ts_ns",         ctypes.c_uint64),
        ("pid",           ctypes.c_uint32),
        ("ppid",          ctypes.c_uint32),
        ("uid",           ctypes.c_uint32),
        ("gid",           ctypes.c_uint32),
        ("sc_type",       ctypes.c_uint8),
        ("flags",         ctypes.c_uint8),
        ("net_port",      ctypes.c_uint16),
        ("net_ip4",       ctypes.c_uint32),
        ("arm64_regs",    ctypes.c_uint64 * 3),
        ("comm",          ctypes.c_char * 16),
        ("resource",      ctypes.c_char * 128),
        ("original_comm", ctypes.c_char * 16),
        ("user_ip",       ctypes.c_uint64),   # PCABP: user-space call-site IP
    ]


class BPFLoader:
    """Loads and manages the eBPF sentinel program via BCC."""

    def __init__(self, obj_path: str, poll_interval_ms: int = 50):
        self._obj_path = obj_path
        self._poll_ms  = poll_interval_ms
        self._bpf      = None
        self.available = False

    def load(self) -> bool:
        if not Path(self._obj_path).exists():
            logger.warning(
                "eBPF object not found: %s — switching to simulation mode",
                self._obj_path,
            )
            return False
        try:
            from bcc import BPF  # type: ignore[import]
            self._bpf      = BPF(src_file=self._obj_path)
            self.available = True
            logger.info("eBPF program loaded: %s", self._obj_path)
            return True
        except ImportError:
            logger.warning("BCC not available — live eBPF mode disabled")
        except Exception as exc:
            logger.error("eBPF load failed: %s", exc)
        return False

    def poll(self, callback: Callable, timeout_ms: Optional[int] = None) -> None:
        if not self.available or self._bpf is None:
            return
        ms = timeout_ms or self._poll_ms
        try:
            self._bpf["events"].open_ring_buffer(callback)
            self._bpf.ring_buffer_poll(ms)
        except Exception as exc:
            logger.debug("Ring buffer poll error: %s", exc)

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
