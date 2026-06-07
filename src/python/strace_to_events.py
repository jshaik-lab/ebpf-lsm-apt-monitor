"""
strace_to_events.py — Parse strace -f -tt -T output into SENTINEL KernelEvent objects.

strace invocation that produces parseable output:
    strace -f -tt -T -q \
        -e trace=execve,openat,open,connect,listen,fork,clone,mmap,ptrace,setuid \
        -o /tmp/trace.log <command>

Output line format (with -tt -T -f):
    <pid> <HH:MM:SS.usec> <syscall>(<args>) = <ret> <<elapsed>>
    <pid> <HH:MM:SS.usec> --- SIG... ---       (signals — skipped)
    <pid> <HH:MM:SS.usec> +++ exited ...        (exit — skipped)
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from sentinel.models import KernelEvent, SyscallType

# ── Regex patterns ────────────────────────────────────────────────────────────

# Line: optional pid, time, syscall(args) = retval <elapsed>
_LINE = re.compile(
    r'^\[?(\d+)\]?\s+'                     # pid
    r'(\d+:\d+:\d+\.\d+)\s+'              # timestamp HH:MM:SS.usec
    r'(\w+)\s*\((.*)\)\s*=\s*(-?\d+|0x[0-9a-f]+)'  # syscall(args) = ret
    r'(?:\s+<([\d.]+)>)?',                # optional elapsed
    re.DOTALL,
)

# Quoted path: "..."  or  AT_FDCWD, "/path/..."
_PATH = re.compile(r'"(/[^"]*)"')

# IP:port from connect: sin_addr=inet_addr("x.x.x.x"), sin_port=htons(N)
_INET_ADDR = re.compile(r'inet_addr\("([^"]+)"\)')
_INET_PORT = re.compile(r'sin_port=htons\((\d+)\)')

_SYSCALL_MAP: Dict[str, int] = {
    "execve":  int(SyscallType.EXEC),
    "openat":  int(SyscallType.FILE_R),   # refined below based on flags
    "open":    int(SyscallType.FILE_R),
    "connect": int(SyscallType.NET_CON),
    "listen":  int(SyscallType.NET_LIS),
    "fork":    int(SyscallType.FORK),
    "clone":   int(SyscallType.CLONE),
    "mmap":    int(SyscallType.MMAP),
    "ptrace":  int(SyscallType.PTRACE),
    "setuid":  int(SyscallType.SETUID),
}


def _parse_time(ts: str) -> int:
    """HH:MM:SS.usec → nanoseconds since midnight (relative ordering only)."""
    parts = ts.split(":")
    h, m, rest = int(parts[0]), int(parts[1]), parts[2]
    s_parts = rest.split(".")
    s  = int(s_parts[0])
    us = int(s_parts[1]) if len(s_parts) > 1 else 0
    return ((h * 3600 + m * 60 + s) * 1_000_000 + us) * 1000


def parse_strace_log(
    log_text: str,
    comm_map: Optional[Dict[int, str]] = None,   # pid→comm override
    default_comm: str = "unknown",
    label: str = "BENIGN",
) -> List[KernelEvent]:
    """
    Parse a strace log into a list of KernelEvent objects.

    comm_map lets callers supply the process name for each PID (because
    strace does not emit comm names, only PIDs).  If absent, default_comm is used.
    """
    if comm_map is None:
        comm_map = {}

    events: List[KernelEvent] = []
    first_ts: Optional[int] = None

    for raw_line in log_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        m = _LINE.match(line)
        if not m:
            continue

        pid_s, ts_s, syscall, args, ret_s, elapsed_s = m.groups()
        pid    = int(pid_s)
        ts_ns  = _parse_time(ts_s)
        if first_ts is None:
            first_ts = ts_ns
        ts_ns -= first_ts   # make relative to first event

        sc_int = _SYSCALL_MAP.get(syscall.lower())
        if sc_int is None:
            continue

        # Determine comm
        comm = comm_map.get(pid, default_comm)

        # Refine FILE_R vs FILE_W for openat/open
        resource = ""
        if syscall.lower() in ("openat", "open"):
            paths = _PATH.findall(args)
            resource = paths[-1] if paths else ""   # last quoted path is the file
            if "O_WRONLY" in args or "O_RDWR" in args or "O_CREAT" in args:
                sc_int = int(SyscallType.FILE_W)
            else:
                sc_int = int(SyscallType.FILE_R)
            # skip failed opens (ret < 0) — file did not exist
            try:
                if int(ret_s) < 0:
                    continue
            except ValueError:
                pass

        elif syscall.lower() == "execve":
            paths = _PATH.findall(args)
            resource = paths[0] if paths else ""
            # Update comm map: the first quoted arg is the new binary
            if resource:
                comm_map[pid] = resource.split("/")[-1][:15]
                comm = comm_map[pid]

        elif syscall.lower() == "connect":
            addr  = _INET_ADDR.search(args)
            port  = _INET_PORT.search(args)
            if addr and port:
                resource = f"{addr.group(1)}:{port.group(1)}"
            else:
                continue   # non-IPv4 connect, skip

        elif syscall.lower() == "listen":
            resource = "0.0.0.0:0"   # placeholder

        events.append(KernelEvent(
            ts_ns    = ts_ns,
            pid      = pid,
            ppid     = max(1, pid - 1),
            uid      = 0,
            comm     = comm,
            sc_type  = sc_int,
            resource = resource,
        ))

    return events


def parse_strace_file(path: str, **kwargs) -> List[KernelEvent]:
    with open(path) as f:
        return parse_strace_log(f.read(), **kwargs)
