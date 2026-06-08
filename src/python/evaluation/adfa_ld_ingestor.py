"""
adfa_ld_ingestor.py — ADFA-LD / ADFA-NI dataset ingestor for SENTINEL.

The ADFA Linux Dataset (ADFA-LD) provides system call traces as integer
sequences (one integer per line = one syscall number), with a label derived
from the subdirectory:
  ADFA-LD/Training_Data_Master/   → BENIGN
  ADFA-LD/Attack_Data_Master/     → MALICIOUS (subdirs named by attack type)

Converts ADFA-LD traces to KernelEvent streams for evaluation.

Reference:
  Creech & Hu, "A Semantic Approach to Host-Based Intrusion Detection Systems
  Using Contiguous and Discontinuous System Call Patterns," IEEE TDSC, 2014.

Usage:
    from evaluation.adfa_ld_ingestor import ADFALDIngestor
    ingestor = ADFALDIngestor("/path/to/ADFA-LD")
    for trace in ingestor.traces():
        events, label = trace.events, trace.label
"""
from __future__ import annotations

import os
import logging
from dataclasses import dataclass
from typing import Iterator, List, Optional

logger = logging.getLogger("sentinel.eval.adfa_ld")

# Linux syscall numbers → SyscallType mapping (x86_64, kernel 4.x / 5.x).
# Only the subset relevant to SENTINEL's detection logic is mapped;
# the remainder collapses to OTHER (15).
_SC_MAP: dict[int, int] = {
    # EXEC family
    59:  0,   # execve
    322: 0,   # execveat
    # FILE_R family
    0:   1,   # read
    17:  1,   # pread64
    19:  1,   # readv
    # FILE_W family
    1:   2,   # write
    18:  2,   # pwrite64
    20:  2,   # writev
    # NET_CON
    42:  3,   # connect
    44:  3,   # sendto
    # NET_LIS
    49:  4,   # bind
    50:  4,   # listen
    # FORK/CLONE
    57:  5,   # fork
    56:  5,   # clone
    58:  5,   # vfork
    # SETUID
    105: 7,   # setuid
    117: 7,   # setresuid
    # MMAP
    9:   8,   # mmap
    10:  8,   # mprotect
    # PTRACE
    101: 9,   # ptrace
    # PRCTL
    157: 10,  # prctl
}
_SC_OTHER = 15

# Synthetic resource strings for ADFA-LD syscall types (no path info available).
_SC_RESOURCE: dict[int, str] = {
    0:  "[exec]",
    1:  "[file_read]",
    2:  "[file_write]",
    3:  "[net_connect]",
    4:  "[net_listen]",
    5:  "[fork]",
    7:  "[setuid]",
    8:  "[mmap]",
    9:  "[ptrace]",
    10: "[prctl]",
    15: "[other]",
}

# Known ADFA-LD attack subdirectory names → MITRE ATT&CK TTP hints.
_ATTACK_DIR_TTP: dict[str, str] = {
    "adduser":         "T1136",  # Create Account
    "hydra_ftp":       "T1110",  # Brute Force
    "hydra_ssh":       "T1110",
    "java_meterpreter":"T1055",  # Process Injection
    "meterpreter":     "T1055",
    "webshell":        "T1505",  # Server Software Component
    "c100":            "T1059",  # Command Interpreter (generic shell)
}


@dataclass
class ADFATrace:
    events: list       # list[KernelEvent]
    label:  str        # "BENIGN" | "MALICIOUS"
    path:   str        # source file path
    attack_type: Optional[str] = None   # ADFA attack subdir name, or None


class ADFALDIngestor:
    """
    Parses ADFA-LD or ADFA-NI directory structure into KernelEvent traces.

    Expected layout:
        <root>/Training_Data_Master/  (benign)
        <root>/Attack_Data_Master/<attack_name>/  (malicious)

    Each file contains one integer syscall number per line.
    """

    def __init__(self, root: str, pid_base: int = 40000):
        self.root = root
        self._pid_base = pid_base

    def traces(self) -> Iterator[ADFATrace]:
        yield from self._scan_dir(
            os.path.join(self.root, "Training_Data_Master"),
            label="BENIGN",
            attack_type=None,
        )
        attack_root = os.path.join(self.root, "Attack_Data_Master")
        if os.path.isdir(attack_root):
            for attack_name in sorted(os.listdir(attack_root)):
                subdir = os.path.join(attack_root, attack_name)
                if os.path.isdir(subdir):
                    yield from self._scan_dir(
                        subdir,
                        label="MALICIOUS",
                        attack_type=attack_name,
                    )

    def _scan_dir(self, path: str, label: str,
                  attack_type: Optional[str]) -> Iterator[ADFATrace]:
        if not os.path.isdir(path):
            logger.warning("ADFA-LD directory not found: %s", path)
            return
        for fname in sorted(os.listdir(path)):
            fpath = os.path.join(path, fname)
            if not os.path.isfile(fpath):
                continue
            events = self._parse_trace(fpath, self._pid_base)
            self._pid_base += 1
            if events:
                yield ADFATrace(
                    events=events,
                    label=label,
                    path=fpath,
                    attack_type=attack_type,
                )

    @staticmethod
    def _parse_trace(path: str, pid: int) -> List:
        """Parse a single ADFA-LD trace file into KernelEvents."""
        try:
            from sentinel.models import KernelEvent
        except ImportError:
            import sys, os
            sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
            from sentinel.models import KernelEvent

        events = []
        try:
            with open(path) as f:
                for ts_idx, line in enumerate(f):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        sc_num = int(line)
                    except ValueError:
                        continue
                    sc_type = _SC_MAP.get(sc_num, _SC_OTHER)
                    resource = _SC_RESOURCE.get(sc_type, "[other]")
                    events.append(KernelEvent(
                        ts_ns=ts_idx * 1_000_000,
                        pid=pid,
                        ppid=max(1, pid - 1),
                        uid=1000,
                        comm="adfa_proc",
                        sc_type=sc_type,
                        resource=resource,
                        ip=0,
                    ))
        except OSError as exc:
            logger.error("Failed to read ADFA-LD trace %s: %s", path, exc)
        return events

    def summary(self) -> dict:
        benign_count = attack_count = 0
        attack_types: dict[str, int] = {}
        for trace in self.traces():
            if trace.label == "BENIGN":
                benign_count += 1
            else:
                attack_count += 1
                if trace.attack_type:
                    attack_types[trace.attack_type] = (
                        attack_types.get(trace.attack_type, 0) + 1
                    )
        return {
            "benign_traces":  benign_count,
            "attack_traces":  attack_count,
            "total_traces":   benign_count + attack_count,
            "attack_types":   attack_types,
        }
