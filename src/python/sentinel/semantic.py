"""Semantic security layer — Core Novelty 2.

Converts low-level kernel events into high-level security insights.
These annotations are injected into the IPG serialization to give the
LLM richer, attack-relevant context without extra token overhead.

Example transformations:
  execve("/tmp/exploit") → "execution from temp: possible staged payload [T1059/HIGH]"
  openat(R, /etc/shadow) → "credential access: system password database [T1003/CRITICAL]"
  connect(185.x:4444)    → "outbound to unusual port: possible C2 beacon [T1071/HIGH]"
  listen(0.0.0.0:80)     → "standard HTTP server binding [BENIGN/LOW]"

Paper contribution: SemanticLabeler produces the 'semantic' field injected
into each IPG edge, improving LLM classification accuracy by providing
pre-computed attack-pattern hints — measurable by comparing LLM accuracy
with and without semantic annotations (ablation study, Section V-C).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple

from sentinel.models import KernelEvent, SyscallType


@dataclass
class SemanticLabel:
    """Security-annotated interpretation of a single kernel event."""
    raw_syscall:       str
    resource:          str
    security_label:    str           # human-readable interpretation
    attack_relevance:  List[str]     # MITRE ATT&CK technique IDs
    risk_level:        str           # LOW | MEDIUM | HIGH | CRITICAL
    is_benign_hint:    bool = False  # True when this strongly suggests benign activity

    def compact(self) -> str:
        """Compact form for IPG edge annotation (~10-15 tokens)."""
        ttps = ",".join(self.attack_relevance) if self.attack_relevance else "BENIGN"
        return f"{self.security_label} [{ttps}/{self.risk_level}]"


# Rule format: (resource_patterns, sc_types, label, ttps, risk, is_benign_hint)
# resource_patterns: list of substrings; ANY match triggers the rule
# sc_types: list of SyscallType ints; EMPTY = any syscall
_SEMANTIC_RULES: List[Tuple] = [
    # ── CRITICAL: direct credential access ─────────────────────────────────────
    (["/etc/shadow"],            [int(SyscallType.FILE_R)],
     "credential access: system password database",        ["T1003"],        "CRITICAL", False),
    (["/etc/passwd"],            [int(SyscallType.FILE_R)],
     "account enumeration: user database read",            ["T1003","T1087"],"HIGH",     False),
    (["/etc/sudoers"],           [int(SyscallType.FILE_R), int(SyscallType.FILE_W)],
     "privilege config: sudo rules accessed",              ["T1003","T1068"],"CRITICAL", False),
    (["/.ssh/id_rsa", "/.ssh/id_ed25519", "/.ssh/id_ecdsa"],
                                 [int(SyscallType.FILE_R)],
     "credential access: SSH private key read",            ["T1003","T1552"],"CRITICAL", False),
    ([".aws/credentials", ".aws/config"],
                                 [int(SyscallType.FILE_R)],
     "credential access: AWS access keys",                 ["T1003","T1552"],"CRITICAL", False),
    (["ssl/private", "server.key", ".pem"],
                                 [int(SyscallType.FILE_R)],
     "credential access: TLS private key",                 ["T1003","T1552"],"CRITICAL", False),

    # ── HIGH: execution anomalies ───────────────────────────────────────────────
    (["/tmp/", "/dev/shm/", "/var/tmp/"],
                                 [int(SyscallType.EXEC)],
     "execution from temp: possible staged payload",       ["T1059","T1105"],"HIGH",     False),
    (["/.hidden/", "/.x", "/.cache/"],
                                 [int(SyscallType.EXEC)],
     "execution from hidden path: evasion attempt",        ["T1059","T1564"],"HIGH",     False),

    # ── HIGH: process injection ─────────────────────────────────────────────────
    ([],                         [int(SyscallType.PTRACE)],
     "process injection: ptrace attach",                   ["T1055"],        "HIGH",     False),
    (["PROT_EXEC", "PROT_WRITE"],
                                 [int(SyscallType.MMAP)],
     "memory injection: RWX page allocation",              ["T1055","T1620"],"HIGH",     False),

    # ── HIGH: privilege escalation ──────────────────────────────────────────────
    ([],                         [int(SyscallType.SETUID)],
     "privilege escalation: setuid call",                  ["T1068"],        "HIGH",     False),

    # ── HIGH: defense evasion ───────────────────────────────────────────────────
    (["/var/log/auth.log", "/var/log/secure", "/var/log/syslog"],
                                 [int(SyscallType.FILE_W)],
     "log tampering: security log overwrite",              ["T1562","T1070"],"HIGH",     False),
    (["/etc/cron.d/", "/etc/crontab", "/etc/rc.local"],
                                 [int(SyscallType.FILE_W)],
     "persistence: cron/init script modification",         ["T1562","T1053"],"HIGH",     False),

    # ── HIGH: C2 patterns ───────────────────────────────────────────────────────
    ([":4444", ":4443", ":1337", ":31337", ":8888", ":9999", ":6666"],
                                 [int(SyscallType.NET_CON)],
     "outbound to unusual port: probable C2 beacon",       ["T1071","T1095"],"HIGH",     False),
    (["185.", "91.", "45.142", "194.165"],
                                 [int(SyscallType.NET_CON)],
     "outbound to known-suspicious IP range",              ["T1071"],        "MEDIUM",   False),

    # ── MEDIUM: lateral movement ────────────────────────────────────────────────
    (["192.168.", "10.0.", "172.16."],
                                 [int(SyscallType.NET_CON)],
     "internal lateral: RFC-1918 outbound connection",     ["T1021","T1210"],"MEDIUM",   False),

    # ── MEDIUM: data staging ────────────────────────────────────────────────────
    (["/tmp/", "/dev/shm/"],     [int(SyscallType.FILE_W)],
     "data staging: write to temp directory",              ["T1074"],        "MEDIUM",   False),

    # ── LOW / BENIGN hints ──────────────────────────────────────────────────────
    (["/var/www/html/", "/srv/www/"],
                                 [int(SyscallType.FILE_R)],
     "web-root read: normal web server file serving",      [],               "LOW",      True),
    (["/var/log/nginx/", "/var/log/apache2/"],
                                 [int(SyscallType.FILE_W)],
     "web server log write: normal operation",             [],               "LOW",      True),
    (["deb.debian.org", "archive.ubuntu.com", "pypi.org", "registry.npmjs.org"],
                                 [int(SyscallType.NET_CON)],
     "package manager connection: normal update operation", [],              "LOW",      True),
    (["/var/lib/postgresql/", "/var/lib/mysql/"],
                                 [int(SyscallType.FILE_R), int(SyscallType.FILE_W)],
     "database I/O: normal database engine operation",     [],               "LOW",      True),
    (["/proc/self/", "/proc/sys/"],
                                 [int(SyscallType.FILE_R)],
     "self-inspection: normal process status read",        [],               "LOW",      True),

    # ── Standard server ports (benign) ──────────────────────────────────────────
    ([":80", ":443", ":8080"],   [int(SyscallType.NET_LIS)],
     "standard web server port: normal bind",              [],               "LOW",      True),
    ([":22"],                    [int(SyscallType.NET_LIS)],
     "SSH server port: normal sshd bind",                  [],               "LOW",      True),
    ([":5432", ":3306", ":6379"],
                                 [int(SyscallType.NET_LIS)],
     "database server port: normal loopback bind",         [],               "LOW",      True),
]

_DEFAULT_LABEL = SemanticLabel(
    raw_syscall="unknown",
    resource="",
    security_label="no specific security pattern matched",
    attack_relevance=[],
    risk_level="LOW",
    is_benign_hint=False,
)


class SemanticLabeler:
    """Maps KernelEvents to human-readable security labels for IPG annotation."""

    def label(self, event: KernelEvent) -> SemanticLabel:
        """Return the most specific SemanticLabel for this event."""
        sc_label = _get_syscall_label(event.sc_type)
        resource = event.resource

        for res_patterns, sc_types, label, ttps, risk, is_benign in _SEMANTIC_RULES:
            # Syscall type match
            sc_match = (not sc_types) or (event.sc_type in sc_types)
            if not sc_match:
                continue

            # Resource pattern match
            if res_patterns:
                res_match = any(p.lower() in resource.lower() for p in res_patterns)
            else:
                res_match = True  # rule applies to all resources for this syscall

            if sc_match and res_match:
                return SemanticLabel(
                    raw_syscall=sc_label,
                    resource=resource,
                    security_label=label,
                    attack_relevance=list(ttps),
                    risk_level=risk,
                    is_benign_hint=is_benign,
                )

        # No rule matched — neutral label
        return SemanticLabel(
            raw_syscall=sc_label,
            resource=resource,
            security_label=f"{sc_label} on {resource[:40] or 'unknown resource'}",
            attack_relevance=[],
            risk_level="LOW",
            is_benign_hint=False,
        )

    def label_window(self, events: List[KernelEvent]) -> List[SemanticLabel]:
        return [self.label(e) for e in events]

    def max_risk(self, events: List[KernelEvent]) -> str:
        """Highest risk level across all events in window."""
        order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        risk_levels = [self.label(e).risk_level for e in events]
        return max(risk_levels, key=lambda r: order.get(r, 0), default="LOW")

    def attack_ttps(self, events: List[KernelEvent]) -> List[str]:
        """Deduplicated list of all TTPs present in the window."""
        seen: set[str] = set()
        result = []
        for lbl in self.label_window(events):
            for ttp in lbl.attack_relevance:
                if ttp not in seen:
                    seen.add(ttp)
                    result.append(ttp)
        return result


def _get_syscall_label(sc_type: int) -> str:
    labels = {
        int(SyscallType.EXEC):    "execve",
        int(SyscallType.FILE_R):  "openat(R)",
        int(SyscallType.FILE_W):  "openat(W)",
        int(SyscallType.NET_CON): "connect",
        int(SyscallType.NET_LIS): "listen",
        int(SyscallType.FORK):    "fork",
        int(SyscallType.CLONE):   "clone",
        int(SyscallType.SETUID):  "setuid",
        int(SyscallType.MMAP):    "mmap",
        int(SyscallType.PTRACE):  "ptrace",
    }
    return labels.get(sc_type, "syscall")
