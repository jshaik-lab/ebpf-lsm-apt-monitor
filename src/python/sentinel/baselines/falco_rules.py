"""Rule-based baseline classifier mimicking Falco's detection logic.

Implements deterministic pattern-matching rules on KernelEvent objects
equivalent to Falco YAML rules. Used as Table III baseline in the paper.

Key limitation vs SENTINEL: rules must be hand-authored for each attack
pattern. Novel attack variations not in the ruleset are missed entirely.
"""
from __future__ import annotations

import time
from typing import List, Tuple

from sentinel.models import KernelEvent, SyscallType, ThreatDecision

# (rule_name, ttp, score, resource_patterns, sc_types_required)
# resource_patterns: any match triggers; sc_types_required: all must appear (empty=any)
_RULES: List[Tuple[str, str, float, List[str], List[int]]] = [
    # Credential access — high confidence (specific sensitive paths)
    ("detect_shadow_read",    "T1003", 0.90, ["/etc/shadow"], [int(SyscallType.FILE_R)]),
    ("detect_key_file_read",  "T1003", 0.85, ["/.ssh/id_rsa", "/.ssh/id_ed25519",
                                               ".aws/credentials", "ssl/private"], []),
    # Privilege escalation
    ("detect_setuid",         "T1068", 0.88, [],              [int(SyscallType.SETUID)]),
    # Process injection
    ("detect_ptrace",         "T1055", 0.92, [],              [int(SyscallType.PTRACE)]),
    # Suspicious execution paths
    ("detect_exec_tmp",       "T1059", 0.75, ["/tmp/", "/dev/shm/", "/.hidden"],
                                             [int(SyscallType.EXEC)]),
    # Defense evasion — log tampering
    ("detect_log_wipe",       "T1562", 0.70, ["/var/log/auth.log", "/var/log/syslog",
                                               "/var/log/secure"], [int(SyscallType.FILE_W)]),
    # Persistence
    ("detect_cron_write",     "T1562", 0.72, ["/etc/cron.d/", "/etc/crontab",
                                               "/etc/sudoers"], [int(SyscallType.FILE_W)]),
    # C2 — known suspicious ports
    ("detect_c2_port",        "T1071", 0.78, [":4444", ":4443", ":1337", ":31337",
                                               ":8888", ":9999"], [int(SyscallType.NET_CON)]),
    # Exfiltration — sensitive file read + outbound connection
    ("detect_exfil_combo",    "T1041", 0.82, [], []),  # handled specially below
    # Lateral movement — multiple outbound connections
    ("detect_lateral",        "T1210", 0.65, [], []),  # handled specially below
]

_BENIGN_DAMPENERS = [
    "nginx", "apache2", "sshd", "systemd", "postgres",
    "/var/www/", "/var/lib/postgresql/", "deb.debian.org",
]

_SENSITIVE_PATTERNS = [
    "/etc/shadow", "/.ssh/id_rsa", ".aws/credentials",
    "ssl/private", "/etc/passwd",
]


def _has_resource(events: List[KernelEvent], patterns: List[str]) -> bool:
    return any(p in e.resource for e in events for p in patterns)


def _has_sc_type(events: List[KernelEvent], sc_types: List[int]) -> bool:
    types_present = {e.sc_type for e in events}
    return all(t in types_present for t in sc_types)


def _count_sc_type(events: List[KernelEvent], sc: int) -> int:
    return sum(1 for e in events if e.sc_type == sc)


class FalcoRulesClassifier:
    """Deterministic rule engine comparable to Falco open-source IDS."""

    def classify(self, events: List[KernelEvent]) -> ThreatDecision:
        t0 = time.perf_counter()
        score = 0.0
        ttps: list[str] = []

        for rule_name, ttp, rule_score, res_patterns, sc_types in _RULES:
            if rule_name == "detect_exfil_combo":
                # Special: sensitive read AND outbound connection in same trace
                has_sensitive = _has_resource(events, _SENSITIVE_PATTERNS)
                has_connect   = _count_sc_type(events, int(SyscallType.NET_CON)) > 0
                if has_sensitive and has_connect:
                    score += rule_score
                    ttps.append(ttp)
                continue

            if rule_name == "detect_lateral":
                # Special: ≥2 distinct outbound connections
                connections = [e.resource for e in events
                               if e.sc_type == int(SyscallType.NET_CON)]
                if len(set(connections)) >= 2:
                    score += rule_score
                    ttps.append(ttp)
                continue

            res_match = (not res_patterns) or _has_resource(events, res_patterns)
            sc_match  = (not sc_types) or _has_sc_type(events, sc_types)
            if res_match and sc_match:
                score += rule_score
                ttps.append(ttp)

        # Benign dampening — known-good processes with no suspicious flags
        is_known_benign = any(
            any(d in e.resource or d in e.comm for d in _BENIGN_DAMPENERS)
            for e in events
        )
        if is_known_benign and score < 0.5:
            score *= 0.3

        score = min(score, 0.99)
        label = "MALICIOUS" if score >= 0.30 else "BENIGN"
        confidence = round(score, 4) if label == "MALICIOUS" else round(max(0.01, 1.0 - score), 4)

        latency_ms = (time.perf_counter() - t0) * 1000
        ttps = list(dict.fromkeys(ttps))[:4]

        return ThreatDecision(
            label=label,
            confidence=confidence,
            reasoning=f"Falco[{len(ttps)} rules matched]: {', '.join(ttps) or 'no alerts'}",
            mitre_ttps=ttps,
            model_used="falco-rules/v1",
            latency_ms=round(latency_ms, 3),
        )
