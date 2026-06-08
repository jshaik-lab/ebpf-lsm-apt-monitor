"""
synthetic_multi_host.py — Synthetic multi-host, multi-workload trace generator.

Generates diverse syscall trace corpora across four representative host roles:
  - web_server   (nginx + PHP-FPM workers)
  - database     (PostgreSQL, 9050–9150 per connection)
  - ci_cd        (Jenkins build agents running pip/cargo/npm)
  - ai_agent     (Python LLM agent with API calls)

Each host role produces configurable benign windows.  Attack injection inserts
one of six MITRE ATT&CK kill-chain templates at a configurable rate.

Usage:
    from evaluation.synthetic_multi_host import MultiHostGenerator
    gen = MultiHostGenerator(seed=42)
    traces = gen.generate(n_benign=500, n_attack=100)
    # traces: list[SyntheticTrace(events, label, host_role, ttp_id)]

Designed to expand SENTINEL's evaluation corpus beyond the 105-trace real-strace
set and the DARPA TC CADETS provenance subset.  All events are synthetic; no
real host credentials or paths are used.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

try:
    from sentinel.models import KernelEvent, SyscallType
except ImportError:
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from sentinel.models import KernelEvent, SyscallType

E = SyscallType

_TEXT_BASE = 0x0040_0000
_TEXT_SIZE = 0x0030_0000
_HEAP_BASE = 0x7F00_0000_0000


def _ke(ts_ms: int, pid: int, comm: str, sc: SyscallType, resource: str,
        ppid: int = 0, ip: int = 0) -> KernelEvent:
    return KernelEvent(
        ts_ns=ts_ms * 1_000_000,
        pid=pid,
        ppid=ppid or max(1, pid - 1),
        uid=1000,
        comm=comm,
        sc_type=int(sc),
        resource=resource,
        ip=ip,
    )


@dataclass
class SyntheticTrace:
    events:    List[KernelEvent]
    label:     str              # "BENIGN" | "MALICIOUS"
    host_role: str
    ttp_id:    Optional[str] = None


# ── Benign workload templates ────────────────────────────────────────────────

def _web_server_window(pid: int, rng: random.Random) -> List[KernelEvent]:
    pages = ["/index.html", "/about.html", "/style.css", "/app.js",
             "/favicon.ico", "/robots.txt", "/api/v1/health"]
    logs  = ["/var/log/nginx/access.log", "/var/log/nginx/error.log"]
    evts  = []
    t = 0
    evts.append(_ke(t, pid, "nginx", E.NET_LIS, "0.0.0.0:80",
                    ip=_TEXT_BASE + rng.randint(0, _TEXT_SIZE - 1)))
    for _ in range(rng.randint(4, 12)):
        t += rng.randint(1, 5)
        evts.append(_ke(t, pid, "nginx", E.FILE_R, rng.choice(pages),
                        ip=_TEXT_BASE + rng.randint(0, _TEXT_SIZE - 1)))
        t += 1
        evts.append(_ke(t, pid, "nginx", E.FILE_W, rng.choice(logs),
                        ip=_TEXT_BASE + rng.randint(0, _TEXT_SIZE - 1)))
    return evts


def _database_window(pid: int, rng: random.Random) -> List[KernelEvent]:
    tables = ["/var/lib/postgresql/data/base/16384/pg_class",
              "/var/lib/postgresql/data/base/16384/pg_attribute",
              "/var/lib/postgresql/data/pg_wal/000000010000000000000001"]
    evts = []
    t = 0
    evts.append(_ke(t, pid, "postgres", E.NET_LIS, "127.0.0.1:5432"))
    for _ in range(rng.randint(3, 10)):
        t += rng.randint(1, 8)
        evts.append(_ke(t, pid, "postgres", E.FILE_R, rng.choice(tables)))
        t += 1
        evts.append(_ke(t, pid, "postgres", E.FILE_W,
                        "/var/lib/postgresql/data/pg_wal/"
                        f"00000001000000000000000{rng.randint(1,9)}"))
    return evts


def _cicd_window(pid: int, rng: random.Random) -> List[KernelEvent]:
    build_steps = [
        ("/usr/bin/pip", E.EXEC, "/usr/bin/pip"),
        ("pip", E.NET_CON, "pypi.org:443"),
        ("pip", E.FILE_W, "/home/jenkins/.cache/pip/wheel.whl"),
        ("/usr/bin/pytest", E.EXEC, "/usr/bin/pytest"),
        ("pytest", E.FILE_R, "/workspace/src/test_main.py"),
        ("pytest", E.FILE_W, "/workspace/test-results/junit.xml"),
        ("/usr/bin/docker", E.EXEC, "/usr/bin/docker"),
        ("docker", E.NET_CON, "registry.hub.docker.com:443"),
    ]
    evts = []
    t = 0
    for comm, sc, res in rng.sample(build_steps, min(len(build_steps),
                                                      rng.randint(3, 6))):
        evts.append(_ke(t, pid, comm, sc, res))
        t += rng.randint(2, 15)
    return evts


def _ai_agent_window(pid: int, rng: random.Random) -> List[KernelEvent]:
    evts = []
    t = 0
    evts.append(_ke(t, pid, "python3", E.EXEC, "/usr/bin/python3"))
    t += 1
    evts.append(_ke(t, pid, "python3", E.NET_CON, "api.anthropic.com:443"))
    t += rng.randint(1, 4)
    for res in rng.sample([
        "/workspace/config.yaml",
        "/workspace/data/input.json",
        "/workspace/results/output.json",
        "/tmp/agent_scratch.txt",
    ], rng.randint(2, 4)):
        t += 1
        sc = E.FILE_W if "output" in res or "results" in res else E.FILE_R
        evts.append(_ke(t, pid, "python3", sc, res))
    return evts


_BENIGN_GENERATORS = {
    "web_server": _web_server_window,
    "database":   _database_window,
    "ci_cd":      _cicd_window,
    "ai_agent":   _ai_agent_window,
}

# ── Attack injection templates ────────────────────────────────────────────────

def _inject_cred_dump(pid: int, t0: int) -> Tuple[List[KernelEvent], str]:
    evts = [
        _ke(t0,   pid, "bash",    E.EXEC,    "/bin/bash"),
        _ke(t0+1, pid, "cat",     E.FILE_R,  "/etc/shadow"),
        _ke(t0+2, pid, "cat",     E.FILE_R,  "/home/user/.ssh/id_rsa"),
        _ke(t0+3, pid, "bash",    E.NET_CON, "185.220.101.1:4444"),
    ]
    return evts, "T1003"


def _inject_priv_esc(pid: int, t0: int) -> Tuple[List[KernelEvent], str]:
    evts = [
        _ke(t0,   pid, "exploit", E.EXEC,    "/tmp/exploit"),
        _ke(t0+1, pid, "exploit", E.SETUID,  "uid=0"),
        _ke(t0+2, pid, "sh",      E.FILE_W,  "/etc/cron.d/backdoor"),
        _ke(t0+3, pid, "sh",      E.NET_CON, "185.220.101.1:9001"),
    ]
    return evts, "T1068"


def _inject_lateral(pid: int, t0: int) -> Tuple[List[KernelEvent], str]:
    evts = [
        _ke(t0,   pid, "bash",  E.FILE_R,  "/home/user/.ssh/id_rsa"),
        _ke(t0+1, pid, "ssh",   E.NET_CON, "192.168.1.10:22"),
        _ke(t0+2, pid, "ssh",   E.NET_CON, "192.168.1.11:22"),
        _ke(t0+3, pid, "bash",  E.FILE_W,  "/tmp/lateral_tool"),
    ]
    return evts, "T1210"


def _inject_exfil(pid: int, t0: int) -> Tuple[List[KernelEvent], str]:
    evts = [
        _ke(t0,   pid, "python3", E.FILE_R,  "/var/db/customers.db"),
        _ke(t0+1, pid, "python3", E.FILE_R,  "/etc/ssl/private/server.key"),
        _ke(t0+2, pid, "python3", E.NET_CON, "34.56.78.90:443"),
        _ke(t0+3, pid, "python3", E.NET_CON, "34.56.78.90:443"),
    ]
    return evts, "T1041"


def _inject_process_injection(pid: int, t0: int) -> Tuple[List[KernelEvent], str]:
    ip_heap = _HEAP_BASE + random.randint(0, 0xFFFF_FFFF)
    evts = [
        _ke(t0,   pid, "malware", E.PTRACE,  "ptrace_target_pid=1"),
        _ke(t0+1, pid, "malware", E.MMAP,    "PROT_EXEC|PROT_WRITE"),
        _ke(t0+2, pid, "malware", E.NET_CON, "185.220.101.1:443", ip=ip_heap),
    ]
    return evts, "T1055"


def _inject_defense_evasion(pid: int, t0: int) -> Tuple[List[KernelEvent], str]:
    evts = [
        _ke(t0,   pid, "bash",    E.EXEC,    "/usr/bin/systemctl"),
        _ke(t0+1, pid, "bash",    E.FILE_W,  "/var/log/syslog"),
        _ke(t0+2, pid, "bash",    E.FILE_W,  "/var/log/auth.log"),
        _ke(t0+3, pid, "bash",    E.NET_CON, "10.0.0.1:8080"),
    ]
    return evts, "T1562"


_ATTACK_INJECTORS = [
    _inject_cred_dump,
    _inject_priv_esc,
    _inject_lateral,
    _inject_exfil,
    _inject_process_injection,
    _inject_defense_evasion,
]


# ── Generator class ───────────────────────────────────────────────────────────

class MultiHostGenerator:
    """
    Generates a balanced synthetic multi-host corpus for SENTINEL evaluation.

    Args:
        seed:           RNG seed for reproducibility.
        pid_start:      Base PID for generated events.
        host_roles:     Which host roles to include.
    """

    def __init__(
        self,
        seed: int = 0,
        pid_start: int = 50000,
        host_roles: Optional[List[str]] = None,
    ):
        self._rng = random.Random(seed)
        self._pid = pid_start
        self._roles = host_roles or list(_BENIGN_GENERATORS.keys())

    def _next_pid(self) -> int:
        p = self._pid
        self._pid += 1
        return p

    def generate(
        self,
        n_benign: int = 200,
        n_attack: int = 50,
    ) -> List[SyntheticTrace]:
        traces: List[SyntheticTrace] = []

        # Benign traces — round-robin across host roles
        for i in range(n_benign):
            role = self._roles[i % len(self._roles)]
            gen  = _BENIGN_GENERATORS[role]
            pid  = self._next_pid()
            evts = gen(pid, self._rng)
            traces.append(SyntheticTrace(events=evts, label="BENIGN",
                                         host_role=role))

        # Attack traces — each is a benign window with an injected kill-chain
        for i in range(n_attack):
            role    = self._roles[i % len(self._roles)]
            gen     = _BENIGN_GENERATORS[role]
            pid     = self._next_pid()
            benign  = gen(pid, self._rng)
            injector = self._rng.choice(_ATTACK_INJECTORS)
            t0      = (benign[-1].ts_ns // 1_000_000) + 5 if benign else 0
            atk_evts, ttp_id = injector(pid, t0)
            combined = benign + atk_evts
            traces.append(SyntheticTrace(events=combined, label="MALICIOUS",
                                         host_role=role, ttp_id=ttp_id))

        self._rng.shuffle(traces)
        return traces

    @staticmethod
    def summary(traces: List[SyntheticTrace]) -> dict:
        from collections import Counter
        role_counts: Counter = Counter()
        ttp_counts:  Counter = Counter()
        benign = attack = 0
        for t in traces:
            role_counts[t.host_role] += 1
            if t.label == "BENIGN":
                benign += 1
            else:
                attack += 1
                if t.ttp_id:
                    ttp_counts[t.ttp_id] += 1
        return {
            "total":         len(traces),
            "benign":        benign,
            "attack":        attack,
            "by_host_role":  dict(role_counts),
            "by_ttp":        dict(ttp_counts),
        }
