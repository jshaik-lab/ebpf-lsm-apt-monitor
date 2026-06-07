"""
demo_runner.py — SENTINEL Live Demo

Simulates realistic attack and benign syscall traces through the complete
SENTINEL pipeline:
  KernelEvent stream → IPG encoder → mock LLM → CWAE enforcement

No eBPF or root access needed. Designed for Docker demo mode.

Usage:
  python3 demo_runner.py --all-scenarios --color --pause=1
  python3 demo_runner.py --scenario T1003 --verbose
  python3 demo_runner.py --interactive
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from dataclasses import dataclass, field
from typing import List

from ipg_encoder import KernelEvent, IPGBuilder, SyscallType
from llm_classifier import LLMClassifier
from enforcement import CWAEEngine, TIER_LABELS

# ── Terminal colours ───────────────────────────────────────────────────────────

USE_COLOR = sys.stdout.isatty() or os.environ.get("SENTINEL_DEMO") == "1"

class C:
    RED    = "\033[91m" if USE_COLOR else ""
    GREEN  = "\033[92m" if USE_COLOR else ""
    YELLOW = "\033[93m" if USE_COLOR else ""
    BLUE   = "\033[94m" if USE_COLOR else ""
    CYAN   = "\033[96m" if USE_COLOR else ""
    WHITE  = "\033[97m" if USE_COLOR else ""
    BOLD   = "\033[1m"  if USE_COLOR else ""
    DIM    = "\033[2m"  if USE_COLOR else ""
    RESET  = "\033[0m"  if USE_COLOR else ""

def _hr(char="─", width=70):
    return char * width

def banner():
    print(C.CYAN + C.BOLD)
    print(_hr("═"))
    print("  SENTINEL — Intent-Based Zero-Trust Kernel Anomaly Detection")
    print("  Autonomous Kernel Observability: eBPF + LLM Pipeline Demo")
    print(_hr("═"))
    print(C.RESET)


# ── Scenario definitions ───────────────────────────────────────────────────────

@dataclass
class Scenario:
    ttp_id:      str
    name:        str
    description: str
    events:      List[KernelEvent]
    expected:    str        # MALICIOUS or BENIGN
    mitre_ttps:  List[str] = field(default_factory=list)


def _e(ms: int, pid: int, comm: str, sc: SyscallType, res: str) -> KernelEvent:
    return KernelEvent(
        ts_ns=ms * 1_000_000, pid=pid, ppid=pid - 1,
        uid=1000 if comm != "root" else 0,
        comm=comm, sc_type=sc, resource=res,
    )

E = SyscallType  # shorthand

SCENARIOS: List[Scenario] = [

    Scenario(
        ttp_id="T1003",
        name="Credential Dumping",
        description="bash reads /etc/shadow then establishes C2 connection",
        expected="MALICIOUS",
        mitre_ttps=["T1003", "T1071"],
        events=[
            _e(0,   1234, "bash",   E.EXEC,    "/bin/bash"),
            _e(2,   1234, "bash",   E.EXEC,    "/usr/bin/cat"),
            _e(3,   1234, "cat",    E.FILE_R,  "/etc/shadow"),
            _e(4,   1234, "cat",    E.FILE_R,  "/etc/passwd"),
            _e(90,  1234, "bash",   E.NET_CON, "104.21.43.12:4444"),
            _e(95,  1234, "bash",   E.EXEC,    "/tmp/sh"),
        ],
    ),

    Scenario(
        ttp_id="T1068",
        name="Privilege Escalation",
        description="Unprivileged process performs fork → setuid(0) → execve root shell",
        expected="MALICIOUS",
        mitre_ttps=["T1068", "T1059"],
        events=[
            _e(0,   2000, "exploit", E.EXEC,    "/tmp/exploit"),
            _e(5,   2000, "exploit", E.FORK,    "fork->pid=2001"),
            _e(6,   2001, "exploit", E.SETUID,  "uid=1000->0"),
            _e(8,   2001, "exploit", E.EXEC,    "/bin/sh"),
            _e(10,  2001, "sh",      E.FILE_R,  "/etc/sudoers"),
            _e(12,  2001, "sh",      E.FILE_W,  "/etc/cron.d/backdoor"),
        ],
    ),

    Scenario(
        ttp_id="T1055",
        name="Process Injection",
        description="Attacker process uses ptrace to inject into a trusted process",
        expected="MALICIOUS",
        mitre_ttps=["T1055"],
        events=[
            _e(0,   3000, "malware", E.EXEC,    "/tmp/.hidden/malware"),
            _e(2,   3000, "malware", E.PTRACE,  "ptrace_target_pid=1"),
            _e(5,   3000, "malware", E.MMAP,    "PROT_EXEC|PROT_WRITE"),
            _e(10,  3000, "malware", E.NET_CON, "185.220.101.1:443"),
        ],
    ),

    Scenario(
        ttp_id="T1562",
        name="Defense Evasion",
        description="Attacker disables auditd/syslog, clears logs, installs persistence",
        expected="MALICIOUS",
        mitre_ttps=["T1562", "T1070"],
        events=[
            _e(0,   4000, "bash",   E.EXEC,   "/bin/bash"),
            _e(1,   4000, "bash",   E.EXEC,   "/usr/bin/systemctl"),
            _e(2,   4000, "bash",   E.FILE_W, "/var/log/syslog"),
            _e(3,   4000, "bash",   E.FILE_W, "/var/log/auth.log"),
            _e(4,   4000, "bash",   E.FILE_W, "/etc/cron.d/persistence"),
            _e(5,   4000, "bash",   E.NET_CON,"10.0.0.1:8080"),
        ],
    ),

    Scenario(
        ttp_id="T1071",
        name="C2 over HTTP",
        description="Staged delivery: curl downloads payload, executes from /tmp",
        expected="MALICIOUS",
        mitre_ttps=["T1071", "T1105", "T1059"],
        events=[
            _e(0,   5000, "bash",   E.EXEC,    "/usr/bin/curl"),
            _e(10,  5000, "curl",   E.NET_CON, "93.184.216.34:80"),
            _e(200, 5000, "curl",   E.FILE_W,  "/tmp/update.sh"),
            _e(201, 5000, "bash",   E.EXEC,    "/tmp/update.sh"),
            _e(202, 5000, "update.sh", E.NET_CON, "93.184.216.34:4443"),
            _e(210, 5000, "update.sh", E.EXEC, "/tmp/backdoor"),
        ],
    ),

    Scenario(
        ttp_id="T1210",
        name="Lateral Movement",
        description="SSH to internal hosts; uses stolen keys from .ssh/",
        expected="MALICIOUS",
        mitre_ttps=["T1210", "T1078"],
        events=[
            _e(0,   6000, "bash",  E.FILE_R,  "/home/user/.ssh/id_rsa"),
            _e(2,   6000, "bash",  E.NET_CON, "192.168.1.10:22"),
            _e(5,   6000, "ssh",   E.NET_CON, "192.168.1.11:22"),
            _e(8,   6000, "ssh",   E.NET_CON, "192.168.1.12:22"),
            _e(10,  6000, "bash",  E.FILE_W,  "/tmp/lateral_tool"),
            _e(12,  6000, "bash",  E.EXEC,    "/tmp/lateral_tool"),
        ],
    ),

    Scenario(
        ttp_id="T1041",
        name="Data Exfiltration",
        description="Bulk read of sensitive files followed by encrypted upload",
        expected="MALICIOUS",
        mitre_ttps=["T1041", "T1003"],
        events=[
            _e(0,   7000, "python3", E.FILE_R, "/var/db/customers.db"),
            _e(1,   7000, "python3", E.FILE_R, "/etc/ssl/private/server.key"),
            _e(2,   7000, "python3", E.FILE_R, "/home/admin/.aws/credentials"),
            _e(100, 7000, "python3", E.NET_CON,"34.56.78.90:443"),
            _e(500, 7000, "python3", E.NET_CON,"34.56.78.90:443"),
        ],
    ),

    # ── Benign scenarios ───────────────────────────────────────────────────────

    Scenario(
        ttp_id="BENIGN-01",
        name="Normal Nginx Web Server",
        description="nginx serves files from web root and writes access log",
        expected="BENIGN",
        mitre_ttps=[],
        events=[
            _e(0,  8000, "nginx", E.NET_LIS,  "0.0.0.0:80"),
            _e(1,  8000, "nginx", E.FILE_R,   "/var/www/html/index.html"),
            _e(2,  8000, "nginx", E.FILE_R,   "/var/www/html/style.css"),
            _e(3,  8000, "nginx", E.FILE_W,   "/var/log/nginx/access.log"),
            _e(4,  8000, "nginx", E.NET_LIS,  "0.0.0.0:443"),
            _e(5,  8000, "nginx", E.FILE_R,   "/var/www/html/app.js"),
        ],
    ),

    Scenario(
        ttp_id="BENIGN-02",
        name="Apt Package Update",
        description="Standard apt upgrade downloads and installs packages",
        expected="BENIGN",
        mitre_ttps=[],
        events=[
            _e(0,  9000, "apt",      E.EXEC,    "/usr/bin/apt"),
            _e(1,  9000, "apt",      E.NET_CON, "deb.debian.org:80"),
            _e(5,  9000, "apt",      E.FILE_W,  "/var/cache/apt/archives/pkg.deb"),
            _e(10, 9000, "dpkg",     E.EXEC,    "/usr/bin/dpkg"),
            _e(11, 9000, "dpkg",     E.FILE_W,  "/usr/lib/x86_64-linux-gnu/libz.so.1"),
            _e(12, 9000, "dpkg",     E.FILE_W,  "/var/lib/dpkg/status"),
        ],
    ),

    Scenario(
        ttp_id="BENIGN-03",
        name="PostgreSQL Normal Operation",
        description="postgres reads/writes database files and listens on port 5432",
        expected="BENIGN",
        mitre_ttps=[],
        events=[
            _e(0,  10000, "postgres", E.NET_LIS, "127.0.0.1:5432"),
            _e(1,  10000, "postgres", E.FILE_R,  "/var/lib/postgresql/data/base/"),
            _e(2,  10000, "postgres", E.FILE_W,  "/var/lib/postgresql/data/pg_wal/"),
            _e(3,  10000, "postgres", E.FILE_R,  "/var/lib/postgresql/data/pg_catalog"),
            _e(4,  10000, "postgres", E.FILE_W,  "/var/lib/postgresql/data/base/16384/1259"),
        ],
    ),
]


# ── Demo runner ────────────────────────────────────────────────────────────────

class DemoRunner:
    def __init__(self, color: bool = True, pause: float = 0.5,
                 verbose: bool = False):
        self._ipg   = IPGBuilder()
        self._clf   = LLMClassifier(model_path="/nonexistent")
        self._cwae  = CWAEEngine(dry_run=True,
                                  audit_log_path="/tmp/sentinel_demo_audit.jsonl")
        self._pause = pause
        self._verbose = verbose
        self._results: List[dict] = []

    def run_scenario(self, sc: Scenario) -> dict:
        print(f"\n{C.BOLD}{_hr()}{C.RESET}")
        print(f"{C.BOLD}Scenario: [{sc.ttp_id}] {sc.name}{C.RESET}")
        print(f"{C.DIM}{sc.description}{C.RESET}")
        print(_hr("·"))

        # Step 1: Show incoming events
        print(f"{C.BLUE}[1/4] Kernel events (simulated ring-buffer output):{C.RESET}")
        sc_names = {
            SyscallType.EXEC:    "execve",
            SyscallType.FILE_R:  "openat(R)",
            SyscallType.FILE_W:  "openat(W)",
            SyscallType.NET_CON: "connect",
            SyscallType.NET_LIS: "listen",
            SyscallType.FORK:    "fork",
            SyscallType.SETUID:  "setuid",
            SyscallType.MMAP:    "mmap",
            SyscallType.PTRACE:  "ptrace",
        }
        for evt in sc.events:
            sc_label = sc_names.get(SyscallType(evt.sc_type), "syscall")
            print(f"  {C.DIM}pid={evt.pid} comm={evt.comm:<12s} "
                  f"{sc_label:<12s} → {evt.resource}{C.RESET}")
            time.sleep(self._pause * 0.1)

        # Step 2: Build IPG
        print(f"\n{C.BLUE}[2/4] Building Intent Provenance Graph (IPG)...{C.RESET}")
        G        = self._ipg.build(sc.events)
        ipg_text = self._ipg.serialize(G)
        entropy  = self._ipg.structural_entropy(G)
        n_tokens = len(ipg_text.split())
        raw_est  = len(sc.events) * 42

        print(f"  Nodes: {G.number_of_nodes()}  Edges: {G.number_of_edges()}")
        print(f"  Structural entropy: {C.YELLOW}{entropy:.3f} bits{C.RESET}")
        print(f"  Token count: {C.GREEN}{n_tokens}{C.RESET} "
              f"(vs raw ~{raw_est}, {(1-n_tokens/raw_est)*100:.0f}% saved)")
        if self._verbose:
            print(f"\n{C.DIM}{ipg_text}{C.RESET}\n")

        # Step 3: LLM classification
        print(f"\n{C.BLUE}[3/4] LLM classification (dual-tier pipeline)...{C.RESET}")
        # Bypass entropy gate when sensitive credential access + exfil network pattern detected
        _CRED_PATTERNS = ("ssl/private", ".aws/credentials", "id_rsa", "/.ssh/", "[sensitive]")
        _has_exfil = (
            any(p in ipg_text.lower() for p in _CRED_PATTERNS)
            and "connect" in ipg_text.lower()
        )
        if entropy < 1.2 and not _has_exfil:
            print(f"  {C.GREEN}Tier-1 gate: entropy {entropy:.2f} < θ_low=1.2 → BENIGN (skipped LLM){C.RESET}")
            decision = self._clf._mock_classify("benign")
        else:
            if _has_exfil and entropy < 1.2:
                tier = "Full model (8B) [sensitive-access bypass]"
            elif entropy < 3.8:
                tier = "Draft model (1B)"
            else:
                tier = "Full model (8B)"
            print(f"  {C.YELLOW}Tier-1 gate: entropy {entropy:.2f} → escalating to {tier}{C.RESET}")
            decision = self._clf._mock_classify(ipg_text)

        label_color = C.RED if decision.label == "MALICIOUS" else C.GREEN
        print(f"  Decision: {label_color}{C.BOLD}{decision.label}{C.RESET}  "
              f"confidence={C.YELLOW}{decision.confidence:.2f}{C.RESET}")
        if decision.mitre_ttps:
            print(f"  MITRE TTPs: {C.CYAN}{', '.join(decision.mitre_ttps)}{C.RESET}")

        # Step 4: CWAE enforcement
        print(f"\n{C.BLUE}[4/4] CWAE enforcement decision...{C.RESET}")
        rec = self._cwae.enforce(
            pid=sc.events[0].pid, comm=sc.events[0].comm,
            label=decision.label, confidence=decision.confidence,
            reasoning=decision.reasoning, mitre_ttps=decision.mitre_ttps,
        )
        tier_color = {
            "LOG_ONLY": C.GREEN, "PAUSE": C.YELLOW,
            "KILL": C.RED, "QUARANTINE": C.RED, "ISOLATE": C.RED,
        }.get(TIER_LABELS[rec.tier], C.WHITE)

        tier_actions = {
            "LOG_ONLY":   "Logged only (no action)",
            "PAUSE":      "SIGSTOP + human alert queued",
            "KILL":       "SIGKILL + memory dump",
            "QUARANTINE": "SIGKILL + XDP network quarantine",
            "ISOLATE":    "SIGKILL + XDP + cgroup freeze + incident report",
        }

        print(f"  Enforcement tier: {tier_color}{C.BOLD}{TIER_LABELS[rec.tier]}{C.RESET}")
        print(f"  Action: {tier_actions.get(TIER_LABELS[rec.tier], '')}")
        print(f"  Latency: {C.CYAN}{rec.latency_us:.1f} µs{C.RESET}")

        # Verdict
        correct = decision.label == sc.expected
        verdict = f"{C.GREEN}✓ CORRECT{C.RESET}" if correct else f"{C.RED}✗ INCORRECT{C.RESET}"
        print(f"\n  Verdict: {verdict} (expected={sc.expected})")

        result = {
            "scenario": sc.ttp_id,
            "name": sc.name,
            "expected": sc.expected,
            "predicted": decision.label,
            "confidence": decision.confidence,
            "tier": TIER_LABELS[rec.tier],
            "latency_us": rec.latency_us,
            "correct": correct,
        }
        self._results.append(result)
        time.sleep(self._pause)
        return result

    def print_summary(self):
        print(f"\n{C.BOLD}{_hr('═')}{C.RESET}")
        print(f"{C.BOLD}  SENTINEL Demo Summary{C.RESET}")
        print(_hr("═"))
        print(f"\n{'Scenario':<20} {'Expected':<12} {'Predicted':<12} "
              f"{'Conf':>6} {'Tier':<14} {'✓'}  ")
        print(_hr("-"))
        correct_total = 0
        for r in self._results:
            ok = "✓" if r["correct"] else "✗"
            color = C.GREEN if r["correct"] else C.RED
            correct_total += int(r["correct"])
            print(f"{r['scenario']:<20} {r['expected']:<12} "
                  f"{color}{r['predicted']:<12}{C.RESET} "
                  f"{r['confidence']:>6.2f} {r['tier']:<14} {color}{ok}{C.RESET}")
        print(_hr("-"))
        total = len(self._results)
        acc = correct_total / total * 100 if total else 0
        print(f"\n  Accuracy: {C.BOLD}{correct_total}/{total} ({acc:.0f}%){C.RESET}")
        avg_lat = sum(r["latency_us"] for r in self._results) / max(total, 1)
        print(f"  Avg enforcement latency: {C.CYAN}{avg_lat:.1f} µs{C.RESET}")
        print(f"\n{C.DIM}  Pipeline: IPG encoder → mock LLM → CWAE enforcement{C.RESET}")
        print(f"{C.DIM}  Real deployment: replace mock LLM with Llama-3-8B-GGUF{C.RESET}")
        print(f"\n{_hr('═')}\n")

    def run_interactive(self):
        banner()
        print("Available scenarios:")
        for i, sc in enumerate(SCENARIOS):
            tag = f"[{sc.expected}]"
            color = C.RED if sc.expected == "MALICIOUS" else C.GREEN
            print(f"  {i+1:2d}. {sc.ttp_id:<14} {color}{tag:<11}{C.RESET} {sc.name}")
        print(f"   0. Run all scenarios")
        print(f"   q. Quit\n")

        while True:
            try:
                choice = input(f"{C.BOLD}Select scenario (0-{len(SCENARIOS)}/q): {C.RESET}").strip()
            except (EOFError, KeyboardInterrupt):
                break

            if choice.lower() == "q":
                break
            if choice == "0":
                for sc in SCENARIOS:
                    self.run_scenario(sc)
                self.print_summary()
                self._results.clear()
                continue
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(SCENARIOS):
                    self.run_scenario(SCENARIOS[idx])
            except ValueError:
                pass


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="SENTINEL Demo — Simulated attack scenarios through the full pipeline")
    parser.add_argument("--all-scenarios", action="store_true",
                        help="Run all scenarios sequentially")
    parser.add_argument("--scenario", metavar="TTP",
                        help="Run a specific scenario by TTP ID (e.g. T1003)")
    parser.add_argument("--interactive", action="store_true",
                        help="Interactive menu to pick scenarios")
    parser.add_argument("--pause", type=float, default=0.5,
                        help="Pause between scenarios in seconds (default: 0.5)")
    parser.add_argument("--verbose", action="store_true",
                        help="Show full IPG text")
    parser.add_argument("--color", action="store_true",
                        help="Force color output")
    args = parser.parse_args()

    global USE_COLOR
    if args.color:
        USE_COLOR = True
        C.RED    = "\033[91m"; C.GREEN  = "\033[92m"; C.YELLOW = "\033[93m"
        C.BLUE   = "\033[94m"; C.CYAN   = "\033[96m"; C.WHITE  = "\033[97m"
        C.BOLD   = "\033[1m";  C.DIM    = "\033[2m";  C.RESET  = "\033[0m"

    runner = DemoRunner(pause=args.pause, verbose=args.verbose)

    if args.interactive:
        runner.run_interactive()
        return

    banner()

    if args.scenario:
        for sc in SCENARIOS:
            if sc.ttp_id == args.scenario:
                runner.run_scenario(sc)
                runner.print_summary()
                return
        print(f"Scenario '{args.scenario}' not found.")
        print("Available:", ", ".join(s.ttp_id for s in SCENARIOS))
        return

    if args.all_scenarios or True:
        print(f"{C.DIM}Running {len(SCENARIOS)} scenarios "
              f"({sum(1 for s in SCENARIOS if s.expected=='MALICIOUS')} malicious, "
              f"{sum(1 for s in SCENARIOS if s.expected=='BENIGN')} benign)...{C.RESET}")
        for sc in SCENARIOS:
            runner.run_scenario(sc)
        runner.print_summary()


if __name__ == "__main__":
    main()
