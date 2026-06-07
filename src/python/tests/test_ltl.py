"""Tests for LTL Symbolic Guardian — Tier-1 RuntimeMonitor + Tier-2 BüchiMonitor."""
from __future__ import annotations

import pytest

from sentinel.ltl import (
    RuntimeMonitor, BuchiMonitor, SymbolicGuardian,
    SimpleAxiom, LTLViolation,
    comm_is, execve, explainability_score,
)
from sentinel.models import KernelEvent, SyscallType


# ── helpers ───────────────────────────────────────────────────────────────────

def _evt(comm: str, sc: SyscallType, resource: str = "",
         pid: int = 1000, ppid: int = 999) -> KernelEvent:
    return KernelEvent(pid=pid, ppid=ppid, uid=1000, comm=comm,
                       sc_type=int(sc), resource=resource, ts_ns=0)


def NGINX(res="", sc=SyscallType.FILE_R):
    return _evt("nginx", sc, res)

def BASH_EXEC(res="/bin/bash"):
    return _evt("nginx", SyscallType.EXEC, res)

def SHADOW_R(comm="bash"):
    return _evt(comm, SyscallType.FILE_R, "/etc/shadow")

def NET_CON(comm="bash", ip="185.220.101.1:4444"):
    return _evt(comm, SyscallType.NET_CON, ip)

def SETUID_0():
    return _evt("exploit", SyscallType.SETUID, "uid=1000->0")

def TMP_EXEC():
    return _evt("sh", SyscallType.EXEC, "/tmp/evil.sh")

def PRCTL_EVT():
    return _evt("malware", SyscallType.PRCTL, "PR_SET_NAME:nginx")


# ── RuntimeMonitor — AX-1 nginx axiom ────────────────────────────────────────

class TestRuntimeMonitorAX1:
    def setup_method(self):
        self.mon = RuntimeMonitor()

    def test_nginx_bash_exec_triggers_violation(self):
        # Feed nginx event first (arms watch), then bash exec (triggers violation)
        violations = self.mon.feed(NGINX())
        assert violations == []
        violations = self.mon.feed(BASH_EXEC())
        assert len(violations) == 1
        assert violations[0].axiom_id == "AX-1"
        assert violations[0].severity == "CRITICAL"

    def test_nginx_non_bash_exec_no_violation(self):
        self.mon.feed(NGINX())
        violations = self.mon.feed(_evt("nginx", SyscallType.EXEC, "/usr/sbin/nginx"))
        # Not /bin/bash — no violation
        assert all(v.axiom_id != "AX-1" for v in violations)

    def test_non_nginx_bash_exec_no_ax1_violation(self):
        # Different process — AX-1 only fires when nginx does it
        self.mon.feed(_evt("sshd", SyscallType.FILE_R, "/etc/ssh/sshd_config"))
        violations = self.mon.feed(_evt("sshd", SyscallType.EXEC, "/bin/bash"))
        assert all(v.axiom_id != "AX-1" for v in violations)

    def test_window_expiry_prevents_violation(self):
        # AX-1 has window=50; after 51 events the watch expires
        axiom = SimpleAxiom(
            axiom_id="AX-TEST",
            formula="test",
            severity="LOW",
            trigger=comm_is("nginx"),
            forbidden=execve("/bin/bash"),
            window=2,
        )
        mon = RuntimeMonitor([axiom])
        mon.feed(NGINX())
        # 2 non-triggering events to expire the watch
        mon.feed(_evt("other", SyscallType.FILE_R, "/tmp/x"))
        mon.feed(_evt("other", SyscallType.FILE_R, "/tmp/y"))
        # Now try to trigger — watch should be expired
        violations = mon.feed(BASH_EXEC())
        assert violations == []

    def test_multiple_pids_independent_watches(self):
        # PID 1000 arms watch, PID 2000 should not cause violation for PID 1000
        mon = RuntimeMonitor()
        mon.feed(_evt("nginx", SyscallType.FILE_R, "", pid=1000))
        violations = mon.feed(_evt("nginx", SyscallType.EXEC, "/bin/bash", pid=2000))
        # AX-1 is same_pid=True; different PID should not cross-trigger
        ax1_violations = [v for v in violations if v.axiom_id == "AX-1"]
        assert len(ax1_violations) == 0

    def test_triggering_event_id_captured(self):
        self.mon.feed(NGINX())
        violations = self.mon.feed(BASH_EXEC())
        if violations:
            assert violations[0].triggering_event_id != ""
            assert len(violations[0].triggering_event_id) == 36  # UUID format


# ── RuntimeMonitor — AX-3 prctl axiom ────────────────────────────────────────

class TestRuntimeMonitorAX3:
    def setup_method(self):
        self.mon = RuntimeMonitor()

    def test_prctl_then_shadow_read_triggers_ax3(self):
        self.mon.feed(PRCTL_EVT())
        violations = self.mon.feed(SHADOW_R("nginx"))
        ax3 = [v for v in violations if v.axiom_id == "AX-3"]
        assert len(ax3) >= 1
        assert ax3[0].severity == "CRITICAL"

    def test_shadow_read_without_prctl_no_ax3(self):
        # Direct shadow read — AX-3 not triggered (but may trigger other axioms)
        violations = self.mon.feed(SHADOW_R("bash"))
        ax3 = [v for v in violations if v.axiom_id == "AX-3"]
        assert len(ax3) == 0


# ── RuntimeMonitor — AX-4 temp execution ─────────────────────────────────────

class TestRuntimeMonitorAX4:
    def setup_method(self):
        self.mon = RuntimeMonitor()

    def test_exec_from_tmp_triggers_ax4(self):
        violations = self.mon.feed(TMP_EXEC())
        ax4 = [v for v in violations if v.axiom_id == "AX-4"]
        assert len(ax4) >= 1
        assert ax4[0].severity == "HIGH"

    def test_exec_from_usr_no_ax4(self):
        violations = self.mon.feed(_evt("sh", SyscallType.EXEC, "/usr/bin/sh"))
        ax4 = [v for v in violations if v.axiom_id == "AX-4"]
        assert len(ax4) == 0

    def test_exec_from_dev_shm_triggers_ax4(self):
        violations = self.mon.feed(_evt("sh", SyscallType.EXEC, "/dev/shm/payload"))
        ax4 = [v for v in violations if v.axiom_id == "AX-4"]
        assert len(ax4) >= 1


# ── RuntimeMonitor — AX-5 setuid+connect ─────────────────────────────────────

class TestRuntimeMonitorAX5:
    def setup_method(self):
        self.mon = RuntimeMonitor()

    def test_setuid_then_connect_triggers_ax5(self):
        self.mon.feed(SETUID_0())
        violations = self.mon.feed(NET_CON("exploit"))
        ax5 = [v for v in violations if v.axiom_id == "AX-5"]
        assert len(ax5) >= 1
        assert ax5[0].severity == "CRITICAL"

    def test_setuid_no_connect_no_ax5(self):
        self.mon.feed(SETUID_0())
        # 6 non-connect events (> window=5)
        for _ in range(6):
            self.mon.feed(_evt("exploit", SyscallType.FILE_R, "/etc/hostname"))
        violations = self.mon.feed(NET_CON("exploit"))
        ax5 = [v for v in violations if v.axiom_id == "AX-5"]
        # Watch should have expired after 5 events
        assert len(ax5) == 0


# ── RuntimeMonitor — feed_window ─────────────────────────────────────────────

class TestFeedWindow:
    def test_feed_window_attack_sequence(self):
        mon = RuntimeMonitor()
        window = [
            NGINX(),
            _evt("nginx", SyscallType.FILE_R, "/etc/nginx/nginx.conf"),
            _evt("nginx", SyscallType.NET_LIS, "0.0.0.0:80"),
            BASH_EXEC(),
        ]
        violations = mon.feed_window(window)
        assert any(v.axiom_id == "AX-1" for v in violations)

    def test_feed_window_benign_nginx(self):
        mon = RuntimeMonitor()
        window = [
            NGINX("/etc/nginx/nginx.conf"),
            NGINX("/var/www/html/index.html"),
            _evt("nginx", SyscallType.NET_LIS, "0.0.0.0:80"),
            _evt("nginx", SyscallType.FILE_W, "/var/log/nginx/access.log"),
        ]
        violations = mon.feed_window(window)
        ax1 = [v for v in violations if v.axiom_id == "AX-1"]
        assert len(ax1) == 0

    def test_feed_window_returns_list(self):
        mon = RuntimeMonitor()
        result = mon.feed_window([])
        assert isinstance(result, list)


# ── RuntimeMonitor — reset ────────────────────────────────────────────────────

class TestReset:
    def test_reset_clears_watches(self):
        mon = RuntimeMonitor()
        mon.feed(NGINX())
        assert mon.stats["active_watches"] > 0
        mon.reset()
        assert mon.stats["active_watches"] == 0
        # After reset, bash exec should not violate (no nginx watch)
        violations = mon.feed(BASH_EXEC())
        ax1 = [v for v in violations if v.axiom_id == "AX-1"]
        assert len(ax1) == 0


# ── BüchiMonitor — AX-2 shadow→exfil ─────────────────────────────────────────

class TestBuchiMonitorAX2:
    def setup_method(self):
        self.mon = BuchiMonitor()

    def test_shadow_then_connect_triggers_ax2(self):
        window = [
            SHADOW_R(),
            _evt("bash", SyscallType.FILE_R, "/etc/hosts"),
            NET_CON(),
        ]
        violations = self.mon.analyze(window)
        ax2 = [v for v in violations if v.axiom_id == "AX-2"]
        assert len(ax2) >= 1
        assert ax2[0].severity == "CRITICAL"

    def test_shadow_no_connect_no_ax2(self):
        window = [SHADOW_R()]  # shadow read but no connect
        violations = self.mon.analyze(window)
        ax2 = [v for v in violations if v.axiom_id == "AX-2"]
        assert len(ax2) == 0   # AX-2 negate=True: violation only when connect IS seen

    def test_benign_connect_no_shadow_no_ax2(self):
        window = [
            _evt("nginx", SyscallType.FILE_R, "/var/www/html/index.html"),
            NET_CON("nginx", "0.0.0.0:80"),
        ]
        violations = self.mon.analyze(window)
        ax2 = [v for v in violations if v.axiom_id == "AX-2"]
        assert len(ax2) == 0

    def test_empty_window_no_violations(self):
        violations = self.mon.analyze([])
        assert violations == []


# ── SymbolicGuardian (combined) ───────────────────────────────────────────────

class TestSymbolicGuardian:
    def test_attack_sequence_triggers_both_tiers(self):
        guardian = SymbolicGuardian()
        # Feed prctl masquerade + shadow read (Tier-1 AX-3)
        guardian.feed(PRCTL_EVT())
        tier1_violations = guardian.feed(SHADOW_R("nginx"))
        assert any(v.axiom_id == "AX-3" for v in tier1_violations)

        # Analyze full window including exfil (Tier-2 AX-2)
        window = [SHADOW_R(), NET_CON()]
        tier2_violations = guardian.analyze_window(window)
        assert any(v.axiom_id == "AX-2" for v in tier2_violations)

    def test_benign_sequence_no_violations(self):
        guardian = SymbolicGuardian()
        benign_window = [
            _evt("nginx", SyscallType.FILE_R, "/var/www/html/index.html"),
            _evt("nginx", SyscallType.NET_LIS, "0.0.0.0:80"),
            _evt("nginx", SyscallType.FILE_W, "/var/log/nginx/access.log"),
        ]
        for evt in benign_window:
            violations = guardian.feed(evt)
            assert all(v.axiom_id not in ("AX-1", "AX-3") for v in violations)
        violations = guardian.analyze_window(benign_window)
        ax2 = [v for v in violations if v.axiom_id == "AX-2"]
        assert len(ax2) == 0


# ── explainability_score ──────────────────────────────────────────────────────

class TestExplainabilityScore:
    def test_full_evidence_no_ltl_gives_half(self):
        # All claims verified, no LTL violations → 0.5 (ltl_component=0.5)
        from sentinel.evidence import EvidenceReport
        report = EvidenceReport(
            total_claims=3, verified_claims=3, unverified_claims=0,
            hallucination_rate=0.0, verified_confidence=0.90, verdict="CLEAN",
        )
        score = explainability_score([], report, total_events=20)
        assert score == pytest.approx(0.5, abs=0.01)

    def test_full_evidence_with_ltl_gives_one(self):
        from sentinel.evidence import EvidenceReport
        report = EvidenceReport(
            total_claims=3, verified_claims=3, unverified_claims=0,
            hallucination_rate=0.0, verified_confidence=0.90, verdict="CLEAN",
        )
        violations = [LTLViolation(
            axiom_id="AX-1", axiom_formula="test", severity="HIGH",
            triggering_event=NGINX(),
        )]
        score = explainability_score(violations, report, total_events=20)
        assert score == pytest.approx(1.0, abs=0.01)

    def test_no_claims_zero_events_returns_zero(self):
        from sentinel.evidence import EvidenceReport
        report = EvidenceReport(
            total_claims=0, verified_claims=0, unverified_claims=0,
            hallucination_rate=0.0, verified_confidence=0.0, verdict="NO_CLAIMS",
        )
        score = explainability_score([], report, total_events=0)
        assert score == 0.0

    def test_hallucinated_evidence_reduces_score(self):
        from sentinel.evidence import EvidenceReport
        report = EvidenceReport(
            total_claims=4, verified_claims=1, unverified_claims=3,
            hallucination_rate=0.75, verified_confidence=0.20, verdict="HALLUCINATED",
        )
        score = explainability_score([], report, total_events=10)
        assert score < 0.5
