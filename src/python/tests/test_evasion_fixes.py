"""Tests for the three red-team evasion countermeasures in agent.py.

Verifies that:
  - EVASION-01 (entropy evasion)   → caught by hard-trigger resource bypass
  - EVASION-03 (slow-and-low)      → caught by hard-trigger on first sensitive read
  - EVASION-04 (kill-chain split)  → caught via flagged-parent bypass
  - Benign processes               → NOT hard-triggered (no false positives)
  - Temperature scaling            → adjusts confidence without changing label
"""
from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock

import pytest

from sentinel.agent import (
    SentinelAgent,
)
from sentinel.llm.temperature import TemperatureScaledClassifier, scale_confidence
from sentinel.models import KernelEvent, SyscallType, ThreatDecision


def _evt(pid: int, sc: SyscallType, resource: str, ppid: int = 1) -> KernelEvent:
    return KernelEvent(ts_ns=0, pid=pid, ppid=ppid, uid=1000,
                       comm="test", sc_type=int(sc), resource=resource)


# ── SentinelAgent unit helpers ─────────────────────────────────────────────────

@pytest.fixture
def agent(cfg):
    """Minimal SentinelAgent for unit testing (no Docker / LLM needed)."""
    return SentinelAgent(cfg)


# ── Hard-trigger resource bypass tests (EVASION-01, EVASION-03) ───────────────

class TestHardTrigger:

    def test_shadow_read_is_hard_trigger(self, agent):
        evt = _evt(1000, SyscallType.FILE_R, "/etc/shadow")
        assert agent._is_hard_trigger(evt)

    def test_ssh_key_is_hard_trigger(self, agent):
        evt = _evt(1000, SyscallType.FILE_R, "/home/user/.ssh/id_rsa")
        assert agent._is_hard_trigger(evt)

    def test_aws_credentials_is_hard_trigger(self, agent):
        evt = _evt(1000, SyscallType.FILE_R, "/home/user/.aws/credentials")
        assert agent._is_hard_trigger(evt)

    def test_normal_file_is_not_hard_trigger(self, agent):
        evt = _evt(1000, SyscallType.FILE_R, "/etc/hostname")
        assert not agent._is_hard_trigger(evt)

    def test_nginx_html_is_not_hard_trigger(self, agent):
        evt = _evt(1000, SyscallType.FILE_R, "/var/www/html/index.html")
        assert not agent._is_hard_trigger(evt)

    def test_postgres_data_is_not_hard_trigger(self, agent):
        evt = _evt(1000, SyscallType.FILE_R, "/var/lib/postgresql/data/base/")
        assert not agent._is_hard_trigger(evt)

    def test_evasion01_single_type_shadow_still_detected(self, agent):
        """EVASION-01: all-FILE_R entropy=0 sequence must trigger on /etc/shadow."""
        shadow_evt = _evt(20000, SyscallType.FILE_R, "/etc/shadow")
        assert agent._is_hard_trigger(shadow_evt), (
            "EVASION-01 NOT FIXED: /etc/shadow must trigger regardless of entropy"
        )

    def test_evasion03_slow_and_low_single_shadow_detected(self, agent):
        """EVASION-03: a single /etc/shadow read buried in benign events triggers."""
        benign_resources = ["/etc/hostname", "/etc/resolv.conf", "/etc/hosts"]
        for res in benign_resources:
            assert not agent._is_hard_trigger(_evt(22000, SyscallType.FILE_R, res))
        # The one malicious event must still be caught
        assert agent._is_hard_trigger(_evt(22000, SyscallType.FILE_R, "/etc/shadow"))


# ── Flagged-parent bypass tests (EVASION-04) ───────────────────────────────────

class TestFlaggedPidBypass:

    def test_unflagged_pid_not_bypassed(self, agent):
        agent._ppid_map[23001] = 23000
        assert not agent._is_flagged_pid(23001)

    def test_flagged_pid_bypassed(self, agent):
        agent._flag_pid(23000)
        assert agent._is_flagged_pid(23000)

    def test_child_of_flagged_parent_bypassed(self, agent):
        """EVASION-04: PID 23001 whose parent 23000 was flagged must be bypassed."""
        agent._ppid_map[23001] = 23000
        agent._flag_pid(23000)
        assert agent._is_flagged_pid(23001), (
            "EVASION-04 NOT FIXED: child of flagged PID must bypass entropy gate"
        )

    def test_flag_expires_after_ttl(self, agent):
        agent._flag_pid(23000)
        # Manually expire
        agent._flagged_pids[23000] = time.monotonic() - 1.0
        assert not agent._is_flagged_pid(23000)

    def test_unrelated_pid_not_affected_by_sibling_flag(self, agent):
        """A PID with a different parent is not caught by sibling flagging."""
        agent._ppid_map[23001] = 23000
        agent._ppid_map[99999] = 1       # different parent
        agent._flag_pid(23000)
        assert not agent._is_flagged_pid(99999)

    def test_evasion04_split_kill_chain_detected(self, agent):
        """End-to-end: parent reads creds (flagged) → child connects out (bypassed)."""
        parent_pid = 23000
        child_pid  = 23001
        agent._ppid_map[child_pid] = parent_pid

        # Simulate parent getting flagged after MALICIOUS verdict
        agent._flag_pid(parent_pid)

        # Child's outbound connection event should now bypass entropy gate
        child_evt = _evt(child_pid, SyscallType.NET_CON, "185.220.101.1:4444",
                         ppid=parent_pid)
        assert agent._is_flagged_pid(child_evt.pid), (
            "EVASION-04 NOT FIXED: child PID must be caught after parent flagged"
        )


# ── Temperature scaling tests ──────────────────────────────────────────────────

class TestTemperatureScaling:

    def test_T1_identity(self):
        assert scale_confidence(0.80, 1.0) == 0.80

    def test_underconfident_sharpened_by_T_below_1(self):
        # T < 1 sharpens: 0.70 raw → higher calibrated
        cal = scale_confidence(0.70, 0.75)
        assert cal > 0.70, "T<1 should increase underconfident scores"

    def test_overconfident_flattened_by_T_above_1(self):
        # T > 1 flattens: 0.99 raw → lower calibrated
        cal = scale_confidence(0.99, 1.5)
        assert cal < 0.99, "T>1 should decrease overconfident scores"

    def test_label_unchanged_after_scaling(self):
        """Temperature scaling must not change MALICIOUS/BENIGN label."""
        raw_decision = ThreatDecision(
            label="MALICIOUS", confidence=0.72,
            reasoning="test", mitre_ttps=["T1003"],
        )
        mock_inner = AsyncMock()
        mock_inner.classify = AsyncMock(return_value=raw_decision)
        mock_inner.tier_name = "mock"
        clf = TemperatureScaledClassifier(mock_inner, temperature=0.75)
        result = asyncio.run(clf.classify("ipg_text"))
        assert result.label == "MALICIOUS"
        assert result.confidence != raw_decision.confidence
        assert result.confidence > raw_decision.confidence   # underconfident → sharpened

    def test_fit_temperature_returns_float(self):
        confidences = [0.65, 0.70, 0.68, 0.72, 0.80, 0.85]
        correct     = [True, True, True, True, True, False]
        T = TemperatureScaledClassifier.fit_temperature(confidences, correct)
        assert 0.5 <= T <= 3.0

    def test_confidence_stays_in_unit_interval(self):
        for raw in [0.01, 0.30, 0.50, 0.70, 0.99]:
            for T in [0.5, 0.75, 1.0, 1.5, 2.0]:
                cal = scale_confidence(raw, T)
                assert 0.0 <= cal <= 1.0, f"Out of range: raw={raw}, T={T}, cal={cal}"
