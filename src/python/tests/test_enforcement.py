"""Tests for sentinel.enforcement — CWAE Engine (Algorithm 3)."""
import json
from unittest.mock import patch

import pytest

from sentinel.models import EnforcementTier, ThreatDecision


def _decision(label: str, confidence: float, ttps: list[str] | None = None) -> ThreatDecision:
    return ThreatDecision(
        label=label,
        confidence=confidence,
        reasoning="test reasoning",
        mitre_ttps=ttps or [],
    )


@pytest.mark.asyncio
async def test_log_only_below_threshold(cwae):
    d   = _decision("MALICIOUS", 0.25)
    rec = await cwae.enforce(1234, "bash", d)
    assert rec.tier == EnforcementTier.LOG_ONLY


@pytest.mark.asyncio
async def test_pause_tier(cwae):
    d   = _decision("MALICIOUS", 0.45)
    rec = await cwae.enforce(1234, "bash", d)
    assert rec.tier == EnforcementTier.PAUSE


@pytest.mark.asyncio
async def test_kill_tier(cwae):
    d   = _decision("MALICIOUS", 0.65)
    rec = await cwae.enforce(1234, "bash", d)
    assert rec.tier == EnforcementTier.KILL


@pytest.mark.asyncio
async def test_quarantine_tier(cwae):
    d   = _decision("MALICIOUS", 0.75)
    rec = await cwae.enforce(1234, "bash", d)
    assert rec.tier == EnforcementTier.QUARANTINE


@pytest.mark.asyncio
async def test_isolate_tier(cwae):
    d   = _decision("MALICIOUS", 0.90)
    rec = await cwae.enforce(1234, "bash", d)
    assert rec.tier == EnforcementTier.ISOLATE


@pytest.mark.asyncio
async def test_benign_always_log_only(cwae):
    d   = _decision("BENIGN", 0.02)
    rec = await cwae.enforce(1234, "nginx", d)
    assert rec.tier == EnforcementTier.LOG_ONLY


@pytest.mark.asyncio
async def test_dry_run_no_os_kill(cwae):
    assert cwae._dry_run is True
    d = _decision("MALICIOUS", 0.70)
    with patch("os.kill") as mock_kill:
        await cwae.enforce(999, "malware", d)
        mock_kill.assert_not_called()


@pytest.mark.asyncio
async def test_audit_log_written(cwae, tmp_path):
    d = _decision("MALICIOUS", 0.60, ttps=["T1003"])
    await cwae.enforce(1234, "bash", d)

    log_path = cwae._audit_path
    assert log_path.exists()
    rows = [json.loads(line) for line in log_path.read_text().splitlines() if line]
    assert len(rows) == 1
    assert rows[0]["label"] == "MALICIOUS"
    assert rows[0]["comm"] == "bash"
    assert rows[0]["mitre_ttps"] == ["T1003"]


@pytest.mark.asyncio
async def test_isolate_writes_incident(cwae, tmp_path):
    d = _decision("MALICIOUS", 0.90, ttps=["T1055"])
    await cwae.enforce(1234, "malware", d)

    log_path = cwae._incident_path
    assert log_path.exists()
    rows = [json.loads(line) for line in log_path.read_text().splitlines() if line]
    assert len(rows) == 1
    assert rows[0]["severity"] == "CRITICAL"


@pytest.mark.asyncio
async def test_enforcement_stats(cwae):
    await cwae.enforce(1, "p1", _decision("MALICIOUS", 0.25))
    await cwae.enforce(2, "p2", _decision("MALICIOUS", 0.45))
    await cwae.enforce(3, "p3", _decision("BENIGN",    0.02))
    stats = cwae.enforcement_stats
    assert stats["LOG_ONLY"] == 2   # one malicious below threshold + one benign
    assert stats["PAUSE"]    == 1
