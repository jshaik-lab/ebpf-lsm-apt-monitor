"""Tests for sentinel.llm — mock classifier and dual-tier logic."""

import pytest

import random

from sentinel.llm.mock import MockClassifier
from sentinel.llm.base import (
    ConformalFastPath,
    DualTierClassifier,
    FastPathSample,
)
from sentinel.llm.base import BaseClassifier
from sentinel.models import ThreatDecision


class _StubClassifier(BaseClassifier):
    """Returns a fixed (label, confidence) — deterministic for fast-path tests."""

    def __init__(self, label: str, confidence: float, tier: str = "stub"):
        self._d = (label, confidence)
        self._tier = tier

    async def classify(self, ipg_text: str) -> ThreatDecision:
        label, conf = self._d
        return ThreatDecision(label=label, confidence=conf,
                              reasoning="stub", model_used=f"stub/{self._tier}")


@pytest.mark.asyncio
async def test_mock_credential_dump_is_malicious():
    clf = MockClassifier()
    ipg = (
        "Behavioral graph (3 nodes, 4 edges):\n"
        "  PROC[bash/EXEC] --[execve, dt=2ms]--> PROC[cat/EXEC]\n"
        "  PROC[cat/FILE]  --[openat(R), dt=1ms]--> PROC[cat/FILE] [SENSITIVE] path=/etc/shadow\n"
        "  PROC[bash/NET]  --[connect, dt=85ms]--> PROC[bash/NET] path=93.184.216.34:4444\n"
        "Processes involved: bash, cat"
    )
    d = await clf.classify(ipg)
    assert d.label == "MALICIOUS"
    assert d.confidence >= 0.30
    assert "T1003" in d.mitre_ttps


@pytest.mark.asyncio
async def test_mock_nginx_is_benign():
    clf = MockClassifier()
    ipg = (
        "Behavioral graph (2 nodes, 3 edges):\n"
        "  PROC[nginx/FILE] --[openat(R), dt=0.5ms]--> PROC[nginx/FILE] path=/var/www/html/index.html\n"
        "  PROC[nginx/NET]  --[listen, dt=1ms]--> PROC[nginx/NET]\n"
        "Processes involved: nginx"
    )
    d = await clf.classify(ipg)
    assert d.label == "BENIGN"
    assert d.confidence < 0.30


@pytest.mark.asyncio
async def test_mock_ptrace_is_malicious():
    clf = MockClassifier()
    ipg = "Behavioral graph (1 node, 1 edge):\n  PROC[malware/MEM] --[ptrace, dt=2ms]--> PROC[target/MEM]\nProcesses involved: malware"
    d = await clf.classify(ipg)
    assert d.label == "MALICIOUS"
    assert "T1055" in d.mitre_ttps


@pytest.mark.asyncio
async def test_dual_tier_draft_accepted_below_entropy():
    """BENIGN-only fast-path: draft BENIGN at high confidence is accepted."""
    draft = MockClassifier(tier="draft")
    full  = MockClassifier(tier="full")
    clf   = DualTierClassifier(draft, full, draft_conf_threshold=0.01, entropy_high=3.8)

    # Nginx-style benign IPG → mock draft returns BENIGN → accepted on fast-path
    ipg = "PROC[nginx/NET] --[listen]--> PROC[nginx/NET]"
    d = await clf.classify(ipg, entropy=1.0)  # low entropy
    assert d.model_used.startswith("mock/draft")
    assert clf.stats["draft_hits"] == 1
    assert clf.stats["full_hits"]  == 0


@pytest.mark.asyncio
async def test_dual_tier_malicious_draft_always_escalates():
    """MALICIOUS verdict from draft always escalates to full model."""
    draft = MockClassifier(tier="draft")
    full  = MockClassifier(tier="full")
    clf   = DualTierClassifier(draft, full, draft_conf_threshold=0.01, entropy_high=3.8)

    # /etc/shadow attack IPG → mock draft returns MALICIOUS → escalates to full
    ipg = "path=/etc/shadow [SENSITIVE]\nconnect :4444"
    d = await clf.classify(ipg, entropy=1.0)
    assert d.model_used.startswith("mock/full")  # escalated even at low entropy
    assert clf.stats["draft_hits"] == 0
    assert clf.stats["full_hits"]  == 1


@pytest.mark.asyncio
async def test_dual_tier_full_invoked_above_entropy():
    """When entropy >= high threshold, full model is always invoked."""
    draft = MockClassifier(tier="draft")
    full  = MockClassifier(tier="full")
    clf   = DualTierClassifier(draft, full, draft_conf_threshold=0.99, entropy_high=3.8)

    d = await clf.classify("benign nginx trace", entropy=4.5)  # high entropy
    assert d.model_used.startswith("mock/full")
    assert clf.stats["full_hits"] == 1


@pytest.mark.asyncio
async def test_invocation_reduction_rate():
    clf = DualTierClassifier(
        MockClassifier("draft"), MockClassifier("full"),
        draft_conf_threshold=0.01, entropy_high=3.8,
    )
    # Benign IPG → draft accepted (fast-path); attack IPG → escalates to full
    benign_ipg = "PROC[nginx/NET] --[listen]--> PROC[nginx/NET]"
    attack_ipg = "path=/etc/shadow [SENSITIVE]"
    for _ in range(8):
        await clf.classify(benign_ipg, entropy=1.0)   # BENIGN fast-path
    await clf.classify(attack_ipg, entropy=1.0)        # MALICIOUS → escalates

    rate = clf.invocation_reduction_rate
    assert 0.0 < rate < 1.0


# ── Conformal fast-path (audit fix #3) ────────────────────────────────────────

def test_conformal_fastpath_coverage():
    """Empirical false-accept rate must respect the α + 1/(n+1) bound."""
    rng = random.Random(42)
    alpha, n, m = 0.05, 500, 5000

    def _attack_fooled_draft_conf() -> float:
        # Draft is overconfident on attacks it mislabels BENIGN.
        return min(0.999, max(0.50, rng.gauss(0.92, 0.04)))

    cal = [FastPathSample("MALICIOUS", "BENIGN", _attack_fooled_draft_conf())
           for _ in range(n)]
    fp = ConformalFastPath(alpha=alpha)
    fp.fit(cal)
    assert fp.is_fitted and fp.accept_threshold is not None

    # Held-out attacks from the same distribution: how many slip the fast-path?
    slipped = sum(1 for _ in range(m)
                  if fp.accepts(_attack_fooled_draft_conf()))
    empirical = slipped / m
    assert empirical <= alpha + 1.0 / (n + 1) + 0.02, empirical
    assert abs(fp.bound - (alpha + 1.0 / (n + 1))) < 1e-9


def test_conformal_fastpath_failsafe_when_unfitted():
    fp = ConformalFastPath(alpha=0.05, min_samples=10)
    fp.fit([FastPathSample("MALICIOUS", "BENIGN", 0.95)])  # only 1 < 10
    assert not fp.is_fitted
    assert fp.accepts(0.999) is False        # fail-safe: never fast-path
    assert fp.bound == 1.0


@pytest.mark.asyncio
async def test_dualtier_conformal_escalates_overconfident_false_negative():
    """The real failure mode: draft says BENIGN@0.95 on an attack.  Legacy
    0.90 threshold accepts it (false negative); the conformal q̂ escalates."""
    # Calibration: attacks fool the draft at confidences 0.90..0.998.
    cal = [FastPathSample("MALICIOUS", "BENIGN", 0.90 + 0.0018 * i)
           for i in range(50)]
    fp = ConformalFastPath(alpha=0.05)
    fp.fit(cal)
    qhat = fp.accept_threshold
    assert 0.95 < qhat < 0.999            # q̂ lands in the overconfident band

    full = _StubClassifier("MALICIOUS", 0.97, tier="full")

    # (a) overconfident FN: draft BENIGN@0.95 — legacy WOULD accept (>=0.90).
    clf = DualTierClassifier(_StubClassifier("BENIGN", 0.95, "draft"), full,
                             draft_conf_threshold=0.90, calibrator=fp)
    d = await clf.classify("ipg", entropy=1.0)
    assert d.label == "MALICIOUS"                  # escalated, FN avoided
    assert clf.stats["full_hits"] == 1
    assert clf.stats["fast_path"] == "conformal"
    assert clf.stats["accept_threshold"] == round(qhat, 4)

    # (b) genuinely confident BENIGN above q̂ still fast-paths (no FN cost).
    clf2 = DualTierClassifier(_StubClassifier("BENIGN", 0.9995, "draft"), full,
                              calibrator=fp)
    d2 = await clf2.classify("ipg", entropy=1.0)
    assert d2.label == "BENIGN" and clf2.stats["draft_hits"] == 1

    # Legacy (no calibrator) accepts the 0.95 FN — proves the gap existed.
    legacy = DualTierClassifier(_StubClassifier("BENIGN", 0.95, "draft"), full,
                                draft_conf_threshold=0.90)
    dl = await legacy.classify("ipg", entropy=1.0)
    assert dl.label == "BENIGN" and legacy.stats["draft_hits"] == 1
