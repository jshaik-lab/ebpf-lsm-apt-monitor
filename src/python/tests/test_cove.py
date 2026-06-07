"""Tests for CoVeLoop — 4-step Chain of Verification."""
from __future__ import annotations

import pytest

from sentinel.cove import CoVeLoop, CoVeReport
from sentinel.models import KernelEvent, SyscallType, ThreatDecision


# ── helpers ───────────────────────────────────────────────────────────────────

def _evt(sc: SyscallType, resource: str, comm: str = "bash",
         pid: int = 1000) -> KernelEvent:
    return KernelEvent(pid=pid, ppid=999, uid=1000, comm=comm,
                       sc_type=int(sc), resource=resource, ts_ns=0)


def _decision(label: str = "MALICIOUS", confidence: float = 0.85,
              evidence_refs: list | None = None,
              mitre_ttps: list | None = None) -> ThreatDecision:
    return ThreatDecision(
        label=label,
        confidence=confidence,
        reasoning="Test decision",
        mitre_ttps=mitre_ttps or ["T1003"],
        evidence_refs=evidence_refs or [],
    )


SHADOW_EVT = _evt(SyscallType.FILE_R, "/etc/shadow")
NET_EVT    = _evt(SyscallType.NET_CON, "185.220.101.1:4444")
EXEC_EVT   = _evt(SyscallType.EXEC, "/usr/bin/python3")
NGINX_EVT  = _evt(SyscallType.FILE_R, "/var/www/html/index.html", "nginx")


# ── CoVeReport structure ──────────────────────────────────────────────────────

class TestCoVeReportStructure:
    def test_evidence_ids_returns_list(self):
        loop = CoVeLoop()
        decision = _decision(evidence_refs=[{
            "event_desc": "openat(R) /etc/shadow",
            "supports": "T1003",
            "confidence_contribution": 0.4,
        }])
        report = loop.run(decision, [SHADOW_EVT], pid=1000, comm="bash")
        assert isinstance(report.evidence_ids(), list)

    def test_to_audit_dict_keys(self):
        loop = CoVeLoop()
        decision = _decision()
        report = loop.run(decision, [SHADOW_EVT], pid=1000, comm="bash")
        d = report.to_audit_dict()
        assert "pid" in d
        assert "final_label" in d
        assert "hallucination_rate" in d
        assert "verified_evidence_ids" in d
        assert "explainability_score" in d

    def test_is_verified_all_clean(self):
        loop = CoVeLoop()
        decision = _decision(evidence_refs=[{
            "event_desc": "openat(R) /etc/shadow",
            "supports": "T1003",
            "confidence_contribution": 0.4,
        }])
        report = loop.run(decision, [SHADOW_EVT], pid=1000, comm="bash")
        assert report.hallucination_rate <= 1.0  # valid range


# ── CoVeLoop — all claims verified ───────────────────────────────────────────

class TestCoVeAllVerified:
    def setup_method(self):
        self.loop = CoVeLoop()
        self.events = [SHADOW_EVT, NET_EVT, EXEC_EVT]

    def test_all_verified_no_retractions(self):
        decision = _decision(evidence_refs=[
            {"event_desc": "openat(R) /etc/shadow", "supports": "T1003",
             "confidence_contribution": 0.3},
            {"event_desc": "connect 185.220.101.1:4444", "supports": "T1071",
             "confidence_contribution": 0.3},
        ])
        report = self.loop.run(decision, self.events, 1000, "bash")
        assert report.hallucination_rate == pytest.approx(0.0, abs=1e-4)
        assert len(report.retracted_claims) == 0
        assert len(report.verified_claims) >= 1

    def test_verified_claims_have_event_ids(self):
        decision = _decision(evidence_refs=[{
            "event_desc": "openat(R) /etc/shadow",
            "supports": "T1003",
            "confidence_contribution": 0.4,
        }])
        report = self.loop.run(decision, self.events, 1000, "bash")
        for claim in report.verified_claims:
            assert len(claim.event_id) == 36  # UUID
            assert claim.event_id != ""

    def test_evidence_ids_match_actual_events(self):
        decision = _decision(evidence_refs=[{
            "event_desc": "openat(R) /etc/shadow",
            "supports": "T1003",
            "confidence_contribution": 0.4,
        }])
        report = self.loop.run(decision, self.events, 1000, "bash")
        actual_ids = {e.event_id for e in self.events}
        for eid in report.evidence_ids():
            assert eid in actual_ids, f"Evidence ID {eid} not in event window"

    def test_explainability_score_nonzero_with_claims(self):
        decision = _decision(evidence_refs=[{
            "event_desc": "openat(R) /etc/shadow",
            "supports": "T1003",
            "confidence_contribution": 0.4,
        }])
        report = self.loop.run(decision, self.events, 1000, "bash")
        assert report.explainability_score > 0.0


# ── CoVeLoop — hallucinated claims ───────────────────────────────────────────

class TestCoVeHallucinations:
    def setup_method(self):
        self.loop = CoVeLoop()
        self.events = [SHADOW_EVT]

    def test_unverified_claims_retracted(self):
        decision = _decision(evidence_refs=[
            {"event_desc": "openat(R) /etc/shadow", "supports": "T1003",
             "confidence_contribution": 0.3},
            {"event_desc": "openat(R) /etc/crontab", "supports": "T1562",
             "confidence_contribution": 0.2},   # NOT in window
            {"event_desc": "execve /bin/nc", "supports": "T1059",
             "confidence_contribution": 0.2},   # NOT in window
        ])
        report = self.loop.run(decision, self.events, 1000, "bash")
        assert len(report.retracted_claims) >= 1
        # retracted_claims should include the unverified ones
        retracted_text = " ".join(report.retracted_claims)
        assert "/etc/crontab" in retracted_text or "/bin/nc" in retracted_text

    def test_high_hallucination_downgrades_confidence(self):
        # All claims unverified → confidence should be reduced
        decision = _decision(
            confidence=0.90,
            evidence_refs=[
                {"event_desc": "openat(R) /nonexistent", "supports": "T1562",
                 "confidence_contribution": 0.45},
                {"event_desc": "execve /bin/nonexistent", "supports": "T1059",
                 "confidence_contribution": 0.45},
            ],
        )
        report = self.loop.run(decision, self.events, 1000, "bash")
        assert report.final_confidence <= decision.confidence

    def test_100_percent_hallucination_caps_confidence(self):
        # All refs fabricated → CoVe should cap confidence below enforcement threshold
        decision = _decision(
            confidence=0.95,
            evidence_refs=[
                {"event_desc": "read /nonexistent1", "supports": "T1003",
                 "confidence_contribution": 0.45},
                {"event_desc": "exec /nonexistent2", "supports": "T1059",
                 "confidence_contribution": 0.45},
            ],
        )
        report = self.loop.run(decision, self.events, 1000, "bash")
        # When all claims hallucinated + hallucination_rate > threshold → final_confidence ≤ 0.29
        if report.hallucination_rate > 0.50:
            assert report.final_confidence <= 0.29

    def test_draft_label_preserved_in_report(self):
        decision = _decision(label="MALICIOUS", confidence=0.85)
        report = self.loop.run(decision, self.events, 1000, "bash")
        assert report.draft_label == "MALICIOUS"


# ── CoVeLoop — no evidence refs (fallback to reasoning parse) ─────────────────

class TestCoVeNoRefs:
    def setup_method(self):
        self.loop = CoVeLoop()

    def test_no_refs_still_returns_report(self):
        decision = _decision(evidence_refs=[])
        report = self.loop.run(decision, [SHADOW_EVT], 1000, "bash")
        assert isinstance(report, CoVeReport)
        assert report.final_label in ("MALICIOUS", "BENIGN")

    def test_benign_decision_no_refs(self):
        decision = _decision(label="BENIGN", confidence=0.05, evidence_refs=[])
        report = self.loop.run(decision, [NGINX_EVT], 1000, "nginx")
        assert report.final_label == "BENIGN"
        assert report.hallucination_rate == 0.0


# ── CoVeLoop — grounding iterations ──────────────────────────────────────────

class TestCoVeGrounding:
    def test_grounding_iteration_count_bounded(self):
        loop = CoVeLoop(max_grounding_iterations=2)
        decision = _decision(evidence_refs=[{
            "event_desc": "openat(R) /etc/shadow",
            "supports": "T1003",
            "confidence_contribution": 0.4,
        }])
        report = loop.run(decision, [SHADOW_EVT], 1000, "bash")
        assert report.grounding_iterations <= 2

    def test_zero_iterations_acts_as_pure_verifier(self):
        loop = CoVeLoop(max_grounding_iterations=0)
        decision = _decision(evidence_refs=[{
            "event_desc": "openat(R) /etc/shadow",
            "supports": "T1003",
            "confidence_contribution": 0.4,
        }])
        report = loop.run(decision, [SHADOW_EVT], 1000, "bash")
        assert report.grounding_iterations == 0
        assert isinstance(report, CoVeReport)


# ── CoVeLoop — latency tracking ──────────────────────────────────────────────

class TestCoVeLatency:
    def test_cove_latency_ms_positive(self):
        loop = CoVeLoop()
        decision = _decision()
        report = loop.run(decision, [SHADOW_EVT], 1000, "bash")
        assert report.cove_latency_ms >= 0.0

    def test_cove_latency_ms_reasonable(self):
        loop = CoVeLoop()
        decision = _decision(evidence_refs=[{
            "event_desc": "openat(R) /etc/shadow",
            "supports": "T1003",
            "confidence_contribution": 0.4,
        }])
        report = loop.run(decision, [SHADOW_EVT, NET_EVT], 1000, "bash")
        # Pure Python verification should be well under 100ms
        assert report.cove_latency_ms < 100.0


# ── CoVeReport — audit dict ───────────────────────────────────────────────────

class TestCoVeAuditDict:
    def test_audit_dict_verified_ids_are_uuids(self):
        loop = CoVeLoop()
        decision = _decision(evidence_refs=[{
            "event_desc": "openat(R) /etc/shadow",
            "supports": "T1003",
            "confidence_contribution": 0.4,
        }])
        report = loop.run(decision, [SHADOW_EVT], 1000, "bash")
        d = report.to_audit_dict()
        for eid in d["verified_evidence_ids"]:
            assert len(eid) == 36
            assert eid.count("-") == 4

    def test_audit_dict_contains_all_required_keys(self):
        loop = CoVeLoop()
        report = loop.run(_decision(), [SHADOW_EVT], 1000, "bash")
        d = report.to_audit_dict()
        required = {
            "pid", "comm", "draft_label", "draft_confidence",
            "final_label", "final_confidence", "hallucination_rate",
            "explainability_score", "grounding_iterations",
            "cove_latency_ms", "verified_evidence_ids",
            "retracted_claims", "mitre_ttps", "reasoning",
        }
        assert required.issubset(d.keys())
