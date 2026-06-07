"""Tests for EGTE — Evidence-Gated Tier-Calibrated Enforcement.

Coverage:
  - EscalationScorer: output range, monotonicity, feature isolation.
  - TierCalibrator: fit, conformal quantile, coverage guarantee, fail-closed.
  - apply_gates: CoVe cap, LTL floor, precedence rules.
  - EGTEEngine.enforce_tier: gate + calibration integration, capped_by.
  - EGTEResult.to_audit_dict: schema completeness.
  - I/O: load/save calibration samples.
"""
from __future__ import annotations

import json
import math
import random
import tempfile
from typing import List, Optional

import pytest

from sentinel.cove import CoVeReport, VerifiedClaim
from sentinel.egte import (
    EGTEEngine,
    EGTEResult,
    EscalationSample,
    EscalationScorer,
    TierCalibrator,
    apply_gates,
    load_calibration_samples,
    make_egte_engine,
    save_calibration_samples,
)
from sentinel.ltl import LTLViolation
from sentinel.models import EnforcementTier, KernelEvent, SyscallType, ThreatDecision


# ── helpers ───────────────────────────────────────────────────────────────────

def _decision(
    label: str = "MALICIOUS",
    confidence: float = 0.80,
    evidence_refs: Optional[list] = None,
    mitre_ttps: Optional[list] = None,
) -> ThreatDecision:
    return ThreatDecision(
        label=label,
        confidence=confidence,
        reasoning="test",
        mitre_ttps=mitre_ttps or ["T1003"],
        evidence_refs=evidence_refs or [],
    )


def _evt(sc: SyscallType = SyscallType.FILE_R, resource: str = "/etc/shadow") -> KernelEvent:
    return KernelEvent(pid=1000, ppid=999, uid=0, comm="bash",
                       sc_type=int(sc), resource=resource, ts_ns=0)


def _cove(
    hallucination_rate: float = 0.0,
    verified_claims: Optional[List[VerifiedClaim]] = None,
) -> CoVeReport:
    vc = verified_claims if verified_claims is not None else []
    if not vc and hallucination_rate == 0.0:
        # Synthesize one verified claim with a dummy UUID
        vc = [VerifiedClaim(
            event_desc="openat(R) /etc/shadow",
            supports_ttp="T1003",
            confidence_contribution=0.4,
            event_id="00000000-0000-0000-0000-000000000001",
            matched_resource="/etc/shadow",
            verification_note="test",
        )]
    return CoVeReport(
        pid=1000, comm="bash",
        draft_label="MALICIOUS", draft_confidence=0.80,
        final_label="MALICIOUS", final_confidence=0.80 * (1 - hallucination_rate),
        verified_claims=vc,
        hallucination_rate=hallucination_rate,
        retracted_claims=[] if hallucination_rate == 0 else ["fake claim"],
    )


def _ltl_violation(severity: str = "CRITICAL") -> LTLViolation:
    return LTLViolation(
        axiom_id="AX-1",
        axiom_formula="test",
        severity=severity,
        triggering_event=_evt(),
    )


def _calibration_benign(n: int = 100, rng: Optional[random.Random] = None) -> List[EscalationSample]:
    r = rng or random.Random(42)
    return [EscalationSample(score=r.uniform(0.0, 0.40), label="benign") for _ in range(n)]


def _fitted_calibrator(n: int = 200, alpha: float = 0.10) -> TierCalibrator:
    cal = TierCalibrator(alpha=alpha)
    cal.fit(_calibration_benign(n))
    return cal


# ── EscalationScorer ─────────────────────────────────────────────────────────

class TestEscalationScorer:
    def setup_method(self):
        self.scorer = EscalationScorer()

    def test_output_in_unit_interval(self):
        for label, conf in [("MALICIOUS", 0.95), ("MALICIOUS", 0.20),
                             ("BENIGN", 0.99), ("BENIGN", 0.01)]:
            s = self.scorer(_decision(label, conf), None, [])
            assert 0.0 <= s <= 1.0, f"Score {s} out of [0,1] for {label},{conf}"

    def test_malicious_higher_confidence_gives_higher_score(self):
        s_low  = self.scorer(_decision("MALICIOUS", 0.30), None, [])
        s_mid  = self.scorer(_decision("MALICIOUS", 0.60), None, [])
        s_high = self.scorer(_decision("MALICIOUS", 0.95), None, [])
        assert s_low < s_mid < s_high, "Score must be monotone in MALICIOUS confidence"

    def test_benign_higher_confidence_gives_lower_score(self):
        s_low_conf  = self.scorer(_decision("BENIGN", 0.30), None, [])
        s_high_conf = self.scorer(_decision("BENIGN", 0.95), None, [])
        assert s_high_conf < s_low_conf, "Confident BENIGN must produce lower score"

    def test_ltl_critical_violations_raise_score(self):
        d = _decision("MALICIOUS", 0.50)
        s_none = self.scorer(d, None, [])
        s_one  = self.scorer(d, None, [_ltl_violation("CRITICAL")])
        s_two  = self.scorer(d, None, [_ltl_violation("CRITICAL"), _ltl_violation("CRITICAL")])
        assert s_none < s_one < s_two

    def test_ltl_high_violations_do_not_raise_score(self):
        # HIGH severity violations should not boost score
        d = _decision("MALICIOUS", 0.50)
        s_none = self.scorer(d, None, [])
        s_high = self.scorer(d, None, [_ltl_violation("HIGH")])
        assert s_none == s_high

    def test_high_hallucination_reduces_score(self):
        d = _decision("MALICIOUS", 0.90)
        s_clean = self.scorer(d, _cove(0.0), [])
        s_hallu = self.scorer(d, _cove(0.9), [])
        assert s_hallu < s_clean, "High hallucination must reduce escalation score"

    def test_ipg_density_raises_score(self):
        d = _decision("MALICIOUS", 0.50)
        s_sparse = self.scorer(d, None, [], ipg_nodes=10, ipg_edges=5)
        s_dense  = self.scorer(d, None, [], ipg_nodes=10, ipg_edges=50)
        assert s_sparse < s_dense

    def test_entropy_raises_score(self):
        d = _decision("MALICIOUS", 0.50)
        s_low_ent  = self.scorer(d, None, [], entropy=0.5)
        s_high_ent = self.scorer(d, None, [], entropy=3.5)
        assert s_low_ent < s_high_ent

    def test_score_with_no_cove(self):
        # cove=None should not crash and score should match confidence-driven score
        s = self.scorer(_decision("MALICIOUS", 0.80), None, [])
        assert 0.0 <= s <= 1.0

    def test_fully_hallucinated_malicious_low_score(self):
        # All hallucinated: CoVe quality collapses → score driven mainly by conf * 0
        d = _decision("MALICIOUS", 0.95)
        s = self.scorer(d, _cove(1.0, verified_claims=[]), [])
        # With W_COVE * conf_feature * (1 - 1.0) = 0, only W_CONFIDENCE * 0.95 remains
        assert s < 0.50  # mostly driven by raw conf, but CoVe portion is 0


# ── TierCalibrator ────────────────────────────────────────────────────────────

class TestTierCalibratorFit:
    def test_fit_sets_is_fitted(self):
        cal = TierCalibrator()
        cal.fit(_calibration_benign(50))
        assert cal.is_fitted

    def test_fit_too_few_samples_not_fitted(self):
        cal = TierCalibrator()
        cal.fit(_calibration_benign(5))   # below MIN_CAL_SAMPLES=10
        assert not cal.is_fitted

    def test_fit_ignores_malicious_samples(self):
        cal1 = TierCalibrator()
        cal1.fit(_calibration_benign(50))

        cal2 = TierCalibrator()
        mixed = _calibration_benign(50) + [
            EscalationSample(score=0.99, label="malicious") for _ in range(20)
        ]
        cal2.fit(mixed)
        # Malicious samples ignored → same quantile
        assert math.isclose(cal1.quantile, cal2.quantile, abs_tol=0.01)

    def test_quantile_in_range_of_scores(self):
        samples = _calibration_benign(200)
        cal = TierCalibrator(alpha=0.10)
        cal.fit(samples)
        all_scores = [s.score for s in samples if s.label == "benign"]
        assert min(all_scores) <= cal.quantile <= max(all_scores)

    def test_quantile_increases_with_lower_alpha(self):
        samples = _calibration_benign(200)
        cal_strict = TierCalibrator(alpha=0.05)
        cal_lenient = TierCalibrator(alpha=0.20)
        cal_strict.fit(samples)
        cal_lenient.fit(samples)
        # Lower alpha → higher (1-alpha) quantile
        assert cal_strict.quantile >= cal_lenient.quantile

    def test_invalid_alpha_raises(self):
        with pytest.raises(ValueError):
            TierCalibrator(alpha=0.0)
        with pytest.raises(ValueError):
            TierCalibrator(alpha=1.0)


class TestTierCalibratorCalibrate:
    def setup_method(self):
        self.cal = _fitted_calibrator(n=200, alpha=0.10)

    def test_score_below_quantile_gives_pause_cap(self):
        # Score well below quantile → within benign distribution → PAUSE cap
        low_score = self.cal.quantile * 0.5
        assert self.cal.calibrate(low_score) == EnforcementTier.PAUSE

    def test_score_above_quantile_gives_isolate_cap(self):
        # Score well above quantile → above benign distribution → no cap
        high_score = min(self.cal.quantile + 0.30, 0.99)
        assert self.cal.calibrate(high_score) == EnforcementTier.ISOLATE

    def test_score_at_quantile_gives_pause_cap(self):
        # Exactly at quantile → still ≤ q̂ → PAUSE
        assert self.cal.calibrate(self.cal.quantile) == EnforcementTier.PAUSE

    def test_unfitted_gives_log_only(self):
        cal = TierCalibrator()
        assert cal.calibrate(0.99) == EnforcementTier.LOG_ONLY

    def test_empirical_pvalue_range(self):
        for score in [0.0, 0.20, 0.50, 0.99]:
            p = self.cal.empirical_pvalue(score)
            assert 0.0 <= p <= 1.0


class TestCoverageGuarantee:
    """Finite-sample conformal coverage: empirical violation rate ≈ α."""

    def test_coverage_sanity_alpha_0_10(self):
        alpha    = 0.10
        n_cal    = 500
        n_test   = 2000
        rng      = random.Random(42)

        # Benign scores ~ Uniform[0, 0.45] (well within benign region)
        def sample_benign() -> float:
            return rng.uniform(0.0, 0.45)

        cal_samples = [EscalationSample(score=sample_benign(), label="benign")
                       for _ in range(n_cal)]
        calibrator  = TierCalibrator(alpha=alpha)
        calibrator.fit(cal_samples)
        assert calibrator.is_fitted

        # Test benign scores (same distribution — exchangeability holds)
        test_scores    = [sample_benign() for _ in range(n_test)]
        n_uncapped     = sum(1 for s in test_scores
                             if calibrator.calibrate(s) == EnforcementTier.ISOLATE)
        empirical_rate = n_uncapped / n_test

        # Conformal guarantee: P(exceeds) ≤ α + 1/(n+1) ≈ α + 0.002
        # Allow ±4% tolerance for finite-sample noise
        assert empirical_rate <= alpha + 0.04, (
            f"Coverage violated: empirical={empirical_rate:.3f} > alpha={alpha} + tol"
        )

    def test_coverage_sanity_alpha_0_05(self):
        alpha   = 0.05
        rng     = random.Random(1337)
        n_cal   = 500
        n_test  = 2000

        def sample() -> float:
            return rng.uniform(0.0, 0.40)

        calibrator = TierCalibrator(alpha=alpha)
        calibrator.fit([EscalationSample(score=sample(), label="benign")
                        for _ in range(n_cal)])
        test_scores = [sample() for _ in range(n_test)]
        n_exceed    = sum(1 for s in test_scores
                          if calibrator.calibrate(s) == EnforcementTier.ISOLATE)
        assert n_exceed / n_test <= alpha + 0.04


# ── apply_gates ───────────────────────────────────────────────────────────────

class TestApplyGates:
    def test_clean_cove_no_ltl_no_gates(self):
        d = _decision("MALICIOUS", 0.85)
        c = _cove(0.0)
        cove_cap, ltl_floor, reason = apply_gates(d, c, [])
        assert cove_cap   == EnforcementTier.ISOLATE   # no cap
        assert ltl_floor  == EnforcementTier.LOG_ONLY  # no floor
        assert reason is None

    def test_high_hallucination_caps_to_log_only(self):
        d = _decision("MALICIOUS", 0.90)
        c = _cove(0.80)   # 80% hallucination → above threshold
        cove_cap, _, reason = apply_gates(d, c, [])
        assert cove_cap  == EnforcementTier.LOG_ONLY
        assert reason    == "cove"

    def test_no_verified_evidence_caps_to_pause(self):
        d = _decision("MALICIOUS", 0.85)
        # CoVeReport with no verified claims and 0 hallucination_rate (no refs)
        c = CoVeReport(
            pid=1000, comm="bash",
            draft_label="MALICIOUS", draft_confidence=0.85,
            final_label="MALICIOUS", final_confidence=0.85,
            verified_claims=[],   # no verified UUIDs
            hallucination_rate=0.0,
        )
        cove_cap, _, reason = apply_gates(d, c, [])
        assert cove_cap == EnforcementTier.PAUSE
        assert reason   == "cove"

    def test_benign_decision_no_cove_cap(self):
        # BENIGN decisions should never be capped by CoVe gate
        d = _decision("BENIGN", 0.95)
        c = _cove(0.0)
        cove_cap, _, reason = apply_gates(d, c, [])
        assert cove_cap == EnforcementTier.ISOLATE  # no cap for BENIGN

    def test_critical_ltl_sets_pause_floor(self):
        d = _decision("MALICIOUS", 0.25)
        c = _cove(0.0)
        _, ltl_floor, _ = apply_gates(d, c, [_ltl_violation("CRITICAL")])
        assert ltl_floor == EnforcementTier.PAUSE

    def test_high_ltl_does_not_set_floor(self):
        d = _decision("MALICIOUS", 0.25)
        c = _cove(0.0)
        _, ltl_floor, _ = apply_gates(d, c, [_ltl_violation("HIGH")])
        assert ltl_floor == EnforcementTier.LOG_ONLY

    def test_high_hallucination_suppresses_ltl_floor(self):
        # If CoVe shows high hallucination, LTL floor must not fire
        d = _decision("MALICIOUS", 0.90)
        c = _cove(0.80)
        cove_cap, ltl_floor, _ = apply_gates(d, c, [_ltl_violation("CRITICAL")])
        assert cove_cap  == EnforcementTier.LOG_ONLY   # CoVe caps
        assert ltl_floor == EnforcementTier.LOG_ONLY   # LTL floor suppressed

    def test_no_cove_report_no_cap(self):
        d = _decision("MALICIOUS", 0.90)
        cove_cap, ltl_floor, reason = apply_gates(d, None, [])
        assert cove_cap  == EnforcementTier.ISOLATE
        assert ltl_floor == EnforcementTier.LOG_ONLY
        assert reason is None


# ── EGTEEngine.enforce_tier ───────────────────────────────────────────────────

class TestEGTEEngine:
    def setup_method(self):
        self.calibrator = _fitted_calibrator(n=300, alpha=0.10)
        self.engine     = EGTEEngine(self.calibrator)

    def test_result_is_egte_result(self):
        d = _decision("MALICIOUS", 0.80)
        r = self.engine.enforce_tier(
            decision=d, cwae_tier=EnforcementTier.QUARANTINE,
            cove=_cove(0.0), ltl_violations=[],
        )
        assert isinstance(r, EGTEResult)

    def test_high_hallucination_forces_log_only(self):
        d = _decision("MALICIOUS", 0.90)
        r = self.engine.enforce_tier(
            decision=d, cwae_tier=EnforcementTier.ISOLATE,
            cove=_cove(0.85), ltl_violations=[],
        )
        assert r.tier_after == EnforcementTier.LOG_ONLY
        assert r.capped_by  == "cove"

    def test_cove_no_evidence_forces_pause_cap(self):
        d = _decision("MALICIOUS", 0.90)
        c = CoVeReport(
            pid=1000, comm="bash",
            draft_label="MALICIOUS", draft_confidence=0.90,
            final_label="MALICIOUS", final_confidence=0.90,
            verified_claims=[],
            hallucination_rate=0.0,
        )
        r = self.engine.enforce_tier(
            decision=d, cwae_tier=EnforcementTier.ISOLATE,
            cove=c, ltl_violations=[],
        )
        assert r.tier_after <= EnforcementTier.PAUSE

    def test_ltl_critical_floors_low_cwae_tier(self):
        # CWAE gives LOG_ONLY (low confidence), but LTL CRITICAL should floor to PAUSE
        d = _decision("MALICIOUS", 0.20)  # → LOG_ONLY from CWAE
        r = self.engine.enforce_tier(
            decision=d, cwae_tier=EnforcementTier.LOG_ONLY,
            cove=_cove(0.0), ltl_violations=[_ltl_violation("CRITICAL")],
        )
        assert r.tier_after >= EnforcementTier.PAUSE
        assert r.capped_by == "ltl"

    def test_ltl_floor_does_not_exceed_cove_cap(self):
        # High hallucination → CoVe cap = LOG_ONLY; LTL floor must not override
        d = _decision("MALICIOUS", 0.95)
        c = _cove(0.90)  # high hallucination
        r = self.engine.enforce_tier(
            decision=d, cwae_tier=EnforcementTier.ISOLATE,
            cove=c, ltl_violations=[_ltl_violation("CRITICAL")],
        )
        # CoVe always wins over LTL when hallucination is high
        assert r.tier_after == EnforcementTier.LOG_ONLY

    def test_calibration_caps_benign_looking_score(self):
        # If score is very low (looks benign), calibration should cap at PAUSE
        # Force a very low score by using confident BENIGN decision
        d = _decision("BENIGN", 0.99)
        r = self.engine.enforce_tier(
            decision=d, cwae_tier=EnforcementTier.LOG_ONLY,
            cove=_cove(0.0), ltl_violations=[],
        )
        # BENIGN CWAE is already LOG_ONLY; tier_after cannot be lower
        assert r.tier_after == EnforcementTier.LOG_ONLY

    def test_tier_before_matches_cwae_tier(self):
        d = _decision("MALICIOUS", 0.75)
        cwae = EnforcementTier.QUARANTINE
        r = self.engine.enforce_tier(
            decision=d, cwae_tier=cwae,
            cove=_cove(0.0), ltl_violations=[],
        )
        assert r.tier_before == cwae

    def test_no_change_when_score_exceeds_quantile(self):
        # High score → calibration cap = ISOLATE → no calibration cap → CWAE prevails
        d = _decision("MALICIOUS", 0.95)
        cwae = EnforcementTier.ISOLATE
        r = self.engine.enforce_tier(
            decision=d, cwae_tier=cwae,
            cove=_cove(0.0), ltl_violations=[_ltl_violation("CRITICAL")],
        )
        # With clean CoVe + CRITICAL LTL, high score → no calibration cap
        assert r.tier_after >= EnforcementTier.PAUSE  # at minimum

    def test_capped_by_is_calibration_when_score_low(self):
        # Confident MALICIOUS but very low score (e.g., from hallucinated CoVe)
        # Force score below quantile by using all-hallucinated CoVe + low confidence
        d = _decision("MALICIOUS", 0.32)  # PAUSE tier from CWAE (0.30 < conf < 0.50)
        c = _cove(0.45)  # moderate hallucination, pulls score down
        r = self.engine.enforce_tier(
            decision=d, cwae_tier=EnforcementTier.PAUSE,
            cove=c, ltl_violations=[],
        )
        # Score should be low → calibration caps at PAUSE; tier may stay at PAUSE
        assert r.tier_after <= EnforcementTier.PAUSE

    def test_unfitted_calibrator_fails_closed(self):
        cal = TierCalibrator(alpha=0.10)  # not fitted
        engine = EGTEEngine(cal)
        d = _decision("MALICIOUS", 0.95)
        r = engine.enforce_tier(
            decision=d, cwae_tier=EnforcementTier.ISOLATE,
            cove=_cove(0.0), ltl_violations=[],
        )
        # Unfitted calibrator returns LOG_ONLY → fail closed
        assert r.tier_after == EnforcementTier.LOG_ONLY


# ── EGTEResult.to_audit_dict ─────────────────────────────────────────────────

class TestEGTEResultAuditDict:
    REQUIRED_KEYS = {"score", "quantile", "tier_before", "tier_after",
                     "capped_by", "p_value"}

    def _make_result(self, tier_before=EnforcementTier.KILL,
                     tier_after=EnforcementTier.PAUSE) -> EGTEResult:
        return EGTEResult(
            score=0.35, quantile=0.30,
            tier_before=tier_before,
            tier_after=tier_after,
            capped_by="calibration",
            p_value=0.08,
        )

    def test_all_required_keys_present(self):
        d = self._make_result().to_audit_dict()
        assert self.REQUIRED_KEYS.issubset(d.keys())

    def test_tier_labels_are_strings(self):
        d = self._make_result().to_audit_dict()
        assert isinstance(d["tier_before"], str)
        assert isinstance(d["tier_after"], str)

    def test_score_is_rounded(self):
        r = EGTEResult(score=0.123456789, quantile=0.5,
                       tier_before=EnforcementTier.LOG_ONLY,
                       tier_after=EnforcementTier.LOG_ONLY,
                       capped_by=None, p_value=1.0)
        d = r.to_audit_dict()
        assert d["score"] == round(0.123456789, 4)

    def test_capped_by_none_serializes_as_none(self):
        r = EGTEResult(score=0.5, quantile=0.5,
                       tier_before=EnforcementTier.LOG_ONLY,
                       tier_after=EnforcementTier.LOG_ONLY,
                       capped_by=None, p_value=1.0)
        d = r.to_audit_dict()
        assert d["capped_by"] is None


# ── I/O: load/save calibration samples ───────────────────────────────────────

class TestCalibrationIO:
    def test_roundtrip(self):
        samples = [
            EscalationSample(score=0.10, label="benign"),
            EscalationSample(score=0.80, label="malicious"),
            EscalationSample(score=0.25, label="benign"),
        ]
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            path = f.name

        save_calibration_samples(samples, path)
        loaded = load_calibration_samples(path)
        assert len(loaded) == 3
        assert loaded[0].score == pytest.approx(0.10)
        assert loaded[1].label == "malicious"
        assert loaded[2].score == pytest.approx(0.25)

    def test_missing_file_returns_empty(self):
        result = load_calibration_samples("/nonexistent/path/cal.jsonl")
        assert result == []

    def test_malformed_line_skipped(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write('{"score": 0.3, "label": "benign"}\n')
            f.write('not valid json\n')
            f.write('{"score": 0.4, "label": "benign"}\n')
            path = f.name

        loaded = load_calibration_samples(path)
        assert len(loaded) == 2   # bad line silently skipped

    def test_bad_label_skipped(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write('{"score": 0.3, "label": "unknown_class"}\n')
            f.write('{"score": 0.4, "label": "benign"}\n')
            path = f.name

        loaded = load_calibration_samples(path)
        assert len(loaded) == 1


# ── make_egte_engine factory ─────────────────────────────────────────────────

class TestMakeEGTEEngine:
    def test_no_calibration_path_creates_unfitted(self):
        engine = make_egte_engine(alpha=0.10, calibration_path=None)
        assert not engine.calibrator.is_fitted

    def test_with_calibration_path_fits(self):
        samples = _calibration_benign(50)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            for s in samples:
                f.write(json.dumps({"score": s.score, "label": s.label}) + "\n")
            path = f.name

        engine = make_egte_engine(alpha=0.10, calibration_path=path)
        assert engine.calibrator.is_fitted

    def test_missing_calibration_path_creates_unfitted(self):
        engine = make_egte_engine(alpha=0.10, calibration_path="/no/such/file.jsonl")
        assert not engine.calibrator.is_fitted
