"""Evidence-Gated Tier-Calibrated Enforcement (EGTE) — Section IV-G.

Scientific intent
-----------------
EGTE controls benign over-escalation: the tendency of a confidence-threshold
enforcement policy (CWAE, Algorithm 3) to assign destructive tiers (KILL+,
QUARANTINE, ISOLATE) to benign host behaviors when the LLM classifier emits a
slightly elevated confidence score.

The module introduces a *distribution-free calibration layer* placed between
the CoVe+LTL verification pipeline and the CWAE enforcement call.  It uses
**split conformal prediction** on a held-out set of benign calibration windows
to produce a maximum allowed EnforcementTier per decision, yielding a
finite-sample guarantee on the benign false-escalation rate.

Paper claim (insert verbatim after implementation is validated):
  "We introduce evidence-gated tier calibration, a split-conformal procedure
  that maps streaming host behaviors to CWAE tiers subject to CoVe-verified
  evidence and LTL feasibility, yielding finite-sample control of benign
  over-escalation under stated calibration assumptions."

Conformal guarantee
-------------------
Let s(x) ∈ [0, 1] be the escalation score for window x.
Let s₁, …, sₙ be calibration scores from benign windows.
Define:
    k   = ⌈(n+1)(1 − α)⌉
    q̂  = sorted(s₁, …, sₙ)[k − 1]    (k-th smallest, 0-indexed at k-1)

Under exchangeability of calibration and test benign windows:
    P(s(x_test) > q̂)  ≤  α  +  1/(n+1)

This means: with α = 0.10, at most ~11% of benign test windows will receive
a calibration_cap of ISOLATE (no cap), controlling destructive-tier assignment.

Precedence rules (enforced in EGTEEngine.enforce_tier)
-------------------------------------------------------
Applied in this strict order — later rules cannot override earlier ones:

  1. CWAE tier T_cwae  — computed from confidence per Algorithm 3.

  2. CoVe gate (evidence cap):
       - hallucination_rate > threshold → T_cove_cap = LOG_ONLY
       - label==MALICIOUS and evidence_ids()==[] → T_cove_cap = PAUSE
       - else: T_cove_cap = ISOLATE (no cap)
     CoVe can only LOWER the tier. This ensures no destructive action is taken
     on decisions whose LLM reasoning is unsupported by real eBPF event UUIDs.

  3. LTL floor (formal safety floor):
       - Any CRITICAL axiom violation AND not high-hallucination → floor = PAUSE
       - else: floor = LOG_ONLY (no minimum enforced)
     LTL floor can only RAISE the tier, but ONLY if CoVe is not in high-
     hallucination mode. If CoVe caps to LOG_ONLY, LTL floor is suppressed
     (we do not raise enforcement based on unreliable evidence).

  4. Calibration cap (conformal quantile):
       - score ≤ q̂ → calibration_cap = PAUSE  (within benign distribution)
       - score > q̂ → calibration_cap = ISOLATE  (above benign quantile, no cap)
     Calibration can only LOWER the tier. It operates within the feasible range
     established by CoVe+LTL.

  5. Final tier:
       T = clip(min(T_cwae, T_cove_cap, calibration_cap), lo=ltl_floor, hi=T_cove_cap)
     The double-clip of T_cove_cap ensures that even when LTL raises the floor,
     a CoVe high-hallucination cap is never violated.

Audit logging
-------------
Every enforcement decision includes an `egte` dict:
    {
        "score":       float,              # escalation score ∈ [0,1]
        "quantile":    float,              # conformal quantile q̂ (or 1.0 if not fitted)
        "tier_before": str,                # CWAE tier before EGTE
        "tier_after":  str,                # final tier after EGTE
        "capped_by":   str | null,         # "cove" | "ltl" | "calibration" | null
        "p_value":     float,              # conformal p-value = fraction cal scores ≥ score
    }
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

import structlog

from sentinel.cove import CoVeReport
from sentinel.ltl import LTLViolation
from sentinel.models import EnforcementTier, ThreatDecision, TIER_LABELS

logger = structlog.get_logger(__name__)

# ── Constants ────────────────────────────────────────────────────────────────

_COVE_HIGH_HAL_THRESHOLD = 0.50   # hallucination_rate above which CoVe caps to LOG_ONLY
_LTL_FLOOR_TIER          = EnforcementTier.PAUSE  # minimum tier when CRITICAL LTL fires
_MAX_ENTROPY             = 4.0    # bits — normalization for Shannon entropy feature
_MAX_IPG_DENSITY         = 5.0    # edges/node — density above which IPG feature saturates

# ── Data types ───────────────────────────────────────────────────────────────

@dataclass
class EscalationSample:
    """One calibration / evaluation sample for TierCalibrator.

    Attributes
    ----------
    score   : escalation score ∈ [0, 1] produced by EscalationScorer.
    label   : "benign" | "malicious" — ground-truth label for this window.
    """
    score: float
    label: str   # "benign" | "malicious"


@dataclass
class EGTEResult:
    """Structured output of one EGTEEngine.enforce_tier() call.

    All fields are included verbatim in the audit log under key "egte".
    """
    score:       float
    quantile:    float
    tier_before: EnforcementTier   # raw CWAE tier (before gates / calibration)
    tier_after:  EnforcementTier   # final tier after all EGTE steps
    capped_by:   Optional[str]     # "cove" | "ltl" | "calibration" | None
    p_value:     float = 1.0       # conformal p-value (fraction cal scores ≥ score)

    def to_audit_dict(self) -> dict:
        """Serialize for inclusion in the AuditorAgent audit log."""
        return {
            "score":       round(self.score, 4),
            "quantile":    round(self.quantile, 4),
            "tier_before": TIER_LABELS.get(self.tier_before, "UNKNOWN"),
            "tier_after":  TIER_LABELS.get(self.tier_after, "UNKNOWN"),
            "capped_by":   self.capped_by,
            "p_value":     round(self.p_value, 4),
        }


# ── Escalation Scorer ────────────────────────────────────────────────────────

class EscalationScorer:
    """Deterministic, observable-quantity function → escalation score ∈ [0, 1].

    Features and their weights (sum = 1.0):

    Feature 1 — classifier_confidence (W=0.40):
        For MALICIOUS:  decision.confidence   (high conf → high score)
        For BENIGN:     1 − decision.confidence  (near 0 when very confident benign)
        Interpretation: raw LLM signal, label-signed.

    Feature 2 — cove_quality (W=0.25):
        = classifier_confidence × (1 − hallucination_rate)
        Modulates feature 1 by evidence reliability. If CoVe shows 100%
        hallucination, this feature collapses to 0 regardless of confidence.
        When no CoVe report is available (cove=None), falls back to feature 1.

    Feature 3 — ltl_critical (W=0.20):
        = min(n_critical_violations × 0.25, 1.0)
        Each CRITICAL LTL axiom violation adds 0.25, saturating at 1.0.
        HIGH violations contribute nothing (only CRITICAL).

    Feature 4 — ipg_density (W=0.10):
        = min(edges / max(nodes, 1) / 5.0, 1.0)
        Denser IPG (more cross-resource edges) → more complex behavior →
        slightly elevated score. Saturates at density = 5 edges/node.

    Feature 5 — entropy_norm (W=0.05):
        = min(entropy / 4.0, 1.0)
        Higher syscall-type entropy = more diverse behavior = higher score.
        4.0 bits ≈ maximum for 16 syscall types (log₂16).

    Monotonicity properties (by design):
        - MALICIOUS, higher confidence → higher score.
        - More CRITICAL LTL violations → higher score.
        - Higher hallucination_rate → lower score (evidence unreliable).
        - BENIGN, higher confidence → lower score.
    """

    W_CONFIDENCE = 0.40
    W_COVE       = 0.25
    W_LTL        = 0.20
    W_IPG        = 0.10
    W_ENTROPY    = 0.05

    def __call__(
        self,
        decision:       ThreatDecision,
        cove:           Optional[CoVeReport],
        ltl_violations: List[LTLViolation],
        ipg_nodes:      int   = 0,
        ipg_edges:      int   = 0,
        entropy:        float = 0.0,
    ) -> float:
        """Compute escalation score for one decision window.

        All inputs are deterministic at inference time — no sampling or LLM calls.
        Safe to call from both sync and async contexts.
        """
        # Feature 1: label-signed confidence
        if decision.label == "MALICIOUS":
            conf_feature = decision.confidence
        else:
            conf_feature = 1.0 - decision.confidence

        # Feature 2: CoVe-modulated confidence
        if cove is None:
            cove_feature = conf_feature
        else:
            evidence_quality = 1.0 - cove.hallucination_rate   # 1.0 = fully verified
            cove_feature = conf_feature * evidence_quality

        # Feature 3: LTL CRITICAL violations
        n_critical   = sum(1 for v in ltl_violations if v.severity == "CRITICAL")
        ltl_feature  = min(n_critical * 0.25, 1.0)

        # Feature 4: IPG structural density
        density      = ipg_edges / max(ipg_nodes, 1)
        ipg_feature  = min(density / _MAX_IPG_DENSITY, 1.0)

        # Feature 5: Normalized entropy
        ent_feature  = min(entropy / _MAX_ENTROPY, 1.0)

        raw = (
            self.W_CONFIDENCE * conf_feature +
            self.W_COVE       * cove_feature +
            self.W_LTL        * ltl_feature  +
            self.W_IPG        * ipg_feature  +
            self.W_ENTROPY    * ent_feature
        )
        return float(max(0.0, min(1.0, raw)))


# ── Tier Calibrator (split conformal) ────────────────────────────────────────

class TierCalibrator:
    """Split conformal calibration of maximum EnforcementTier.

    Maintains a sorted list of benign calibration scores (fit on held-out data).
    calibrate(score) returns the calibration cap:

        score ≤ q̂  →  EnforcementTier.PAUSE  (benign-compatible → cap destructive tiers)
        score > q̂  →  EnforcementTier.ISOLATE (above benign quantile → no calibration cap)

    The conformal quantile is:
        k   = ⌈(n+1)(1−α)⌉
        q̂  = sorted_benign_scores[min(k, n) − 1]

    Finite-sample guarantee:
        Under exchangeability, P(s(benign_test) > q̂)  ≤  α + 1/(n+1).

    Fail-safe:  if fit() was never called or calibration set is too small,
    calibrate() returns EnforcementTier.LOG_ONLY (most restrictive cap).
    This is intentional — missing calibration data fails closed.
    """

    MIN_CAL_SAMPLES = 10   # below this, fail closed

    def __init__(self, alpha: float = 0.10):
        if not (0.0 < alpha < 1.0):
            raise ValueError(f"alpha must be in (0, 1), got {alpha}")
        self._alpha              = alpha
        self._calibration_scores: List[float] = []
        self._quantile:          float        = float("inf")
        self._is_fitted:         bool         = False

    def fit(self, samples: List[EscalationSample]) -> None:
        """Fit calibration from a list of EscalationSamples.

        Only samples with label=="benign" are used.  Malicious samples are
        silently ignored (they provide no information about the benign distribution).
        """
        benign_scores = sorted(s.score for s in samples if s.label == "benign")
        n = len(benign_scores)

        if n < self.MIN_CAL_SAMPLES:
            logger.warning(
                "egte_calibration_insufficient",
                n_benign=n, required=self.MIN_CAL_SAMPLES,
                note="EGTE will fail closed (cap=LOG_ONLY) until more data is provided",
            )
            self._is_fitted = False
            return

        # Conformal quantile: k-th smallest (1-indexed), k = ceil((n+1)*(1-alpha))
        k = min(math.ceil((n + 1) * (1.0 - self._alpha)), n)
        self._quantile           = benign_scores[k - 1]
        self._calibration_scores = benign_scores
        self._is_fitted          = True

        logger.info(
            "egte_calibrator_fitted",
            n_calibration=n,
            alpha=self._alpha,
            quantile=round(self._quantile, 4),
        )

    def calibrate(self, score: float) -> EnforcementTier:
        """Return calibration cap (maximum allowed tier) for this score.

        See class docstring for the guarantee statement.
        """
        if not self._is_fitted:
            # Fail closed: no calibration data available
            return EnforcementTier.LOG_ONLY

        if score <= self._quantile:
            return EnforcementTier.PAUSE   # within benign distribution → cap
        else:
            return EnforcementTier.ISOLATE  # above benign quantile → no cap

    def empirical_pvalue(self, score: float) -> float:
        """Conformal p-value = fraction of calibration scores ≥ test score.

        p-value < α → reject benign hypothesis at level α.
        Under exchangeability: P(p_val(benign) < α) ≤ α.
        """
        if not self._calibration_scores:
            return 1.0
        n = len(self._calibration_scores)
        n_above = sum(1 for s in self._calibration_scores if s >= score)
        return (n_above + 1) / (n + 1)

    @property
    def quantile(self) -> float:
        """Current conformal quantile q̂ (float('inf') if not fitted)."""
        return self._quantile

    @property
    def is_fitted(self) -> bool:
        return self._is_fitted

    @property
    def alpha(self) -> float:
        return self._alpha

    @property
    def n_calibration(self) -> int:
        return len(self._calibration_scores)


# ── Gate logic ───────────────────────────────────────────────────────────────

def apply_gates(
    decision:       ThreatDecision,
    cove:           Optional[CoVeReport],
    ltl_violations: List[LTLViolation],
    cove_hal_threshold: float = _COVE_HIGH_HAL_THRESHOLD,
) -> Tuple[EnforcementTier, EnforcementTier, Optional[str]]:
    """Apply CoVe evidence gate (cap) and LTL floor (minimum tier).

    Returns
    -------
    cove_cap : EnforcementTier
        Maximum tier permitted by the CoVe evidence gate.
        ISOLATE = no cap; LOG_ONLY = most restrictive.
    ltl_floor : EnforcementTier
        Minimum tier mandated by the LTL Symbolic Guardian.
        LOG_ONLY = no minimum; PAUSE = at least PAUSE.
    gate_reason : str | None
        Human-readable reason for any cap/floor, or None if neither gate fired.

    Precedence notes:
    - CoVe gate fires when evidence is unreliable (high hallucination or
      no verified evidence IDs for a MALICIOUS verdict).
    - LTL floor fires only when CoVe is NOT in high-hallucination mode.
      If both CoVe high-hal AND LTL critical fire, CoVe wins (we never
      raise a tier that relies on unverified evidence).
    """
    high_hallucination = (
        cove is not None and cove.hallucination_rate > cove_hal_threshold
    )

    # ── CoVe evidence gate (cap) ──────────────────────────────────────────────
    cove_cap    = EnforcementTier.ISOLATE   # default: no cap
    gate_reason: Optional[str] = None

    if cove is not None and decision.label == "MALICIOUS":
        if high_hallucination:
            cove_cap    = EnforcementTier.LOG_ONLY
            gate_reason = "cove"
        elif not cove.evidence_ids():
            # MALICIOUS verdict but no verified eBPF event IDs → allow only PAUSE
            cove_cap    = EnforcementTier.PAUSE
            gate_reason = "cove"

    # ── LTL floor (minimum tier) ──────────────────────────────────────────────
    ltl_floor = EnforcementTier.LOG_ONLY   # default: no minimum

    critical_violations = [v for v in ltl_violations if v.severity == "CRITICAL"]
    if critical_violations and not high_hallucination:
        ltl_floor = _LTL_FLOOR_TIER   # PAUSE — formal axiom mandates at least PAUSE

    return cove_cap, ltl_floor, gate_reason


# ── EGTE Engine ───────────────────────────────────────────────────────────────

class EGTEEngine:
    """Evidence-Gated Tier-Calibrated Enforcement — top-level orchestrator.

    Usage in AuditorAgent (after CoVe + LTL, before CWAEEngine.enforce):

        egte_result = self._egte.enforce_tier(
            decision        = decision,
            cwae_tier       = cwae.compute_tier(decision),
            cove            = cove_report,
            ltl_violations  = ltl_violations,
            ipg_nodes       = result.ipg_nodes,
            ipg_edges       = result.ipg_edges,
            entropy         = result.signal.entropy,
        )
        # Pass egte_result.tier_after as max_tier to CWAEEngine.enforce()
        rec = await cwae.enforce(pid, comm, decision,
                                 max_tier=egte_result.tier_after)

    The engine is disabled by default in config (egte.enabled = false).
    When disabled, AuditorAgent skips all EGTE calls and produces a null
    egte dict in the audit log.
    """

    def __init__(
        self,
        calibrator:         TierCalibrator,
        scorer:             Optional[EscalationScorer] = None,
        cove_hal_threshold: float = _COVE_HIGH_HAL_THRESHOLD,
    ):
        self._calibrator      = calibrator
        self._scorer          = scorer or EscalationScorer()
        self._cove_hal_thresh = cove_hal_threshold

    def enforce_tier(
        self,
        decision:       ThreatDecision,
        cwae_tier:      EnforcementTier,
        cove:           Optional[CoVeReport],
        ltl_violations: List[LTLViolation],
        ipg_nodes:      int   = 0,
        ipg_edges:      int   = 0,
        entropy:        float = 0.0,
    ) -> EGTEResult:
        """Apply EGTE pipeline and return the gated/calibrated tier.

        Steps (see module docstring for full precedence rules):

          1. Score this window with EscalationScorer.
          2. Apply CoVe gate → cove_cap (max tier from evidence quality).
          3. Apply LTL floor → ltl_floor (min tier from formal safety).
          4. Apply calibration cap → calibration_cap (conformal quantile).
          5. Compute final tier = clip(
                 min(cwae_tier, cove_cap, calibration_cap),
                 lo = ltl_floor if not high_hallucination else LOG_ONLY,
                 hi = cove_cap
             ).
          6. Determine capped_by from what actually changed.
        """
        # ── Step 1: escalation score ─────────────────────────────────────────
        score = self._scorer(
            decision, cove, ltl_violations, ipg_nodes, ipg_edges, entropy
        )

        # ── Step 2-3: gates ───────────────────────────────────────────────────
        cove_cap, ltl_floor, gate_reason = apply_gates(
            decision, cove, ltl_violations,
            cove_hal_threshold=self._cove_hal_thresh,
        )

        # ── Step 4: calibration cap ───────────────────────────────────────────
        calibration_cap = self._calibrator.calibrate(score)
        p_val           = self._calibrator.empirical_pvalue(score)

        # ── Step 5: final tier ────────────────────────────────────────────────
        # Start from CWAE tier; lower by CoVe cap; lower by calibration cap.
        tier = min(cwae_tier, cove_cap, calibration_cap)

        # Raise by LTL floor, but only if CoVe is not in high-hallucination mode.
        high_hallucination = (
            cove is not None and
            cove.hallucination_rate > self._cove_hal_thresh
        )
        if not high_hallucination:
            tier = max(tier, ltl_floor)

        # CoVe cap is always the hard ceiling (applied last to prevent LTL override).
        tier = min(tier, cove_cap)

        # ── Step 6: determine capped_by ───────────────────────────────────────
        if tier == cwae_tier:
            capped_by = None
        elif tier > cwae_tier:
            # LTL floor raised the tier
            capped_by = "ltl"
        elif gate_reason == "cove":
            capped_by = "cove"
        elif calibration_cap < cwae_tier and tier == min(cwae_tier, calibration_cap):
            capped_by = "calibration"
        else:
            capped_by = gate_reason   # "cove" or None

        logger.debug(
            "egte_decision",
            score=round(score, 4),
            quantile=round(self._calibrator.quantile, 4) if self._calibrator.is_fitted else "?",
            tier_before=TIER_LABELS.get(cwae_tier, str(cwae_tier)),
            tier_after=TIER_LABELS.get(tier, str(tier)),
            capped_by=capped_by,
            p_value=round(p_val, 4),
        )

        return EGTEResult(
            score       = score,
            quantile    = self._calibrator.quantile if self._calibrator.is_fitted else float("inf"),
            tier_before = cwae_tier,
            tier_after  = tier,
            capped_by   = capped_by,
            p_value     = p_val,
        )

    @property
    def calibrator(self) -> TierCalibrator:
        return self._calibrator

    @property
    def scorer(self) -> EscalationScorer:
        return self._scorer


# ── Calibration data I/O ─────────────────────────────────────────────────────

def load_calibration_samples(path: str | Path) -> List[EscalationSample]:
    """Load EscalationSamples from a JSONL file.

    Each line must be a JSON object with keys:
        score  : float
        label  : "benign" | "malicious"

    Lines with missing or malformed fields are skipped with a warning.
    """
    samples: List[EscalationSample] = []
    p = Path(path)
    if not p.exists():
        logger.warning("egte_calibration_file_missing", path=str(p))
        return samples

    for i, line in enumerate(p.read_text().splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            s   = float(obj["score"])
            lbl = str(obj["label"]).lower()
            if lbl not in ("benign", "malicious"):
                raise ValueError(f"label must be benign|malicious, got {lbl!r}")
            samples.append(EscalationSample(score=s, label=lbl))
        except Exception as exc:
            logger.warning("egte_calibration_parse_error", line=i + 1, error=str(exc))

    logger.info("egte_calibration_loaded", path=str(p), n_samples=len(samples))
    return samples


def save_calibration_samples(
    samples: List[EscalationSample],
    path: str | Path,
) -> None:
    """Persist EscalationSamples to a JSONL file for later reuse."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w") as f:
        for s in samples:
            f.write(json.dumps({"score": s.score, "label": s.label}) + "\n")
    logger.info("egte_calibration_saved", path=str(p), n_samples=len(samples))


# ── Convenience factory ───────────────────────────────────────────────────────

def make_egte_engine(
    alpha:             float         = 0.10,
    calibration_path:  Optional[str] = None,
    cove_hal_threshold: float        = _COVE_HIGH_HAL_THRESHOLD,
) -> EGTEEngine:
    """Construct an EGTEEngine, optionally loading calibration data from disk.

    If calibration_path is None or file doesn't exist, the calibrator is not
    fitted and will fail closed (cap=LOG_ONLY) until fit() is called.
    """
    calibrator = TierCalibrator(alpha=alpha)
    if calibration_path:
        samples = load_calibration_samples(calibration_path)
        if samples:
            calibrator.fit(samples)

    return EGTEEngine(
        calibrator         = calibrator,
        scorer             = EscalationScorer(),
        cove_hal_threshold = cove_hal_threshold,
    )
