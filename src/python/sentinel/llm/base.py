"""Abstract classifier interface + DualTierClassifier (Algorithm 2)."""
from __future__ import annotations

import logging
import math
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Optional

from sentinel.models import ThreatDecision

logger = logging.getLogger(__name__)


@dataclass
class FastPathSample:
    """One labeled calibration window for the conformal fast-path.

    true_label       : ground-truth "BENIGN" | "MALICIOUS".
    draft_label      : the 1B draft model's predicted label on this window.
    draft_confidence : the 1B draft model's confidence in *its* prediction.
    """
    true_label:       str
    draft_label:      str
    draft_confidence: float


class ConformalFastPath:
    """Split-conformal acceptance threshold for the BENIGN fast-path.

    Audit fix #3.  The legacy fast-path accepts a draft \"BENIGN\" verdict at
    a hand-set confidence (0.90).  A fixed threshold on an uncalibrated 1B
    model gives *no* bound on the dangerous event --- a true attack the draft
    confidently mislabels BENIGN and thus drops from full-model review.

    The nonconformity score is the draft model's BENIGN-confidence on
    *known-malicious* calibration windows it (wrongly) labels BENIGN.  With
    these scores sorted ascending and

        k  = ⌈(n+1)(1−α)⌉,    q̂ = scores[min(k, n) − 1],

    accepting the fast-path only when draft confidence > q̂ gives, under
    exchangeability, the finite-sample false-accept bound

        P(attack fast-pathed as BENIGN)  ≤  α + 1/(n+1).

    This is the same split-conformal order statistic used by
    sentinel.egte.TierCalibrator, kept purpose-built here to avoid coupling
    Algorithm 2 to EGTE's tier semantics.

    Fail-safe: until fitted on >= MIN_CAL_SAMPLES dangerous samples the
    fast-path is *disabled* (every window escalates to the full model) --- the
    unbounded-FN path is never taken silently.
    """

    MIN_CAL_SAMPLES = 10

    def __init__(self, alpha: float = 0.05,
                 fallback_threshold: float = 0.90,
                 min_samples: Optional[int] = None):
        if not (0.0 < alpha < 1.0):
            raise ValueError(f"alpha must be in (0, 1), got {alpha}")
        self._alpha     = alpha
        self._fallback  = fallback_threshold
        self._min       = min_samples if min_samples is not None else self.MIN_CAL_SAMPLES
        self._qhat:  Optional[float] = None
        self._n:     int             = 0
        self._fitted: bool           = False

    def fit(self, samples: List[FastPathSample]) -> None:
        scores = sorted(
            s.draft_confidence for s in samples
            if s.true_label == "MALICIOUS" and s.draft_label == "BENIGN"
        )
        n = len(scores)
        self._n = n
        if n < self._min:
            self._fitted = False
            logger.warning(
                "conformal_fastpath_insufficient n=%d required=%d "
                "-> fast-path DISABLED (fail-safe, all windows escalate)",
                n, self._min,
            )
            return
        k = min(math.ceil((n + 1) * (1.0 - self._alpha)), n)
        self._qhat   = scores[k - 1]
        self._fitted = True
        logger.info(
            "conformal_fastpath_fitted n=%d alpha=%.3f qhat=%.4f bound=%.4f",
            n, self._alpha, self._qhat, self.bound,
        )

    def accepts(self, confidence: float) -> bool:
        """True iff a draft BENIGN at this confidence may skip the full model."""
        if not self._fitted or self._qhat is None:
            return False                       # fail-safe: no bound -> escalate
        return confidence > self._qhat

    @property
    def is_fitted(self) -> bool:
        return self._fitted

    @property
    def accept_threshold(self) -> Optional[float]:
        return self._qhat

    @property
    def bound(self) -> float:
        """Finite-sample false-accept bound α + 1/(n+1) (1.0 if not fitted)."""
        return self._alpha + 1.0 / (self._n + 1) if self._fitted else 1.0


class BaseClassifier(ABC):
    """All LLM backends implement this async interface."""

    @abstractmethod
    async def classify(self, ipg_text: str) -> ThreatDecision: ...

    async def health(self) -> bool:
        return True

    @property
    def tier_name(self) -> str:
        return "unknown"


class DualTierClassifier:
    """
    Algorithm 2: Entropy-gated two-model inference pipeline.

    BENIGN-only fast-path: the draft model's BENIGN verdict at high confidence
    is accepted without invoking the full model.  MALICIOUS verdicts from the
    draft model always escalate to the full model for confirmation, preventing
    false-positive enforcement actions based on draft errors alone.

    This asymmetric design avoids the draft model's known calibration failure
    mode (high-confidence MALICIOUS on benign processes like PostgreSQL) while
    still reducing full-model invocations for clearly benign workloads.
    """

    def __init__(
        self,
        draft: BaseClassifier,
        full:  BaseClassifier,
        draft_conf_threshold: float = 0.90,
        entropy_high:         float = 3.8,
        calibrator: Optional[ConformalFastPath] = None,
    ):
        self._draft  = draft
        self._full   = full
        self._thresh = draft_conf_threshold
        self._high   = entropy_high
        # Optional split-conformal acceptance bound (audit fix #3).  When
        # supplied, the hand-set threshold is replaced by the conformal q̂,
        # giving P(attack fast-pathed) ≤ α + 1/(n+1).  None = legacy behavior.
        self._calib  = calibrator
        self._draft_hits = 0
        self._full_hits  = 0

    def _fast_path_ok(self, decision: ThreatDecision) -> bool:
        if decision.label != "BENIGN":
            return False                       # MALICIOUS always escalates
        if self._calib is not None:
            return self._calib.accepts(decision.confidence)
        return decision.confidence >= self._thresh

    async def classify(self, ipg_text: str, entropy: float) -> ThreatDecision:
        if entropy < self._high:
            draft_decision = await self._draft.classify(ipg_text)
            if self._fast_path_ok(draft_decision):
                self._draft_hits += 1
                logger.debug("Draft BENIGN accepted: conf=%.3f", draft_decision.confidence)
                return draft_decision

        self._full_hits += 1
        return await self._full.classify(ipg_text)

    @property
    def invocation_reduction_rate(self) -> float:
        total = self._draft_hits + self._full_hits
        return self._draft_hits / total if total else 0.0

    @property
    def stats(self) -> dict:
        if self._calib is not None and self._calib.is_fitted:
            policy = {
                "fast_path": "conformal",
                "accept_threshold": round(self._calib.accept_threshold, 4),
                "false_accept_bound": round(self._calib.bound, 4),
            }
        elif self._calib is not None:
            policy = {"fast_path": "disabled (calibrator unfitted, fail-safe)"}
        else:
            policy = {"fast_path": "fixed", "accept_threshold": self._thresh}
        return {
            "draft_hits":  self._draft_hits,
            "full_hits":   self._full_hits,
            "reduction_%": round(self.invocation_reduction_rate * 100, 1),
            **policy,
        }
