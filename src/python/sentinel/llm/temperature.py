"""Temperature scaling for LLM confidence calibration.

Wraps any BaseClassifier and applies temperature scaling (Guo et al., ICML 2017)
to correct systematic over- or under-confidence.

The SENTINEL LLM is underconfident (ECE=0.174, actual accuracy > stated confidence).
A temperature T < 1.0 sharpens the distribution; T > 1.0 flattens it.

For underconfident classifiers (accuracy > confidence): use T < 1.0 (e.g., T=0.7).
For overconfident classifiers (confidence > accuracy): use T > 1.0 (e.g., T=1.3).

The calibrated confidence is computed as:
    logit(p) = log(p / (1-p))
    logit_scaled = logit(p) / T
    p_cal = sigmoid(logit_scaled) = 1 / (1 + exp(-logit_scaled))

Fit T using a held-out calibration set via minimize_scalar on NLL loss.
Default T=0.75 is a reasonable starting point given the measured ECE=0.174
(underconfident, real accuracy higher than stated confidence).

Usage:
    raw_clf = OllamaClassifier(...)
    clf = TemperatureScaledClassifier(raw_clf, temperature=0.75)
    decision = await clf.classify(ipg_text)
"""
from __future__ import annotations

import math

from sentinel.llm.base import BaseClassifier
from sentinel.models import ThreatDecision


def _sigmoid(x: float) -> float:
    if x >= 0:
        return 1.0 / (1.0 + math.exp(-x))
    exp_x = math.exp(x)
    return exp_x / (1.0 + exp_x)


def _logit(p: float) -> float:
    p = max(1e-7, min(1 - 1e-7, p))
    return math.log(p / (1.0 - p))


def scale_confidence(confidence: float, temperature: float) -> float:
    """Apply temperature scaling to a raw confidence probability."""
    if temperature <= 0:
        raise ValueError(f"Temperature must be > 0, got {temperature}")
    if temperature == 1.0:
        return confidence
    scaled_logit = _logit(confidence) / temperature
    return round(_sigmoid(scaled_logit), 4)


class TemperatureScaledClassifier(BaseClassifier):
    """Wraps any BaseClassifier with temperature-scaled confidence output.

    Does not change the label (MALICIOUS/BENIGN), only the confidence score.
    Downstream CWAE thresholds then operate on calibrated probabilities.
    """

    def __init__(self, inner: BaseClassifier, temperature: float = 0.75):
        self._inner = inner
        self._T = temperature

    @property
    def tier_name(self) -> str:
        return f"{self._inner.tier_name}/T={self._T}"

    async def health(self) -> bool:
        return await self._inner.health()

    async def classify(self, ipg_text: str) -> ThreatDecision:
        raw = await self._inner.classify(ipg_text)
        calibrated = scale_confidence(raw.confidence, self._T)
        return ThreatDecision(
            label           = raw.label,
            confidence      = calibrated,
            reasoning       = raw.reasoning,
            mitre_ttps      = raw.mitre_ttps,
            chain_of_thought= raw.chain_of_thought,
            model_used      = f"{raw.model_used}/temp={self._T}",
            latency_ms      = raw.latency_ms,
            ts_ns           = raw.ts_ns,
        )

    @staticmethod
    def fit_temperature(
        confidences: list[float],
        correct: list[bool],
        n_bins: int = 10,
    ) -> float:
        """Simple grid search for optimal temperature on a calibration set.

        Args:
            confidences: raw confidence values from the classifier
            correct:     whether each prediction was correct
            n_bins:      number of ECE bins

        Returns:
            temperature T that minimises ECE on the provided calibration set
        """
        best_T, best_ece = 1.0, float("inf")
        for T_int in range(5, 31):   # T in [0.5, 3.0] at 0.1 steps
            T = T_int / 10.0
            scaled = [scale_confidence(c, T) for c in confidences]
            # Compute ECE
            bins: dict[int, list] = {}
            for c, ok in zip(scaled, correct):
                b = min(int(c * n_bins), n_bins - 1)
                bins.setdefault(b, []).append((c, ok))
            n = len(confidences)
            ece = sum(
                (len(v) / n) * abs(sum(ok for _, ok in v) / len(v) -
                                    sum(c for c, _ in v) / len(v))
                for v in bins.values()
            )
            if ece < best_ece:
                best_ece, best_T = ece, T
        return best_T
