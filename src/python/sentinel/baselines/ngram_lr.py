"""N-gram Logistic Regression syscall classifier — standard IDS baseline.

Implements the Forrest (1996) / Hofmeyr (1998) n-gram syscall IDS approach
using modern scikit-learn. Trains on simulation scenarios (synthetic),
tests on real strace traces.

Key limitation vs SENTINEL: features are syscall TYPE sequences only —
the resource name (/etc/shadow vs /etc/hostname) is invisible to this
classifier. Demonstrates why resource-aware IPG encoding is necessary.
"""
from __future__ import annotations

import time
from typing import List

from sklearn.feature_extraction.text import CountVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from sentinel.models import KernelEvent, ThreatDecision
from sentinel.simulation import SCENARIOS


def _events_to_sequence(events: List[KernelEvent]) -> str:
    """Convert event list to space-separated syscall type string for n-gram."""
    return " ".join(str(e.sc_type) for e in events)


class NGramLRClassifier:
    """Unigram + bigram Logistic Regression on syscall type sequences.

    Trained on 14 simulation scenarios (synthetic ground truth).
    Tested on real strace traces for the comparison table.
    """

    def __init__(self) -> None:
        self._pipeline: Pipeline | None = None
        self._trained = False

    def train(self) -> None:
        X = [_events_to_sequence(s.events) for s in SCENARIOS]
        y = [1 if s.expected == "MALICIOUS" else 0 for s in SCENARIOS]

        self._pipeline = Pipeline([
            ("vec", CountVectorizer(analyzer="word", ngram_range=(1, 2),
                                    min_df=1, token_pattern=r"\d+")),
            ("clf", LogisticRegression(max_iter=1000, C=1.0,
                                       class_weight="balanced",
                                       random_state=42)),
        ])
        self._pipeline.fit(X, y)
        self._trained = True

    def classify(self, events: List[KernelEvent]) -> ThreatDecision:
        if not self._trained:
            self.train()

        t0  = time.perf_counter()
        seq = _events_to_sequence(events)
        assert self._pipeline is not None
        prob = self._pipeline.predict_proba([seq])[0]  # [p_benign, p_malicious]
        label = "MALICIOUS" if prob[1] >= 0.5 else "BENIGN"
        confidence = round(float(prob[1] if label == "MALICIOUS" else prob[0]), 4)
        latency_ms = (time.perf_counter() - t0) * 1000

        return ThreatDecision(
            label=label,
            confidence=confidence,
            reasoning=f"NGram-LR: p(malicious)={prob[1]:.3f}",
            mitre_ttps=[],
            model_used="ngram-lr/sklearn",
            latency_ms=round(latency_ms, 3),
        )
