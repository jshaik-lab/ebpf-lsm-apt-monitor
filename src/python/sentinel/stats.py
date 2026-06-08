"""Statistical helpers for paper-grade evaluation reporting.

Reviewers of IEEE TIFS expect bootstrap CIs on every reported metric and
statistical-significance tests when comparing system configurations. This
module provides:

- bootstrap_ci: percentile bootstrap 95% CI on any scalar statistic
- bootstrap_metric: TPR/FPR/Precision/F1/Accuracy CIs from per-window outcomes
- mcnemar_pvalue: paired-binary McNemar's test (CoVe on vs off, dual-tier vs full)
- cohens_d: standardized effect size for latency / overhead deltas

All functions are deterministic given a seed and have no external dependencies
beyond the stdlib + numpy (numpy is already in requirements.txt).
"""
from __future__ import annotations

import math
import random
from typing import Callable, Iterable, Sequence

import numpy as np


def bootstrap_ci(
    values: Sequence[float],
    statistic: Callable[[Sequence[float]], float] | None = None,
    *,
    n_resamples: int = 2000,
    alpha: float = 0.05,
    seed: int = 0,
) -> tuple[float, float]:
    """Percentile bootstrap CI at level (1 - alpha) for a scalar statistic.

    Default statistic is the mean.
    """
    if not values:
        return (float("nan"), float("nan"))
    if statistic is None:
        statistic = lambda xs: float(sum(xs) / max(len(xs), 1))
    rng = random.Random(seed)
    n = len(values)
    samples = []
    for _ in range(n_resamples):
        idx = [rng.randrange(n) for _ in range(n)]
        samples.append(statistic([values[i] for i in idx]))
    samples.sort()
    lo = samples[int(alpha / 2 * n_resamples)]
    hi = samples[int((1 - alpha / 2) * n_resamples) - 1]
    return (round(lo, 4), round(hi, 4))


def bootstrap_metric(
    outcomes: Sequence[tuple[bool, bool]],
    metric: str,
    *,
    n_resamples: int = 2000,
    alpha: float = 0.05,
    seed: int = 0,
) -> tuple[float, float]:
    """Bootstrap CI for tpr/fpr/precision/f1/accuracy.

    outcomes: sequence of (ground_truth_positive, predicted_positive) tuples.
    """
    if not outcomes:
        return (float("nan"), float("nan"))

    def _calc(sample: Sequence[tuple[bool, bool]]) -> float:
        tp = sum(1 for gt, pr in sample if gt and pr)
        fp = sum(1 for gt, pr in sample if not gt and pr)
        tn = sum(1 for gt, pr in sample if not gt and not pr)
        fn = sum(1 for gt, pr in sample if gt and not pr)
        if metric == "tpr":      return tp / max(tp + fn, 1)
        if metric == "fpr":      return fp / max(fp + tn, 1)
        if metric == "precision":return tp / max(tp + fp, 1)
        if metric == "accuracy": return (tp + tn) / max(len(sample), 1)
        if metric == "f1":
            prec = tp / max(tp + fp, 1)
            rec  = tp / max(tp + fn, 1)
            return 2 * prec * rec / max(prec + rec, 1e-9)
        raise ValueError(f"unknown metric: {metric}")

    rng = random.Random(seed)
    n = len(outcomes)
    samples = []
    for _ in range(n_resamples):
        idx = [rng.randrange(n) for _ in range(n)]
        samples.append(_calc([outcomes[i] for i in idx]))
    samples.sort()
    lo = samples[int(alpha / 2 * n_resamples)]
    hi = samples[int((1 - alpha / 2) * n_resamples) - 1]
    return (round(lo, 4), round(hi, 4))


def mcnemar_pvalue(b: int, c: int) -> float:
    """Two-sided McNemar's test p-value (exact binomial for small samples).

    b: count where system A correct, B wrong
    c: count where system A wrong,   B correct
    Use to compare paired predictions (e.g. CoVe-on vs CoVe-off on same DARPA windows).
    Returns 1.0 if no discordant pairs.
    """
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    # Two-sided exact binomial under H0: p = 0.5
    p = 2.0 * sum(math.comb(n, i) * 0.5 ** n for i in range(k + 1))
    return min(1.0, p)


def cohens_d(group_a: Sequence[float], group_b: Sequence[float]) -> float:
    """Pooled-SD standardized effect size (positive = A > B)."""
    if not group_a or not group_b:
        return float("nan")
    a = np.array(group_a, dtype=float)
    b = np.array(group_b, dtype=float)
    pooled = math.sqrt(((a.var(ddof=1) * (len(a) - 1)) + (b.var(ddof=1) * (len(b) - 1)))
                       / max(len(a) + len(b) - 2, 1))
    if pooled == 0:
        return float("nan")
    return round(float((a.mean() - b.mean()) / pooled), 4)
