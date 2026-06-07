"""Baseline classifiers for SENTINEL comparison (Section V-D, Table III).

Three baselines run on the same parsed KernelEvent objects as SENTINEL:
  FalcoRulesClassifier  — deterministic rule engine, ~0.1 ms, no ML
  NGramLRClassifier     — unigram+bigram LogisticRegression, ~5 ms
"""
from sentinel.baselines.falco_rules import FalcoRulesClassifier
from sentinel.baselines.ngram_lr import NGramLRClassifier

__all__ = ["FalcoRulesClassifier", "NGramLRClassifier"]
