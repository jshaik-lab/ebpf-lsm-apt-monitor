"""Optional GBDT/LightGBM detector wrapper for IPG feature vectors."""
from __future__ import annotations

import pickle
from pathlib import Path
from typing import Dict

import networkx as nx

from sentinel.ipg import IPGMeta
from sentinel.provenance_ml.features import extract_features


class GBDTDetector:
    """Wrapper for GBDT classification on IPG features."""

    def __init__(self, model_path: str | Path | None = None):
        self._model_path = Path(model_path) if model_path else Path(__file__).parent / "cadets_gbdt.pkl"
        self._model = None
        if self._model_path.exists():
            try:
                with open(self._model_path, "rb") as f:
                    self._model = pickle.load(f)
            except Exception:
                pass

    def predict_proba(self, meta: IPGMeta, G: nx.MultiDiGraph) -> float:
        """Return the probability of the graph being malicious.
        
        If no fitted model is found, returns 0.0 as a safe fallback.
        """
        if self._model is None:
            return 0.0
        
        features = extract_features(meta, G)
        # Extract features in sorted order to ensure consistent array format
        X = [features[k] for k in sorted(features.keys())]
        try:
            # Assumes sklearn/lightgbm model format
            return float(self._model.predict_proba([X])[0][1])
        except Exception:
            return 0.0
