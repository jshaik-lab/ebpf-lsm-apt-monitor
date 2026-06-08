"""Measure dual-tier LLM invocation reduction on 14 simulation scenarios.

Compares DualTierClassifier (draft → full) against 8B-only baseline.
Output: results/evaluations/dual_tier_reduction.json

Usage:
    PYTHONPATH=src/python python3 src/python/measure_dual_tier_reduction.py
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from sentinel.config import SentinelConfig
from sentinel.ipg import IPGBuilder
from sentinel.llm import make_classifier
from sentinel.llm.base import DualTierClassifier
from sentinel.llm.ollama import OllamaClassifier
from sentinel.provenance import make_meta
from sentinel.simulation import SCENARIOS

OUT = Path("results/evaluations/dual_tier_reduction.json")


async def main() -> None:
    # sentinel.yaml has localhost Ollama URL; sentinel.ollama.yaml uses Docker host "ollama".
    cfg = SentinelConfig.from_yaml("config/sentinel.yaml")
    cfg.llm.backend = "ollama"  # type: ignore[assignment]
    ollama_url = os.environ.get("SENTINEL__LLM__OLLAMA_URL")
    if ollama_url:
        cfg.llm.ollama_url = ollama_url
    dual: DualTierClassifier = make_classifier(cfg.llm)
    full_only = OllamaClassifier(
        base_url=cfg.llm.ollama_url,
        model=cfg.llm.full_model,
        timeout=cfg.llm.timeout_seconds,
        max_retries=cfg.llm.max_retries,
        tier="full",
    )
    if not await full_only.health():
        print("ERROR: Ollama not reachable")
        sys.exit(1)

    builder = IPGBuilder()
    per_scenario = []
    dual_correct = b8_correct = 0

    for sc in SCENARIOS:
        G = builder.build(sc.events)
        ipg = builder.serialize(G)
        H = 2.5

        t0 = time.perf_counter()
        d = await dual.classify(ipg, H)
        dual_ms = (time.perf_counter() - t0) * 1000

        t0 = time.perf_counter()
        b = await full_only.classify(ipg)
        b8_ms = (time.perf_counter() - t0) * 1000

        expected = sc.expected
        dc = d.label == expected
        bc = b.label == expected
        dual_correct += int(dc)
        b8_correct += int(bc)

        per_scenario.append({
            "scenario": sc.name,
            "expected": expected,
            "dual_label": d.label,
            "dual_conf": round(d.confidence, 3),
            "dual_tier_used": d.model_used,
            "dual_latency_ms": round(dual_ms, 1),
            "dual_correct": dc,
            "b8_label": b.label,
            "b8_conf": round(b.confidence, 3),
            "b8_latency_ms": round(b8_ms, 1),
            "b8_correct": bc,
        })
        print(f"  {sc.name}: dual={d.label}@{d.confidence:.2f} ({d.model_used})  "
              f"8b={b.label}@{b.confidence:.2f}")

    n = len(per_scenario)
    draft_hits = dual.stats.get("draft_hits", 0)
    full_hits = dual.stats.get("full_hits", 0)
    reduction = round(100.0 * draft_hits / max(n, 1), 1)

    result = {
        "model_draft": cfg.llm.draft_model,
        "model_full": cfg.llm.full_model,
        "draft_conf_threshold": cfg.llm.draft_conf_threshold,
        "fast_path": "BENIGN-only",
        "n_scenarios": n,
        "draft_hits": draft_hits,
        "full_hits": full_hits,
        "invocation_reduction_pct": reduction,
        "accuracy_dual_tier": dual_correct,
        "accuracy_8b_only": b8_correct,
        "per_scenario": per_scenario,
        "meta": make_meta(),
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=2))
    print(f"\nReduction: {reduction}% ({draft_hits}/{n} draft hits)")
    print(f"Accuracy: dual {dual_correct}/{n}  8b-only {b8_correct}/{n}")
    print(f"→ {OUT}")


if __name__ == "__main__":
    asyncio.run(main())
