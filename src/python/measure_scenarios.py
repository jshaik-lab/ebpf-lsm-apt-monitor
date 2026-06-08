"""
measure_scenarios.py — Run all SENTINEL simulation scenarios through the real
Ollama llama3.1:8b classifier and print exact measured confidence scores.

This script produces the ground-truth numbers for Table 1 of the paper.
No mock classifier is used.  Run with:

    PYTHONPATH=src/python python3 src/python/measure_scenarios.py

Requires Ollama running at http://localhost:11434 with llama3.1:8b loaded.
"""
import asyncio
import json
import sys
import time

sys.path.insert(0, "src/python")

from sentinel.ipg import IPGBuilder
from sentinel.llm.ollama import OllamaClassifier
from sentinel.simulation import SCENARIOS

OLLAMA_URL = "http://localhost:11434"
MODEL      = "llama3.1:8b"
SEPARATOR  = "-" * 80


async def main() -> None:
    # Match the DARPA config (config/sentinel.yaml): 300 s timeout, 3 retries.
    # Lower values caused silent MockClassifier fallback on the first window of
    # the IONOS VPS run because CPU-only llama3.1:8b inference can exceed 60 s
    # on a cold worker. See sentinel/llm/ollama.py:188 — fallback is logged
    # via ollama_fallback_to_mock and counted in sentinel.provenance.
    classifier = OllamaClassifier(
        base_url=OLLAMA_URL,
        model=MODEL,
        timeout=300,
        max_retries=3,
        tier="full",
    )
    builder = IPGBuilder()

    # Verify model is reachable before running
    ok = await classifier.health()
    if not ok:
        print(f"ERROR: {MODEL} not available at {OLLAMA_URL}")
        sys.exit(1)
    print(f"Model: {MODEL}  URL: {OLLAMA_URL}\n{SEPARATOR}")

    results = []
    for scenario in SCENARIOS:
        G        = builder.build(scenario.events)
        ipg_text = builder.serialize(G)
        H        = builder.structural_entropy(G)

        t0       = time.perf_counter()
        decision = await classifier.classify(ipg_text)
        elapsed  = (time.perf_counter() - t0) * 1000

        correct = decision.label == scenario.expected
        status  = "OK" if correct else "MISMATCH"

        print(f"[{status}] {scenario.name} ({scenario.ttp_id})")
        print(f"       Expected : {scenario.expected}")
        print(f"       Got      : {decision.label}  confidence={decision.confidence:.4f}  latency={elapsed:.0f}ms")
        print(f"       Reasoning: {decision.reasoning}")
        print(f"       TTPs     : {decision.mitre_ttps}")
        print(f"       Entropy  : {H:.3f}")
        print()

        results.append({
            "scenario":   scenario.name,
            "ttp_id":     scenario.ttp_id,
            "expected":   scenario.expected,
            "label":      decision.label,
            "confidence": decision.confidence,
            "reasoning":  decision.reasoning,
            "mitre_ttps": decision.mitre_ttps,
            "entropy":    round(H, 3),
            "latency_ms": round(elapsed, 1),
            "correct":    correct,
        })

    # Summary
    print(SEPARATOR)
    correct_count = sum(r["correct"] for r in results)
    print(f"Accuracy: {correct_count}/{len(results)} scenarios correct\n")

    # LaTeX table rows — copy-paste into main.tex Table 1
    print("=== LaTeX Table 1 rows (copy into paper) ===")
    tier_map = {
        (True,  True,  0.85): "ISOLATE",
        (True,  True,  0.70): "QUARANTINE",
        (True,  True,  0.50): "KILL",
        (True,  True,  0.30): "PAUSE",
        (True,  True,  0.00): "LOG\\_ONLY",
        (False, True,  0.00): "LOG\\_ONLY",
        (False, False, 0.00): "LOG\\_ONLY",
    }

    def get_tier(label: str, conf: float) -> str:
        if label == "BENIGN":
            return "LOG\\_ONLY"
        if conf >= 0.85: return "ISOLATE"
        if conf >= 0.70: return "QUARANTINE"
        if conf >= 0.50: return "KILL"
        if conf >= 0.30: return "PAUSE"
        return "LOG\\_ONLY"

    for r in results:
        tier  = get_tier(r["label"], r["confidence"])
        ttps  = ",".join(r["mitre_ttps"][:2]) if r["mitre_ttps"] else "---"
        label = r["label"] if r["correct"] else f"{r['label']}(!)"
        print(f"{r['scenario']:<20} & {ttps:<15} & {label:<10} & {r['confidence']:.2f} & {tier:<12} \\\\")

    # Machine-readable dump
    out_path = "results/evaluations/scenario_results.json"
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nFull results written to {out_path}")


if __name__ == "__main__":
    asyncio.run(main())
