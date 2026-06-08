"""
evaluate_adfa_ld.py — SENTINEL evaluation on ADFA-LD syscall traces.

Runs SENTINEL's MockClassifier (and optionally Ollama) over ADFA-LD traces,
computing F1 / TPR / FPR against ground-truth labels derived from the
directory structure.

Dataset:
    ADFA Linux Dataset (ADFA-LD), Creech & Hu, IEEE TDSC 2014.
    Download: https://github.com/verazuo/a-dataset-for-developing-IDS

Directory layout expected:
    <root>/Training_Data_Master/   (benign)
    <root>/Attack_Data_Master/<attack_type>/  (malicious)

Run:
    PYTHONPATH=src/python python3 src/python/evaluate_adfa_ld.py \
        --dataset /path/to/ADFA-LD \
        [--ollama] [--max-traces 500] \
        [--out results/evaluations/adfa_ld_results.json]
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
import pathlib

sys.path.insert(0, "src/python")

from sentinel.ipg import IPGBuilder
from sentinel.llm.mock import MockClassifier
from evaluation.adfa_ld_ingestor import ADFALDIngestor

OUT_DEFAULT = "results/evaluations/adfa_ld_results.json"
SEP = "=" * 72


async def evaluate(dataset_path: str, use_ollama: bool,
                   max_traces: int, out_path: str) -> None:
    if use_ollama:
        from sentinel.llm.ollama import OllamaClassifier
        classifier = OllamaClassifier(
            base_url="http://localhost:11434",
            model="llama3.1:8b",
            timeout=300,
            max_retries=3,
            tier="full",
        )
        ok = await classifier.health()
        if not ok:
            print("ERROR: Ollama llama3.1:8b not available. Use --mock or start Ollama.")
            sys.exit(1)
        clf_name = "llama3.1:8b (Ollama)"
    else:
        classifier = MockClassifier(tier="full")
        clf_name   = "MockClassifier (heuristic)"

    builder  = IPGBuilder()
    ingestor = ADFALDIngestor(dataset_path)

    print(SEP)
    print("SENTINEL — ADFA-LD Evaluation")
    print(f"Dataset : {dataset_path}")
    print(f"Classifier: {clf_name}")

    # Pre-flight: count traces
    all_traces = list(ingestor.traces())
    if max_traces > 0:
        all_traces = all_traces[:max_traces]

    n_benign  = sum(1 for t in all_traces if t.label == "BENIGN")
    n_attack  = sum(1 for t in all_traces if t.label == "MALICIOUS")
    print(f"Traces  : {len(all_traces)} total ({n_benign} benign / {n_attack} attack)")
    print(SEP)

    tp = fp = tn = fn = 0
    results = []
    t_start = time.perf_counter()

    for trace in all_traces:
        if not trace.events:
            continue
        window   = trace.events[-20:]   # last 20 events = one IPG window
        G        = builder.build(window)
        ipg_text = builder.serialize(G)
        t0       = time.perf_counter()
        decision = await classifier.classify(ipg_text)
        lat_ms   = (time.perf_counter() - t0) * 1000

        predicted = decision.label
        gt        = trace.label

        if gt == "MALICIOUS" and predicted == "MALICIOUS":
            tp += 1
        elif gt == "MALICIOUS" and predicted == "BENIGN":
            fn += 1
        elif gt == "BENIGN" and predicted == "MALICIOUS":
            fp += 1
        else:
            tn += 1

        results.append({
            "path":         trace.path,
            "attack_type":  trace.attack_type,
            "label":        gt,
            "predicted":    predicted,
            "confidence":   round(decision.confidence, 4),
            "latency_ms":   round(lat_ms, 3),
            "correct":      gt == predicted,
        })

    elapsed = time.perf_counter() - t_start

    precision = tp / max(tp + fp, 1)
    recall    = tp / max(tp + fn, 1)
    f1        = 2 * precision * recall / max(precision + recall, 1e-9)
    fpr       = fp / max(fp + tn, 1)
    accuracy  = (tp + tn) / max(len(results), 1)

    print(f"\nResults ({len(results)} traces, {elapsed:.1f}s total):")
    print(f"  F1        : {f1:.3f}")
    print(f"  TPR       : {recall:.3f}")
    print(f"  FPR       : {fpr:.3f}")
    print(f"  Precision : {precision:.3f}")
    print(f"  Accuracy  : {accuracy:.3f}")
    print(f"  TP={tp}  FP={fp}  TN={tn}  FN={fn}")

    summary = {
        "dataset":    dataset_path,
        "classifier": clf_name,
        "n_traces":   len(results),
        "n_benign":   n_benign,
        "n_attack":   n_attack,
        "f1":         round(f1, 4),
        "tpr":        round(recall, 4),
        "fpr":        round(fpr, 4),
        "precision":  round(precision, 4),
        "accuracy":   round(accuracy, 4),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "elapsed_s":  round(elapsed, 2),
        "results":    results,
    }

    pathlib.Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nResults → {out_path}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Evaluate SENTINEL on ADFA-LD")
    ap.add_argument("--dataset",    required=True,
                    help="Path to ADFA-LD root directory")
    ap.add_argument("--ollama",     action="store_true",
                    help="Use Ollama llama3.1:8b instead of MockClassifier")
    ap.add_argument("--max-traces", type=int, default=0,
                    help="Max traces to evaluate (0 = all)")
    ap.add_argument("--out",        default=OUT_DEFAULT,
                    help=f"Output JSON path (default: {OUT_DEFAULT})")
    args = ap.parse_args()
    asyncio.run(evaluate(args.dataset, args.ollama, args.max_traces, args.out))


if __name__ == "__main__":
    main()
