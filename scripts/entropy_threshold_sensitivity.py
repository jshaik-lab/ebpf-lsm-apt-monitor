#!/usr/bin/env python3
"""Entropy threshold sensitivity on real strace corpus (gate-skip analysis).

For each theta_low, traces whose max window Shannon entropy stays below the
threshold are classified BENIGN without LLM; others use the stored LLM label
from a prior real_data_results JSON.

Usage:
  PYTHONPATH=src/python python3 scripts/entropy_threshold_sensitivity.py \\
    --traces data/input/real_traces \\
    --labels results/evaluations_gcp/real_data_results_gcp.json \\
    --out results/evaluations_gcp/entropy_sensitivity_gcp.json
"""
from __future__ import annotations

import argparse
import glob
import json
import math
import os
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, "src/python")

from sentinel.provenance import make_meta, require_gcp_eval
from strace_to_events import parse_strace_file

WINDOW = 20
SC_TYPES = 16
THRESHOLDS = [0.8, 1.0, 1.2, 1.5, 2.0]


def shannon_bits(events) -> float:
    counts: dict[int, int] = defaultdict(int)
    for e in events:
        counts[e.sc_type] += 1
    total = sum(counts.values())
    if total == 0:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in counts.values() if c > 0)


def max_window_entropy(events) -> float:
    if len(events) <= WINDOW:
        return shannon_bits(events)
    best = 0.0
    for i in range(0, len(events) - WINDOW + 1):
        best = max(best, shannon_bits(events[i : i + WINDOW]))
    return best


def metrics(rows: list[dict]) -> dict:
    tp = fn = tn = fp = 0
    for r in rows:
        gt, pred = r["ground_truth"], r["predicted"]
        if gt == "MALICIOUS" and pred == "MALICIOUS":
            tp += 1
        elif gt == "MALICIOUS" and pred != "MALICIOUS":
            fn += 1
        elif gt == "BENIGN" and pred == "MALICIOUS":
            fp += 1
        elif gt == "BENIGN" and pred == "BENIGN":
            tn += 1
    n = tp + fn + tn + fp
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    acc = (tp + tn) / n if n else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {
        "tp": tp, "fn": fn, "tn": tn, "fp": fp,
        "f1": round(f1, 4),
        "tpr": round(rec, 4),
        "fpr": round(fpr, 4),
        "accuracy": round(acc, 4),
        "gate_skipped": sum(1 for r in rows if r.get("gate_skipped")),
    }


def main() -> None:
    require_gcp_eval("entropy threshold sensitivity (evaluations_gcp)")
    ap = argparse.ArgumentParser()
    ap.add_argument("--traces", default="data/input/real_traces")
    ap.add_argument("--labels", required=True)
    ap.add_argument("--out", default="results/evaluations_gcp/entropy_sensitivity_gcp.json")
    ap.add_argument("--thresholds", default=",".join(str(t) for t in THRESHOLDS))
    args = ap.parse_args()

    label_data = json.loads(Path(args.labels).read_text())
    label_by_scenario = {r["scenario"]: r for r in label_data.get("results", [])}

    trace_files = sorted(
        glob.glob(os.path.join(args.traces, "*.log"))
        + glob.glob(os.path.join(args.traces, "*.strace"))
    )
    entropy_by_scenario: dict[str, float] = {}
    for path in trace_files:
        base = os.path.basename(path)
        for ext in (".log", ".strace"):
            if base.endswith(ext):
                base = base[: -len(ext)]
                break
        events = parse_strace_file(path, default_comm="proc")
        if events:
            entropy_by_scenario[base] = max_window_entropy(events)

    thresholds = [float(x) for x in args.thresholds.split(",")]
    sweep = []
    for theta in thresholds:
        rows = []
        for scenario, llm_row in label_by_scenario.items():
            gt = llm_row.get("ground_truth")
            if not gt or llm_row.get("label") == "SKIP":
                continue
            H = entropy_by_scenario.get(scenario, 999.0)
            if H < theta:
                predicted = "BENIGN"
                gate_skipped = True
            else:
                predicted = llm_row.get("label", "BENIGN")
                gate_skipped = False
            rows.append({
                "scenario": scenario,
                "ground_truth": gt,
                "predicted": predicted,
                "max_window_entropy": round(H, 4),
                "gate_skipped": gate_skipped,
            })
        sweep.append({"theta_low": theta, **metrics(rows)})

    out_doc = {
        "method": "max-window Shannon entropy gate; skipped traces → BENIGN",
        "window_size": WINDOW,
        "n_scenarios": len(label_by_scenario),
        "baseline_theta_low": 1.2,
        "thresholds": sweep,
        "meta": make_meta(extra={"analysis": "entropy_threshold_sensitivity"}),
        "note": (
            "Uses stored LLM labels for non-skipped traces from real_data_results. "
            "Shows FPR/TPR trade-off of entropy gate without re-invoking Ollama."
        ),
    }

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(out_doc, indent=2))
    print(f"Entropy sensitivity → {out}")
    for row in sweep:
        print(f"  θ_low={row['theta_low']:.1f}  F1={row['f1']}  FPR={row['fpr']}  "
              f"TPR={row['tpr']}  skipped={row['gate_skipped']}")


if __name__ == "__main__":
    main()
