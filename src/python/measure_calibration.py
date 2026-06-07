"""
measure_calibration.py — Confidence calibration analysis (ECE + reliability diagram).

Computes Expected Calibration Error (ECE) from saved evaluation results.
A well-calibrated classifier has ECE < 0.05 (events at 0.8 confidence
are correct ~80% of the time). The 1B draft model is known to be poorly
calibrated (PostgreSQL FP at 0.99 conf, T1562 FN at 0.98 conf).

Methodology (Guo et al., ICML 2017):
  - Sort predictions into M=10 equal-width confidence bins [0.0-0.1, ..., 0.9-1.0]
  - For each bin b: acc(b) = fraction correct, conf(b) = mean confidence
  - ECE = Σ (|bin| / N) × |acc(b) - conf(b)|

Outputs:
  - ECE score
  - Reliability diagram data (for TikZ plot in paper)
  - Overconfidence / underconfidence analysis

Input: results/evaluations/real_data_results.json  (from evaluate_real_data.py)

Run:
    PYTHONPATH=src/python python3 src/python/measure_calibration.py
"""
from __future__ import annotations

import json
import math
import pathlib
import sys
from collections import defaultdict
from typing import List

sys.path.insert(0, "src/python")

IN_FILE  = "results/evaluations/real_data_results.json"
OUT_FILE = "results/evaluations/calibration_results.json"
SEP      = "=" * 60
N_BINS   = 10


def _ece(predictions: List[dict], n_bins: int = 10) -> dict:
    """Compute ECE and per-bin statistics."""
    bins: dict[int, list] = defaultdict(list)
    for p in predictions:
        conf  = p["confidence"]
        correct = p["correct"]
        # Map to MALICIOUS-confidence for calibration
        # (for BENIGN, confidence represents certainty of being benign)
        if p["label"] == "BENIGN":
            # Convert to probability of correct prediction
            eff_conf = conf  # already represents P(BENIGN) which is the "right" label if GT is BENIGN
        else:
            eff_conf = conf  # P(MALICIOUS) when label is MALICIOUS
        bin_idx = min(int(eff_conf * n_bins), n_bins - 1)
        bins[bin_idx].append((eff_conf, 1 if correct else 0))

    n_total = len(predictions)
    bin_stats = []
    ece = 0.0

    for b in range(n_bins):
        lo = b / n_bins
        hi = (b + 1) / n_bins
        items = bins.get(b, [])
        n_b   = len(items)
        if n_b == 0:
            bin_stats.append({
                "bin":      b,
                "range":    [round(lo, 2), round(hi, 2)],
                "n":        0,
                "acc":      None,
                "conf":     None,
                "gap":      None,
            })
            continue
        acc_b  = sum(c for _, c in items) / n_b
        conf_b = sum(c for c, _ in items) / n_b
        gap    = abs(acc_b - conf_b)
        ece   += (n_b / n_total) * gap
        bin_stats.append({
            "bin":   b,
            "range": [round(lo, 2), round(hi, 2)],
            "n":     n_b,
            "acc":   round(acc_b, 4),
            "conf":  round(conf_b, 4),
            "gap":   round(gap, 4),
            "overconfident": conf_b > acc_b,
        })

    return {"ece": round(ece, 4), "bins": bin_stats}


def _interpret_ece(ece: float) -> str:
    if ece < 0.05:
        return "WELL-CALIBRATED (ECE < 0.05) — confidence scores are reliable"
    if ece < 0.10:
        return "MODERATELY CALIBRATED (ECE 0.05–0.10) — usable but temperature scaling recommended"
    if ece < 0.20:
        return "POORLY CALIBRATED (ECE 0.10–0.20) — confidence scores are unreliable for thresholding"
    return "SEVERELY MISCALIBRATED (ECE > 0.20) — CWAE thresholds should not rely on raw confidence"


def _tikz_reliability(bin_stats: list[dict]) -> str:
    """Generate TikZ coordinates for reliability diagram."""
    lines = [
        "% Reliability diagram — paste into paper Figure X",
        "% Perfect calibration: \\addplot [dashed] coordinates {(0,0)(1,1)};",
        "\\addplot [blue, mark=*, mark size=2pt] coordinates {",
    ]
    for b in bin_stats:
        if b["n"] > 0:
            mid = (b["range"][0] + b["range"][1]) / 2
            lines.append(f"  ({mid:.2f}, {b['acc']:.4f})  % n={b['n']}, gap={b['gap']:.3f}")
    lines.append("};")
    return "\n".join(lines)


def main() -> None:
    if not pathlib.Path(IN_FILE).exists():
        print(f"ERROR: {IN_FILE} not found.")
        print("Run:  PYTHONPATH=src/python python3 src/python/evaluate_real_data.py  first.")
        sys.exit(1)

    with open(IN_FILE) as f:
        data = json.load(f)

    results = [r for r in data.get("results", []) if r.get("label") not in ("SKIP", None)]

    if len(results) < 5:
        print(f"WARNING: Only {len(results)} non-skipped results — ECE estimate unreliable.")

    print(SEP)
    print("SENTINEL — Confidence Calibration Analysis")
    print(f"Input: {IN_FILE}  ({len(results)} predictions)")
    print(SEP)

    cal = _ece(results, n_bins=N_BINS)
    ece = cal["ece"]

    print(f"\n  ECE (Expected Calibration Error): {ece:.4f}")
    print(f"  Interpretation: {_interpret_ece(ece)}")
    print()
    print(f"  {'Bin':>4}  {'Range':>12}  {'n':>4}  {'Acc':>6}  {'Conf':>6}  {'Gap':>6}  {'Over/Under'}")
    print("  " + "─" * 60)
    for b in cal["bins"]:
        if b["n"] == 0:
            continue
        direction = "OVER" if b["overconfident"] else "under"
        print(f"  {b['bin']:>4}  [{b['range'][0]:.1f}–{b['range'][1]:.1f}]"
              f"  {b['n']:>4}  {b['acc']:>6.3f}  {b['conf']:>6.3f}  {b['gap']:>6.3f}  {direction}")

    # Additional stats
    overconf_count = sum(1 for r in results
                         if r["correct"] == False and r["confidence"] > 0.80)
    print(f"\n  High-confidence errors (conf>0.80, wrong): {overconf_count}/{len(results)}")
    print(f"  These represent the most dangerous miscalibration instances.")

    tikz = _tikz_reliability(cal["bins"])
    print(f"\n  TikZ reliability diagram coordinates:")
    print("  " + "-" * 50)
    for line in tikz.split("\n"):
        print("  " + line)

    output = {
        "input_file":    IN_FILE,
        "n_predictions": len(results),
        "ece":           ece,
        "interpretation": _interpret_ece(ece),
        "n_high_conf_errors": overconf_count,
        "calibration_note": (
            "ECE computed from n=15 traces. This is insufficient for reliable "
            "calibration estimation — need ≥200 predictions for ECE to be "
            "statistically meaningful. Values shown are directional only."
        ),
        "bins": cal["bins"],
        "tikz_reliability_diagram": tikz,
        "recommendation": (
            "If ECE > 0.10: apply temperature scaling (T ≈ 1.3–2.0) "
            "to re-calibrate confidence scores before CWAE thresholding. "
            "Alternatively, learn thresholds from a held-out calibration set."
        ),
    }

    pathlib.Path(OUT_FILE).parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_FILE, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults → {OUT_FILE}")


if __name__ == "__main__":
    main()
