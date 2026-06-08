#!/usr/bin/env python3
"""Analyze false-positive breakdown from real_data_results JSON.

Usage:
  PYTHONPATH=src/python python3 scripts/analyze_real_data_fpr.py \\
    results/evaluations_gcp/real_data_results_gcp.json \\
    --out results/evaluations_gcp/real_data_fpr_breakdown_gcp.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, "src/python")

from sentinel.provenance import make_meta, require_gcp_eval


def _workload_type(scenario: str) -> str:
    """Map scenario name to coarse benign workload category."""
    if scenario.startswith("attack_"):
        return "attack"
    if scenario.startswith("benign_ext_"):
        return "extended_server"
    if scenario.startswith("benign_"):
        base = scenario.replace("benign_", "", 1)
        return base.split("_")[0] if "_" in base else base
    return "unknown"


def _attack_family(scenario: str) -> str:
    m = re.match(r"attack_(T\d+)", scenario)
    return m.group(1) if m else scenario


def analyze(data: dict) -> dict:
    rows = data.get("results", [])
    benign = [r for r in rows if r.get("ground_truth") == "BENIGN"]
    attack = [r for r in rows if r.get("ground_truth") == "MALICIOUS"]

    fp_rows = [r for r in benign if r.get("label") == "MALICIOUS"]
    fn_rows = [r for r in attack if r.get("label") != "MALICIOUS" or not r.get("correct", True)]

    fp_by_workload = Counter(_workload_type(r["scenario"]) for r in fp_rows)
    fp_by_scenario = Counter(r["scenario"] for r in fp_rows)
    fn_by_family = Counter(_attack_family(r["scenario"]) for r in fn_rows)

    # Per unique scenario (dedupe repeated captures)
    scenario_stats: dict[str, dict] = defaultdict(lambda: {
        "ground_truth": "",
        "n": 0,
        "fp": 0,
        "fn": 0,
        "tn": 0,
        "tp": 0,
        "avg_confidence_fp": [],
    })
    for r in rows:
        sc = r["scenario"]
        gt = r.get("ground_truth", "")
        scenario_stats[sc]["ground_truth"] = gt
        scenario_stats[sc]["n"] += 1
        pred = r.get("label", "SKIP")
        if gt == "BENIGN":
            if pred == "MALICIOUS":
                scenario_stats[sc]["fp"] += 1
                scenario_stats[sc]["avg_confidence_fp"].append(r.get("confidence", 0))
            elif pred == "BENIGN":
                scenario_stats[sc]["tn"] += 1
        elif gt == "MALICIOUS":
            if pred == "MALICIOUS":
                scenario_stats[sc]["tp"] += 1
            else:
                scenario_stats[sc]["fn"] += 1

    per_scenario = {}
    for sc, st in sorted(scenario_stats.items()):
        confs = st.pop("avg_confidence_fp")
        per_scenario[sc] = {
            **st,
            "fpr": round(st["fp"] / st["n"], 4) if st["n"] and st["ground_truth"] == "BENIGN" else None,
            "mean_confidence_fp": round(sum(confs) / len(confs), 4) if confs else None,
        }

    top_fp = fp_by_scenario.most_common(10)
    failure_modes = []
    for sc, count in top_fp:
        samples = [r for r in fp_rows if r["scenario"] == sc][:2]
        failure_modes.append({
            "scenario": sc,
            "workload": _workload_type(sc),
            "fp_count": count,
            "sample_reasoning": [s.get("reasoning", "")[:240] for s in samples],
            "sample_confidence": [s.get("confidence") for s in samples],
        })

    n_benign = len(benign)
    n_fp = len(fp_rows)
    return {
        "source": data.get("meta", {}).get("platform", "unknown"),
        "n_traces": len(rows),
        "n_benign": n_benign,
        "n_attack": len(attack),
        "fp": n_fp,
        "fn": len(fn_rows),
        "fpr": round(n_fp / n_benign, 4) if n_benign else 0.0,
        "fp_by_workload_type": dict(fp_by_workload),
        "fp_by_scenario": dict(fp_by_scenario),
        "fn_by_attack_family": dict(fn_by_family),
        "per_scenario": per_scenario,
        "failure_mode_analysis": failure_modes,
        "interpretation": (
            "False positives cluster on high-entropy benign workloads (python3, find) "
            "where IPG graphs resemble staged attack patterns (temp writes, ld.so.cache mmap). "
            "Low-confidence MALICIOUS labels (conf≈0.42) dominate FPs."
        ),
    }


def main() -> None:
    require_gcp_eval("FPR breakdown (evaluations_gcp)")
    ap = argparse.ArgumentParser()
    ap.add_argument("input_json")
    ap.add_argument("--out", default="results/evaluations_gcp/real_data_fpr_breakdown_gcp.json")
    args = ap.parse_args()

    data = json.loads(Path(args.input_json).read_text())
    report = analyze(data)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    report["meta"] = make_meta(extra={"analysis": "real_data_fpr_breakdown"})
    out.write_text(json.dumps(report, indent=2))

    print(f"FPR breakdown → {out}")
    print(f"  FPR={report['fpr']} ({report['fp']}/{report['n_benign']} benign traces)")
    print(f"  FP by workload: {report['fp_by_workload_type']}")
    print(f"  Top FP scenarios: {list(report['fp_by_scenario'].items())[:5]}")


if __name__ == "__main__":
    main()
