"""
evaluate_baselines.py — Baseline comparison for Table III (Section V-D).

Runs three classifiers on the same 15 real strace traces:
  1. FalcoRulesClassifier   — rule-based, ~0.1 ms, no ML
  2. NGramLRClassifier      — syscall n-gram + LogisticRegression, ~5 ms
  3. SENTINEL MockClassifier — IPG + heuristic mock (no Ollama required)

All classifiers receive the same parsed KernelEvent objects. SENTINEL mock
is used here so the comparison can run without Ollama. Replace with
OllamaClassifier for the final paper numbers.

Run:
    PYTHONPATH=src/python python3 src/python/evaluate_baselines.py
"""
from __future__ import annotations

import asyncio
import glob
import json
import os
import sys
import time

sys.path.insert(0, "src/python")

from sentinel.baselines.falco_rules import FalcoRulesClassifier
from sentinel.baselines.ngram_lr import NGramLRClassifier
from sentinel.cove import CoVeLoop
from sentinel.ipg import IPGBuilder
from sentinel.llm.mock import MockClassifier
from sentinel.ltl import SymbolicGuardian, explainability_score
from strace_to_events import parse_strace_file

TRACE_DIR = "data/input/real_traces"
OUT_FILE  = "results/evaluations/baseline_comparison.json"
SEP = "=" * 72

GROUND_TRUTH = {
    "benign_cat_hostname":      "BENIGN",
    "benign_ls_usr":            "BENIGN",
    "benign_python_json":       "BENIGN",
    "benign_find_libs":         "BENIGN",
    "benign_cat_os_release":    "BENIGN",
    "benign_python_math":       "BENIGN",
    "benign_which_bash":        "BENIGN",
    "attack_T1003_shadow":      "MALICIOUS",
    "attack_T1003_T1071":       "MALICIOUS",
    "attack_T1059_scripted":    "MALICIOUS",
    "attack_T1068_setuid":      "MALICIOUS",
    "attack_T1055_ptrace":      "MALICIOUS",
    "attack_T1041_exfil":       "MALICIOUS",
    "attack_T1562_evasion":     "MALICIOUS",
    "attack_T1078_valid_accts": "MALICIOUS",
}

COMM_HINTS = {
    "benign_cat_hostname":      "cat",
    "benign_ls_usr":            "ls",
    "benign_python_json":       "python3",
    "benign_find_libs":         "find",
    "benign_cat_os_release":    "cat",
    "benign_python_math":       "python3",
    "benign_which_bash":        "which",
    "attack_T1003_shadow":      "bash",
    "attack_T1003_T1071":       "bash",
    "attack_T1059_scripted":    "bash",
    "attack_T1068_setuid":      "bash",
    "attack_T1055_ptrace":      "bash",
    "attack_T1041_exfil":       "bash",
    "attack_T1562_evasion":     "bash",
    "attack_T1078_valid_accts": "bash",
}


def _metrics(results: list[dict], classifier_key: str) -> dict:
    valid = [r for r in results if r["events"] > 0]
    benign  = [r for r in valid if r["ground_truth"] == "BENIGN"]
    attacks = [r for r in valid if r["ground_truth"] == "MALICIOUS"]
    tp = sum(1 for r in attacks if r[classifier_key]["label"] == "MALICIOUS")
    fn = sum(1 for r in attacks if r[classifier_key]["label"] == "BENIGN")
    tn = sum(1 for r in benign  if r[classifier_key]["label"] == "BENIGN")
    fp = sum(1 for r in benign  if r[classifier_key]["label"] == "MALICIOUS")
    tpr = tp / max(tp + fn, 1)
    fpr = fp / max(fp + tn, 1)
    acc = (tp + tn) / max(len(valid), 1)
    latencies = [r[classifier_key]["latency_ms"] for r in valid]
    avg_lat = sum(latencies) / len(latencies) if latencies else 0.0
    # Explainability Score: only SENTINEL has verifiable logic proof chains
    es_scores = [r[classifier_key].get("explainability_score", 0.0)
                 for r in valid if r[classifier_key]]
    avg_es = sum(es_scores) / len(es_scores) if es_scores else 0.0
    return dict(tp=tp, fn=fn, tn=tn, fp=fp,
                tpr=round(tpr, 4), fpr=round(fpr, 4),
                accuracy=round(acc, 4),
                avg_latency_ms=round(avg_lat, 3),
                explainability_score=round(avg_es, 4))


async def main() -> None:
    traces = sorted(glob.glob(os.path.join(TRACE_DIR, "*.log")))
    if not traces:
        print(f"ERROR: No .log files in {TRACE_DIR}")
        print("Run:  make capture-traces  first.")
        sys.exit(1)

    falco    = FalcoRulesClassifier()
    ngram_lr = NGramLRClassifier()
    ngram_lr.train()
    sentinel_mock = MockClassifier(tier="draft")
    builder       = IPGBuilder()
    cove_loop     = CoVeLoop(max_grounding_iterations=1)
    guardian      = SymbolicGuardian()

    print(SEP)
    print("SENTINEL — Baseline Comparison (Table III)")
    print(f"Traces: {len([t for t in traces if os.path.basename(t).replace('.log','') in GROUND_TRUTH])}")
    print(f"Classifiers: Falco-rules  |  N-gram LR  |  SENTINEL (mock)")
    print(f"Metrics: TPR, FPR, Accuracy, Avg latency, Explainability Score (ES)")
    print(SEP)

    results = []
    for trace_path in traces:
        scenario = os.path.basename(trace_path).replace(".log", "")
        gt = GROUND_TRUTH.get(scenario)
        if gt is None:
            continue

        comm   = COMM_HINTS.get(scenario, "proc")
        events = parse_strace_file(trace_path, default_comm=comm)

        if not events:
            results.append({"scenario": scenario, "ground_truth": gt, "events": 0,
                             "falco": {}, "ngram_lr": {}, "sentinel_mock": {}})
            continue

        # Falco (sync) — no verifiable logic proof, ES=0
        t0 = time.perf_counter()
        f_dec = falco.classify(events)
        f_lat = (time.perf_counter() - t0) * 1000

        # N-gram LR (sync) — statistical, no logic proof, ES=0
        t0 = time.perf_counter()
        n_dec = ngram_lr.classify(events)
        n_lat = (time.perf_counter() - t0) * 1000

        # SENTINEL mock (async) — uses IPG encoding + CoVe grounding + LTL guardian
        G         = builder.build(events)
        ipg_text  = builder.serialize(G)
        t0        = time.perf_counter()
        s_dec     = await sentinel_mock.classify(ipg_text)
        s_lat     = (time.perf_counter() - t0) * 1000

        # CoVe grounding: verify evidence_refs against actual events
        cove_report = cove_loop.run(s_dec, events, pid=events[0].pid, comm=comm)
        # LTL Büchi post-hoc analysis of window
        ltl_violations = guardian.analyze_window(events)
        from sentinel.evidence import EvidenceReport as _ER
        ev_report = _ER(
            total_claims=max(len(s_dec.evidence_refs or []), 1),
            verified_claims=len(cove_report.verified_claims),
            unverified_claims=len(cove_report.retracted_claims),
            hallucination_rate=cove_report.hallucination_rate,
            verified_confidence=cove_report.final_confidence,
            verdict="CLEAN" if cove_report.hallucination_rate == 0 else "PARTIAL",
        )
        es = explainability_score(ltl_violations, ev_report, total_events=len(events))

        row = {
            "scenario":     scenario,
            "ground_truth": gt,
            "events":       len(events),
            "falco": {
                "label":               f_dec.label,
                "confidence":          round(f_dec.confidence, 4),
                "correct":             f_dec.label == gt,
                "latency_ms":          round(f_lat, 3),
                "explainability_score": 0.0,  # no verifiable logic proof
            },
            "ngram_lr": {
                "label":               n_dec.label,
                "confidence":          round(n_dec.confidence, 4),
                "correct":             n_dec.label == gt,
                "latency_ms":          round(n_lat, 3),
                "explainability_score": 0.0,  # statistical model, no proof chain
            },
            "sentinel_mock": {
                "label":               s_dec.label,
                "confidence":          round(s_dec.confidence, 4),
                "correct":             s_dec.label == gt,
                "latency_ms":          round(s_lat, 3),
                "mitre_ttps":          s_dec.mitre_ttps,
                "cove_hal_rate":       round(cove_report.hallucination_rate, 4),
                "ltl_violations":      len(ltl_violations),
                "explainability_score": round(es, 4),
            },
        }
        results.append(row)

        f_ok = "✓" if f_dec.label == gt else "✗"
        n_ok = "✓" if n_dec.label == gt else "✗"
        s_ok = "✓" if s_dec.label == gt else "✗"
        print(f"  {scenario:<35}  Falco:{f_ok}  N-gram:{n_ok}  SENTINEL:{s_ok}  ES={es:.3f}")

    # Summary table
    print(f"\n{SEP}")
    print(f"{'Classifier':<20} {'TPR':>6} {'FPR':>6} {'Accuracy':>9} {'Latency':>10} {'ES':>7}")
    print("─" * 68)
    for key, name in [("falco", "Falco-rules"), ("ngram_lr", "N-gram LR"),
                       ("sentinel_mock", "SENTINEL (mock)")]:
        m = _metrics(results, key)
        print(f"  {name:<18} {m['tpr']:>6.3f} {m['fpr']:>6.3f} {m['accuracy']:>9.3f} "
              f"{m['avg_latency_ms']:>7.3f} ms  {m['explainability_score']:>6.3f}")

    print(f"""
Explainability Score (ES) interpretation:
  ES = 0.0 — no verifiable logic proof (Falco rules, N-gram statistics)
  ES > 0.0 — SENTINEL: CoVe-verified evidence chain + LTL axiom coverage
  ES = 1.0 — all claims verified + at least one LTL axiom fired
  Falco and N-gram baselines always ES=0: opaque rules or black-box weights.
  SENTINEL ES > 0 even for BENIGN (LTL all-clear is itself a proof).""")

    from sentinel.simulation import SCENARIOS as _SCEN
    print(f"\nNote: SENTINEL (mock) uses heuristic classifier, not Ollama.")
    print(f"      Replace with OllamaClassifier for final paper numbers.")
    print(f"      N-gram LR trained on {len(_SCEN)} simulation scenarios (synthetic), "
          f"tested on real traces.")

    summary = {
        "n_traces": len([r for r in results if r["events"] > 0]),
        "falco":    _metrics(results, "falco"),
        "ngram_lr": _metrics(results, "ngram_lr"),
        "sentinel_mock": _metrics(results, "sentinel_mock"),
        "results":  results,
        "note": (
            "NGram-LR trained on 14 simulation scenarios, tested on 15 real traces. "
            "SENTINEL uses mock classifier (no Ollama). Replace with Ollama for paper. "
            "ES (Explainability Score) = CoVe-verified evidence ratio × LTL coverage. "
            "Falco and N-gram always ES=0 (no verifiable proof chain)."
        ),
    }

    import pathlib
    pathlib.Path(OUT_FILE).parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_FILE, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nResults → {OUT_FILE}")


if __name__ == "__main__":
    asyncio.run(main())
