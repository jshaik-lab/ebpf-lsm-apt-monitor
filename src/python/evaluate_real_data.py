"""
evaluate_real_data.py — Evaluate SENTINEL on real Linux kernel syscall traces
captured via strace inside Docker.

Methodology:
  1. Each trace is a real strace log from a real Docker Linux VM kernel.
  2. The trace is parsed into KernelEvent objects (same format as simulation).
  3. An IPG is built and serialised to YAML.
  4. Ollama Llama-3.1-8B classifies the IPG.
  5. The label is compared against ground-truth (benign/attack).

This is NOT simulated data — these are actual kernel syscalls intercepted by
strace in the Docker Linux VM. The evaluation measures whether SENTINEL's
IPG + LLM pipeline correctly classifies real (not hand-crafted) process
behaviour patterns.

Run:
    PYTHONPATH=src/python python3 src/python/evaluate_real_data.py
"""
from __future__ import annotations

import asyncio
import glob
import json
import os
import random
import sys
import time

sys.path.insert(0, "src/python")

from sentinel.ipg import IPGBuilder
from sentinel.llm.ollama import OllamaClassifier
from strace_to_events import parse_strace_file

OLLAMA_URL = "http://localhost:11434"
MODEL      = "llama3.1:8b"
TRACE_DIR  = "data/input/real_traces"
OUT_FILE   = "results/evaluations/real_data_results.json"
SEP        = "=" * 70

# Ground-truth labels for each trace file prefix
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


def _load_label_sidecar(scenario: str) -> dict | None:
    """Load ground truth from capture-time .label.json sidecar if present."""
    path = os.path.join(TRACE_DIR, f"{scenario}.label.json")
    if not os.path.isfile(path):
        return None
    with open(path) as f:
        return json.load(f)


def _ground_truth_for(scenario: str) -> str | None:
    sidecar = _load_label_sidecar(scenario)
    if sidecar and sidecar.get("ground_truth"):
        return sidecar["ground_truth"]
    return GROUND_TRUTH.get(scenario)


def _comm_hint_for(scenario: str) -> str:
    sidecar = _load_label_sidecar(scenario)
    if sidecar:
        cmd = sidecar.get("command", "")
        if cmd.startswith("python3"):
            return "python3"
        if cmd.startswith("bash"):
            return "bash"
        tok = cmd.split()[0].split("/")[-1]
        if tok:
            return tok
    return COMM_HINTS.get(scenario, "proc")


def _detect_platform() -> str:
    return os.environ.get(
        "SENTINEL_EVAL_PLATFORM",
        "auto-detect: set SENTINEL_EVAL_PLATFORM for paper table",
    )


async def evaluate_trace(
    path: str,
    scenario: str,
    ground_truth: str,
    classifier: OllamaClassifier,
    builder: IPGBuilder,
) -> dict:
    comm = _comm_hint_for(scenario)
    events = parse_strace_file(path, default_comm=comm)

    if not events:
        return {
            "scenario": scenario,
            "ground_truth": ground_truth,
            "events": 0,
            "label": "SKIP",
            "confidence": 0.0,
            "correct": False,
            "reasoning": "No parseable events in trace",
            "mitre_ttps": [],
            "latency_ms": 0,
        }

    G         = builder.build(events)
    ipg_text  = builder.serialize(G)
    t0        = time.perf_counter()
    decision  = await classifier.classify(ipg_text)
    latency   = (time.perf_counter() - t0) * 1000
    correct   = (decision.label == ground_truth)

    print(f"\n  {'✓' if correct else '✗'} [{scenario}]")
    print(f"    Ground truth: {ground_truth}  →  Got: {decision.label} "
          f"(conf={decision.confidence:.3f})  latency={latency:.0f}ms")
    print(f"    Events: {len(events)}  IPG: {G.number_of_nodes()}n/{G.number_of_edges()}e")
    print(f"    Reasoning: {decision.reasoning}")

    return {
        "scenario":      scenario,
        "ground_truth":  ground_truth,
        "events":        len(events),
        "nodes":         G.number_of_nodes(),
        "edges":         G.number_of_edges(),
        "label":         decision.label,
        "confidence":    round(decision.confidence, 4),
        "correct":       correct,
        "reasoning":     decision.reasoning,
        "mitre_ttps":    decision.mitre_ttps,
        "latency_ms":    round(latency, 1),
        "cot":           decision.chain_of_thought,
    }


async def main() -> None:
    # Health check
    classifier = OllamaClassifier(
        base_url=OLLAMA_URL, model=MODEL, timeout=5, max_retries=1
    )
    if not await classifier.health():
        print(f"ERROR: {MODEL} not available at {OLLAMA_URL}")
        sys.exit(1)

    # Find trace files
    traces = sorted(glob.glob(os.path.join(TRACE_DIR, "*.log")))
    if not traces:
        print(f"ERROR: No .log files in {TRACE_DIR}")
        print(f"Run:  bash src/python/capture_real_traces.sh  first.")
        sys.exit(1)

    print(SEP)
    print("SENTINEL — Real Kernel Syscall Trace Evaluation")
    print(f"Model: {MODEL}  Traces: {len(traces)}")
    print(f"Source: { _detect_platform() }")
    print(f"Capture tool: strace -f -tt -T (actual kernel calls, not simulated)")
    print(SEP)

    builder    = IPGBuilder()
    classifier = OllamaClassifier(
        base_url=OLLAMA_URL, model=MODEL, timeout=90, max_retries=1, tier="full"
    )
    results = []

    for trace_path in traces:
        scenario = os.path.basename(trace_path).replace(".log", "")
        gt = _ground_truth_for(scenario)
        if gt is None:
            print(f"  (skipping unknown scenario: {scenario})")
            continue
        r = await evaluate_trace(trace_path, scenario, gt, classifier, builder)
        results.append(r)

    # ── Summary ────────────────────────────────────────────────────────────────
    print(f"\n{SEP}")
    print("RESULTS SUMMARY")
    print(SEP)

    benign  = [r for r in results if r["ground_truth"] == "BENIGN"  and r["label"] != "SKIP"]
    attacks = [r for r in results if r["ground_truth"] == "MALICIOUS" and r["label"] != "SKIP"]
    skipped = [r for r in results if r["label"] == "SKIP"]

    tp = sum(1 for r in attacks if r["label"] == "MALICIOUS")
    fn = sum(1 for r in attacks if r["label"] == "BENIGN")
    tn = sum(1 for r in benign  if r["label"] == "BENIGN")
    fp = sum(1 for r in benign  if r["label"] == "MALICIOUS")

    tpr = tp / max(tp + fn, 1)
    fpr = fp / max(fp + tn, 1)
    acc = (tp + tn) / max(len(benign) + len(attacks), 1)

    # Bootstrap 95% confidence intervals (n=1000 resamples)
    rng = random.Random(42)
    n_boot = 1000
    boot_tpr, boot_fpr, boot_acc = [], [], []
    combined = [(r, "attack") for r in attacks] + [(r, "benign") for r in benign]
    for _ in range(n_boot):
        sample = [rng.choice(combined) for _ in range(len(combined))]
        s_att  = [r for r, t in sample if t == "attack"]
        s_ben  = [r for r, t in sample if t == "benign"]
        b_tp   = sum(1 for r in s_att if r["label"] == "MALICIOUS")
        b_tn   = sum(1 for r in s_ben if r["label"] == "BENIGN")
        boot_tpr.append(b_tp / max(len(s_att), 1))
        boot_fpr.append((len(s_ben) - b_tn) / max(len(s_ben), 1))
        boot_acc.append((b_tp + b_tn) / max(len(sample), 1))
    boot_tpr.sort(); boot_fpr.sort(); boot_acc.sort()
    ci_lo, ci_hi = int(0.025 * n_boot), int(0.975 * n_boot)
    tpr_ci = (round(boot_tpr[ci_lo], 3), round(boot_tpr[ci_hi], 3))
    fpr_ci = (round(boot_fpr[ci_lo], 3), round(boot_fpr[ci_hi], 3))
    acc_ci = (round(boot_acc[ci_lo], 3), round(boot_acc[ci_hi], 3))

    print(f"\n  Evaluated: {len(results)} traces  ({len(benign)} benign, {len(attacks)} attack)"
          + (f"  Skipped (empty trace): {len(skipped)}" if skipped else ""))
    print(f"\n  Confusion matrix:")
    print(f"    True  Positives (attack→MALICIOUS): {tp}/{len(attacks)}")
    print(f"    False Negatives (attack→BENIGN):    {fn}/{len(attacks)}")
    print(f"    True  Negatives (benign→BENIGN):    {tn}/{len(benign)}")
    print(f"    False Positives (benign→MALICIOUS): {fp}/{len(benign)}")
    print(f"\n  TPR (Recall):  {tpr:.3f}  [95% CI: {tpr_ci[0]:.3f}–{tpr_ci[1]:.3f}]")
    print(f"  FPR:           {fpr:.3f}  [95% CI: {fpr_ci[0]:.3f}–{fpr_ci[1]:.3f}]")
    print(f"  Accuracy:      {acc:.3f}  [95% CI: {acc_ci[0]:.3f}–{acc_ci[1]:.3f}]")
    print(f"  Note: Wide CIs reflect small sample size — expand dataset for tighter bounds.")

    platform = _detect_platform()
    sidecar_modes = set()
    for trace_path in traces:
        sc = os.path.basename(trace_path).replace(".log", "")
        sc_data = _load_label_sidecar(sc)
        if sc_data and sc_data.get("capture_mode"):
            sidecar_modes.add(sc_data["capture_mode"])
    if sidecar_modes:
        platform = f"{platform}; capture_modes={','.join(sorted(sidecar_modes))}"

    if skipped:
        print(f"\n  Skipped (no parseable events):")
        for r in skipped:
            print(f"    {r['scenario']}: {r['reasoning']}")

    print(f"\n  Per-scenario:")
    hdr = f"  {'Scenario':<35} {'GT':<10} {'Label':<10} {'Conf':>6}  {'OK'}"
    print(hdr)
    print("  " + "─" * 70)
    for r in results:
        ok = "✓" if r["correct"] else "✗"
        print(f"  {r['scenario']:<35} {r['ground_truth']:<10} {r['label']:<10} "
              f"{r['confidence']:>6.3f}  {ok}")

    summary = {
        "model":    MODEL,
        "platform": platform,
        "capture":  "strace -f -tt -T (real kernel syscalls)",
        "n_benign":  len(benign),
        "n_attack":  len(attacks),
        "n_skipped": len(skipped),
        "tp": tp, "fn": fn, "tn": tn, "fp": fp,
        "tpr": round(tpr, 4),
        "fpr": round(fpr, 4),
        "accuracy": round(acc, 4),
        "bootstrap_ci_95": {
            "tpr": list(tpr_ci),
            "fpr": list(fpr_ci),
            "accuracy": list(acc_ci),
            "n_resamples": n_boot,
        },
        "results": results,
    }
    import pathlib
    pathlib.Path(OUT_FILE).parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_FILE, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nFull results written to {OUT_FILE}")
    print(f"\nNote: These are REAL kernel syscall traces from Docker Linux VM.")
    print(f"TPR/FPR are measured on real process behavior, not hand-crafted IPGs.")


if __name__ == "__main__":
    asyncio.run(main())
