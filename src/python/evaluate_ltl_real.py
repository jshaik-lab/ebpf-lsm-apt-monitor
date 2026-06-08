"""LTL FPR evaluation on real benign strace traces (paper §IV-E).

Replaces the prior "0 FP on 3 synthetic scenarios" claim with a real measurement
over the VPS-captured benign workloads (nginx, sshd, postgres, systemctl,
journalctl, python, ls, etc.). For each benign trace we parse syscall events,
slide a window across the event stream, and run the full SymbolicGuardian
(RuntimeMonitor + BuchiMonitor). Any LTL axiom violation on a benign window is
a false positive — the metric of interest.

Output: results/evaluations/ltl_fpr_real_ionos.json with per-axiom FP counts
and overall FPR plus bootstrap 95% CI.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from sentinel.ltl import SymbolicGuardian
from sentinel.provenance import make_meta
from sentinel.stats import bootstrap_metric
from strace_to_events import parse_strace_file

TRACES_DIR = Path("data/input/real_traces")
OUT_PATH   = Path("results/evaluations/ltl_fpr_real_ionos.json")
WINDOW     = 20  # matches deployed config


def evaluate(trace_dir: Path, window: int, only_benign: bool) -> dict:
    files = sorted(trace_dir.glob("benign_*.log" if only_benign else "*.log"))
    if not files:
        raise SystemExit(f"No traces found under {trace_dir}")

    per_file: list[dict] = []
    # Used to compute bootstrap CI on FPR — each window contributes one outcome.
    # outcomes[i] = (ground_truth_positive=False, predicted_positive=any_violation)
    outcomes: list[tuple[bool, bool]] = []
    axiom_violations: dict[str, int] = {}
    total_windows = 0
    total_events  = 0

    for f in files:
        try:
            events = parse_strace_file(f)
        except Exception as e:
            print(f"  parse error on {f.name}: {e}", file=sys.stderr)
            continue
        if not events:
            continue

        # Slide a window of length WINDOW across the event sequence (stride = WINDOW)
        guardian = SymbolicGuardian()
        file_windows  = 0
        file_violations: list[str] = []
        for start in range(0, len(events), window):
            window_events = events[start : start + window]
            if len(window_events) < 2:
                continue
            file_windows += 1
            total_windows += 1

            # Tier-1: per-event runtime monitor (resets per window for FPR analysis)
            guardian.reset()
            t1_violations = []
            for evt in window_events:
                t1_violations.extend(guardian.feed(evt))
            # Tier-2: Büchi over the full window
            t2_violations = guardian.analyze_window(window_events)

            window_axioms = [v.axiom_id for v in (t1_violations + t2_violations)]
            for axid in window_axioms:
                axiom_violations[axid] = axiom_violations.get(axid, 0) + 1
            file_violations.extend(window_axioms)

            any_violation = bool(window_axioms)
            outcomes.append((False, any_violation))

        total_events += len(events)
        per_file.append({
            "trace":          f.name,
            "events":         len(events),
            "windows":        file_windows,
            "violations":     len(file_violations),
            "axioms_hit":     sorted(set(file_violations)),
        })

    n_fp = sum(1 for _, pred in outcomes if pred)
    fpr  = n_fp / max(len(outcomes), 1)
    fpr_ci = bootstrap_metric(outcomes, "fpr")

    return {
        "task":             "ltl_fpr_real_benign",
        "trace_dir":        str(trace_dir),
        "only_benign":      only_benign,
        "window_size":      window,
        "n_traces":         len(per_file),
        "n_windows":        total_windows,
        "n_events":         total_events,
        "n_false_positive": n_fp,
        "fpr":              round(fpr, 4),
        "fpr_ci_95":        list(fpr_ci),
        "axiom_violations": axiom_violations,
        "per_file":         per_file,
        "meta":             make_meta(),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="SENTINEL LTL FPR on real traces")
    ap.add_argument("--trace-dir",   default=str(TRACES_DIR))
    ap.add_argument("--out",         default=str(OUT_PATH))
    ap.add_argument("--window-size", type=int, default=WINDOW)
    ap.add_argument("--all",         action="store_true",
                    help="Include attack traces too (default: benign only — FPR metric)")
    args = ap.parse_args()

    summary = evaluate(
        Path(args.trace_dir),
        window=args.window_size,
        only_benign=not args.all,
    )
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(summary, indent=2))

    print(f"\nLTL FPR on real benign traces (n_traces={summary['n_traces']}, "
          f"n_windows={summary['n_windows']}):")
    print(f"  FPR              = {summary['fpr']}  (95% CI {summary['fpr_ci_95']})")
    print(f"  False positives  = {summary['n_false_positive']}")
    print(f"  Axiom hits       = {summary['axiom_violations']}")
    print(f"  → {out_path}")


if __name__ == "__main__":
    main()
