"""Measure IPG token reduction vs. raw strace text (Algorithm 1 claim).

Runs on strace-format .log files in data/input/real_traces/, parses events,
builds the IPG, and compares token counts against the raw strace line text
for the same window — which is what an LLM would receive without IPG.

Two measurements are reported:
  window=20 : matches the deployed syscall_window_size=20 configuration
  full_trace: all parsed events (shows maximum deduplication benefit)

Output: results/evaluations/ipg_token_reduction.json

Usage:
    PYTHONPATH=src/python python src/python/measure_ipg_token_reduction.py
    make eval-ipg-tokens
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import tiktoken

sys.path.insert(0, str(Path(__file__).parent))

from sentinel.ipg import IPGBuilder
from strace_to_events import parse_strace_file

_RESULTS_DIR = Path("results/evaluations")
_TRACES_DIR  = Path("data/input/real_traces")
_OUT_FILE    = _RESULTS_DIR / "ipg_token_reduction.json"

# Strace line pattern — same as strace_to_events._LINE
_STRACE_LINE = re.compile(
    r'^\[?(\d+)\]?\s+'
    r'(\d+:\d+:\d+\.\d+)\s+'
    r'(\w+)\s*\(.*\)\s*=\s*(-?\d+|0x[0-9a-f]+)',
    re.DOTALL,
)

WINDOW = 20  # matches config/sentinel.yaml syscall_window_size


def _is_strace_file(path: Path) -> bool:
    """Return True if the first non-empty line is a strace-format line."""
    for line in path.read_text().splitlines():
        line = line.strip()
        if line:
            return bool(_STRACE_LINE.match(line))
    return False


def _raw_strace_lines(path: Path, n: int) -> list[str]:
    """Extract first n strace-format lines from the file."""
    lines = []
    for line in path.read_text().splitlines():
        if _STRACE_LINE.match(line.strip()):
            lines.append(line.strip())
        if len(lines) >= n:
            break
    return lines


def main() -> None:
    _RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    enc     = tiktoken.get_encoding("cl100k_base")
    builder = IPGBuilder()

    all_traces  = sorted(_TRACES_DIR.glob("*.log"))
    strace_only = [p for p in all_traces if _is_strace_file(p)]

    if not strace_only:
        print(f"No strace-format files found in {_TRACES_DIR}. Run: make capture-traces")
        sys.exit(1)

    print(f"Tokenizer: tiktoken cl100k_base")
    print(f"Baseline:  raw strace text (what LLM receives without IPG)")
    print(f"Traces:    {len(strace_only)} strace-format files (of {len(all_traces)} total)")
    print()

    # ── Window=20 measurement ──────────────────────────────────────────────────
    print(f"window={WINDOW}:")
    print(f"  {'File':<35} {'Raw':>6} {'IPG':>6} {'Reduction':>10}")
    print("  " + "-" * 62)

    w20_results   = []
    total_raw_w20 = 0
    total_ipg_w20 = 0

    for p in strace_only:
        raw_lines = _raw_strace_lines(p, WINDOW)
        if not raw_lines:
            continue
        events = parse_strace_file(str(p))[:WINDOW]
        if not events:
            continue

        raw_text  = "\n".join(raw_lines)
        G         = builder.build(events)
        ipg_text  = builder.serialize(G)

        t_raw = enc.encode(raw_text).__len__()
        t_ipg = enc.encode(ipg_text).__len__()
        red   = (1.0 - t_ipg / t_raw) * 100.0 if t_raw else 0.0

        total_raw_w20 += t_raw
        total_ipg_w20 += t_ipg

        label = "BENIGN" if "benign" in p.name else "ATTACK"
        print(f"  {p.name:<35} {t_raw:>6} {t_ipg:>6}  {red:>7.1f}%  [{label}]")

        w20_results.append({
            "file": p.name, "label": label,
            "raw_tokens": t_raw, "ipg_tokens": t_ipg,
            "reduction_pct": round(red, 2),
            "ipg_nodes": G.number_of_nodes(), "ipg_edges": G.number_of_edges(),
        })

    overall_w20 = (1.0 - total_ipg_w20 / total_raw_w20) * 100.0 if total_raw_w20 else 0.0
    avg_raw_w20 = total_raw_w20 / len(w20_results) if w20_results else 0
    avg_ipg_w20 = total_ipg_w20 / len(w20_results) if w20_results else 0

    print("  " + "-" * 62)
    print(f"  {'OVERALL':<35} {total_raw_w20:>6} {total_ipg_w20:>6}  {overall_w20:>7.1f}%")
    print(f"  avg raw={avg_raw_w20:.0f} tokens  avg IPG={avg_ipg_w20:.0f} tokens")
    print()

    # ── Full trace measurement ─────────────────────────────────────────────────
    print("full trace (all parsed events):")
    print(f"  {'File':<35} {'Events':>7} {'Raw':>6} {'IPG':>6} {'Reduction':>10}")
    print("  " + "-" * 70)

    full_results   = []
    total_raw_full = 0
    total_ipg_full = 0

    for p in strace_only:
        raw_lines = [l.strip() for l in p.read_text().splitlines() if _STRACE_LINE.match(l.strip())]
        events    = parse_strace_file(str(p))
        if not events:
            continue

        raw_text  = "\n".join(raw_lines)
        G         = builder.build(events)
        ipg_text  = builder.serialize(G)

        t_raw = enc.encode(raw_text).__len__()
        t_ipg = enc.encode(ipg_text).__len__()
        red   = (1.0 - t_ipg / t_raw) * 100.0 if t_raw else 0.0

        total_raw_full += t_raw
        total_ipg_full += t_ipg

        label = "BENIGN" if "benign" in p.name else "ATTACK"
        print(f"  {p.name:<35} {len(events):>7} {t_raw:>6} {t_ipg:>6}  {red:>7.1f}%")

        full_results.append({
            "file": p.name, "label": label, "events": len(events),
            "raw_tokens": t_raw, "ipg_tokens": t_ipg,
            "reduction_pct": round(red, 2),
        })

    overall_full = (1.0 - total_ipg_full / total_raw_full) * 100.0 if total_raw_full else 0.0
    avg_raw_full = total_raw_full / len(full_results) if full_results else 0
    avg_ipg_full = total_ipg_full / len(full_results) if full_results else 0

    print("  " + "-" * 70)
    print(f"  {'OVERALL':<42} {total_raw_full:>6} {total_ipg_full:>6}  {overall_full:>7.1f}%")
    print(f"  avg raw={avg_raw_full:.0f} tokens  avg IPG={avg_ipg_full:.0f} tokens")
    print()

    # ── Summary ────────────────────────────────────────────────────────────────
    print(f"Summary:")
    print(f"  window={WINDOW} reduction: {overall_w20:.1f}%  (range {min(r['reduction_pct'] for r in w20_results):.1f}–{max(r['reduction_pct'] for r in w20_results):.1f}%)")
    print(f"  full-trace reduction: {overall_full:.1f}%  (range {min(r['reduction_pct'] for r in full_results):.1f}–{max(r['reduction_pct'] for r in full_results):.1f}%)")
    print(f"  prior paper claim: 73.2%  → replace with measured {overall_w20:.1f}% (window={WINDOW})")

    output = {
        "method": "tiktoken cl100k_base vs raw strace line text",
        "n_strace_files": len(strace_only),
        "n_total_files": len(all_traces),
        "window_20": {
            "overall_reduction_pct": round(overall_w20, 2),
            "avg_raw_tokens": round(avg_raw_w20, 1),
            "avg_ipg_tokens": round(avg_ipg_w20, 1),
            "traces": w20_results,
        },
        "full_trace": {
            "overall_reduction_pct": round(overall_full, 2),
            "avg_raw_tokens": round(avg_raw_full, 1),
            "avg_ipg_tokens": round(avg_ipg_full, 1),
            "traces": full_results,
        },
        "paper_claim_pct": 73.2,
        "recommended_claim": f"{overall_w20:.1f}% at window={WINDOW}; {overall_full:.1f}% at full trace",
        "verdict": (
            f"Window={WINDOW} achieves {overall_w20:.1f}% token reduction vs raw strace text "
            f"(range {min(r['reduction_pct'] for r in w20_results):.1f}–{max(r['reduction_pct'] for r in w20_results):.1f}%). "
            f"Full-trace achieves {overall_full:.1f}%. "
            "Prior claim of 73.2% was not empirically measured. "
            "Reduction grows with window size as deduplication amortises YAML header overhead."
        ),
    }
    _OUT_FILE.write_text(json.dumps(output, indent=2))
    print(f"\n  Results → {_OUT_FILE}")


if __name__ == "__main__":
    main()
