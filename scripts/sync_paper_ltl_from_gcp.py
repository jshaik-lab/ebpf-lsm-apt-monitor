#!/usr/bin/env python3
"""Patch paper/main.tex LTL FPR paragraph from ltl_fpr_real_gcp.json."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEX = ROOT / "paper" / "main.tex"
LTL = ROOT / "results" / "evaluations_gcp" / "ltl_fpr_real_gcp.json"

OLD_BLOCK = re.compile(
    r"On seven benign strace traces from.*?eval host\.",
    re.DOTALL,
)

OLD_XREF = re.compile(
    r"the LTL FPR subset \(\\S\\ref\{sec:ltl\}, 0/\d+ benign windows on .*?\)",
)


def _ltl_body(j: dict) -> str:
    n_tr = j["n_traces"]
    n_win = j["n_windows"]
    return (
        f"On {n_tr} benign strace traces from \\texttt{{data/input/real\\_traces}} "
        f"present on the GCP VM at eval time, the Symbolic Guardian raises "
        f"\\textbf{{zero violations}} across {n_win} sliding 20-event windows:\n"
        f"FPR\\,$=$\\,{j['fpr']:.3f}, bootstrap 95\\% CI\\,$=$\\,"
        f"[{j['fpr_ci_95'][0]:.3f}, {j['fpr_ci_95'][1]:.3f}]. JSON:\n"
        f"\\texttt{{ltl\\_fpr\\_real\\_gcp.json}}."
    )


def _ltl_xref(j: dict) -> str:
    return (
        f"the LTL FPR subset (\\S\\ref{{sec:ltl}}, 0/{j['n_windows']} benign windows "
        f"on {j['n_traces']} traces in \\texttt{{ltl\\_fpr\\_real\\_gcp.json}})"
    )


def main() -> int:
    if not LTL.is_file():
        print(f"ERROR: missing {LTL}", file=sys.stderr)
        return 2
    j = json.loads(LTL.read_text())
    tex = TEX.read_text()

    body = _ltl_body(j)
    if OLD_BLOCK.search(tex):
        tex = OLD_BLOCK.sub(body, tex, count=1)
    else:
        print("WARN: LTL body block not found — manual update needed", file=sys.stderr)

    xref = _ltl_xref(j)
    if OLD_XREF.search(tex):
        tex = OLD_XREF.sub(xref, tex, count=1)
    else:
        print("WARN: LTL xref not found — manual update needed", file=sys.stderr)

    TEX.write_text(tex)
    print(f"Patched LTL claims: {j['n_traces']} traces, {j['n_windows']} windows, FPR={j['fpr']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
