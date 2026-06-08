#!/usr/bin/env python3
"""Ship gate: paper/main.tex headline claims vs results/evaluations_gcp/*.json.

Exit 0 only when every check passes. Run before PDF submission:
    python3 scripts/validate_paper_claims.py
    make validate-paper-claims
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
TEX = ROOT / "paper" / "main.tex"
GCP = ROOT / "results" / "evaluations_gcp"

REQUIRED_ARTIFACTS = [
    "ipg_token_reduction_gcp.json",
    "dual_tier_reduction_gcp.json",
    "scenario_results_gcp.json",
    "real_data_results_gcp.json",
    "real_data_fpr_breakdown_gcp.json",
    "entropy_sensitivity_gcp.json",
    "ltl_fpr_real_gcp.json",
    "overhead_gcp.json",
    "darpa_tc_behavioral_v4_gcp.json",
    "darpa_tc_behavioral_v5_gcp.json",
    "darpa_tc_v8_ti_aided_gcp.json",
    "darpa_ablation_gcp.json",
    "red_team_results_gcp.json",
    "toctou_race_gcp.json",
    "pcabp_real_nginx_gcp.json",
    "calibration_results_gcp.json",
]

# Stale Mac/IONOS/pilot values that must not reappear in the paper body.
FORBIDDEN_IN_TEX: list[tuple[str, str]] = [
    (r"74\.0\s*\\%", "stale IPG @ n=20 (GCP: 57.5%)"),
    (r"92\.7", "stale IPG full-trace reduction (GCP: 83.3%)"),
    (r"94\.7\s*\\%", "stale dual-tier reduction (GCP: 35.7%)"),
    (r"0\.568", "stale DARPA behavioral F1 (GCP v5: 0.603)"),
    (r"0\.931", "stale TI-aided F1 Mac run (GCP: 0.915)"),
    (r"T1078\) is accepted as \\textsc\{Benign\}",
     "stale dual-tier FN #2 (GCP: Data Exfiltration T1041)"),
    (r"BENIGN@0\.05", "stale EV-10 claim (GCP: MALICIOUS@0.83)"),
]

CHECKS: list[tuple[str, Callable[..., str | None]]] = []


def check(name: str):
    def deco(fn: Callable[..., str | None]):
        CHECKS.append((name, fn))
        return fn

    return deco


def _load(name: str) -> dict[str, Any]:
    return json.loads((GCP / name).read_text())


def _tex() -> str:
    return TEX.read_text()


def _fmt_pct(val: float) -> str:
    return f"{val:.1f}"


def _fmt_metric(val: float, ndigits: int = 3) -> str:
    return f"{val:.{ndigits}f}"


def _json_cite(name: str) -> str:
    """Filename as it appears inside \\texttt{...} in main.tex."""
    return name.replace("_", r"\_")


def _tex_has(tex: str, *fragments: str) -> bool:
    return all(f in tex for f in fragments)


def _require_fragments(tex: str, label: str, fragments: list[str]) -> str | None:
    missing = [f for f in fragments if f not in tex]
    if missing:
        return f"{label}: missing {missing!r}"
    return None


def _require_metric(tex: str, label: str, val: float, ndigits: int = 3) -> str | None:
    s = _fmt_metric(val, ndigits)
    if s not in tex:
        return f"{label}: expected {_fmt_metric(val, ndigits + 1)} (paper rounds to {s})"
    return None


@check("paper/main.tex exists")
def _tex_exists() -> str | None:
    if not TEX.is_file():
        return f"missing {TEX}"
    return None


@check("GCP artifact bundle present")
def _artifacts_present() -> str | None:
    if not GCP.is_dir():
        return f"missing directory {GCP}"
    missing = [n for n in REQUIRED_ARTIFACTS if not (GCP / n).is_file()]
    if missing:
        return f"missing JSONs: {', '.join(missing)}"
    return None


@check("no forbidden stale claims in paper")
def _forbidden() -> str | None:
    tex = _tex()
    hits = [msg for pat, msg in FORBIDDEN_IN_TEX if re.search(pat, tex)]
    if hits:
        return "; ".join(hits)
    return None


@check("IPG compression (57.5% / 83.3%)")
def _ipg() -> str | None:
    j = _load("ipg_token_reduction_gcp.json")
    tex = _tex()
    w20 = j["window_20"]["overall_reduction_pct"]
    full = j["full_trace"]["overall_reduction_pct"]
    err = _require_fragments(
        tex,
        "IPG",
        [
            f"{_fmt_pct(w20)}\\%",
            f"{_fmt_pct(full)}\\%",
            str(int(j["window_20"]["avg_ipg_tokens"])),
            str(int(j["full_trace"]["avg_ipg_tokens"])),
            str(j["n_total_files"]),
        ],
    )
    return err


@check("dual-tier 35.7% + draft FNs")
def _dual_tier() -> str | None:
    j = _load("dual_tier_reduction_gcp.json")
    tex = _tex()
    if abs(j["invocation_reduction_pct"] - 35.7) > 0.05:
        return f"expected 35.7% reduction, got {j['invocation_reduction_pct']}"
    fns = {r["scenario"] for r in j["per_scenario"] if not r["dual_correct"]}
    if fns != {"Lateral Movement", "Data Exfiltration"}:
        return f"unexpected draft FNs: {fns}"
    if "T1041" not in tex or "Data Exfiltration" not in tex:
        return "paper must cite Data Exfiltration (T1041) as draft FN"
    return _require_fragments(tex, "dual-tier", ["35.7", "0.86", "14/14"])


@check("MITRE scenario table (14 rows)")
def _scenarios() -> str | None:
    j = _load("scenario_results_gcp.json")
    tex = _tex()
    rows = j["data"]
    if len(rows) != 14:
        return f"expected 14 scenarios, got {len(rows)}"
    for row in rows:
        conf = _fmt_metric(row["confidence"], 2)
        lat_s = _fmt_metric(row["latency_ms"] / 1000.0, 1)
        label = row["label"]
        if conf not in tex:
            return f"{row['scenario']}: confidence {conf} not in paper"
        if f"{lat_s}\\," not in tex and f"{lat_s} " not in tex:
            return f"{row['scenario']}: latency {lat_s}s not in paper"
        if label == "MALICIOUS" and "ISOLATE" not in tex:
            return "attack scenarios should map to ISOLATE tier in tab:accuracy"
    if "14/14 = 100.0\\%" not in tex:
        return "scenario coverage line must show 14/14 = 100.0%"
    return None


@check("real-data TPR/FPR/Acc")
def _real_data() -> str | None:
    j = _load("real_data_results_gcp.json")
    ent = _load("entropy_sensitivity_gcp.json")
    tex = _tex()
    for label, val in [
        ("TPR", j["tpr"]),
        ("ungated FPR", j["fpr"]),
        ("ungated Acc", j["accuracy"]),
    ]:
        if err := _require_metric(tex, label, val, 3):
            return err
    theta12 = next(r for r in ent["thresholds"] if r["theta_low"] == 1.2)
    for label, val in [
        ("gated FPR", theta12["fpr"]),
        ("gated Acc", theta12["accuracy"]),
    ]:
        if err := _require_metric(tex, label, val, 3):
            return err
    if "0.273" not in tex:
        return "production headline FPR 0.273 missing"
    return None


@check("LTL FPR (7 traces / 13 windows)")
def _ltl() -> str | None:
    j = _load("ltl_fpr_real_gcp.json")
    tex = _tex()
    if j["n_false_positive"] != 0:
        return f"expected 0 LTL FPs, got {j['n_false_positive']}"
    return _require_fragments(
        tex,
        "LTL",
        [
            str(j["n_traces"]),
            str(j["n_windows"]),
            f"0/{j['n_windows']}",
            _json_cite("ltl_fpr_real_gcp.json"),
        ],
    )


@check("DARPA table v4 / v5 / v8")
def _darpa() -> str | None:
    tex = _tex()
    specs = [
        ("v5 hybrid", "darpa_tc_behavioral_v5_gcp.json", "0.603"),
        ("v4 LLM-only", "darpa_tc_behavioral_v4_gcp.json", "0.597"),
        ("v8 TI-aided", "darpa_tc_v8_ti_aided_gcp.json", "0.915"),
    ]
    for label, fname, f1_paper in specs:
        j = _load(fname)
        if _fmt_metric(j["f1"], 3) != f1_paper:
            return f"{label}: JSON F1={j['f1']}, paper cites {f1_paper}"
        row = (
            f"{f1_paper} & {_fmt_metric(j['tpr'], 3)} & "
            f"{_fmt_metric(j['fpr'], 3)} & {_fmt_metric(j['precision'], 3)} & "
            f"{_fmt_metric(j['accuracy'], 3)}"
        )
        if row not in tex:
            return f"{label}: table row fragment missing: {row!r}"
    v4 = _load("darpa_tc_behavioral_v4_gcp.json")["f1"]
    v5 = _load("darpa_tc_behavioral_v5_gcp.json")["f1"]
    if abs(v4 - v5) < 0.001:
        return "v4 and v5 F1 identical — copy-paste risk"
    return None


@check("ablation F1 + latencies")
def _ablation() -> str | None:
    j = _load("darpa_ablation_gcp.json")
    tex = _tex()
    llm = j["llm_only"]
    hybrid = j["hybrid"]
    if llm["mean_latency_ms"] < 1000:
        return (
            f"llm_only mean_latency_ms={llm['mean_latency_ms']} too low "
            "(re-run evaluate_darpa_ablation.py with latency fix)"
        )
    if hybrid["mean_latency_ms"] > 500:
        return f"hybrid mean_latency_ms={hybrid['mean_latency_ms']} too high"
    for mode, f1_paper in [
        ("llm_only", "0.603"),
        ("graph_only", "0.611"),
        ("hybrid", "0.603"),
        ("hybrid_ltl", "0.611"),
        ("full", "0.611"),
    ]:
        if _fmt_metric(j[mode]["f1"], 3) != f1_paper:
            return f"{mode}: JSON F1={j[mode]['f1']}, paper {f1_paper}"
    return _require_fragments(
        tex,
        "ablation latency",
        ["7484\\,", "75\\,", _json_cite("darpa_ablation_gcp.json")],
    )


@check("overhead table")
def _overhead() -> str | None:
    j = _load("overhead_gcp.json")
    tex = _tex()
    ipg = j["ipg_ms"]
    cwae = j["cwae_ms"]
    thr = j["detector_throughput"]["events_per_s"]
    frags = [
        _fmt_metric(ipg["p50"], 3),
        _fmt_metric(ipg["p99"], 3),
        _fmt_metric(cwae["p50"], 3),
        _fmt_metric(cwae["p99"], 3),
        f"{thr:,}".replace(",", "{,}"),
    ]
    return _require_fragments(tex, "overhead", frags)


@check("TOCTOU micro-benchmark")
def _toctou() -> str | None:
    j = _load("toctou_race_gcp.json")
    tex = _tex()
    proxy = j["userspace_proxy"]
    opens = proxy["tracepoint_opens"]
    miss = proxy["tracepoint_miss_rate"] * 100
    return _require_fragments(
        tex,
        "TOCTOU",
        [
            f"{opens:,}".replace(",", "{,}"),
            _fmt_pct(miss),
            _json_cite("toctou_race_gcp.json"),
        ],
    )


@check("red-team 14/15 + EV-10")
def _red_team() -> str | None:
    j = _load("red_team_results_gcp.json")
    tex = _tex()
    if j["n_detected"] != 14 or j["n_evaded"] != 1:
        return f"expected 14 detected / 1 evaded, got {j['n_detected']}/{j['n_evaded']}"
    ev10 = next(r for r in j["results"] if r["scenario"] == "EVASION-10")
    pid = ev10["pids"][0]
    if pid["label"] != "MALICIOUS" or pid["confidence"] < 0.5:
        return f"EV-10 label={pid['label']} conf={pid['confidence']}"
    return _require_fragments(tex, "red-team", ["14/15", "93.3", "0.83"])


@check("PCABP nginx call sites")
def _pcabp() -> str | None:
    j = _load("pcabp_real_nginx_gcp.json")
    tex = _tex()
    n = j["n_call_sites_in_bloom"]
    return _require_fragments(tex, "PCABP", [str(n), _json_cite("pcabp_real_nginx_gcp.json")])


@check("abstract + conclusion headline strings")
def _headlines() -> str | None:
    tex = _tex()
    return _require_fragments(
        tex,
        "headlines",
        [
            "F1\\,$=$\\,0.603",
            "0.597",
            "0.915",
            "57.5\\%",
            "83.3\\%",
            "TPR\\,=\\,0.714",
            "FPR\\,=\\,0.273",
        ],
    )


def main() -> int:
    failed = 0
    for name, fn in CHECKS:
        try:
            err = fn()
        except Exception as exc:  # noqa: BLE001 — gate must surface any crash
            err = str(exc)
        if err:
            print(f"FAIL  {name}: {err}", file=sys.stderr)
            failed += 1
        else:
            print(f"OK    {name}")
    total = len(CHECKS)
    print(f"\n{total - failed}/{total} checks passed")
    if failed:
        print("Paper cannot ship until all checks pass.", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
