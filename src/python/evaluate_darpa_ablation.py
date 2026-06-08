"""5-mode Ablation study on DARPA TC E3.

Modes:
  1. llm_only:    Bypass pre-filter/thresholds, always call LLM.
  2. graph_only:  Only use graph score threshold (no LLM, no LTL, no PCABP).
  3. hybrid:      Graph threshold high/low + gray-zone LLM.
  4. hybrid_ltl:  Hybrid + LTL Symbolic Guardian.
  5. full:        Hybrid + LTL + PCABP (0.0) + CoVe Cap (Algorithm 4).

Usage:
    PYTHONPATH=src/python python3 src/python/evaluate_darpa_ablation.py \
      --dataset cadets --max-windows 100 \
      --strip-annotations --hard-fraction 0.5 \
      --darpa-path data/darpa/ta1-cadets-e3-official.json.2 \
      --out results/evaluations/darpa_ablation.json
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from evaluate_darpa_tc import (
    CDM18Parser,
    build_labeled_windows,
    _strip_annotations,
    CADETS_ATTACK_WINDOWS,
    THEIA_ATTACK_WINDOWS,
    CADETS_ATTACK_COMMS,
    THEIA_ATTACK_COMMS,
    CADETS_PATH,
    THEIA_PATH,
    FREEBSD_CONTEXT,
    CADETS_FEW_SHOT_BEHAVIORAL,
)
from sentinel.ipg import IPGBuilder
from sentinel.provenance_ml import provenance_score, fuse_scores
from sentinel.ltl import SymbolicGuardian
from sentinel.cove import CoVeLoop
from sentinel.llm.ollama import OllamaClassifier
from sentinel.models import ThreatDecision
from sentinel.config import SentinelConfig

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)-8s] %(message)s")
logger = logging.getLogger("darpa_ablation")


@dataclass
class ModeMetrics:
    mode_name: str
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    llm_invocations: int = 0
    total_latency_ms: float = 0.0


async def main() -> None:
    ap = argparse.ArgumentParser(description="SENTINEL DARPA TC Ablation Study")
    ap.add_argument("--dataset",           choices=["cadets", "theia"], default="cadets")
    ap.add_argument("--max-windows",       type=int,   default=100)
    ap.add_argument("--window-size",       type=int,   default=20)
    ap.add_argument("--darpa-path",        default="")
    ap.add_argument("--out",               default="")
    ap.add_argument("--strip-annotations", action="store_true", default=True)
    ap.add_argument("--hard-fraction",     type=float, default=0.5)
    args = ap.parse_args()

    if args.dataset == "cadets":
        data_path    = Path(args.darpa_path) if args.darpa_path else CADETS_PATH
        attack_wins  = CADETS_ATTACK_WINDOWS
        out_path     = Path(args.out) if args.out else Path(
            "results/evaluations/darpa_ablation.json")
    else:
        data_path    = Path(args.darpa_path) if args.darpa_path else THEIA_PATH
        attack_wins  = THEIA_ATTACK_WINDOWS
        out_path     = Path(args.out) if args.out else Path(
            "results/evaluations/theia_ablation.json")

    if not data_path.exists():
        logger.error("Dataset file not found: %s", data_path)
        sys.exit(1)

    config = SentinelConfig.from_yaml(
        Path(__file__).parent.parent.parent / "config" / "sentinel.yaml"
    )

    classifier = OllamaClassifier(
        base_url=config.llm.ollama_url,
        model=config.llm.full_model,
        timeout=config.llm.timeout_seconds,
        max_retries=config.llm.max_retries,
        tier="full",
        extra_context=FREEBSD_CONTEXT,
        extra_examples=CADETS_FEW_SHOT_BEHAVIORAL,
    )

    ipg_builder = IPGBuilder()
    cove_loop = CoVeLoop(max_grounding_iterations=0)
    guardian = SymbolicGuardian()

    attack_comms = CADETS_ATTACK_COMMS if args.dataset == "cadets" else THEIA_ATTACK_COMMS
    n_attack = args.max_windows // 2
    n_benign = args.max_windows // 2

    logger.info("Dataset: %s (%s)", args.dataset.upper(), data_path.name)
    parser  = CDM18Parser()
    windows = build_labeled_windows(
        parser.stream(data_path),
        attack_windows=attack_wins,
        window_size=args.window_size,
        max_attack=n_attack,
        max_benign=n_benign,
        attack_comms=attack_comms,
        hard_fraction=args.hard_fraction,
    )

    if not windows:
        logger.error("No windows built.")
        sys.exit(1)

    # Load cached decisions if available to speed up execution
    cached_results = None
    for cache_path in [
        Path("/home/sentinel/Paper1_ZeroTrustAgent/results/evaluations/darpa_tc_behavioral_v4_test_n100.json"),
        Path("/Users/jshaik/projects/EB1A/IEEETechnicalPapers/Paper1_ZeroTrustAgent/results/evaluations_gcp/darpa_tc_behavioral_v5_gcp.json"),
        Path("results/evaluations/darpa_tc_behavioral_v4_test_n100.json")
    ]:
        if cache_path.exists():
            try:
                with open(cache_path) as f:
                    cached_results = json.load(f).get("results", [])
                    logger.info("Loaded %d cached LLM decisions from %s", len(cached_results), cache_path.name)
                    break
            except Exception as e:
                logger.warning("Failed to load cache %s: %s", cache_path, e)

    # Instantiate metrics for the 5 modes
    modes = {
        "llm_only":   ModeMetrics("llm_only"),
        "graph_only": ModeMetrics("graph_only"),
        "hybrid":     ModeMetrics("hybrid"),
        "hybrid_ltl": ModeMetrics("hybrid_ltl"),
        "full":       ModeMetrics("full"),
    }

    logger.info("Evaluating %d windows in 5 modes...", len(windows))
    records = []

    for idx, w in enumerate(windows):
        G        = ipg_builder.build(w.events)
        meta     = ipg_builder.analyze(G)
        ipg_text = ipg_builder.serialize(G, meta)

        if args.strip_annotations:
            ipg_text = _strip_annotations(ipg_text)

        graph_score = provenance_score(meta, G)

        # Pre-run Symbolic Guardian (LTL)
        violations = guardian.analyze_window(w.events)
        _SEV_MAP = {"CRITICAL": 0.95, "HIGH": 0.85, "MEDIUM": 0.65}
        ltl_severity = max(_SEV_MAP.get(v.severity, 0.0) for v in violations) if violations else 0.0

        # LLM decisions (minimizing calls via shared cache)
        llm_decision = None
        llm_elapsed = 0.0
        cove_report_hal_rate = None

        if cached_results and idx < len(cached_results) and cached_results[idx].get("pid") == w.pid:
            c_res = cached_results[idx]
            llm_decision = ThreatDecision(
                label=c_res.get("pred", "BENIGN"),
                confidence=c_res.get("confidence", 0.5),
                reasoning="Cached decision",
                mitre_ttps=c_res.get("mitre_ttps", []),
                chain_of_thought="Cached from previous run.",
                model_used="llama3.1:8b",
                latency_ms=0.0,
            )
            cove_report_hal_rate = c_res.get("cove_hal_rate", 0.0)
            raw_lat = float(c_res.get("latency_ms") or 0.0)
            default_lat = float(os.environ.get("SENTINEL_DEFAULT_LLM_LATENCY_MS", "7484"))
            llm_elapsed = raw_lat if raw_lat > 100.0 else default_lat
        else:
            t_start = time.perf_counter()
            llm_decision = await classifier.classify(ipg_text)
            llm_elapsed = (time.perf_counter() - t_start) * 1000

        # Pre-run CoVe verification (very fast verify-only)
        comm = w.events[0].comm if w.events else ""
        cove_report = cove_loop.run(llm_decision, w.events, pid=w.pid, comm=comm)
        if cove_report_hal_rate is not None:
            cove_report.hallucination_rate = cove_report_hal_rate

        # ----------------------------------------------------------------------
        # Mode 1: LLM-only
        # ----------------------------------------------------------------------
        m = modes["llm_only"]
        m.llm_invocations += 1
        m.total_latency_ms += llm_elapsed
        pred_attack = llm_decision.label == "MALICIOUS"
        if pred_attack == w.is_attack:
            if w.is_attack: m.tp += 1
            else: m.tn += 1
        else:
            if w.is_attack: m.fn += 1
            else: m.fp += 1

        # ----------------------------------------------------------------------
        # Mode 2: Graph-only
        # ----------------------------------------------------------------------
        m = modes["graph_only"]
        pred_attack = graph_score >= 0.50
        if pred_attack == w.is_attack:
            if w.is_attack: m.tp += 1
            else: m.tn += 1
        else:
            if w.is_attack: m.fn += 1
            else: m.fp += 1

        # ----------------------------------------------------------------------
        # Mode 3: Hybrid (Graph + LLM gray zone)
        # ----------------------------------------------------------------------
        m = modes["hybrid"]
        if graph_score >= 0.55:
            hybrid_label = "MALICIOUS"
            m.total_latency_ms += 0.0
        elif graph_score <= 0.15:
            hybrid_label = "BENIGN"
            m.total_latency_ms += 0.0
        else:
            hybrid_label = llm_decision.label
            m.llm_invocations += 1
            m.total_latency_ms += llm_elapsed

        pred_attack = hybrid_label == "MALICIOUS"
        if pred_attack == w.is_attack:
            if w.is_attack: m.tp += 1
            else: m.tn += 1
        else:
            if w.is_attack: m.fn += 1
            else: m.fp += 1

        # Save hybrid decision for fusion downstream
        hybrid_decision = ThreatDecision(
            label=hybrid_label,
            confidence=graph_score if hybrid_label == "MALICIOUS" else 1.0 - graph_score,
            reasoning="Hybrid decision",
            mitre_ttps=[],
            chain_of_thought="",
            model_used="hybrid",
            latency_ms=0.0,
        )

        # ----------------------------------------------------------------------
        # Mode 4: Hybrid + LTL
        # ----------------------------------------------------------------------
        m = modes["hybrid_ltl"]
        if graph_score >= 0.55 or graph_score <= 0.15:
            m.total_latency_ms += 0.0
        else:
            m.llm_invocations += 1
            m.total_latency_ms += llm_elapsed

        fused_label_ltl, _ = fuse_scores(
            graph_score=graph_score,
            llm_label=hybrid_decision.label,
            llm_conf=hybrid_decision.confidence,
            ltl_severity=ltl_severity,
            pcabp_score=0.0,
            cove_cap=None,
        )
        pred_attack = fused_label_ltl == "MALICIOUS"
        if pred_attack == w.is_attack:
            if w.is_attack: m.tp += 1
            else: m.tn += 1
        else:
            if w.is_attack: m.fn += 1
            else: m.fp += 1

        # ----------------------------------------------------------------------
        # Mode 5: Full (Hybrid + LTL + PCABP + CoVe Cap)
        # ----------------------------------------------------------------------
        m = modes["full"]
        if graph_score >= 0.55 or graph_score <= 0.15:
            m.total_latency_ms += 0.0
        else:
            m.llm_invocations += 1
            m.total_latency_ms += llm_elapsed

        cove_cap = 0.29 if (hybrid_decision.label == "MALICIOUS" and cove_report.hallucination_rate > 0.10) else None
        fused_label_full, _ = fuse_scores(
            graph_score=graph_score,
            llm_label=hybrid_decision.label,
            llm_conf=hybrid_decision.confidence,
            ltl_severity=ltl_severity,
            pcabp_score=0.0,
            cove_cap=cove_cap,
        )
        pred_attack = fused_label_full == "MALICIOUS"
        if pred_attack == w.is_attack:
            if w.is_attack: m.tp += 1
            else: m.tn += 1
        else:
            if w.is_attack: m.fn += 1
            else: m.fp += 1

        records.append({
            "pid": w.pid,
            "gt": "MALICIOUS" if w.is_attack else "BENIGN",
            "graph_score": round(graph_score, 4),
            "ltl_severity": ltl_severity,
            "cove_hal_rate": cove_report.hallucination_rate,
            "modes": {
                "llm_only": llm_decision.label,
                "graph_only": "MALICIOUS" if graph_score >= 0.50 else "BENIGN",
                "hybrid": hybrid_label,
                "hybrid_ltl": fused_label_ltl,
                "full": fused_label_full,
            }
        })

        if (idx + 1) % 10 == 0:
            logger.info("Processed %d / %d windows...", idx + 1, len(windows))

    # Compile results
    summary = {}
    table_rows = []
    for mode_key, m in modes.items():
        total = m.tp + m.fp + m.tn + m.fn
        tpr = m.tp / max(m.tp + m.fn, 1)
        fpr = m.fp / max(m.fp + m.tn, 1)
        prec = m.tp / max(m.tp + m.fp, 1)
        f1 = 2 * prec * tpr / max(prec + tpr, 1e-9)
        acc = (m.tp + m.tn) / max(total, 1)
        mean_per_window = m.total_latency_ms / max(total, 1)
        mean_llm_call = m.total_latency_ms / max(m.llm_invocations, 1) if m.llm_invocations else 0.0

        summary[mode_key] = {
            "tp": m.tp, "fp": m.fp, "tn": m.tn, "fn": m.fn,
            "tpr": round(tpr, 4),
            "fpr": round(fpr, 4),
            "precision": round(prec, 4),
            "f1": round(f1, 4),
            "accuracy": round(acc, 4),
            "llm_invocations": m.llm_invocations,
            "mean_latency_ms": round(mean_per_window, 2),
            "mean_llm_call_ms": round(mean_llm_call, 2),
        }
        table_rows.append(
            f"| {mode_key:<12} | {f1:.3f} | {tpr:.3f} | {fpr:.3f} | {m.llm_invocations:<11} | {mean_per_window:7.1f}ms |"
        )

    summary["windows_details"] = records

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(summary, indent=2))

    print("\n" + "=" * 70)
    print(f"SENTINEL 5-MODE ABLATION RESULTS ({args.dataset.upper()})")
    print("=" * 70)
    print("| Mode         | F1    | TPR   | FPR   | Invocations | Mean Latency |")
    print("|--------------|-------|-------|-------|-------------|--------------|")
    for row in table_rows:
        print(row)
    print("=" * 70)
    print(f"Results written to: {out_path}\n")


if __name__ == "__main__":
    asyncio.run(main())
