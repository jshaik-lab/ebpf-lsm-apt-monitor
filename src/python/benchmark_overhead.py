"""benchmark_overhead.py — CPU, memory, latency, and throughput benchmarks for SENTINEL.

Measures:
  1. IPGBuilder.build() + serialize() latency (Algorithm 1)
  2. DualTierClassifier dispatch latency (mock, simulates Algorithm 2 both tiers)
  3. CWAEEngine.enforce() latency (Algorithm 3)
  4. End-to-end per-event latency through the full pipeline
  5. DetectorAgent._triage() throughput (events/sec)
  6. Peak RSS memory before/after loading components

Run with:
    python src/python/benchmark_overhead.py
    python src/python/benchmark_overhead.py --json   # machine-readable output
    python src/python/benchmark_overhead.py --n 5000 # more samples for tighter CIs

All benchmarks run without root, Docker, or a real LLM.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import resource
import statistics
import sys
import time
from pathlib import Path

# -- path setup ---------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).parent))

from sentinel.config import SentinelConfig
from sentinel.ipg import IPGBuilder
from sentinel.llm.mock import MockClassifier
from sentinel.llm.base import DualTierClassifier
from sentinel.enforcement import CWAEEngine
from sentinel.models import KernelEvent, SyscallType, ThreatDecision
from sentinel.simulation import SCENARIOS, EVASION_SCENARIOS


# ── helpers ──────────────────────────────────────────────────────────────────

def _rss_mb() -> float:
    """Current RSS in megabytes (macOS: ru_maxrss is bytes; Linux: kilobytes)."""
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform == "darwin":
        return rss / 1024 / 1024
    return rss / 1024  # Linux: KB → MB


def _events_from_scenarios(n: int) -> list[KernelEvent]:
    """Collect n events by cycling through all scenarios."""
    all_events: list[KernelEvent] = []
    for s in SCENARIOS + EVASION_SCENARIOS:
        all_events.extend(s.events)
    result: list[KernelEvent] = []
    while len(result) < n:
        result.extend(all_events)
    return result[:n]


def _make_attack_window() -> list[KernelEvent]:
    """Return a realistic 20-event attack window (T1003 credential dump)."""
    for s in SCENARIOS:
        if s.name == "ATK-T1003":
            return list(s.events)
    # fallback: any attack scenario
    for s in SCENARIOS:
        if s.expected == "MALICIOUS":
            return list(s.events)
    return list(SCENARIOS[0].events)


def _percentile(data: list[float], p: float) -> float:
    sorted_data = sorted(data)
    idx = (len(sorted_data) - 1) * p / 100
    lo, hi = int(idx), min(int(idx) + 1, len(sorted_data) - 1)
    return sorted_data[lo] + (sorted_data[hi] - sorted_data[lo]) * (idx - lo)


def _stats(samples: list[float]) -> dict:
    return {
        "n":    len(samples),
        "mean": round(statistics.mean(samples), 3),
        "p50":  round(_percentile(samples, 50), 3),
        "p95":  round(_percentile(samples, 95), 3),
        "p99":  round(_percentile(samples, 99), 3),
        "min":  round(min(samples), 3),
        "max":  round(max(samples), 3),
        "stdev": round(statistics.stdev(samples) if len(samples) > 1 else 0.0, 3),
    }


# ── individual benchmarks ────────────────────────────────────────────────────

def bench_ipg(n: int) -> dict:
    """IPGBuilder.build() + serialize() latency in milliseconds."""
    builder = IPGBuilder()
    window = _make_attack_window()
    samples: list[float] = []

    # Warmup
    for _ in range(10):
        G = builder.build(window)
        builder.serialize(G)

    for _ in range(n):
        t0 = time.perf_counter()
        G = builder.build(window)
        builder.serialize(G)
        samples.append((time.perf_counter() - t0) * 1000)

    return _stats(samples)


def bench_cwae(n: int) -> dict:
    """CWAEEngine enforcement latency (dry_run=True, no real signal)."""
    cwae = CWAEEngine(
        enforce_map_fd=-1,
        xdp_quarantine_fd=-1,
        audit_log_path="/tmp/sentinel_bench_audit.jsonl",
        incident_log_path="/tmp/sentinel_bench_incidents.jsonl",
        dry_run=True,
    )

    async def _run() -> list[float]:
        samples: list[float] = []
        # High-confidence decisions to hit QUARANTINE tier
        decision = ThreatDecision(
            label="MALICIOUS",
            confidence=0.92,
            reasoning="Benchmark trace",
            mitre_ttps=["T1003"],
        )
        for i in range(n):
            t0 = time.perf_counter()
            await cwae.enforce(pid=9999 + i % 100, comm="bench", decision=decision)
            samples.append((time.perf_counter() - t0) * 1000)
        return samples

    samples = asyncio.run(_run())
    return _stats(samples)


def bench_mock_classifier(n: int) -> dict:
    """MockClassifier.classify() latency (pure Python, no LLM)."""
    clf = MockClassifier()
    builder = IPGBuilder()
    window = _make_attack_window()
    G = builder.build(window)
    ipg_text = builder.serialize(G)

    async def _run() -> list[float]:
        samples: list[float] = []
        for _ in range(n):
            t0 = time.perf_counter()
            await clf.classify(ipg_text)
            samples.append((time.perf_counter() - t0) * 1000)
        return samples

    samples = asyncio.run(_run())
    return _stats(samples)


def bench_dual_tier_draft_path(n: int) -> dict:
    """DualTierClassifier draft-only path (high-conf draft → skips full model)."""
    draft = MockClassifier()
    full  = MockClassifier()
    clf = DualTierClassifier(
        draft=draft,
        full=full,
        draft_conf_threshold=0.90,
        entropy_high=3.8,
    )
    builder = IPGBuilder()
    window = _make_attack_window()
    G = builder.build(window)
    ipg_text = builder.serialize(G)
    # Low entropy → draft path used
    H = 1.0

    async def _run() -> list[float]:
        samples: list[float] = []
        for _ in range(n):
            t0 = time.perf_counter()
            await clf.classify(ipg_text, H)
            samples.append((time.perf_counter() - t0) * 1000)
        return samples

    samples = asyncio.run(_run())
    return _stats(samples)


def bench_detector_triage(n: int) -> dict:
    """DetectorAgent._triage() throughput — events/sec (pure Python, no I/O)."""
    from sentinel.agents.detector import DetectorAgent
    import asyncio

    async def _run() -> tuple[float, float]:
        det = DetectorAgent(
            out_queue=asyncio.Queue(maxsize=10000),
            window_size=20,
            entropy_low=1.2,
            entropy_high=3.8,
            entropy_window=64,
        )
        events = _events_from_scenarios(n)
        t0 = time.perf_counter()
        for evt in events:
            await det.handle(evt)
        elapsed = time.perf_counter() - t0
        return elapsed, det.stats["signals"]

    elapsed, signals = asyncio.run(_run())
    eps = round(n / elapsed)
    return {
        "events":       n,
        "elapsed_s":    round(elapsed, 3),
        "events_per_s": eps,
        "signals_emitted": signals,
        "signal_rate":  round(signals / n, 3),
    }


def bench_e2e_pipeline(n: int) -> dict:
    """End-to-end latency: push_event → AuditorAgent writes audit log.

    Uses a real AgentPipeline with mock classifier.
    Measures wall-clock time for n events to fully process through all 3 stages.
    """
    from sentinel.agents.pipeline import AgentPipeline
    from sentinel.config import SentinelConfig

    cfg_path = Path(__file__).parent.parent.parent / "config" / "sentinel.yaml"
    if not cfg_path.exists():
        return {"skipped": "config/sentinel.yaml not found"}

    cfg = SentinelConfig.from_yaml(str(cfg_path))

    async def _run() -> dict:
        pipeline = AgentPipeline.from_config(cfg)
        events = _events_from_scenarios(n)
        audit_path = Path(cfg.enforcement.audit_log)

        # Count audit entries before run
        pre_count = 0
        if audit_path.exists():
            with open(audit_path) as f:
                pre_count = sum(1 for _ in f)

        async with pipeline:
            t0 = time.perf_counter()
            for evt in events:
                await pipeline.push_event(evt)
            push_elapsed = time.perf_counter() - t0

            # Wait for audit log to drain (up to 30s)
            deadline = time.monotonic() + 30.0
            post_count = pre_count
            while time.monotonic() < deadline:
                await asyncio.sleep(0.05)
                if audit_path.exists():
                    with open(audit_path) as f:
                        post_count = sum(1 for _ in f)
                if post_count > pre_count:
                    break

        total_elapsed = time.perf_counter() - t0
        audited = post_count - pre_count
        return {
            "events":      n,
            "push_ms":     round(push_elapsed * 1000, 2),
            "total_ms":    round(total_elapsed * 1000, 2),
            "audited":     audited,
            "pipeline_stats": pipeline.stats(),
        }

    return asyncio.run(_run())


def bench_memory() -> dict:
    """RSS before and after loading core components."""
    rss_before = _rss_mb()

    builder = IPGBuilder()
    clf = MockClassifier()
    cwae = CWAEEngine(
        enforce_map_fd=-1, xdp_quarantine_fd=-1,
        audit_log_path="/tmp/bench_mem_audit.jsonl",
        incident_log_path="/tmp/bench_mem_incidents.jsonl",
        dry_run=True,
    )

    # Force some allocations
    windows = [_make_attack_window() for _ in range(20)]
    graphs  = [builder.build(w) for w in windows]
    texts   = [builder.serialize(g) for g in graphs]

    rss_after = _rss_mb()
    return {
        "rss_before_mb": round(rss_before, 1),
        "rss_after_mb":  round(rss_after, 1),
        "delta_mb":      round(rss_after - rss_before, 1),
        "platform":      sys.platform,
    }


# ── main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="SENTINEL overhead benchmarks")
    parser.add_argument("--n", type=int, default=1000,
                        help="Number of samples per benchmark (default: 1000)")
    parser.add_argument("--json", action="store_true",
                        help="Output machine-readable JSON")
    args = parser.parse_args()

    N = args.n

    print(f"\n{'='*60}")
    print(f"  SENTINEL Overhead Benchmarks  (n={N} per benchmark)")
    print(f"{'='*60}\n")

    results: dict = {}

    # 1. IPG build + serialize
    print("▶  IPGBuilder.build() + serialize()  ...", end=" ", flush=True)
    r = bench_ipg(N)
    results["ipg_ms"] = r
    print(f"p50={r['p50']}ms  p95={r['p95']}ms  p99={r['p99']}ms")

    # 2. Mock classifier
    print("▶  MockClassifier.classify()         ...", end=" ", flush=True)
    r = bench_mock_classifier(N)
    results["mock_classifier_ms"] = r
    print(f"p50={r['p50']}ms  p95={r['p95']}ms  p99={r['p99']}ms")

    # 3. DualTier draft path
    print("▶  DualTierClassifier (draft path)   ...", end=" ", flush=True)
    r = bench_dual_tier_draft_path(N)
    results["dual_tier_draft_ms"] = r
    print(f"p50={r['p50']}ms  p95={r['p95']}ms  p99={r['p99']}ms")

    # 4. CWAE enforce
    print("▶  CWAEEngine.enforce() (dry_run)    ...", end=" ", flush=True)
    r = bench_cwae(N)
    results["cwae_ms"] = r
    print(f"p50={r['p50']}ms  p95={r['p95']}ms  p99={r['p99']}ms")

    # 5. Detector triage throughput
    print(f"▶  DetectorAgent._triage() ({N} events) ...", end=" ", flush=True)
    r = bench_detector_triage(N)
    results["detector_throughput"] = r
    print(f"{r['events_per_s']:,} events/s  (signal_rate={r['signal_rate']:.1%})")

    # 6. Memory
    print("▶  Memory baseline                   ...", end=" ", flush=True)
    r = bench_memory()
    results["memory"] = r
    print(f"Δ={r['delta_mb']}MB  (after={r['rss_after_mb']}MB RSS)")

    # 7. E2E pipeline (optional, skipped if config missing)
    print(f"▶  E2E pipeline ({min(N, 100)} events)          ...", end=" ", flush=True)
    r = bench_e2e_pipeline(min(N, 100))
    results["e2e_pipeline"] = r
    if "skipped" in r:
        print(f"SKIPPED ({r['skipped']})")
    else:
        print(f"push={r['push_ms']}ms  total={r['total_ms']}ms  audited={r['audited']}")

    print(f"\n{'='*60}")
    print("Summary (for paper Table III: System Overhead)")
    print(f"{'='*60}")
    print(f"  IPG latency (p50/p99):          {results['ipg_ms']['p50']} / {results['ipg_ms']['p99']} ms")
    print(f"  Mock classifier (p50/p99):      {results['mock_classifier_ms']['p50']} / {results['mock_classifier_ms']['p99']} ms")
    print(f"  CWAE enforce (p50/p99):         {results['cwae_ms']['p50']} / {results['cwae_ms']['p99']} ms")
    print(f"  Detector throughput:            {results['detector_throughput']['events_per_s']:,} events/s")
    print(f"  Memory delta:                   {results['memory']['delta_mb']} MB")
    print()
    print("  NOTE: Ollama LLM latency measured separately on Hetzner CAX11 ARM64 hardware.")
    print("        Expected: p50≈3.6s (HTTP API for 8B models), p50<100ms (native llama.cpp).")
    print(f"{'='*60}\n")

    if args.json:
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
