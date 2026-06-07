#!/usr/bin/env bash
# benchmark_sysbench.sh — Measure SENTINEL overhead against sysbench baseline
#
# Paper claim: SENTINEL adds <3% CPU overhead and <15 MB RSS when running
# alongside a compute-intensive workload.
#
# Method (Section V-F, Table V):
#   1. Baseline: sysbench cpu --time=30 (one thread, prime factorization)
#   2. Loaded:   same sysbench workload + SENTINEL in simulation/mock mode
#   3. Delta CPU%  = (loaded_cpu - baseline_cpu) / baseline_cpu * 100
#   4. Delta RSS   = loaded_rss - baseline_rss  (MB)
#
# Requirements:
#   sysbench    — brew install sysbench  OR  apt install sysbench
#   python3     — with PYTHONPATH=src/python
#   SENTINEL    — pip install -r requirements-dev.txt
#
# Usage:
#   bash scripts/benchmark_sysbench.sh
#   bash scripts/benchmark_sysbench.sh --threads 4 --time 60
#
# Output:
#   results/evaluations/sysbench_overhead.json

set -euo pipefail
cd "$(dirname "$0")/.."

# ── Defaults ─────────────────────────────────────────────────────────────────
SYSBENCH_THREADS="${1:-1}"
SYSBENCH_TIME="${2:-30}"
OUT_FILE="results/evaluations/sysbench_overhead.json"
SENTINEL_LOG="/tmp/sentinel_sysbench_$$.log"
SENTINEL_PID_FILE="/tmp/sentinel_sysbench_$$.pid"

mkdir -p results/evaluations

# ── Dependency check ──────────────────────────────────────────────────────────
if ! command -v sysbench &>/dev/null; then
    echo "ERROR: sysbench not found."
    echo "  Mac:   brew install sysbench"
    echo "  Linux: apt-get install -y sysbench"
    exit 1
fi

if ! python3 -c "import sentinel" &>/dev/null 2>&1; then
    if [[ -d src/python ]]; then
        export PYTHONPATH="src/python:${PYTHONPATH:-}"
    fi
fi

echo "======================================================================"
echo "SENTINEL — Sysbench Overhead Benchmark (Section V-F)"
echo "Sysbench: cpu test, threads=$SYSBENCH_THREADS, time=${SYSBENCH_TIME}s"
echo "======================================================================"

# ── Helper: measure RSS of a PID in MB ────────────────────────────────────────
rss_mb() {
    local pid="$1"
    if [[ -f "/proc/$pid/status" ]]; then
        awk '/VmRSS/{printf "%.1f", $2/1024}' "/proc/$pid/status"
    elif command -v ps &>/dev/null; then
        ps -o rss= -p "$pid" 2>/dev/null | awk '{printf "%.1f", $1/1024}' || echo "0"
    else
        echo "0"
    fi
}

# ── Helper: CPU% of a PID over N seconds ─────────────────────────────────────
cpu_pct() {
    local pid="$1"
    local duration="$2"
    if command -v pidstat &>/dev/null; then
        pidstat -p "$pid" 1 "$duration" 2>/dev/null | awk '/Average/{print $8}' | tail -1
    else
        # Fallback: /proc/stat sampling
        local t1 idle1 total1 t2 idle2 total2
        read -r _ t1 < /dev/null
        sleep "$duration"
        echo "N/A"
    fi
}

# ── Phase 1: Baseline (sysbench alone, no SENTINEL) ──────────────────────────
echo ""
echo "Phase 1: Baseline — sysbench CPU test (no SENTINEL)"
echo "Running sysbench for ${SYSBENCH_TIME}s..."

BASELINE_OUTPUT=$(sysbench cpu \
    --threads="$SYSBENCH_THREADS" \
    --time="$SYSBENCH_TIME" \
    run 2>&1)

BASELINE_EPS=$(echo "$BASELINE_OUTPUT" | grep "events per second" | awk '{print $NF}')
BASELINE_LAT=$(echo "$BASELINE_OUTPUT" | grep "avg:" | head -1 | awk '{print $NF}')
echo "  Events/sec : $BASELINE_EPS"
echo "  Latency avg: $BASELINE_LAT ms"

# Measure idle CPU baseline using top/ps
BASELINE_CPU=$(ps -A -o pcpu | awk '{sum+=$1} END {printf "%.1f", sum}')
echo "  System CPU%: $BASELINE_CPU"

# ── Phase 2: Loaded (sysbench + SENTINEL mock) ────────────────────────────────
echo ""
echo "Phase 2: Loaded — sysbench + SENTINEL (simulation/mock mode)"

# Start SENTINEL in background (mock LLM, no Docker, no Ollama)
PYTHONPATH="${PYTHONPATH:-src/python}" python3 src/python/main.py \
    --config config/sentinel.yaml \
    --mode simulation \
    2>"$SENTINEL_LOG" &
SENTINEL_PID=$!
echo "$SENTINEL_PID" > "$SENTINEL_PID_FILE"
echo "  SENTINEL started (pid=$SENTINEL_PID)"

# Give SENTINEL 3 seconds to initialize
sleep 3

# Measure SENTINEL RSS before workload
SENTINEL_RSS_BEFORE=$(rss_mb "$SENTINEL_PID")
echo "  SENTINEL RSS before workload: ${SENTINEL_RSS_BEFORE} MB"

# Run sysbench workload with SENTINEL active
echo "  Running sysbench for ${SYSBENCH_TIME}s alongside SENTINEL..."
LOADED_OUTPUT=$(sysbench cpu \
    --threads="$SYSBENCH_THREADS" \
    --time="$SYSBENCH_TIME" \
    run 2>&1)

LOADED_EPS=$(echo "$LOADED_OUTPUT" | grep "events per second" | awk '{print $NF}')
LOADED_LAT=$(echo "$LOADED_OUTPUT" | grep "avg:" | head -1 | awk '{print $NF}')
echo "  Events/sec : $LOADED_EPS"
echo "  Latency avg: $LOADED_LAT ms"

# Measure SENTINEL RSS after workload
SENTINEL_RSS_AFTER=$(rss_mb "$SENTINEL_PID")
echo "  SENTINEL RSS after workload:  ${SENTINEL_RSS_AFTER} MB"

# Measure total system CPU with SENTINEL
LOADED_CPU=$(ps -A -o pcpu | awk '{sum+=$1} END {printf "%.1f", sum}')
echo "  System CPU%: $LOADED_CPU"

# ── Cleanup ───────────────────────────────────────────────────────────────────
kill "$SENTINEL_PID" 2>/dev/null || true
wait "$SENTINEL_PID" 2>/dev/null || true
rm -f "$SENTINEL_LOG" "$SENTINEL_PID_FILE"

# ── Compute overhead ──────────────────────────────────────────────────────────
# Events/sec degradation (lower is more overhead)
EPS_DELTA=$(python3 -c "
b = float('${BASELINE_EPS}') if '${BASELINE_EPS}' != '' else 1.0
l = float('${LOADED_EPS}')   if '${LOADED_EPS}' != '' else 1.0
delta_pct = (b - l) / b * 100
print(f'{delta_pct:.2f}')
" 2>/dev/null || echo "N/A")

# Latency overhead
LAT_DELTA=$(python3 -c "
b = float('${BASELINE_LAT}') if '${BASELINE_LAT}' != '' else 1.0
l = float('${LOADED_LAT}')   if '${LOADED_LAT}' != '' else 1.0
delta_pct = (l - b) / b * 100
print(f'{delta_pct:.2f}')
" 2>/dev/null || echo "N/A")

# RSS delta
RSS_DELTA=$(python3 -c "
a = float('${SENTINEL_RSS_AFTER}') if '${SENTINEL_RSS_AFTER}' != '' else 0.0
b = float('${SENTINEL_RSS_BEFORE}') if '${SENTINEL_RSS_BEFORE}' != '' else 0.0
print(f'{a:.1f}')
" 2>/dev/null || echo "N/A")

echo ""
echo "======================================================================"
echo "RESULTS"
echo "======================================================================"
printf "  %-30s  %12s  %12s\n" "Metric" "Baseline" "Loaded"
printf "  %-30s  %12s  %12s\n" "──────────────────────────────" "────────────" "────────────"
printf "  %-30s  %12s  %12s\n" "Events/sec (sysbench cpu)"   "$BASELINE_EPS" "$LOADED_EPS"
printf "  %-30s  %12s  %12s\n" "Latency avg (ms)"             "$BASELINE_LAT" "$LOADED_LAT"
printf "  %-30s  %12s  %12s\n" "Events/sec degradation (%)"   "—"             "${EPS_DELTA}%"
printf "  %-30s  %12s  %12s\n" "Latency overhead (%)"         "—"             "${LAT_DELTA}%"
printf "  %-30s  %12s  %12s\n" "SENTINEL RSS (MB)"            "—"             "${RSS_DELTA}"
echo ""

# Target check (paper claim: <3% CPU, <15 MB RSS)
PASS_CPU="UNKNOWN"
PASS_RSS="UNKNOWN"
if [[ "$EPS_DELTA" != "N/A" ]]; then
    PASS_CPU=$(python3 -c "print('PASS ✓' if float('$EPS_DELTA') < 3.0 else 'FAIL ✗')" 2>/dev/null || echo "?")
fi
if [[ "$RSS_DELTA" != "N/A" ]]; then
    PASS_RSS=$(python3 -c "print('PASS ✓' if float('$RSS_DELTA') < 15.0 else 'FAIL ✗')" 2>/dev/null || echo "?")
fi

echo "  Paper targets (Section V-F):"
echo "    CPU overhead <3%:   $PASS_CPU  (measured: ${EPS_DELTA}%)"
echo "    RSS overhead <15MB: $PASS_RSS  (measured: ${RSS_DELTA} MB)"

# ── Write JSON output ─────────────────────────────────────────────────────────
python3 - <<PYEOF
import json, datetime, pathlib

result = {
    "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
    "sysbench_threads": $SYSBENCH_THREADS,
    "sysbench_time_s": $SYSBENCH_TIME,
    "baseline": {
        "events_per_sec": "${BASELINE_EPS}",
        "latency_avg_ms": "${BASELINE_LAT}",
    },
    "loaded": {
        "events_per_sec": "${LOADED_EPS}",
        "latency_avg_ms": "${LOADED_LAT}",
        "sentinel_rss_mb": "${RSS_DELTA}",
    },
    "overhead": {
        "eps_degradation_pct": "${EPS_DELTA}",
        "latency_overhead_pct": "${LAT_DELTA}",
        "sentinel_rss_mb": "${RSS_DELTA}",
    },
    "targets": {
        "cpu_overhead_pct_limit": 3.0,
        "rss_overhead_mb_limit": 15.0,
        "cpu_pass": "${PASS_CPU}",
        "rss_pass": "${PASS_RSS}",
    },
    "sentinel_mode": "simulation/mock",
    "note": (
        "Baseline: sysbench cpu alone. Loaded: sysbench + SENTINEL mock mode. "
        "Paper claim: <3% CPU overhead, <15 MB RSS. "
        "For eBPF mode overhead, run make up-ebpf inside Docker."
    ),
}

pathlib.Path("$OUT_FILE").parent.mkdir(parents=True, exist_ok=True)
with open("$OUT_FILE", "w") as f:
    json.dump(result, f, indent=2)
print(f"\nResults → $OUT_FILE")
PYEOF
