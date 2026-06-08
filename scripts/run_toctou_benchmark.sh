#!/usr/bin/env bash
# TOCTOU micro-benchmark: userspace proxy + eBPF tracepoint vs lsm/file_open (GCP).
#
# Usage (GCP VM):
#   export SENTINEL_EVAL_PLATFORM="GCP g2-standard-4 NVIDIA L4 Ubuntu $(uname -r)"
#   bash scripts/run_toctou_benchmark.sh [attempts] [out.json]
#
# Produces merged artifact with both measurement layers + EV-11 cross-reference.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

ITERATIONS="${1:-50000}"
OUT="${2:-results/evaluations_gcp/toctou_race_gcp.json}"
TOCTOU_DIR="$ROOT/scripts/toctou"
BUILD="$TOCTOU_DIR/build"
TMP_US="$BUILD/toctou_userspace.json"
TMP_EBPF="$BUILD/toctou_ebpf.json"

mkdir -p "$BUILD" "$(dirname "$OUT")"

if [[ "$OUT" == *evaluations_gcp* ]]; then
  if [[ "$(uname -s)" == "Darwin" ]]; then
    echo "ERROR: TOCTOU paper results must be produced on GCP sentinel-gpu-vm." >&2
    exit 1
  fi
  export SENTINEL_EVAL_PLATFORM="${SENTINEL_EVAL_PLATFORM:-GCP g2-standard-4 NVIDIA L4 Ubuntu $(uname -r)}"
fi

run_userspace() {
  echo "▶ TOCTOU userspace proxy ($ITERATIONS open attempts)..."
  gcc -O2 -pthread -o "$BUILD/toctou_race_measured" "$TOCTOU_DIR/toctou_race_measured.c"
  WORK="$BUILD/work_$$"
  mkdir -p "$WORK"
  echo benign > "$WORK/safe.txt"
  echo 'root:$6$shadow_target$deadbeef' > "$WORK/shadow_target"
  ln -sf "$WORK/safe.txt" "$WORK/race_link"
  "$BUILD/toctou_race_measured" "$WORK" "$ITERATIONS" "$TMP_US"
  rm -rf "$WORK"
}

merge_results() {
  export PYTHONPATH=src/python
  if [[ -f "$TMP_EBPF" ]]; then
    python3 scripts/merge_toctou_results.py "$OUT" "$TMP_US" "$TMP_EBPF"
  else
    python3 scripts/merge_toctou_results.py "$OUT" "$TMP_US"
  fi
}

run_userspace

EBPF_OK=0
if sudo -n env PATH="$PATH" bash "$TOCTOU_DIR/run_ebpf_layer.sh" "$ITERATIONS" "$TMP_EBPF"; then
  EBPF_OK=1
else
  echo "WARN: eBPF layer skipped (sudo, BTF, or CONFIG_BPF_LSM)" >&2
fi

merge_results

echo "Results → $OUT (ebpf_layer=${EBPF_OK})"
cat "$OUT"
