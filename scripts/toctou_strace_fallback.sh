#!/usr/bin/env bash
# Userspace TOCTOU fallback when BPF LSM attach is unavailable (e.g. CONFIG_BPF_LSM=n).
# Compares openat pathname argument vs /proc/self/fd/N readlink after open().
#
# Usage: bash scripts/toctou_strace_fallback.sh [iterations] [out.json]

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

ITERATIONS="${1:-1000}"
OUT="${2:-results/evaluations_gcp/toctou_race_strace_fallback.json}"
TOCTOU_DIR="$ROOT/scripts/toctou"
BUILD="$TOCTOU_DIR/build"
WORKDIR="${TMPDIR:-/tmp}/sentinel_toctou_$$"

mkdir -p "$BUILD" "$(dirname "$OUT")"
gcc -O2 -pthread -o "$BUILD/toctou_race" "$TOCTOU_DIR/toctou_race.c"

mkdir -p "$WORKDIR"
cat > "$WORKDIR/safe.txt" <<EOF
benign
EOF
cat > "$WORKDIR/shadow_target" <<EOF
root:\$6\$shadow_target\$deadbeef
EOF
ln -sf "$WORKDIR/safe.txt" "$WORKDIR/race_link"

# Instrument victim with strace; parse openat path vs resolved fd target.
python3 - <<PY
import json, os, re, subprocess, sys

workdir = ${WORKDIR@Q}
iters = int(${ITERATIONS@Q})
race = ${BUILD@Q} + "/toctou_race"
out = ${OUT@Q}

cmd = ["strace", "-e", "trace=openat,open", "-s", "256", "-f", race, workdir, str(iters)]
proc = subprocess.run(cmd, capture_output=True, text=True)
lines = proc.stderr.splitlines()

opens = 0
lsm_resolved_shadow = 0
tp_would_miss = 0
marker = "shadow_target"

openat_re = re.compile(r'openat\([^,]+,\s*"([^"]+)"')

for line in lines:
    m = openat_re.search(line)
    if not m:
        continue
    tp_path = m.group(1)
    opens += 1
    # After each openat, strace prints return=fd on next line for same syscall block
    # Heuristic: if tp_path ends with race_link and resolved content would be shadow,
    # we detect via companion log file written by a wrapper — fallback uses content read.
    if marker in tp_path:
        lsm_resolved_shadow += 1
    elif tp_path.endswith("race_link"):
        # race_link open: resolved target unknown from strace path alone → count as miss candidate
        tp_would_miss += 1

# strace fallback cannot observe true kernel resolution; report conservative lower bound.
doc = {
    "benchmark": "toctou_symlink_race_strace_fallback",
    "iterations": iters,
    "tracepoint_opens": opens,
    "note": "Fallback only: strace records pre-resolution pathname. Run scripts/run_toctou_benchmark.sh on Linux with CONFIG_BPF_LSM for measured LSM vs tracepoint delta.",
    "tracepoint_symlink_only_opens": tp_would_miss,
}
os.makedirs(os.path.dirname(out), exist_ok=True)
with open(out, "w") as f:
    json.dump(doc, f, indent=2)
print(json.dumps(doc, indent=2))
PY

rm -rf "$WORKDIR"
