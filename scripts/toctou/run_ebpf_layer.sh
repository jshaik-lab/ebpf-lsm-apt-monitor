#!/usr/bin/env bash
# eBPF-only layer for TOCTOU benchmark (invoked with sudo from run_toctou_benchmark.sh).
set -euo pipefail

ITERATIONS="${1:?iterations}"
TMP_EBPF="${2:?out json}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TOCTOU_DIR="$ROOT/scripts/toctou"
BUILD="$TOCTOU_DIR/build"
ARCH="$(uname -m)"

mkdir -p "$BUILD"

if [[ ! -r /sys/kernel/btf/vmlinux ]]; then
  echo "WARN: BTF missing" >&2
  exit 1
fi

case "$ARCH" in
  x86_64)  BPF_ARCH=x86 ;;
  aarch64) BPF_ARCH=arm64 ;;
  *) echo "unsupported arch: $ARCH" >&2; exit 1 ;;
esac

command -v clang >/dev/null || { echo "clang missing" >&2; exit 1; }

BPFTOOL=""
for candidate in bpftool /usr/sbin/bpftool "$BUILD/bpftool"; do
  if command -v "$candidate" >/dev/null 2>&1 && "$candidate" version >/dev/null 2>&1; then
    if "$candidate" btf dump file /sys/kernel/btf/vmlinux format c 2>/dev/null | head -1 | grep -q struct; then
      BPFTOOL="$candidate"
      break
    fi
  fi
done

if [[ -z "$BPFTOOL" ]]; then
  if [[ ! -x "$BUILD/bpftool" ]]; then
    rm -rf "$BUILD/bpftool-src"
    git clone --depth 1 --recurse-submodules https://github.com/libbpf/bpftool "$BUILD/bpftool-src"
    make -C "$BUILD/bpftool-src/src" -j"$(nproc)" 2>/dev/null || make -C "$BUILD/bpftool-src/src" -j2
    cp "$BUILD/bpftool-src/src/bpftool" "$BUILD/bpftool"
  fi
  BPFTOOL="$BUILD/bpftool"
fi

"$BPFTOOL" btf dump file /sys/kernel/btf/vmlinux format c > "$BUILD/vmlinux.h"
clang -O2 -g -target bpf "-D__TARGET_ARCH_${BPF_ARCH}" \
  -I"$BUILD" -c "$TOCTOU_DIR/toctou.bpf.c" -o "$BUILD/toctou.bpf.o"
gcc -O2 -pthread -o "$BUILD/toctou_race" "$TOCTOU_DIR/toctou_race.c"
gcc -O2 -o "$BUILD/toctou_loader" "$TOCTOU_DIR/toctou_loader.c" -lbpf -lelf -lz

RAW="$BUILD/toctou_ebpf_raw.json"
"$BUILD/toctou_loader" "$BUILD/toctou.bpf.o" "$ITERATIONS" "$RAW"

python3 - <<PY
import json
from pathlib import Path
raw = json.loads(Path("$RAW").read_text())
iters = max(raw.get("iterations", 1), 1)
opens = raw.get("tracepoint_opens", 0)
out = {
    "method": "ebpf_sys_enter_openat_vs_lsm_file_open",
    "open_attempts": raw.get("iterations"),
    "tracepoint_opens": opens,
    "open_success_rate": opens / iters,
    "lsm_resolved_shadow": raw.get("lsm_resolved_shadow"),
    "tracepoint_would_miss_shadow": raw.get("tracepoint_would_miss_shadow"),
    "tracepoint_miss_rate": raw.get("tracepoint_miss_rate"),
    "lsm_shadow_resolution_rate": raw.get("lsm_shadow_resolution_rate"),
    "note": "Kernel bpf_d_path at lsm/file_open vs sys_enter_openat pathname.",
}
Path("$TMP_EBPF").write_text(json.dumps(out, indent=2))
PY

echo "eBPF layer → $TMP_EBPF"
