#!/usr/bin/env bash
# TOCTOU micro-benchmark: pre-resolution openat path vs post-resolution identity.
#
# Primary (Linux + root + CONFIG_BPF_LSM): eBPF tracepoint vs lsm/file_open
#   sudo bash scripts/run_toctou_benchmark.sh [iterations] [out.json]
#
# Portable fallback (any Linux, no root): open path vs readlink(/proc/self/fd/N)
#   bash scripts/run_toctou_benchmark.sh --userspace [iterations] [out.json]
#
# Example (GCP):
#   export SENTINEL_EVAL_PLATFORM="GCP g2-standard-4 Ubuntu $(uname -r)"
#   sudo bash scripts/run_toctou_benchmark.sh 1000 results/evaluations_gcp/toctou_race_gcp.json

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

MODE="ebpf"
if [[ "${1:-}" == "--userspace" ]]; then
  MODE="userspace"
  shift
fi

ITERATIONS="${1:-1000}"
OUT="${2:-results/evaluations_gcp/toctou_race_gcp.json}"
TOCTOU_DIR="$ROOT/scripts/toctou"
BUILD="$TOCTOU_DIR/build"

mkdir -p "$BUILD" "$(dirname "$OUT")"

if [[ "$OUT" == *evaluations_gcp* ]]; then
  if [[ "$(uname -s)" == "Darwin" ]]; then
    echo "ERROR: TOCTOU results for the paper must be produced on GCP, not Mac." >&2
    echo "  Run on VM: bash scripts/run_gcp_eval_chain.sh" >&2
    exit 1
  fi
  export SENTINEL_EVAL_PLATFORM="${SENTINEL_EVAL_PLATFORM:-GCP sentinel-gpu-vm $(uname -r)}"
fi

if [[ "$MODE" == "userspace" ]]; then
  echo "▶ TOCTOU userspace benchmark ($ITERATIONS iterations)..."
  gcc -O2 -pthread -o "$BUILD/toctou_race_measured" "$TOCTOU_DIR/toctou_race_measured.c"
  WORK="$BUILD/work_$$"
  mkdir -p "$WORK"
  echo benign > "$WORK/safe.txt"
  echo 'root:$6$shadow_target$deadbeef' > "$WORK/shadow_target"
  ln -sf "$WORK/safe.txt" "$WORK/race_link"
  "$BUILD/toctou_race_measured" "$WORK" "$ITERATIONS" "$OUT"
  rm -rf "$WORK"
  if [[ -f .venv/bin/activate ]]; then source .venv/bin/activate; fi
  export PYTHONPATH=src/python
  python3 scripts/add_meta_to_json.py "$OUT" "$OUT" 2>/dev/null || true
  echo "Results → $OUT"
  cat "$OUT"
  exit 0
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "WARN: eBPF mode needs root; falling back to --userspace" >&2
  exec bash "$0" --userspace "$ITERATIONS" "$OUT"
fi

if [[ ! -r /sys/kernel/btf/vmlinux ]]; then
  echo "ERROR: BTF not available at /sys/kernel/btf/vmlinux" >&2
  exit 1
fi

# Map uname -m to BPF target arch
case "$ARCH" in
  x86_64)  BPF_ARCH=x86 ;;
  aarch64) BPF_ARCH=arm64 ;;
  *) echo "unsupported arch: $ARCH" >&2; exit 1 ;;
esac

if ! command -v clang >/dev/null; then
  echo "ERROR: install clang libbpf-dev bpftool linux-headers-generic" >&2
  exit 1
fi

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
  echo "▶ Building standalone bpftool (host wrapper mismatched kernel)..."
  if [[ ! -x "$BUILD/bpftool" ]]; then
    rm -rf "$BUILD/bpftool-src"
    git clone --depth 1 --recurse-submodules https://github.com/libbpf/bpftool "$BUILD/bpftool-src"
    apt-get install -y -qq libcap-dev pkg-config 2>/dev/null || true
    make -C "$BUILD/bpftool-src/src" -j"$(nproc)" 2>/dev/null || make -C "$BUILD/bpftool-src/src" -j2
    cp "$BUILD/bpftool-src/src/bpftool" "$BUILD/bpftool"
  fi
  BPFTOOL="$BUILD/bpftool"
fi

echo "▶ Generating vmlinux.h from BTF (bpftool=$BPFTOOL)..."
"$BPFTOOL" btf dump file /sys/kernel/btf/vmlinux format c > "$BUILD/vmlinux.h"

echo "▶ Compiling toctou.bpf.o (arch=$BPF_ARCH)..."
clang -O2 -g -target bpf "-D__TARGET_ARCH_${BPF_ARCH}" \
  -I"$BUILD" -c "$TOCTOU_DIR/toctou.bpf.c" -o "$BUILD/toctou.bpf.o"

echo "▶ Compiling toctou_race..."
gcc -O2 -pthread -o "$BUILD/toctou_race" "$TOCTOU_DIR/toctou_race.c"

echo "▶ Compiling toctou_loader..."
gcc -O2 -o "$BUILD/toctou_loader" "$TOCTOU_DIR/toctou_loader.c" -lbpf -lelf -lz

echo "▶ Running $ITERATIONS symlink race iterations..."
"$BUILD/toctou_loader" "$BUILD/toctou.bpf.o" "$ITERATIONS" "$OUT"

if [[ -f .venv/bin/activate ]]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi
if [[ -d src/python ]]; then
  export PYTHONPATH=src/python
  python3 scripts/add_meta_to_json.py "$OUT" "$OUT" || true
fi

echo "Results → $OUT"
cat "$OUT"
