#!/usr/bin/env bash
# Wipe all evaluation artifacts for a clean GCP rerun.
# Safe to run on Mac or on sentinel-gpu-vm (repo root as cwd).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "=== Stopping eval services (VM only) ==="
if command -v systemctl >/dev/null 2>&1; then
  sudo systemctl stop ollama 2>/dev/null || true
fi
pkill -f "ollama runner" 2>/dev/null || true
pkill -f "evaluate_darpa" 2>/dev/null || true
pkill -f "evaluate_real" 2>/dev/null || true
pkill -f "measure_scenarios" 2>/dev/null || true

echo "=== Removing result JSON/logs/pickles ==="
find results/evaluations results/evaluations_gcp results/evaluations_linux results/logs \
  -type f ! -name '.gitkeep' -delete 2>/dev/null || true

# Stray GCP-named files outside canonical dirs
find results -name '*_ionos.*' -delete 2>/dev/null || true
find results -name '*_gcp.*' ! -path 'results/evaluations_gcp/*' -delete 2>/dev/null || true
# Keep PCABP bloom pickles — expensive to rebuild; not evaluation JSON artifacts.

mkdir -p results/{evaluations,evaluations_gcp,evaluations_linux,logs}
touch results/evaluations/.gitkeep \
      results/evaluations_gcp/.gitkeep \
      results/evaluations_linux/.gitkeep \
      results/logs/.gitkeep

echo "=== Remaining under results/ (should be .gitkeep only) ==="
find results -type f | sort

echo "Done."
