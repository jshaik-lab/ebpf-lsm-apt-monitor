#!/usr/bin/env bash
# Full GCP evaluation chain for IEEE TIFS paper-grade results.
# Run on sentinel-gpu-vm after: git pull, venv, Ollama models pulled.
#
# Usage:
#   cd ~/Paper1_ZeroTrustAgent
#   bash scripts/cleanup_stale_results.sh   # first boot after wipe
#   bash scripts/run_gcp_eval_chain.sh 2>&1 | tee results/evaluations_gcp/gcp_chain.log
#
# Sync back to Mac:
#   rsync -avz sentinel@34.74.43.57:~/Paper1_ZeroTrustAgent/results/evaluations_gcp/ \
#     ./results/evaluations_gcp/

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ -f .venv/bin/activate ]]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi

pip install -q tiktoken pyelftools capstone 2>/dev/null || true
sudo systemctl start ollama 2>/dev/null || true

export PYTHONPATH=src/python
export SENTINEL__LLM__BACKEND=ollama
export SENTINEL__LLM__FULL_MODEL=llama3.1:8b
export SENTINEL__LLM__DRAFT_MODEL=llama3.2:1b
export SENTINEL__LLM__TIMEOUT_SECONDS=300
export SENTINEL_EVAL_PLATFORM="GCP g2-standard-4 NVIDIA L4 Ubuntu $(uname -r)"
export SENTINEL_GIT_SHA="$(git rev-parse HEAD 2>/dev/null || echo unknown)"

OUT=results/evaluations_gcp
DARPA="${DARPA_PATH:-data/darpa/ta1-cadets-e3-official.json.2}"
LOG="$OUT/gcp_chain.log"

mkdir -p "$OUT" results/logs data/input/real_traces

meta() {
  local src="$1" dst="$2"
  python3 scripts/add_meta_to_json.py "$src" "$dst"
}

run() {
  local name="$1"; shift
  echo ""
  echo "════════════════════════════════════════"
  echo "▶ $name  $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
  echo "════════════════════════════════════════"
  "$@"
}

# ── Phase 0: unit tests (no LLM) ─────────────────────────────────────────────
run "make test" make test

# ── Phase 1: non-LLM / fast measurements ─────────────────────────────────────
run "benchmark-overhead" \
  python3 src/python/benchmark_overhead.py --out "$OUT/overhead_gcp.json"

run "ipg-token-reduction" \
  python3 src/python/measure_ipg_token_reduction.py
meta results/evaluations/ipg_token_reduction.json "$OUT/ipg_token_reduction_gcp.json"

run "ltl-fpr-real" \
  python3 src/python/evaluate_ltl_real.py --out "$OUT/ltl_fpr_real_gcp.json"

run "pcabp-real-nginx" \
  env PCABP_OUT_PATH="$OUT/pcabp_real_nginx_gcp.json" \
      PCABP_CSM_PATH="src/python/sentinel/pcabp/nginx_callsites_x86_64_gcp.pkl" \
  python3 scripts/pcabp_real_nginx.py

# ── Phase 2: LLM evaluations ─────────────────────────────────────────────────
run "eval-scenarios (14 MITRE)" \
  python3 src/python/measure_scenarios.py
meta results/evaluations/scenario_results.json "$OUT/scenario_results_gcp.json"

run "dual-tier-reduction" \
  python3 src/python/measure_dual_tier_reduction.py
meta results/evaluations/dual_tier_reduction.json "$OUT/dual_tier_reduction_gcp.json"

run "capture-real-traces" \
  bash src/python/capture_real_traces.sh

run "eval-real (≥50 benign + ≥50 attack)" \
  python3 src/python/evaluate_real_data.py
meta results/evaluations/real_data_results.json "$OUT/real_data_results_gcp.json"

run "eval-calibration (ECE)" \
  python3 src/python/measure_calibration.py
meta results/evaluations/calibration_results.json "$OUT/calibration_results_gcp.json"

# ── Phase 3: DARPA TC (requires dataset at $DARPA) ───────────────────────────
if [[ ! -f "$DARPA" ]]; then
  echo "WARNING: DARPA dataset not found at $DARPA — skipping DARPA evals."
  echo "  Upload with: rsync -avP /path/to/ta1-cadets-e3-official.json.2 sentinel@VM:$DARPA"
else
  run "darpa-behavioral-v5 (hybrid Option A)" \
    python3 src/python/evaluate_darpa_tc.py \
      --dataset cadets --max-windows 100 \
      --strip-annotations --hard-fraction 0.5 \
      --detector-mode hybrid \
      --darpa-path "$DARPA" \
      --out "$OUT/darpa_tc_behavioral_v5_gcp.json"

  run "darpa-behavioral-v4 (llm_only baseline)" \
    python3 src/python/evaluate_darpa_tc.py \
      --dataset cadets --max-windows 100 \
      --strip-annotations --hard-fraction 0.5 \
      --detector-mode llm_only \
      --darpa-path "$DARPA" \
      --out "$OUT/darpa_tc_behavioral_v4_gcp.json"

  run "darpa-ti-aided (circularity caveat — not competitor comparable)" \
    python3 src/python/evaluate_darpa_tc.py \
      --dataset cadets --max-windows 100 \
      --hard-fraction 0.0 \
      --darpa-path "$DARPA" \
      --out "$OUT/darpa_tc_v8_ti_aided_gcp.json"

  run "darpa-ablation (5 modes)" \
    python3 src/python/evaluate_darpa_ablation.py \
      --dataset cadets --max-windows 100 \
      --strip-annotations --hard-fraction 0.5 \
      --darpa-path "$DARPA" \
      --out "$OUT/darpa_ablation_gcp.json"
fi

# ── Phase 4: manifest ────────────────────────────────────────────────────────
run "generate-manifest" python3 scripts/generate_manifest.py

echo ""
echo "=== GCP eval chain complete $(date -u) ==="
echo "Results: $OUT/"
ls -lh "$OUT"/*.json 2>/dev/null || true
