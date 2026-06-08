#!/usr/bin/env bash
# Resume GCP eval chain after overhead + ipg (or any partial progress).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
[[ -f .venv/bin/activate ]] && source .venv/bin/activate

export PYTHONPATH=src/python
export SENTINEL__LLM__BACKEND=ollama
export SENTINEL__LLM__FULL_MODEL=llama3.1:8b
export SENTINEL__LLM__DRAFT_MODEL=llama3.2:1b
export SENTINEL__LLM__TIMEOUT_SECONDS=300
export SENTINEL_EVAL_PLATFORM="GCP g2-standard-4 NVIDIA L4 Ubuntu $(uname -r)"
export SENTINEL_GIT_SHA="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
export SENTINEL_REQUIRE_GCP=1

if [[ "$(uname -s)" == "Darwin" ]]; then
  echo "ERROR: run_gcp_eval_resume.sh must run on GCP sentinel-gpu-vm, not Mac." >&2
  exit 1
fi

OUT=results/evaluations_gcp
DARPA="${DARPA_PATH:-data/darpa/ta1-cadets-e3-official.json.2}"
LOG="$OUT/gcp_chain.log"
mkdir -p "$OUT"

pip install -q tiktoken pyelftools capstone 2>/dev/null || true
sudo systemctl start ollama 2>/dev/null || true

meta() { python3 scripts/add_meta_to_json.py "$1" "$2"; }
run() {
  local name="$1"; shift
  echo "" | tee -a "$LOG"
  echo "▶ $name $(date -u)" | tee -a "$LOG"
  "$@" 2>&1 | tee -a "$LOG"
}

[[ -f "$OUT/overhead_gcp.json" ]]          || run "benchmark-overhead" python3 src/python/benchmark_overhead.py --out "$OUT/overhead_gcp.json"
[[ -f "$OUT/ipg_token_reduction_gcp.json" ]] || { run "ipg-token-reduction" python3 src/python/measure_ipg_token_reduction.py; meta results/evaluations/ipg_token_reduction.json "$OUT/ipg_token_reduction_gcp.json"; }
[[ -f "$OUT/ltl_fpr_real_gcp.json" ]]      || run "ltl-fpr-real" python3 src/python/evaluate_ltl_real.py --out "$OUT/ltl_fpr_real_gcp.json"
[[ -f "$OUT/pcabp_real_nginx_gcp.json" ]]  || run "pcabp-real-nginx" env PCABP_OUT_PATH="$OUT/pcabp_real_nginx_gcp.json" PCABP_CSM_PATH="$ROOT/src/python/sentinel/pcabp/nginx_callsites_x86_64_gcp.pkl" python3 scripts/pcabp_real_nginx.py
[[ -f "$OUT/toctou_race_gcp.json" && "${TOCTOU_FORCE:-0}" != "1" ]] \
  || run "toctou-race-benchmark" bash scripts/run_toctou_benchmark.sh 50000 "$OUT/toctou_race_gcp.json"
[[ -f "$OUT/scenario_results_gcp.json" ]]  || { run "eval-scenarios" python3 src/python/measure_scenarios.py; meta results/evaluations/scenario_results.json "$OUT/scenario_results_gcp.json"; }
[[ -f "$OUT/dual_tier_reduction_gcp.json" ]] || { run "dual-tier-reduction" python3 src/python/measure_dual_tier_reduction.py; meta results/evaluations/dual_tier_reduction.json "$OUT/dual_tier_reduction_gcp.json"; }
[[ -f "$OUT/real_data_results_gcp.json" ]] || { run "eval-real" python3 src/python/evaluate_real_data.py; meta results/evaluations/real_data_results.json "$OUT/real_data_results_gcp.json"; }
[[ -f "$OUT/real_data_fpr_breakdown_gcp.json" ]] || run "real-data-fpr-breakdown" python3 scripts/analyze_real_data_fpr.py "$OUT/real_data_results_gcp.json" --out "$OUT/real_data_fpr_breakdown_gcp.json"
[[ -f "$OUT/entropy_sensitivity_gcp.json" ]] || run "entropy-threshold-sensitivity" python3 scripts/entropy_threshold_sensitivity.py --traces data/input/real_traces --labels "$OUT/real_data_results_gcp.json" --out "$OUT/entropy_sensitivity_gcp.json"
[[ -f "$OUT/red_team_results_gcp.json" ]] || run "red-team-ollama" python3 src/python/evaluate_red_team.py --out "$OUT/red_team_results_gcp.json"
[[ -f "$OUT/calibration_results_gcp.json" ]] || { run "eval-calibration" python3 src/python/measure_calibration.py; meta results/evaluations/calibration_results.json "$OUT/calibration_results_gcp.json"; }

if [[ -f "$DARPA" ]]; then
  [[ -f "$OUT/darpa_tc_behavioral_v5_gcp.json" ]] || run "darpa-behavioral-v5" python3 src/python/evaluate_darpa_tc.py --dataset cadets --max-windows 100 --strip-annotations --hard-fraction 0.5 --detector-mode hybrid --darpa-path "$DARPA" --out "$OUT/darpa_tc_behavioral_v5_gcp.json"
  [[ -f "$OUT/darpa_tc_behavioral_v4_gcp.json" ]] || run "darpa-behavioral-v4-llm-only" python3 src/python/evaluate_darpa_tc.py --dataset cadets --max-windows 100 --strip-annotations --hard-fraction 0.5 --detector-mode llm_only --darpa-path "$DARPA" --out "$OUT/darpa_tc_behavioral_v4_gcp.json"
  [[ -f "$OUT/darpa_tc_v8_ti_aided_gcp.json" ]]   || run "darpa-ti-aided" python3 src/python/evaluate_darpa_tc.py --dataset cadets --max-windows 100 --hard-fraction 0.0 --darpa-path "$DARPA" --out "$OUT/darpa_tc_v8_ti_aided_gcp.json"
  [[ -f "$OUT/darpa_ablation_gcp.json" ]]         || run "darpa-ablation" python3 src/python/evaluate_darpa_ablation.py --dataset cadets --max-windows 100 --strip-annotations --hard-fraction 0.5 --darpa-path "$DARPA" --out "$OUT/darpa_ablation_gcp.json"
fi

run "generate-manifest" python3 scripts/generate_manifest.py
echo "=== RESUME COMPLETE $(date -u) ===" | tee -a "$LOG"
ls -lh "$OUT"/*.json 2>/dev/null | tee -a "$LOG"
