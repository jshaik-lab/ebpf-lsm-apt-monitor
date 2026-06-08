#!/usr/bin/env bash
# Phase-5 chain: run the 4 LLM evals back-to-back as `sentinel` with provenance.
# Logs go to results/evaluations/phase5_chain.log; JSONs use _ionos suffix.

set -uo pipefail

cd /home/sentinel/Paper1_ZeroTrustAgent
source .venv/bin/activate

export SENTINEL_EVAL_PLATFORM="IONOS VPS XL Ubuntu 24.04 $(uname -r); Ollama llama3.1:8b timeout=300s"
export SENTINEL_GIT_SHA=3658c7bc1b102e50d35d8d21c2797d32da6a4ee9
export SENTINEL__LLM__BACKEND=ollama
export SENTINEL__LLM__FULL_MODEL=llama3.1:8b
export SENTINEL__LLM__DRAFT_MODEL=llama3.2:1b
export SENTINEL__LLM__TIMEOUT_SECONDS=300
export PYTHONPATH=src/python

LOG=results/evaluations/phase5_chain.log
echo "=== Phase-5 chain start $(date -u) ===" | tee "$LOG"

run() {
    local name="$1"; shift
    echo ""                                                 | tee -a "$LOG"
    echo "──────────────────────────────────────────────"  | tee -a "$LOG"
    echo "▶ $name $(date -u)"                              | tee -a "$LOG"
    echo "──────────────────────────────────────────────"  | tee -a "$LOG"
    "$@" 2>&1 | tee -a "$LOG"
    echo "▶ done $name $(date -u)"                         | tee -a "$LOG"
}

# 1. eval-scenarios → rename to _ionos
run "eval-scenarios" \
    python3 src/python/measure_scenarios.py
[ -f results/evaluations/scenario_results.json ] && \
    python3 scripts/add_meta_to_json.py \
        results/evaluations/scenario_results.json \
        results/evaluations/scenario_results_ionos.json

# 2. eval-real → rename to _ionos
run "eval-real" \
    python3 src/python/evaluate_real_data.py
[ -f results/evaluations/real_data_results.json ] && \
    python3 scripts/add_meta_to_json.py \
        results/evaluations/real_data_results.json \
        results/evaluations/real_data_results_ionos.json

# 3. eval-calibration (needs eval-real to have written real_data_results.json)
run "eval-calibration" \
    python3 src/python/measure_calibration.py
[ -f results/evaluations/calibration_results.json ] && \
    python3 scripts/add_meta_to_json.py \
        results/evaluations/calibration_results.json \
        results/evaluations/calibration_results_ionos.json

# 4. DARPA TI-aided + CoVe ablation (the BIG one — ~3-4 hours)
run "darpa-ti-aided + cove-ablation" \
    python3 src/python/evaluate_darpa_tc.py \
        --dataset cadets --max-windows 100 \
        --darpa-path data/darpa/ta1-cadets-e3-official.json.2 \
        --cove-ablation \
        --out results/evaluations/darpa_tc_v8_ti_aided_ionos.json

echo "" | tee -a "$LOG"
echo "=== Phase-5 chain end $(date -u) ===" | tee -a "$LOG"
