#!/usr/bin/env bash
set -euo pipefail

export PYTHONPATH="${PYTHONPATH:-}/code/src/python"

RESULTS_DIR="/results"
mkdir -p "$RESULTS_DIR"

echo "============================================================"
echo "SENTINEL — Simulation Mode + Unit Tests"
echo "============================================================"

echo ""
echo "[1/2] Running unit tests (no LLM/kernel needed)..."
python -m pytest src/python/tests/ -v --tb=short \
    --junitxml="$RESULTS_DIR/test_results.xml" || true

echo ""
echo "[2/2] Running simulation mode (mock LLM)..."
SENTINEL__MODE=simulation \
SENTINEL__LLM__BACKEND=mock \
python src/python/main.py \
    --mode simulation \
    --llm-backend mock \
    --max-events 50 \
    > "$RESULTS_DIR/simulation_output.log" 2>&1 || true

echo ""
echo "Done. Results saved to $RESULTS_DIR/"
