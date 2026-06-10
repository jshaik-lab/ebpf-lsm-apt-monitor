#!/usr/bin/env bash
set -euo pipefail

cd /code
RESULTS_DIR="/results"
mkdir -p "$RESULTS_DIR"

echo "============================================================"
echo "SENTINEL — Simulation Mode + Unit Tests"
echo "============================================================"

echo "[1/2] Running unit tests..."
TESTS_DIR=$(find . -type d -name "tests" 2>/dev/null | grep -v __pycache__ | head -1)
if [ -z "$TESTS_DIR" ]; then
    echo "WARNING: no tests/ directory found, skipping"
else
    echo "Tests found at: $TESTS_DIR"
    PYTHONPATH=/code/src/python python -m pytest "$TESTS_DIR" -v --tb=short \
        --junitxml="$RESULTS_DIR/test_results.xml" || true
fi

echo "[2/2] Running simulation mode (mock LLM)..."
PYTHONPATH=/code/src/python \
SENTINEL__MODE=simulation \
SENTINEL__LLM__BACKEND=mock \
python src/python/main.py \
    --mode simulation \
    --llm-backend mock \
    --max-events 50 \
    > "$RESULTS_DIR/simulation_output.log" 2>&1 || true

echo "Simulation log:"
cat "$RESULTS_DIR/simulation_output.log" || true

echo "Done. Results in $RESULTS_DIR/"
