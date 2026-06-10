#!/usr/bin/env bash
set -euo pipefail

cd /code
RESULTS_DIR="/results"
mkdir -p "$RESULTS_DIR"

echo "============================================================"
echo "SENTINEL — Simulation Mode + Unit Tests"
echo "============================================================"

echo "[1/2] Running unit tests..."
for TESTS_DIR in src/python/tests tests; do
    if [ -d "$TESTS_DIR" ]; then
        echo "Tests found at: $TESTS_DIR"
        PYTHONPATH=/code/src/python timeout 120 python -m pytest "$TESTS_DIR" \
            -v --tb=short --ignore="$TESTS_DIR/test_provenance_ml.py" \
            --junitxml="$RESULTS_DIR/test_results.xml" || true
        break
    fi
done

echo "[2/2] Running simulation mode (mock LLM)..."
PYTHONPATH=/code/src/python \
SENTINEL__MODE=simulation \
SENTINEL__LLM__BACKEND=mock \
timeout 60 python src/python/main.py \
    --mode simulation \
    --llm-backend mock \
    --max-events 50 \
    > "$RESULTS_DIR/simulation_output.log" 2>&1 || true

echo "Simulation log:"
cat "$RESULTS_DIR/simulation_output.log" || true

echo "Done. Results in $RESULTS_DIR/"
