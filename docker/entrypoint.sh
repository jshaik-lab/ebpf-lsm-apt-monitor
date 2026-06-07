#!/bin/bash
# SENTINEL container entrypoint
# Waits for Ollama (if configured), then starts the agent.
# Logs go to: /var/log/sentinel/  → bind-mounted to results/logs/ on host Mac
set -euo pipefail

OLLAMA_URL="${SENTINEL__LLM__OLLAMA_URL:-}"
WAIT_TIMEOUT=120
WAIT_INTERVAL=3
LOG_DIR="/sentinel/results/logs"

# Ensure log and results directories exist (bind-mount creates the parent dir
# on the host, but the subdirs may not exist yet on a fresh Linux server).
mkdir -p "$LOG_DIR" /sentinel/results/evaluations

# Startup banner — visible in `docker compose logs sentinel`
echo "[entrypoint] ============================================"
echo "[entrypoint] SENTINEL starting at $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "[entrypoint] Results dir : /sentinel/results/  (bind → project results/)"
echo "[entrypoint] Audit log   : ${LOG_DIR}/audit.jsonl"
echo "[entrypoint] Incidents   : ${LOG_DIR}/incidents.jsonl"
echo "[entrypoint] Evaluations : /sentinel/results/evaluations/"
echo "[entrypoint] ============================================"

# If Ollama URL is set, wait for it to be healthy
if [[ -n "$OLLAMA_URL" ]]; then
    echo "[entrypoint] Waiting for Ollama at ${OLLAMA_URL} (timeout ${WAIT_TIMEOUT}s)..."
    elapsed=0
    until curl -sf "${OLLAMA_URL}/api/tags" > /dev/null 2>&1; do
        if [[ $elapsed -ge $WAIT_TIMEOUT ]]; then
            echo "[entrypoint] ⚠ WARNING: Ollama not ready after ${WAIT_TIMEOUT}s"
            echo "[entrypoint] ⚠ SENTINEL will fall back to mock LLM classifier"
            echo "[entrypoint] ⚠ Detections will use heuristic rules, not Llama-3.1-8B"
            break
        fi
        echo "[entrypoint] Ollama not ready yet (${elapsed}/${WAIT_TIMEOUT}s)..."
        sleep $WAIT_INTERVAL
        elapsed=$((elapsed + WAIT_INTERVAL))
    done
    if curl -sf "${OLLAMA_URL}/api/tags" > /dev/null 2>&1; then
        echo "[entrypoint] ✓ Ollama is ready at ${OLLAMA_URL}"
    fi
fi

echo "[entrypoint] Starting SENTINEL agent..."
exec python /sentinel/src/python/main.py "$@"
