#!/usr/bin/env bash
# Abort unless running on GCP sentinel-gpu-vm (blocks Mac/local paper evals).
set -euo pipefail
if [[ "$(uname -s)" == "Darwin" ]]; then
  echo "ERROR: paper evaluations must run on GCP sentinel-gpu-vm, not Mac." >&2
  echo "  Dev on Mac: make test, lint, edit, rsync — then bash scripts/run_gcp_eval_chain.sh on VM." >&2
  exit 1
fi
if [[ -z "${SENTINEL_EVAL_PLATFORM:-}" ]] || [[ "${SENTINEL_EVAL_PLATFORM}" != *GCP* ]]; then
  echo "ERROR: set SENTINEL_EVAL_PLATFORM (run_gcp_eval_chain.sh does this automatically)." >&2
  exit 1
fi
