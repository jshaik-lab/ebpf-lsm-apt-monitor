#!/usr/bin/env bash
# Wait for Mac-side gcp_orchestrate.sh to finish, then validate paper, build PDF, stop VM.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
source "$ROOT/scripts/gcp_env.sh"

LOG="$ROOT/results/evaluations_gcp/finalize.log"
mkdir -p "$ROOT/results/evaluations_gcp"

log() { echo "[finalize $(date '+%H:%M:%S')] $*" | tee -a "$LOG"; }

stop_vm() {
  log "Stopping GCP instance to save billing..."
  if command -v gcloud >/dev/null; then
    gcloud compute instances stop "$GCP_INSTANCE" --project="$GCP_PROJECT" --zone="$GCP_ZONE" --quiet \
      2>&1 | tee -a "$LOG" || log "WARNING: gcloud stop failed"
  fi
}
trap stop_vm EXIT

log "Waiting for gcp_orchestrate.sh to exit..."
while true; do
  if ! pgrep -f "scripts/gcp_orchestrate.sh" >/dev/null 2>&1; then
    break
  fi
  sleep 60
done
log "Orchestrator finished."

# Safety pull if orchestrate died before rsync
if command -v gcloud >/dev/null; then
  st="$(gcloud compute instances describe "$GCP_INSTANCE" --project="$GCP_PROJECT" --zone="$GCP_ZONE" --format='get(status)' 2>/dev/null || echo UNKNOWN)"
  if [[ "$st" == "RUNNING" ]]; then
    # shellcheck disable=SC1091
    source "$ROOT/scripts/gcp_lib.sh"
    refresh_host_ip
    if gcp_ssh "echo ok" >/dev/null 2>&1; then
      log "Extra rsync pull (safety)..."
      rsync_from_gcp "$ROOT" 2>&1 | tee -a "$LOG" || true
    fi
  fi
fi

log "Sync LTL paragraph from GCP JSON..."
python3 "$ROOT/scripts/sync_paper_ltl_from_gcp.py" 2>&1 | tee -a "$LOG" || true

log "Validate paper claims..."
if ! python3 "$ROOT/scripts/validate_paper_claims.py" 2>&1 | tee -a "$LOG"; then
  log "WARNING: validate_paper_claims failed — fix paper/main.tex before submission"
fi

log "Build paper PDF..."
bash "$ROOT/scripts/build_paper.sh" 2>&1 | tee -a "$LOG" || log "WARNING: paper build failed (see finalize.log)"

# stop_vm runs via EXIT trap (always, even on earlier failures)
exit 0
