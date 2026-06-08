#!/usr/bin/env bash
# Mac-side one-shot: start GCP VM → rsync code → run paper eval chain → pull results → stop VM.
#
# Usage:
#   bash scripts/gcp_orchestrate.sh              # resume missing steps (default)
#   bash scripts/gcp_orchestrate.sh --full       # full chain from scratch
#   bash scripts/gcp_orchestrate.sh --fresh      # wipe remote results then --full
#   bash scripts/gcp_orchestrate.sh --no-stop      # leave VM running after success
#   bash scripts/gcp_orchestrate.sh --sync-only  # rsync results back (VM must be up)
#   bash scripts/gcp_orchestrate.sh --deploy-only # start + rsync, no eval
#
# Requires: gcloud auth, ~/.ssh/id_ed25519_sentinel, GCP project access.
#
# Typical wall time: 6–10 h (--full with DARPA). Safe to run under nohup:
#   nohup bash scripts/gcp_orchestrate.sh --full > results/evaluations_gcp/orchestrate.log 2>&1 &

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# shellcheck disable=SC1091
source "$ROOT/scripts/gcp_env.sh"
# shellcheck disable=SC1091
source "$ROOT/scripts/gcp_lib.sh"

MODE="resume"       # resume | full
FRESH=0
NO_STOP=0
SYNC_ONLY=0
DEPLOY_ONLY=0
MONITOR_INTERVAL="${MONITOR_INTERVAL:-120}"
STOP_ON_ERROR=1

usage() {
  sed -n '2,20p' "$0" | sed 's/^# \?//'
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --full) MODE=full ;;
    --resume) MODE=resume ;;
    --fresh) FRESH=1; MODE=full ;;
    --no-stop) NO_STOP=1 ;;
    --sync-only) SYNC_ONLY=1 ;;
    --deploy-only) DEPLOY_ONLY=1 ;;
    -h|--help) usage 0 ;;
    *) echo "Unknown option: $1" >&2; usage 1 ;;
  esac
  shift
done

ORCH_LOG="$ROOT/results/evaluations_gcp/orchestrate.log"
mkdir -p "$ROOT/results/evaluations_gcp"

log() { echo "[orchestrate $(date '+%H:%M:%S')] $*" | tee -a "$ORCH_LOG"; }

cleanup() {
  local rc=$?
  if [[ "$NO_STOP" -eq 1 ]]; then
    log "Leaving VM running (--no-stop)"
    exit "$rc"
  fi
  if [[ "$STOP_ON_ERROR" -eq 1 || "$rc" -eq 0 ]]; then
    stop_instance 2>&1 | tee -a "$ORCH_LOG" || true
  else
    log "VM left running due to error (fix and re-run --sync-only or --resume)"
  fi
  exit "$rc"
}
trap cleanup EXIT

require_gcloud

log "=== SENTINEL GCP orchestration ==="
log "project=$GCP_PROJECT zone=$GCP_ZONE instance=$GCP_INSTANCE mode=$MODE"

ensure_instance_running
refresh_host_ip
wait_for_ssh 72

if [[ "$SYNC_ONLY" -eq 1 ]]; then
  rsync_from_gcp "$ROOT"
  log "Sync-only complete → results/evaluations_gcp/"
  exit 0
fi

rsync_to_gcp "$ROOT"
remote_bootstrap

if [[ "$DEPLOY_ONLY" -eq 1 ]]; then
  log "Deploy-only complete. Run eval manually or re-run without --deploy-only."
  exit 0
fi

GIT_SHA="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
REMOTE_SCRIPT="run_gcp_eval_resume.sh"
[[ "$MODE" == "full" ]] && REMOTE_SCRIPT="run_gcp_eval_chain.sh"

REMOTE_ENV=(
  "export SENTINEL_GIT_SHA=$GIT_SHA"
  "export SENTINEL_EVAL_PLATFORM=\"GCP g2-standard-4 NVIDIA L4 Ubuntu \$(uname -r)\""
  "export TOCTOU_FORCE=1"
  "export LTL_FORCE=1"
  "export ABLATION_FORCE=1"
)

if [[ "$FRESH" -eq 1 ]]; then
  log "Wiping stale remote results (--fresh)..."
  gcp_ssh "cd ~/${GCP_REMOTE_DIR} && bash scripts/cleanup_stale_results.sh" | tee -a "$ORCH_LOG"
fi

log "Launching remote eval: $REMOTE_SCRIPT"
gcp_ssh bash -s <<REMOTE | tee -a "$ORCH_LOG"
set -euo pipefail
cd ~/${GCP_REMOTE_DIR}
source .venv/bin/activate
${REMOTE_ENV[0]}
${REMOTE_ENV[1]}
${REMOTE_ENV[2]}
${REMOTE_ENV[3]}
${REMOTE_ENV[4]}
mkdir -p results/evaluations_gcp
nohup bash scripts/${REMOTE_SCRIPT} >> results/evaluations_gcp/gcp_chain.log 2>&1 &
echo \$! > /tmp/sentinel_gcp_eval.pid
echo "Remote PID=\$(cat /tmp/sentinel_gcp_eval.pid)"
REMOTE

monitor_remote_eval "$MONITOR_INTERVAL" "$ORCH_LOG"

# Verify exit status from remote log
if gcp_ssh "grep -q 'GCP eval chain complete\\|RESUME COMPLETE' ~/${GCP_REMOTE_DIR}/results/evaluations_gcp/gcp_chain.log 2>/dev/null"; then
  log "Eval chain reported success"
else
  log "WARNING: success marker not found in gcp_chain.log — check log before citing numbers"
fi

rsync_from_gcp "$ROOT"
log "Pulled artifacts:"
ls -lh "$ROOT/results/evaluations_gcp/"*.json 2>/dev/null | tee -a "$ORCH_LOG" || true

# Also mirror trace corpus counts for debugging (VM-owned; not overwritten on deploy)
gcp_ssh "ls ~/${GCP_REMOTE_DIR}/data/input/real_traces/*.log 2>/dev/null | wc -l" \
  | tee -a "$ORCH_LOG" || true

log "=== Syncing paper LTL paragraph from GCP JSON ==="
python3 "$ROOT/scripts/sync_paper_ltl_from_gcp.py" | tee -a "$ORCH_LOG" || true

log "=== Validating paper ↔ GCP JSON sync ==="
if ! python3 "$ROOT/scripts/validate_paper_claims.py" | tee -a "$ORCH_LOG"; then
  log "ERROR: validate_paper_claims.py failed — fix paper/main.tex or re-run eval before citing numbers"
  exit 1
fi

log "=== Done. Rebuild PDF: bash scripts/build_paper.sh ==="
