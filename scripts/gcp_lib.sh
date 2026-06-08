#!/usr/bin/env bash
# GCP helper functions (source after gcp_env.sh).

_gcp_log() { echo "[gcp $(date '+%H:%M:%S')] $*"; }

gcloud_cmd() {
  gcloud "$@" --project="$GCP_PROJECT" --zone="$GCP_ZONE"
}

require_gcloud() {
  command -v gcloud >/dev/null || {
    echo "ERROR: gcloud not found. Install: brew install google-cloud-sdk" >&2
    exit 1
  }
  command -v rsync >/dev/null || {
    echo "ERROR: rsync not found." >&2
    exit 1
  }
  [[ -f "$GCP_SSH_KEY" ]] || {
    echo "ERROR: SSH key missing: $GCP_SSH_KEY" >&2
    exit 1
  }
}

instance_status() {
  gcloud_cmd compute instances describe "$GCP_INSTANCE" --format='get(status)' 2>/dev/null || echo "UNKNOWN"
}

instance_ip() {
  gcloud_cmd compute instances describe "$GCP_INSTANCE" \
    --format='get(networkInterfaces[0].accessConfigs[0].natIP)' 2>/dev/null
}

wait_for_status() {
  local want="$1" timeout="${2:-600}" elapsed=0
  while (( elapsed < timeout )); do
    local st
    st="$(instance_status)"
    [[ "$st" == "$want" ]] && return 0
    _gcp_log "  instance status=$st (waiting for $want)..."
    sleep 10
    elapsed=$((elapsed + 10))
  done
  echo "ERROR: timed out waiting for instance status=$want" >&2
  return 1
}

ensure_instance_running() {
  local st
  st="$(instance_status)"
  case "$st" in
    RUNNING)
      _gcp_log "Instance already RUNNING"
      return 0
      ;;
    TERMINATED|STOPPED|SUSPENDED|UNKNOWN)
      _gcp_log "Starting $GCP_INSTANCE (was: $st)..."
      gcloud_cmd compute instances start "$GCP_INSTANCE" --quiet
      wait_for_status RUNNING 600
      ;;
    STAGING|PROVISIONING|REPAIRING|STOPPING)
      wait_for_status RUNNING 600
      ;;
    *)
      echo "ERROR: unexpected instance status: $st" >&2
      return 1
      ;;
  esac
}

gcp_ssh() {
  ssh -i "$GCP_SSH_KEY" $GCP_SSH_OPTS "${GCP_SSH_USER}@${GCP_HOST}" "$@"
}

wait_for_ssh() {
  local retries="${1:-60}"
  _gcp_log "Waiting for SSH on ${GCP_HOST}..."
  while (( retries > 0 )); do
    if gcp_ssh "echo ok" >/dev/null 2>&1; then
      _gcp_log "SSH ready"
      return 0
    fi
    sleep 5
    retries=$((retries - 1))
  done
  echo "ERROR: SSH not reachable on ${GCP_HOST}" >&2
  return 1
}

refresh_host_ip() {
  GCP_HOST="$(instance_ip)"
  if [[ -z "$GCP_HOST" ]]; then
    echo "ERROR: could not resolve external IP for $GCP_INSTANCE" >&2
    return 1
  fi
  _gcp_log "VM IP: $GCP_HOST"
}

rsync_to_gcp() {
  local root="$1"
  _gcp_log "Rsync code → ${GCP_SSH_USER}@${GCP_HOST}:~/${GCP_REMOTE_DIR}/"
  rsync -avz --delete \
    -e "ssh -i $GCP_SSH_KEY $GCP_SSH_OPTS" \
    --exclude '.venv/' \
    --exclude '.git/' \
    --exclude '.cursor/' \
    --exclude '__pycache__/' \
    --exclude '*.pyc' \
    --exclude '.pytest_cache/' \
    --exclude 'results/evaluations_gcp/' \
    --exclude 'results/evaluations/' \
    --exclude 'results/evaluations_linux/' \
    --exclude 'results/logs/' \
    --exclude 'paper/main.aux' \
    --exclude 'paper/main.log' \
    --exclude 'paper/main.out' \
    --exclude 'paper/main.bbl' \
    --exclude 'paper/main.blg' \
    --exclude 'paper/main.fls' \
    --exclude 'paper/main.fdb_latexmk' \
    --exclude 'data/input/real_traces/' \
    --exclude 'data/darpa/' \
    --exclude 'scripts/toctou/build/bpftool-src/' \
    "$root/" "${GCP_SSH_USER}@${GCP_HOST}:~/${GCP_REMOTE_DIR}/"

  # Deploy metadata (VM has no git)
  local sha
  sha="$(git -C "$root" rev-parse HEAD 2>/dev/null || echo unknown)"
  gcp_ssh "printf '%s\n' 'GIT_SHA=$sha' 'DEPLOYED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)' > ~/${GCP_REMOTE_DIR}/.sentinel_deploy_meta"
}

rsync_from_gcp() {
  local root="$1"
  mkdir -p "$root/results/evaluations_gcp" "$root/results/evaluations" "$root/results/logs"

  _gcp_log "Rsync results ← GCP"
  rsync -avz \
    -e "ssh -i $GCP_SSH_KEY $GCP_SSH_OPTS" \
    "${GCP_SSH_USER}@${GCP_HOST}:~/${GCP_REMOTE_DIR}/results/evaluations_gcp/" \
    "$root/results/evaluations_gcp/"

  rsync -avz \
    -e "ssh -i $GCP_SSH_KEY $GCP_SSH_OPTS" \
    "${GCP_SSH_USER}@${GCP_HOST}:~/${GCP_REMOTE_DIR}/results/evaluations/" \
    "$root/results/evaluations/" 2>/dev/null || true

  rsync -avz \
    -e "ssh -i $GCP_SSH_KEY $GCP_SSH_OPTS" \
    "${GCP_SSH_USER}@${GCP_HOST}:~/${GCP_REMOTE_DIR}/results/logs/" \
    "$root/results/logs/" 2>/dev/null || true

  rsync -avz \
    -e "ssh -i $GCP_SSH_KEY $GCP_SSH_OPTS" \
    "${GCP_SSH_USER}@${GCP_HOST}:~/${GCP_REMOTE_DIR}/.sentinel_deploy_meta" \
    "$root/.sentinel_deploy_meta" 2>/dev/null || true
}

stop_instance() {
  _gcp_log "Stopping $GCP_INSTANCE (save compute billing)..."
  gcloud_cmd compute instances stop "$GCP_INSTANCE" --quiet || true
}

remote_bootstrap() {
  _gcp_log "Ensuring remote venv + Ollama + PCABP bloom filter..."
  gcp_ssh "GCP_REMOTE_DIR=$GCP_REMOTE_DIR bash -s" <<'REMOTE'
set -euo pipefail
cd ~/"$GCP_REMOTE_DIR"
if [[ ! -d .venv ]]; then
  python3 -m venv .venv
fi
source .venv/bin/activate
echo "[bootstrap] pip install..."
pip install -q -r requirements-dev.txt 2>/dev/null || pip install -r requirements-dev.txt
sudo systemctl start ollama 2>/dev/null || true
mkdir -p results/evaluations_gcp results/evaluations results/logs data/input/real_traces data/darpa
PCABP_OUT="src/python/sentinel/pcabp/nginx_callsites_x86_64_gcp.pkl"
if [[ ! -f "$PCABP_OUT" ]]; then
  echo "[bootstrap] rebuilding PCABP bloom filter from /usr/sbin/nginx..."
  python3 scripts/rebuild_pcabp_x86.py
fi
echo "[bootstrap] done"
REMOTE
}

remote_eval_running() {
  gcp_ssh "bash -c 'pid=\$(cat /tmp/sentinel_gcp_eval.pid 2>/dev/null || echo); [[ -n \"\$pid\" ]] && kill -0 \"\$pid\" 2>/dev/null && tr \"\\0\" \" \" < /proc/\$pid/cmdline 2>/dev/null | grep -q run_gcp_eval'" \
    2>/dev/null
}

print_remote_progress() {
  gcp_ssh "GCP_REMOTE_DIR=$GCP_REMOTE_DIR bash -s" <<'REMOTE' 2>/dev/null || true
APP=~/"$GCP_REMOTE_DIR"
LOG="$APP/results/evaluations_gcp/gcp_chain.log"
echo "── remote progress $(date -u '+%H:%M:%S UTC') ──"
if [[ -f "$LOG" ]]; then
  grep -E '^▶ |^=== |ERROR|WARNING' "$LOG" 2>/dev/null | tail -8 || tail -5 "$LOG"
else
  echo "(no gcp_chain.log yet)"
fi
n=$(ls "$APP/results/evaluations_gcp/"*_gcp.json 2>/dev/null | wc -l | tr -d ' ')
echo "JSON artifacts: ${n} files in evaluations_gcp/"
if pgrep -f 'run_gcp_eval_chain|run_gcp_eval_resume' >/dev/null; then
  echo "Status: EVAL RUNNING"
else
  echo "Status: eval process not running"
fi
REMOTE
}

monitor_remote_eval() {
  local interval="${1:-120}" log_file="$2"
  _gcp_log "Monitoring eval (poll every ${interval}s). Local mirror: $log_file"
  while remote_eval_running; do
    {
      echo ""
      echo "══════════════════════════════════════════════════════════════"
      date -u '+%Y-%m-%d %H:%M:%S UTC'
      print_remote_progress
      echo "══════════════════════════════════════════════════════════════"
    } | tee -a "$log_file"
    # Mirror tail of remote log locally
    gcp_ssh "tail -n 30 ~/${GCP_REMOTE_DIR}/results/evaluations_gcp/gcp_chain.log 2>/dev/null" \
      >> "$log_file" 2>/dev/null || true
    sleep "$interval"
  done
  _gcp_log "Remote eval process finished"
  print_remote_progress | tee -a "$log_file"
}
