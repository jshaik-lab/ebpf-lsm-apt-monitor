#!/usr/bin/env bash
# deploy_to_ionos.sh — Deploy SENTINEL to IONOS VPS and run first evals.
# Requires: SSH key authorized on server (see docs/IONOS_SSH_SETUP.md)
# Optional: IONOS_ROOT_PASSWORD for first-time ssh-copy-id only.
set -euo pipefail

HOST="${IONOS_HOST:-sentinel-ionos}"
REPO="https://github.com/jshaik-lab/ebpf-lsm-apt-monitor.git"
ROOT="${IONOS_ROOT:-root@<IONOS-VPS-IP>}"
KEY="${IONOS_SSH_KEY:-$HOME/.ssh/id_ed25519_sentinel}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

ssh_ok() {
  ssh -i "$KEY" -o BatchMode=yes -o ConnectTimeout=10 "$ROOT" 'echo ok' 2>/dev/null
}

if ! ssh_ok; then
  if [[ -n "${IONOS_ROOT_PASSWORD:-}" ]] && command -v sshpass &>/dev/null; then
    echo "Attempting ssh-copy-id with IONOS_ROOT_PASSWORD..."
    sshpass -p "$IONOS_ROOT_PASSWORD" ssh-copy-id -i "${KEY}.pub" -o StrictHostKeyChecking=accept-new "$ROOT"
  else
    echo "ERROR: SSH to $ROOT failed."
    echo "Add the public key from docs/IONOS_SSH_SETUP.md via IONOS panel or KVM console."
    echo "Or: brew install sshpass && IONOS_ROOT_PASSWORD='...' $0"
    exit 1
  fi
fi

echo "=== Upload bootstrap script ==="
scp -i "$KEY" "$SCRIPT_DIR/bootstrap_ionos.sh" "$ROOT:/root/bootstrap_ionos.sh"

echo "=== Run bootstrap (20–40 min with model pull) ==="
ssh -i "$KEY" "$ROOT" "bash /root/bootstrap_ionos.sh '$REPO'"

echo "=== First validation runs ==="
ssh -i "$KEY" "$ROOT" "sudo -u sentinel bash -lc '
  cd ~/ebpf-lsm-apt-monitor
  source .venv/bin/activate
  make eval-scenarios
  make capture-traces
  make eval-real
  make eval-calibration
  make benchmark-overhead
'"

echo "=== Download results to Mac ==="
mkdir -p "$PROJECT_ROOT/results/evaluations_linux"
scp -i "$KEY" -r "$ROOT:/home/sentinel/ebpf-lsm-apt-monitor/results/evaluations/*" \
  "$PROJECT_ROOT/results/evaluations_linux/" 2>/dev/null || true

echo "Deploy complete. See results/evaluations_linux/ on Mac."
