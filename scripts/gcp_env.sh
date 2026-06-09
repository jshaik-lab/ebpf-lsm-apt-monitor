#!/usr/bin/env bash
# Shared GCP VM settings for Mac-side orchestration (source, do not execute).
# Override any variable in the environment or ~/.config/sentinel/gcp.env

GCP_PROJECT="${GCP_PROJECT:-project-ce92648b-727e-446c-9d7}"
GCP_ZONE="${GCP_ZONE:-us-east1-c}"
GCP_INSTANCE="${GCP_INSTANCE:-sentinel-gpu-vm}"
GCP_SSH_USER="${GCP_SSH_USER:-sentinel}"
GCP_SSH_KEY="${GCP_SSH_KEY:-$HOME/.ssh/id_ed25519_sentinel}"
GCP_REMOTE_DIR="${GCP_REMOTE_DIR:-ebpf-lsm-apt-monitor}"
GCP_SSH_OPTS="${GCP_SSH_OPTS:--o StrictHostKeyChecking=no -o ConnectTimeout=15 -o ServerAliveInterval=30}"

# IPs are NOT stored in git — load from ~/.config/sentinel/gcp.env
# GCP IP changes each time the VM restarts — get it with:
#   gcloud compute instances describe sentinel-gpu-vm --zone=us-east1-c \
#     --format='get(networkInterfaces[0].accessConfigs[0].natIP)'
GCP_VM_IP="${GCP_VM_IP:-}"
IONOS_VPS_IP="${IONOS_VPS_IP:-}"

# Load user overrides first so IPs are available for derived variables below
if [[ -f "$HOME/.config/sentinel/gcp.env" ]]; then
  # shellcheck disable=SC1091
  source "$HOME/.config/sentinel/gcp.env"
fi

# Derived convenience variables (built after overrides are loaded)
GCP_HOST="${GCP_HOST:-${GCP_SSH_USER}@${GCP_VM_IP}}"
IONOS_HOST="${IONOS_HOST:-root@${IONOS_VPS_IP}}"
