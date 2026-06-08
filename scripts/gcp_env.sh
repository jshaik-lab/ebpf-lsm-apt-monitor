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

# Load user overrides
if [[ -f "$HOME/.config/sentinel/gcp.env" ]]; then
  # shellcheck disable=SC1091
  source "$HOME/.config/sentinel/gcp.env"
fi
