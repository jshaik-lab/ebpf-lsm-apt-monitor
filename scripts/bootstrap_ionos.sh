#!/usr/bin/env bash
# bootstrap_ionos.sh — IONOS VPS baseline for SENTINEL (Ubuntu 24.04)
# Run as root on 74.208.76.97 after SSH is configured.
# Usage: bash bootstrap_ionos.sh [GITHUB_REPO_URL]
set -euo pipefail

REPO_URL="${1:-https://github.com/jshaik-lab/Paper1_ZeroTrustAgent.git}"
INSTALL_USER="${INSTALL_USER:-sentinel}"
APP_DIR="/home/${INSTALL_USER}/Paper1_ZeroTrustAgent"

log() { echo "[bootstrap] $*"; }

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run as root: sudo bash $0" >&2
  exit 1
fi

log "Platform: $(uname -a)"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get upgrade -y -qq
apt-get install -y -qq \
  git curl wget strace build-essential \
  python3 python3-pip python3-venv \
  clang llvm libbpf-dev \
  "linux-headers-$(uname -r)" \
  ufw docker.io docker-compose-v2 \
  sysbench

# Firewall — SSH only
ufw default deny incoming || true
ufw allow 22/tcp || true
ufw --force enable || true

systemctl enable --now docker

# Deploy user
if ! id "$INSTALL_USER" &>/dev/null; then
  adduser --disabled-password --gecos "" "$INSTALL_USER"
fi
usermod -aG docker "$INSTALL_USER"
mkdir -p "/home/${INSTALL_USER}/.ssh"
if [[ -f /root/.ssh/authorized_keys ]]; then
  cp /root/.ssh/authorized_keys "/home/${INSTALL_USER}/.ssh/"
  chown -R "${INSTALL_USER}:${INSTALL_USER}" "/home/${INSTALL_USER}/.ssh"
  chmod 700 "/home/${INSTALL_USER}/.ssh"
  chmod 600 "/home/${INSTALL_USER}/.ssh/authorized_keys" 2>/dev/null || true
fi

# Ollama (localhost only — do not expose 11434)
if ! command -v ollama &>/dev/null; then
  log "Installing Ollama..."
  curl -fsSL https://ollama.com/install.sh | sh
fi
systemctl enable ollama 2>/dev/null || true
systemctl start ollama 2>/dev/null || true
sleep 2

log "Pulling LLM models (10–30 min)..."
ollama pull llama3.1:8b
ollama pull llama3.2:1b
ollama list

# Clone repo
if [[ ! -d "$APP_DIR/.git" ]]; then
  sudo -u "$INSTALL_USER" git clone "$REPO_URL" "$APP_DIR"
else
  sudo -u "$INSTALL_USER" git -C "$APP_DIR" pull --ff-only || true
fi

sudo -u "$INSTALL_USER" bash -lc "
  cd '$APP_DIR'
  python3 -m venv .venv
  source .venv/bin/activate
  pip install -q -U pip
  pip install -q -r requirements-dev.txt
  make dirs
  make test
"

log "Bootstrap complete."
log "Next (as ${INSTALL_USER}):"
log "  cd ${APP_DIR} && source .venv/bin/activate"
log "  make eval-scenarios && make eval-real && make benchmark-overhead"
log "Platform metadata:"
uname -r
uname -m
free -h | head -2
