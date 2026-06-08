#!/usr/bin/env bash
# monitor_progress.sh — log job progress every 2 minutes (survives Cursor close if run with nohup)
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOG="$ROOT/results/evaluations/progress_monitor.log"
INTERVAL="${1:-120}"
KEY="${IONOS_SSH_KEY:-$HOME/.ssh/id_ed25519_sentinel}"
VPS="${GCP_HOST:-sentinel@34.74.43.57}"
DARPA_SRC="/Volumes/Extreme SSD/DARPA_TC/cadets/ta1-cadets-e3-official.json.2"
DARPA_SIZE=$(stat -f%z "$DARPA_SRC" 2>/dev/null || stat -c%s "$DARPA_SRC" 2>/dev/null || echo 0)

prev_bytes=0
prev_ts=$(date +%s)

snapshot() {
  local now ts elapsed rate eta_h eta_m
  now=$(date '+%Y-%m-%d %H:%M:%S')
  ts=$(date +%s)
  elapsed=$((ts - prev_ts))
  [[ $elapsed -lt 1 ]] && elapsed=1

  {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║  SENTINEL Progress  │  $now"
    echo "╠══════════════════════════════════════════════════════════════╣"

    # DARPA rsync (parse rsync log — file not visible on VPS until transfer completes)
    RSYNC_LOG="$ROOT/results/evaluations/darpa_rsync.log"
    if pgrep -f "ta1-cadets-e3-official.json.2" >/dev/null 2>&1; then
      RSYNC_LINE=$(grep -oE '[0-9]+%[^[:cntrl:]]*' "$RSYNC_LOG" 2>/dev/null | tail -1 || true)
      pct=$(echo "$RSYNC_LINE" | grep -oE '^[0-9]+%' | tr -d '%' || echo "?")
      eta_str=$(echo "$RSYNC_LINE" | grep -oE '[0-9]{2}:[0-9]{2}:[0-9]{2}' | tail -1 || echo "calculating…")
      rem_mb=$(python3 -c "
import re, pathlib
log = pathlib.Path('$RSYNC_LOG')
if log.exists():
    for line in reversed(log.read_text(errors='ignore').splitlines()):
        m = re.search(r'(\d+)\s+(\d+)%', line)
        if m:
            print(int(int(m.group(1))/1e6)); break
    else:
        print('?')
else:
    print('?')
" 2>/dev/null)
      tot_mb=$(python3 -c "print(f'{int($DARPA_SIZE/1e6)}')")
      printf "║  📦 DARPA rsync → VPS     %5s%%  (~%s / %s MB)  ETA ~%s\n" "$pct" "$rem_mb" "$tot_mb" "$eta_str"
      echo "║     Status: RUNNING"
    else
      echo "║  📦 DARPA rsync → VPS     100%   complete or stopped"
      echo "║     Status: DONE"
    fi

    # Mac capture
    mac_n=$(ls "$ROOT/data/input/real_traces/"*.log 2>/dev/null | wc -l | tr -d ' ')
    if pgrep -f "CAPTURE_MODE=docker.*capture_real_traces" >/dev/null 2>&1; then
      printf "║  🖥  Mac trace capture      %3s / ~100 traces   ETA ~%s\n" "$mac_n" "$(( (100 - mac_n) * 2 ))m (est)"
      echo "║     Status: RUNNING (docker)"
    else
      printf "║  🖥  Mac trace capture      %3s traces captured\n" "$mac_n"
      echo "║     Status: DONE"
    fi

    # VPS remote
    ssh -i "$KEY" -o BatchMode=yes -o ConnectTimeout=10 "$VPS" 'bash -s' <<REMOTE
APP=/home/sentinel/Paper1_ZeroTrustAgent
if pgrep -f measure_scenarios.py >/dev/null 2>&1; then
  DONE=\$(grep -cE '^\[OK\]|^\[FAIL\]' "\$APP/results/evaluations/scenario_results_linux.log" 2>/dev/null || echo 0)
  MOCK=\$(grep -c ollama_fallback_to_mock "\$APP/results/evaluations/scenario_results_linux.log" 2>/dev/null || echo 0)
  REM=\$((14 - DONE))
  ETA=\$((REM * 2))
  echo "║  🐧 VPS eval-scenarios     \${DONE}/14 scenarios   ETA ~\${ETA}m (est)"
  echo "║     Status: RUNNING  ⚠ mock_fallbacks=\${MOCK}"
elif grep -q "Accuracy:" "\$APP/results/evaluations/scenario_results_linux.log" 2>/dev/null; then
  ACC=\$(grep "Accuracy:" "\$APP/results/evaluations/scenario_results_linux.log" | tail -1 | sed 's/.*Accuracy: //')
  echo "║  🐧 VPS eval-scenarios     DONE  \${ACC}"
else
  echo "║  🐧 VPS eval-scenarios     not finished / not started"
fi
if pgrep -f capture_real_traces.sh >/dev/null 2>&1; then
  N=\$(ls "\$APP/data/input/real_traces/"*.log 2>/dev/null | wc -l)
  REM=\$((100 - N)); [[ \$REM -lt 0 ]] && REM=0
  echo "║  🐧 VPS native capture     \${N}/~100 traces   ETA ~\$((REM * 1))m (est)"
  echo "║     Status: RUNNING"
else
  N=\$(ls "\$APP/data/input/real_traces/"*.log 2>/dev/null | wc -l)
  echo "║  🐧 VPS native capture     \${N} traces"
  echo "║     Status: DONE"
fi
REMOTE

    echo "╚══════════════════════════════════════════════════════════════╝"
  } | tee -a "$LOG"
}

echo "Monitor started (interval=${INTERVAL}s) → $LOG"
while true; do
  snapshot
  # exit when all jobs done
  mac_run=0; rsync_run=0
  pgrep -f "CAPTURE_MODE=docker.*capture_real_traces" >/dev/null 2>&1 && mac_run=1
  pgrep -f "ta1-cadets-e3-official.json.2" >/dev/null 2>&1 && rsync_run=1
  vps_run=$(ssh -i "$KEY" -o BatchMode=yes -o ConnectTimeout=8 "$VPS" \
    'pgrep -f "measure_scenarios|capture_real_traces" >/dev/null && echo 1 || echo 0' 2>/dev/null || echo 1)
  if [[ $mac_run -eq 0 && $rsync_run -eq 0 && "$vps_run" == "0" ]]; then
    snapshot
    echo "All jobs complete — monitor exiting." | tee -a "$LOG"
    break
  fi
  sleep "$INTERVAL"
done
