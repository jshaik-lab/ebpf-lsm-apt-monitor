#!/usr/bin/env bash
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOG="$ROOT/results/evaluations/progress_monitor.log"
while true; do
  sleep 120
  bash "$ROOT/scripts/monitor_progress.sh" 999999 2>/dev/null &
  MP=$!
  sleep 8
  kill $MP 2>/dev/null || true
  SNAPSHOT=$(tail -12 "$LOG" 2>/dev/null | grep -v '^Monitor started' | tail -10)
  echo "AGENT_LOOP_TICK_PROGRESS {\"prompt\":\"Read results/evaluations/progress_monitor.log tail and give user a brief progress update with ETA. Stop loop when DARPA rsync, Mac capture, and VPS capture are all DONE.\",\"snapshot\":$(python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))' <<< "$SNAPSHOT")}"
done
