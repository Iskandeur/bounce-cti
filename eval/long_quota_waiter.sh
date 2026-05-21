#!/bin/bash
# Wait for Anthropic 5-hour quota to refill, then restart the runner.
# Quota typically refills 5 hours after the FIRST request in a window.
# Current window started at 22:25 UTC → reset at ~03:30 UTC.
# After reset, restart the sequential runner for cases 5-12.

LOG=/tmp/eval_run/long_waiter.log
exec > >(tee -a "$LOG") 2>&1
echo "[$(date -u +%H:%M:%S)] long_quota_waiter started"

# Sleep until 03:30 UTC (start of expected reset)
TARGET_EPOCH=$(date -u -d "tomorrow 03:30:00" +%s)
NOW=$(date +%s)
if [ "$TARGET_EPOCH" -le "$NOW" ]; then
  TARGET_EPOCH=$((NOW + 18000))  # 5h from now
fi
SLEEP_SECS=$((TARGET_EPOCH - NOW))
echo "[$(date -u +%H:%M:%S)] sleeping ${SLEEP_SECS}s until $(date -u -d @$TARGET_EPOCH +%H:%M:%S)"
sleep $SLEEP_SECS

# After sleep, poll the quota status by retry-loop
echo "[$(date -u +%H:%M:%S)] quota-window expired, probing recovery"
attempt=0
while [ $attempt -lt 6 ]; do
  attempt=$((attempt + 1))
  # Test with a quick resume of Case 5 (the quota_exceeded inv)
  inv_id="e49a2383c73d"
  before=$(curl -s -b /tmp/cookies.txt "https://bounce.alexandre-pinoteau.fr/api/investigations/$inv_id/transcript" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(len([e for e in d['entries'] if e.get('kind')=='tool']))" 2>/dev/null)
  curl -s -b /tmp/cookies.txt -X POST "https://bounce.alexandre-pinoteau.fr/api/investigations/$inv_id/resume" > /dev/null
  sleep 60
  after=$(curl -s -b /tmp/cookies.txt "https://bounce.alexandre-pinoteau.fr/api/investigations/$inv_id/transcript" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(len([e for e in d['entries'] if e.get('kind')=='tool']))" 2>/dev/null)
  echo "[$(date -u +%H:%M:%S)] attempt $attempt: before=$before after=$after"
  if [ "${after:-0}" -gt "${before:-0}" ] 2>/dev/null; then
    if [ "${after:-0}" -gt "$((${before:-0} + 2))" ]; then
      echo "[$(date -u +%H:%M:%S)] QUOTA BACK — kicking runner"
      curl -s -b /tmp/cookies.txt -X POST "https://bounce.alexandre-pinoteau.fr/api/investigations/$inv_id/stop" > /dev/null
      cd /tmp/eval_run && nohup python3 sequential_runner.py 4 5 6 7 8 9 10 11 12 >> runner_stdout.log 2>&1 &
      echo "[$(date -u +%H:%M:%S)] runner kicked"
      exit 0
    fi
  fi
  echo "[$(date -u +%H:%M:%S)] sleep 600s before next attempt"
  sleep 600
done
echo "[$(date -u +%H:%M:%S)] FAILED after 6 attempts, giving up"
exit 1
