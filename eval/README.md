# Eval harness — recovery instructions

If the agent container restarted mid-run, reconstruct state as follows:

```bash
# 1. Login + persist cookies
mkdir -p /tmp/eval_run
curl -s -c /tmp/cookies.txt -X POST \
  -H 'Content-Type: application/json' \
  -d '{"pin":"995737"}' \
  https://bounce.alexandre-pinoteau.fr/api/auth/login

# 2. Copy harness back into /tmp/eval_run/
cp eval/*.py eval/*.sh /tmp/eval_run/
cp eval/meta.json /tmp/eval_run/
echo "$(git rev-parse --short HEAD)" > /tmp/eval_run/sha.txt
echo "runs/$(date -u +%Y-%m-%d)_$(git rev-parse --short HEAD)" > /tmp/eval_run/dir.txt

# 3. Fetch latest data for all cases
cd /tmp/eval_run && python3 fetch.py

# 4. Score + render
python3 scorer.py
python3 render_reports.py
```

The `meta.json` tracks per-case inv_ids on the production VPS. If you need
to re-run a quota_exceeded case, use:

```bash
cd /tmp/eval_run && python3 sequential_runner.py 4 5 6 7 8 9 10 11 12
```

For a **fresh iteration** (measure currently-deployed code, ignore any pinned
inv_ids and always submit new investigations), set `FORCE_NEW=1`:

```bash
cd /tmp/eval_run && FORCE_NEW=1 python3 sequential_runner.py 1 2 3 4 5 6 7 8 9 10 11 12
```

Notes for one-by-one discipline:
- Launch the runner fully detached (`setsid ... < /dev/null &`) so it survives
  shell-wrapper cleanup; then confirm exactly ONE `sequential_runner.py` PID
  (PPID 1) before walking away. Duplicate runners double VT's 4-req/min load.
- `wait_for_terminal` keeps polling a still-`running` backend past the soft
  deadline (up to a 120-min hard cap) instead of abandoning it — abandoning a
  live investigation to launch the next case causes accidental parallelism on
  the VPS, which burns the 5-hour Anthropic budget.
- A `quota_exceeded` case is resumed in place via `POST /resume` (no graph
  reset); a fresh-iteration `FORCE_NEW=1` run submits new instead.
