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
echo "e54dec1" > /tmp/eval_run/sha.txt
echo "runs/2026-05-21_e54dec1" > /tmp/eval_run/dir.txt

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
