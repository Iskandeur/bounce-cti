# Eval harness — recovery instructions

If the agent container restarted mid-run, reconstruct state as follows.

The harness logs in as the eval bench user. Its PIN is **not** kept in this
repo — export `BOUNCE_EVAL_PIN` in the shell first, from wherever the operator
stores secrets. (An admin can issue a new one with
`POST /api/admin/users/<id>/rotate_pin`, which keeps the bench's investigations.)

```bash
# 1. Login + persist cookies
mkdir -p /tmp/eval_run
curl -s -c /tmp/cookies.txt -X POST \
  -H 'Content-Type: application/json' \
  -d "{\"pin\":\"$BOUNCE_EVAL_PIN\"}" \
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

## Bounce-CTI with the context pool (the "with web" arm)

`eval/baseline.py --arm web` gives the bare model the web. To give Bounce-CTI
the same reach, with everything it reads kept as capped leads that a source
tool must corroborate (`backend/context_pool.py`), run the cases with the
context pool forced on for those investigations only (admin cookie jar, as for
a capture below):

```bash
cd /tmp/eval_run && FORCE_NEW=1 BOUNCE_EVAL_CONTEXT_POOL=1 python3 sequential_runner.py 2 3 8 9 12
```

The runner gives up on a 403 (not admin) or a 409 (kill switch
`BOUNCE_CTX_ENABLED=0` on the server), and stops a run the server did not
acknowledge with `context_pool` and `context_pool_web` both true. `GET
/api/investigations/<id>/leads` then gives the corroboration rate (COR,
EVAL_PROTOCOL). Score with `eval/scorer.py` as usual. Note the scorer counts a
name (actor, family, tool) found in any node's metadata or tags, leads
included: report the score both with and without lead nodes, or a name the
model only read on the web counts as found.

## Prospective cases (no write-up yet, EVAL_PROTOCOL §4.E)

Seeds picked when first listed, every arm run in the same window, judged after a
horizon by what an independent feed lists later. The seeding rules and the
contamination rule are in §4.E: the code writes the batch's `seeds.json` before
any run.

```bash
B=/path/outside/the/repo/lot1                    # the batch: seeds.json, then the seal
S="--server https://cti.alexandre-pinoteau.fr --cookies <admin jar>"
python3 eval/prospective.py seeds --batch $B $S --n 6     # once
python3 eval/prospective.py preflight --batch $B $S       # must exit 0 before any run
# Bounce-CTI: one investigation per seed on opus-5, ONE AT A TIME (~30 min each).
# Exit 5 = a run did not end done or is still going: run it again, it picks up
# where it stopped and never submits a seed twice. No bounce-cti merge meanwhile:
# a deploy restarts the service (the run is resumed, and the resume is recorded).
python3 eval/prospective.py bounce --batch $B --out $B-bounce $S
python3 eval/baseline.py run --arm web --model claude-opus-5 --out $B-base \
    --seeds $B/seeds.json P1 P2 P3 P4 P5 P6
python3 eval/prospective.py pivot --batch $B --out $B-pivot $S   # last: seal within the hour
python3 eval/prospective.py seal --batch $B --arm bounce=$B-bounce --arm web=$B-base/web \
    --arm pivot-1=$B-pivot $S
# seal refuses a run started over 48 h after its seed was first listed, a Bounce-CTI
# run not done, and a web run without an answer.
# copy $B/commitment.json to eval/prospective/<batch>/ and commit it TODAY
# (sha256 + counts, no value): its commit date is the pre-registration
python3 eval/prospective.py check --batch $B          # after due_at (exit 3 before)
python3 eval/prospective.py score --batch $B --write  # results.json + results.md
```

## Fixture sets (deterministic replay, EVAL_PROTOCOL §4.C)

Capture a case's source responses once, then replay them offline as often as
needed (mechanism: `backend/fixtures.py`).

```bash
# Capture one case, for that investigation only (no .env change). Capture is
# admin-only, so this run's cookie jar logs in with the ADMIN PIN (sent on stdin,
# so it stays out of the process list and the shell history).
printf '{"pin":"%s"}' "$BOUNCE_ADMIN_PIN" | curl -s -c /tmp/cookies.txt -X POST \
  -H 'Content-Type: application/json' -d @- https://bounce.alexandre-pinoteau.fr/api/auth/login
cd /tmp/eval_run && FORCE_NEW=1 BOUNCE_EVAL_CAPTURE=1 python3 sequential_runner.py 2
# The runner gives up on a 403 and stops a run the server did not acknowledge
# as captured. The investigation list shows "fixture_capture": 1 on it.

# From a WORKING checkout (files left untracked in the deployed one block its
# next git pull): promote that capture to the committed set, and check it.
python eval/fixture_tool.py promote <inv_id> case02 \
  --capture-root /opt/bounce-cti/data/fixtures/capture --dotenv /opt/bounce-cti/.env
python eval/fixture_tool.py stats case02

# Replay (dev instance only): every source answers from the set, network off.
BOUNCE_FIXTURE_DIR=eval/fixtures/case02 uvicorn backend.main:app --port 8001
wc -l data/fixtures/replay-misses/<inv_id>.jsonl      # report this next to the CAP
```

`verify` exits 1 if a value from this checkout's `.env` secrets, or a credential
shape inside a cache key, appears in a fixture. A credential shape inside a
response is only a warning: phishing URLs carry tokens. Read them before you
commit.

Before scoring, check that the event log is whole (on the VPS, read-only):

```bash
python3 eval/stream_audit.py --db data/bounce.db --since <start of the run, e.g. 2026-10-20T08:00Z>
```

Exit 1 means a phase exited without its `result` event in the log, or the
reader logged `agent_stream_error` / `agent_stdout_oversize`: the transcript
the scorer reads is cut and `cti_calls` undercounts. Exit 3 means no phase ran
in the window (wrong `--since`?): an empty window is never green. After a
deploy that touches the stream reader, add `--prove-fix` with the deploy time:
it also needs one line of 64 KiB or more logged in full before it says 0. Every run under
`runs/` predates the 2026-10-15 fix: 62 of their 99 scored investigations still
in the database are cut this way (EVAL_PROTOCOL §4.A note).

## Demo snapshots (static demo, roadmap J3)

A scored investigation can also become a page anyone opens with no PIN:
`python3 eval/demo_export.py <inv_id> case02 --db data/bounce.db --dotenv .env`
writes `eval/demo/case02.json`, and `npm run build:demo` (in `frontend/`) builds
the static viewer. How to make one, which run to pick, and what to check before
committing to this public repo: [`demo/README.md`](demo/README.md).
