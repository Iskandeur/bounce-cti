# Nightly EVAL_PROTOCOL routine — runnable prompt

This is the canonical prompt for the **nightly autonomous improvement run**
(Claude Code web scheduled session). Paste it into the trigger. It is the v3
successor to the original night-routine prompt: same shape (clone → run against
prod → score → ship one fix → push), but decay-proof scoring, a tighter
fresh-subset default, and the quota-survival + restart-safety lessons baked in.

> **Secrets stay in the trigger config, NOT in this file.** The placeholders
> `<AUTH_PIN>` and `<ADMIN_PIN>` must be supplied by the scheduled-trigger
> environment (or the env-var/setup-script of the Claude Code environment).
> Never commit the literal PINs to the repo.

---

## TASK (paste into the scheduled trigger)

You are running the **next nightly iteration** of `EVAL_PROTOCOL.md` (v3) against
the live Bounce-CTI deployment. Read `EVAL_PROTOCOL.md` first — it defines the
two-track scoring (CAP headline + freshness-gated REC), the failure taxonomy,
the cadence, and the artifact layout. Execute end-to-end, ship the single
highest-leverage mechanical fix you identify, and push to `main`. Stay
autonomous — do not ask questions.

### Environment
- **Target**: https://bounce.alexandre-pinoteau.fr/
- **Auth** (POST `/api/auth/login {"pin": "<AUTH_PIN>"}`): supplied by the trigger.
- **Model whitelist**: only `opus-4.7`. Use it; don't waste a round-trip discovering this.
- **Lessons-learned ledger** (admin): `POST /api/auth/login {"pin": "<ADMIN_PIN>"}`
  then `GET /api/admin/lessons_learned`. Pull it after the run — it is the agent's
  own diagnosis of blockers/waste and is the best source of mechanical-fix ideas.
- **Repo**: you are inside it. Harness is `eval/` (cases, runner, scorer, render).
- **Deploy**: `git push origin main` → immediate VPS redeploy via
  `.github/workflows/deploy.yml`. No staging, no rollback. Frontend rebuilds only
  if `frontend/` changed; Python deps only if `requirements.txt` changed.
- **Sandbox network is restrictive** (DNS/crt.sh blocked). Do NOT build
  verification that needs direct external lookups — the Bounce backend has egress;
  your harness only talks to the backend.

### EXCEPTIONAL MEASURE — one-by-one, quota-survivable (overrides everything below)
The backend `claude -p` investigations burn the **same** Anthropic 5-hour window
as this session. **Run cases sequentially, never in parallel.** The `eval/`
harness already handles this: it waits on the `/api/quota` window and resumes
`quota_exceeded` investigations in place (`POST /api/investigations/{id}/resume`),
retries 429 submits, and records each `inv_id` at submit-time so a mid-wait
death never spawns a duplicate. If the window dies, this session may halt and be
restarted manually — the run must resume cleanly (see Recovery).

### Scope (decide by cadence)
- **Default (nightly CI)**: the **fresh subset** — Cases **2, 3, 8, 9, 12**
  (decay-resistant: hashes don't decay + recent marker-pivot domains) + the
  **negative cases** (N1–N3). Fits one 5-hour window. This is what you run unless
  it's a weekly/milestone night.
- **Weekly / milestone** (e.g. Sunday, or when explicitly told): the **full 12 +
  negatives**, refresh the Case-11 seed (pick a fresh Smishing-Triad FQDN per
  §3 — NameSilo + Cloudflare + abused TLD + toll/USPS lure, distinct from recent
  runs) and re-confirm the §3 decay verdicts.

### Procedure
1. **Capture the SHA** (`git rev-parse --short HEAD`) before any fix — the run
   dir is `runs/$(date -u +%Y-%m-%d)_<sha>/`. Confirm `HEAD == origin/main` so
   you're scoring deployed code.
2. **Read the most recent `runs/*/`** scorecard + proposed_fixes; note any item
   marked deferred/next-iteration and any prior **CAP** per case (your delta
   baseline). Regression on **CAP** for any case is P0.
3. **Set up + launch the harness** (one detached runner only — verify exactly one
   `sequential_runner.py` PID, PPID 1):
   ```
   mkdir -p /tmp/eval_run && cp eval/*.py /tmp/eval_run/
   echo "<sha>" > /tmp/eval_run/sha.txt
   echo "runs/$(date -u +%F)_<sha>" > /tmp/eval_run/dir.txt
   echo '{"started":'"$(date +%s)"',"cases":{}}' > /tmp/eval_run/meta.json
   # login → /tmp/cookies.txt (see eval/README.md), then:
   cd /tmp/eval_run && FORCE_NEW=1 setsid nohup python3 sequential_runner.py <case ids> < /dev/null >> runner_stdout.log 2>&1 &
   ```
   Then **idle-wait** with a single backgrounded waiter (`until grep -q 'ALL DONE'
   runner.log || ! kill -0 <pid>; do sleep 90; done`) — do not actively poll;
   that competes with the backend for the shared quota.
4. **Score**: `python3 scorer.py` (emits CAP/REC + freshness gate + negatives) →
   `python3 render_reports.py`. CAP is the headline. Hand-audit the hallucination
   heuristic on the largest graphs (never trust the heuristic alone for the 0% gate).
5. **Pull the lessons-learned ledger** (admin) — aggregate blockers / missing
   capabilities / suggestions; this is your top fix-idea source.
6. **Write the 5 report files** (§6 layout) into the run dir. Flag DATA_DECAYED
   cases, CAP regressions, borderline terminals, and any quota-throttle.
7. **Ship ONE mechanical fix** (§6 priority): F-HALLUCINATION → CAP-regression →
   F-SRC-ABSENT(≥3) → top F-PIVOT-MISS/F-DEFUSE/F-OVER-ATTRIBUTION. **Prefer**
   `_missing_mandatory_tools` / `_adaptive_followup_targets` /
   `pivot_mapping._PIVOT_RULES` / `backend/hints.py` over `SYSTEM_PROMPT` prose.
   Log exogenous misses (F-DATA-DECAYED, F-SRC-TOKEN-DEAD) under **ops-actions**
   (seed refresh, token renewal) — do NOT "fix" them in code.
   - **Standing engineering objective** (do incrementally on idle budget): build
     the §4.C deterministic **fixture-replay** capability track — snapshot the
     fresh-subset source responses under `eval/fixtures/` so CAP becomes
     byte-reproducible.
8. **Verify + ship**: Python import check
   (`python3 -c "from backend import agent_runner, hints, pivot_mapping, key_pool"`
   — needs `pip install python-dotenv` in the sandbox; py_compile the MCP servers,
   which need the `mcp` SDK). Don't block on the frontend build unless you touched
   `frontend/`. Commit (list failure modes + cite the run dir; update docs in the
   same commit per CLAUDE.md). FF-merge the dev branch into `main`, push, and poll
   `/api/auth/me` until 200 (expect a ~30–90 s 502 restart window).

### Gate (fail the run if)
- any **hallucination** (untraceable node/edge),
- any **CAP regression** vs the prior run on any case,
- the **PS floor** (<70) or **restraint floor** (<80, incl. negatives) breached.
Recall (REC) decay never fails the gate.

### Recovery (container reclaim / session restart)
`/tmp` may be wiped on a full reclaim. To resume after a manual restart:
- Re-login (PIN from the trigger), `git checkout` the dev branch (harness lives there).
- **Recovery anchor**: this run's investigations are the ones with
  `created_at >= <run-start epoch>` (record it in the run dir's `meta` and in your
  first status message). Re-derive each case's `inv_id` by matching its seed to
  the newest investigation with `created_at >= run-start` (prior-run invs are
  older; the Case-11 seed is unique), rebuild `/tmp/eval_run/meta.json`, then
  relaunch the runner — it resumes/continues tracked invs (never resubmits).
- If the runner is alive and `/api/quota` shows exhausted, do nothing — it
  self-heals when the window refills.

### Constraints
- VirusTotal free tier ~4 req/min; Phase-3 sources have their own quotas —
  `{"error": "no <X> key ... exhausted"}` is expected graceful degradation, not a
  regression.
- Each claude-phase has a 20-min watchdog; the fresh subset should finish in
  ~1–2 h, full-12 in ~3–6 h (longer if it crosses a quota window).
- Never touch `.env`, `data/`, or any secret. Don't force-push or skip hooks.
- You have authorization to push to `main` for this task.

### Done when
- `runs/<today>_<sha>/` has the 5 report files,
- the one fix is on `main` and live (service back at 200),
- you've posted a short summary: **Δ-CAP vs prior**, the fix shipped, floors still
  breached, the LIVE/REC count + decayed list, top ops-action (e.g. refresh
  `OPENCTI_TOKEN` if F-SRC-TOKEN-DEAD), and one sentence on next iteration's priority.
