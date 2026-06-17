# Proposed Fixes — 2026-06-17 (90c516b)

The nightly run was **blocked** before any case scored, so this list is driven
by the blocker diagnosis rather than capability gaps. Priorities are ordered by
what unblocks the eval and protects production.

## P0 — `claude` binary off the service PATH (BLOCKER) — FIXED (`c53a4eb`)

**Symptom.** Every `claude -p` investigation spawned and produced zero
`stream-json` output — 0 tool calls, 0 nodes — leaving a zombie `running` state.

**Confirmed cause.** The `claude` CLI moved to `/home/bounce/.local/bin/claude`
(Claude Code native installer), which is **not on the systemd service's PATH**
(`…:/usr/bin:/snap/bin`). `agent_runner` used `shutil.which("claude") → None`,
fell back to the bare name, and `create_subprocess_exec` raised
`FileNotFoundError` (recorded verbatim as `agent_error` in `data/bounce.db`). A
secondary bug — the `FileNotFoundError` handler returned a 3-tuple while callers
unpack 4 — crashed `run_investigation` and produced the zombie `running` status
instead of a clean failure.

> The earlier "June-15 subscription-subsidy removal" guess was **wrong**: that
> change was postponed (Anthropic email 2026-06-15), and manual `claude -p` on
> the VPS authenticates and runs end-to-end.

**Fix (shipped, commit `c53a4eb`, PR #19).**
1. `agent_runner._resolve_claude_bin()` — after the PATH lookup, probe
   `~/.local/bin`, `~/.npm-global/bin`, `/usr/local/bin`, `/usr/bin`.
2. The `FileNotFoundError` handler returns the proper 4-tuple, so a missing CLI
   fails cleanly (`error rc=None`) instead of a zombie `running`.
3. **Operational unblock (applied):** `CLAUDE_BIN=/home/bounce/.local/bin/claude`
   in `.env` + service restart.

**Hardening follow-up (still open).** Add a **"no first event within N seconds"**
watchdog in `_run_claude_phase`: if `claude -p` emits no `stream-json` within
(say) 120s, kill it and flip to `failed` with an `agent_no_output` reason — so
any *other* silent-spawn failure surfaces instead of hanging.

## P1 — Live-validate the shipped CDN/parking tag-suppression fix

The `c127a80` fix (this run's mechanical fix) is code-clean but **was never
exercised live**. On the next unblocked run, confirm:
- N1 (Cloudflare anycast), N2 (jsDelivr), N3 (Wikipedia) all score **RST=100**.
- Restraint floor (cases 4/6/11/12 + negatives) clears **≥80** (prior breach: 75).
- No CAP regression on c02/c03/c08/c09/c12 (hard gate).

Until then, treat the restraint-floor breach as **open**.

## P2 — Sequential-runner resilience to platform outages

When a case produces 0 nodes and times out, the current runner proceeds to the
next case and hits the identical wall, burning `hard_cap_minutes` (150) per case
— up to ~20 h of futile spinning, after which `finish.sh` would score empty
graphs and `commit_reports.sh` could commit a misleading all-zero scorecard.

**Fix.** Add a **circuit breaker**: if the first 1–2 cases produce 0 nodes and
time out, abort the whole run and write a BLOCKED marker instead of marching
through the remaining cases. (This run was halted manually and documented by
hand for exactly this reason.)

---

### Reference: prior run's open items (still relevant, unverified this cycle)

Carried forward from `2026-06-01_de5a31b/proposed_fixes.md`; none could be
re-measured because no case ran. Re-evaluate on the next unblocked nightly.
