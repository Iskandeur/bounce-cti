# Proposed Fixes — 2026-06-17 (90c516b)

The nightly run was **blocked** before any case scored, so this list is driven
by the blocker diagnosis rather than capability gaps. Priorities are ordered by
what unblocks the eval and protects production.

## P0 — Restore `claude -p` execution on the VPS (BLOCKER)

**Symptom.** Every `claude -p` investigation spawns and then produces zero
`stream-json` output — 0 tool calls, 0 nodes — leaving the investigation in a
zombie `running` state. The quota gate reads `exhausted:false`, so the agent's
own quota detector never fires.

**Cause (leading).** 2026-06-15 removed the `claude -p` / Agent-SDK subscription
subsidy. The VPS authenticates `claude -p` via the subscription and has **no
`ANTHROPIC_API_KEY` fallback** (PR #15, which adds the `billing_mode`
api-fallback to `agent_runner._build_env`, is still a **draft**). This is the
first investigation attempted since the change; the last green eval was June 1.

**Fix.**
1. Set `ANTHROPIC_API_KEY` in the VPS `.env` (agentic credit is billed at API
   rates regardless) — fastest unblock.
2. **Or** finish + merge **PR #15** so `billing_mode` flips to `api_fallback`
   automatically when the agentic credit is exhausted.

**Hardening follow-up.** The current quota detector doesn't recognise this new
failure mode (subprocess produces *no* output instead of a quota-error line). Add
a **"no first event within N seconds"** watchdog in `agent_runner._run_claude`
that, when `claude -p` emits no `stream-json` within (say) 120s, kills the
subprocess and flips the investigation to `failed` with a clear
`agent_no_output` reason — instead of leaving it `running` forever. This converts
a silent hang into an actionable, surfaced failure and prevents the
sequential-runner from wedging for 150 min per case.

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
