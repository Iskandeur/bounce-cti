# EVAL_PROTOCOL Scorecard — 2026-06-17 · commit 90c516b

> **RUN STATUS: BLOCKED — no cases completed.** The production VPS could not
> execute a single `claude -p` investigation. This scorecard documents the
> blocker and its diagnosis rather than capability scores; **no CAP/PS/RST/HYP
> numbers were produced** because zero graph nodes were ever generated.

**Run environment**
- Branch: `claude/wizardly-pascal-s9tq75` (local), against `main` deployed VPS at https://bounce.alexandre-pinoteau.fr/ (HEAD == origin/main == `90c516b` at run start; fix `c127a80` deployed at 10:06 UTC)
- Model: `opus-4.8`
- Mode: **nightly fresh subset** — Cases 2, 3, 8, 9, 12 + Negative N1–N3, sequential one-by-one (quota-survivable runner).
- Date: 2026-06-17 (note: **2 days after the 2026-06-15 `claude -p` subscription-subsidy removal**).

## Outcome

| Case | Submitted | Nodes | Status | Result |
|-----:|:---------:|------:|:-------|:-------|
| c02 (MuddyWater, hash) | 09:55 UTC | **0** | running (zombie) | BLOCKED — agent never produced a tool call |
| c03, c08, c09, c12 | — | — | not reached | runner halted (futile; same VPS wall) |
| N1, N2, N3 | — | — | not reached | runner halted |

c02 was attempted **three times**:
1. **Original spawn** (09:55) — killed at 10:06 by the GitHub Actions deploy that shipped fix `c127a80` (our own push triggered the auto-deploy / service restart).
2. **Rerun** (10:18) — ran 26 min, **0 nodes**, transcript stuck at `phase:main:starting`.
3. **Resume** (10:44) — ran 27 min, **0 nodes**, transcript stuck at `phase:main:starting`.

## Root-cause diagnosis

The agent emits `phase_main_starting` (logged in `agent_runner.py:2367`, **before** the
`claude -p` subprocess is spawned at line 2369) and then nothing: **zero
`stream-json` output, zero tool calls, zero nodes.** This is the signature of a
`claude -p` subprocess that launches but never produces output.

Evidence ruling causes in/out:

| Hypothesis | Verdict | Evidence |
|---|---|---|
| **June-15 subscription-subsidy removal broke programmatic `claude -p` auth** | **LEADING** | Today is 2 days post-change. The API-key fallback (draft **PR #15**) is unmerged, so the VPS has no `ANTHROPIC_API_KEY` to fall back to. Only **1** investigation has run since June 15 (this one); last successful eval was **June 1** (pre-change). |
| Normal quota gate | ruled out | `GET /api/quota` → `exhausted:false`. The agent's quota detector never fired. |
| Our `c127a80` fix broke the graph MCP server | ruled out | `graph_store.py` imports cleanly; `_NOISE_TAGS`/`_MALICIOUS_TAGS` guards in `tag_node`/`add_node` are logically sound (set ops on strings, no error path). Deploy `c127a80` **succeeded** (GH Actions green at 10:06). |
| Deploy left the service degraded | ruled out | Backend API healthy throughout (investigation list / graph / transcript endpoints all responsive). |
| Backend down | ruled out | API responds normally. |

## Recommended action (owner)

1. **Unblock the VPS `claude -p` auth** — set `ANTHROPIC_API_KEY` in the VPS env
   (the agentic credit is billed at API rates anyway), **or** finish + merge
   **PR #15** (the `billing_mode` API-fallback in `agent_runner._build_env`).
2. Confirm with a single lightweight investigation (e.g. a parked domain) that
   nodes appear, then **re-run this nightly subset** — phases are idempotent, so
   a fresh run is clean.

## Fix shipped this run

**CDN/parking malicious-tag suppression** (`backend/graph_store.py`, commit
`c127a80`, already on `main`). Suppresses malicious-family tags
(`malicious`/`c2`/`phishing`/`malware`/`attacker`) on nodes already tagged
`cdn`/`parking`, in both `tag_node()` and the `add_node()` upsert path. Targets
the prior-run restraint-floor breach (N2 jsDelivr / N3 Wikipedia scored RST=50
from ThreatFox/OTX false-positives on shared CDN infra).

> ⚠️ **NOT live-validated** — the eval that would confirm N1/N2/N3 → RST=100 and
> the restraint floor ≥80 could not run. The fix is code-reviewed and
> import-clean; live confirmation is **deferred to the next unblocked run.**
