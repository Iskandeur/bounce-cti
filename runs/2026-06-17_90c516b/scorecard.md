# EVAL_PROTOCOL Scorecard — 2026-06-17 · commit 90c516b

> **RUN STATUS: BLOCKED — no cases completed.** The production VPS could not
> execute a single `claude -p` investigation. This scorecard documents the
> blocker and its diagnosis rather than capability scores; **no CAP/PS/RST/HYP
> numbers were produced** because zero graph nodes were ever generated.
>
> **ROOT CAUSE CONFIRMED (post-mortem, 2026-06-17 ~12:00 UTC):** the `claude`
> CLI binary was **not on the systemd service's PATH** — it had moved to
> `/home/bounce/.local/bin/claude` (native-installer location), which the
> service PATH (`…:/usr/bin:/snap/bin`) does not include. `agent_runner`
> resolved it with `shutil.which("claude") → None`, fell back to the bare name,
> and every spawn raised `FileNotFoundError`. The `agent_error` events in
> `data/bounce.db` say exactly this: `claude CLI not found: [Errno 2] No such
> file or directory`. **The June-15 subscription hypothesis below was WRONG** —
> the change was postponed, and a manual `claude -p` on the VPS (with the binary
> located) works end-to-end. Fixed in commit `c53a4eb` (binary resolver +
> tuple-arity fix) and unblocked operationally by setting `CLAUDE_BIN` to the
> absolute path.

**Run environment**
- Branch: `claude/wizardly-pascal-s9tq75` (local), against `main` deployed VPS at https://bounce.alexandre-pinoteau.fr/ (HEAD == origin/main == `90c516b` at run start; fix `c127a80` deployed at 10:06 UTC)
- Model: `opus-4.8`
- Mode: **nightly fresh subset** — Cases 2, 3, 8, 9, 12 + Negative N1–N3, sequential one-by-one (quota-survivable runner).
- Date: 2026-06-17.

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

The agent emits `phase_main_starting` (logged in `agent_runner.py`, **before** the
`claude -p` subprocess is spawned) and then nothing: **zero `stream-json` output,
zero tool calls, zero nodes.** That is the signature of a spawn that fails before
producing any output.

**Confirmed cause — `claude` binary not on the service PATH.** The `events` table
for inv `b701e131ab3c` shows, on every attempt:

```
agent_error | claude CLI not found: [Errno 2] No such file or directory
```

The binary is at `/home/bounce/.local/bin/claude` (Claude Code's native
installer), and the systemd service PATH is
`/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/snap/bin` — `~/.local/bin` is
absent. `agent_runner` used `shutil.which("claude")`, got `None`, fell back to the
bare name `"claude"`, and `create_subprocess_exec` raised `FileNotFoundError`. A
secondary bug compounded it: the `FileNotFoundError` handler returned a 3-tuple
while callers unpack 4, so `run_investigation` crashed on the unpack and left the
row stuck `running` (the "zombie") instead of failing cleanly.

Evidence ruling other causes out:

| Hypothesis | Verdict | Evidence |
|---|---|---|
| `claude` binary not on service PATH | **CONFIRMED** | `agent_error: claude CLI not found` in `data/bounce.db`; `which claude` → `/home/bounce/.local/bin/claude`, not on the service PATH. Manual `claude -p` with the binary located runs end-to-end (MCP servers `connected`). |
| ~~June-15 subscription-subsidy removal~~ | **WRONG / withdrawn** | The change was **postponed** (Anthropic email, 2026-06-15). Subscription `claude -p` is unchanged; manual runs authenticate fine. |
| Normal quota gate | ruled out | `GET /api/quota` → `exhausted:false`. |
| `c127a80` CDN fix broke the graph MCP server | ruled out | `graph_store.py` imports cleanly; standalone `run_mcp.py graph_mcp` (in the venv) starts fine. |
| Deploy left the service degraded | ruled out | Backend API healthy throughout. |

## Resolution

- **Operational unblock (applied):** set `CLAUDE_BIN=/home/bounce/.local/bin/claude`
  in `/opt/bounce-cti/.env` and restart the service. Points the backend straight
  at the binary regardless of the service PATH.
- **Code fix (commit `c53a4eb`, on PR #19):** `agent_runner._resolve_claude_bin()`
  now probes `~/.local/bin`, `~/.npm-global/bin`, `/usr/local/bin`, `/usr/bin`
  after the PATH lookup, and the `FileNotFoundError` handler returns the proper
  4-tuple so a missing CLI fails cleanly (`error rc=None`) instead of zombie
  `running`.
- Confirm with a single lightweight investigation (e.g. a parked domain) that
  nodes appear, then **re-run this nightly subset** — phases are idempotent.

## Other fix shipped this run

**CDN/parking malicious-tag suppression** (`backend/graph_store.py`, commit
`c127a80`, already on `main`). Suppresses malicious-family tags
(`malicious`/`c2`/`phishing`/`malware`/`attacker`) on nodes already tagged
`cdn`/`parking`, in both `tag_node()` and the `add_node()` upsert path. Targets
the prior-run restraint-floor breach (N2 jsDelivr / N3 Wikipedia scored RST=50
from ThreatFox/OTX false-positives on shared CDN infra).

> ⚠️ **NOT live-validated** — the eval that would confirm N1/N2/N3 → RST=100 and
> the restraint floor ≥80 could not run. The fix is code-reviewed and
> import-clean; live confirmation is **deferred to the next unblocked run.**
