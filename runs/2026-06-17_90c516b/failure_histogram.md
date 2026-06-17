# Failure Histogram — 2026-06-17 (90c516b)

> Run blocked at the infrastructure layer. There is exactly **one** failure
> mode, and it is not a capability/scoring failure — it is a platform outage.

## Failure modes observed

| Count | Mode | Layer | Cases affected |
|------:|:-----|:------|:---------------|
| 1 | `claude -p` subprocess spawns but emits zero `stream-json` output (0 tool calls, 0 nodes) | **platform / auth** | c02 (×3 attempts); c03/c08/c09/c12/N1–N3 never reached |

No per-case capability failures (pivot-miss, hallucination, restraint, hypothesis)
were observed because **no case produced any graph**.

## Transcript signature (identical across all 3 c02 attempts)

```
{"kind":"phase","ts":...,"phase":"main","stage":"starting"}
<nothing — no tool_use, no node_added, no result>
```

`agent_runner.py` logs `phase_main_starting` *before* spawning `claude -p`
(line 2367 vs 2369), so this signature = the subprocess launched and then
produced no output whatsoever.

## Not failure modes (explicitly ruled out)

- ❌ Quota exhaustion — `/api/quota` → `exhausted:false`.
- ❌ The `c127a80` CDN-tag fix — imports clean, logic sound, deploy green.
- ❌ Deploy/build failure — GH Actions deploy succeeded; backend API healthy.

## Single root cause

All paths converge on the **2026-06-15 `claude -p` subscription-subsidy
removal** breaking programmatic auth on the VPS, with no `ANTHROPIC_API_KEY`
fallback configured (PR #15 unmerged). See `scorecard.md`.
