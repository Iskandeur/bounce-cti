# Failure Histogram — 2026-06-17 (90c516b)

> Run blocked at the infrastructure layer. There is exactly **one** failure
> mode, and it is not a capability/scoring failure — it is a platform outage.

## Failure modes observed

| Count | Mode | Layer | Cases affected |
|------:|:-----|:------|:---------------|
| 1 | `claude` binary not on service PATH → `FileNotFoundError` on spawn → zero output (0 tool calls, 0 nodes) | **platform / deploy** | c02 (×3 attempts); c03/c08/c09/c12/N1–N3 never reached |

No per-case capability failures (pivot-miss, hallucination, restraint, hypothesis)
were observed because **no case produced any graph**.

## Transcript signature (identical across all 3 c02 attempts)

```
{"kind":"phase","ts":...,"phase":"main","stage":"starting"}
<nothing — no tool_use, no node_added, no result>
```

`agent_runner.py` logs `phase_main_starting` *before* spawning `claude -p`, so
this signature = the spawn failed before producing any output. The `events`
table confirms it: `agent_error: claude CLI not found: [Errno 2] No such file
or directory`.

## Not failure modes (explicitly ruled out)

- ❌ Quota exhaustion — `/api/quota` → `exhausted:false`.
- ❌ The `c127a80` CDN-tag fix — imports clean; standalone `run_mcp.py` starts.
- ❌ June-15 subscription change — **postponed**; manual `claude -p` authenticates.

## Single root cause (CONFIRMED)

The `claude` binary was **not on the systemd service's PATH** — it lives at
`/home/bounce/.local/bin/claude` (native installer), absent from the service
PATH. `shutil.which("claude") → None` → bare-name fallback → `FileNotFoundError`
on every spawn. A secondary bug (3-tuple return from the `FileNotFoundError`
handler vs. 4-tuple unpack) crashed `run_investigation` and produced the zombie
`running` status. Both fixed in commit `c53a4eb`; operationally unblocked by
setting `CLAUDE_BIN` to the absolute path. See `scorecard.md`.
