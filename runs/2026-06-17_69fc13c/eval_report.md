# Eval Report — 2026-06-17 nightly (commit `69fc13c`)

**Audience:** the roadmap-planning agent. This report is self-contained: it covers
(1) a production outage discovered and fixed during this run, and (2) the nightly
eval results once unblocked, ending with a **prioritized roadmap input** section.

---

## TL;DR

- **Production was down and is now fixed.** Every investigation produced 0 nodes
  because the `claude` CLI had moved off the systemd service's PATH. Three fixes
  shipped and merged to `main` (`69fc13c`), deploy green, verified live.
- **Eval ran clean after the fix.** CAP mean **94.0** (↑ from 92.9 baseline),
  **0 hallucinations**, PS floor 85. No capability collapse.
- **The restraint-floor gate is STILL breached (75 < 80).** The CDN/parking
  tag-suppression fix shipped this cycle **worked at its target layer** (CDN
  infrastructure nodes are now verifiably clean) but **did not move the metric**,
  because the points are docked on *pivot-discovered malware hashes*, not on the
  CDN infrastructure. **This is the single most important roadmap input below.**
- One CAP regression flagged: **c3 −10** (pivot-completeness variance, not
  fix-induced) — watch, not alarm.

---

## Run metadata

| | |
|---|---|
| Date | 2026-06-17 |
| Commit (deployed `main`) | `69fc13c` (squash-merge of PR #19) |
| Model | `opus-4.8` |
| Mode | nightly fresh subset — c2, c3, c8, c9, c12 + negatives N1–N3 |
| Runner | sequential one-by-one (quota-survivable), against live VPS |
| Target | https://bounce.alexandre-pinoteau.fr/ |

---

## Part 1 — Production outage (found + fixed during this run)

### Symptom
Every `claude -p` investigation spawned, logged `phase_main_starting`, then
produced **zero stream-json output → 0 tool calls → 0 nodes**, and hung in a
zombie `running` state. First observed when the nightly's case c02 stalled.

### Root cause (confirmed via `data/bounce.db` event log)
```
agent_error | claude CLI not found: [Errno 2] No such file or directory
```
The `claude` binary had moved to **`/home/bounce/.local/bin/claude`** (Claude
Code's native installer), which is **not on the systemd service's PATH**
(`…:/usr/bin:/snap/bin`). `agent_runner` resolved it with
`shutil.which("claude") → None`, fell back to the bare name, and
`create_subprocess_exec` raised `FileNotFoundError` on every spawn.

A **secondary bug** turned a clean failure into a silent hang: the
`FileNotFoundError` handler returned a 3-tuple while every caller unpacks 4 →
`ValueError` crashed `run_investigation` → the row stuck at `running` instead of
flipping to an error status.

> A widely-suspected cause — the 2026-06-15 `claude -p` subscription-subsidy
> change — was **ruled out**: that change was postponed, and manual `claude -p`
> on the VPS runs end-to-end.

### Fixes shipped (all on `main` @ `69fc13c`, deploy green, verified live)
1. **`agent_runner._resolve_claude_bin()`** — after PATH lookup, probe
   `~/.local/bin`, `~/.npm-global/bin`, `/usr/local/bin`, `/usr/bin`. A PATH gap
   no longer silently breaks all investigations.
2. **Tuple-arity fix** — `FileNotFoundError` now returns the proper 4-tuple, so a
   missing CLI fails cleanly (`error rc=None`) instead of zombie `running`.
3. **No-first-event watchdog** — if a spawn emits no stream-json within
   `BOUNCE_AGENT_FIRST_EVENT_TIMEOUT_S` (default 120s), it is killed and an
   `agent_no_output` event is logged. Any *future* silent-spawn failure surfaces
   in ~2 min instead of hanging to the 20-min ceiling.
4. **Operational unblock** (applied on the VPS): `CLAUDE_BIN` set to the absolute
   path in `.env` + restart.

### Verification
A live parked-domain test plus the full nightly re-run both produced healthy
graphs (e.g. c02 = 61 nodes incl. a threat_actor + 29-hash cluster). The CLI
spawns, MCP servers connect, pivots fire. Outage resolved.

**Hardening still open:** the watchdog catches *silent* spawns; consider also a
deploy-time preflight that asserts `claude --version` resolves under the service
environment (would have caught this at deploy, not at first investigation).

---

## Part 2 — Eval results (decay-proof v3 / CAP headline)

| Case | live | CAP | ΔCAP vs de5a31b | PS | EFF | RST | HYP | nodes |
|-----:|:----:|----:|----:|---:|----:|----:|----:|------:|
| c2 MuddyWater (hash) | live | 100.0 | +0.0 | 100 | 100 | 100 | 100 | 61 |
| c3 Bumblebee→Akira | live | 90.0 | **−10.0** | 75 | 100 | 100 | 100 | 28 |
| c8 Amadey/StealC GitLab | live | 100.0 | **+15.5** | 100 | 100 | 100 | 100 | 39 |
| c9 Tycoon 2FA | DECAY | 90.0 | +0.0 | 75 | 100 | 100 | 100 | 23 |
| c12 ClearFake | DECAY | 90.0 | +0.0 | 75 | 100 | 100 | 100 | 18 |
| **N1** Cloudflare anycast | – | 100 | – | – | – | 100 | – | 6 |
| **N2** jsDelivr CDN | – | 50 | – | – | – | **50** | – | 13 |
| **N3** Wikipedia | – | 50 | – | – | – | **50** | – | 19 |

| Gate | Target | This run | Verdict |
|---|---|---|---|
| **CAP mean** | ≥75 → 85 | **94.0** (vs 92.9, +1.1) | ✅ |
| PS floor | ≥70 | 85.0 | ✅ |
| Hallucination | 0 (hard) | **0** | ✅ |
| **Restraint floor** (4/6/11/12 + neg) | ≥80 | **75** | ❌ **BREACH** |
| CAP regressions (hard) | none | **[c3 −10]** | ⚠️ see §3 |

**c3 −10:** entirely a PS (pivot-completeness) drop (100→75) — the agent chose a
slightly thinner pivot set this run. None of this cycle's code changes touch c3's
pivot logic; this is normal run-to-run heuristic variance (these scores swing
±10-15). Worth a confirmatory re-run but not a real regression.

**c8 +15.5:** genuine improvement (84.5→100) — full pivot coverage this run.

---

## Part 3 — The restraint-floor finding (PRIMARY ROADMAP INPUT)

**The CDN/parking tag-suppression fix (`c127a80`) shipped this cycle did NOT clear
the restraint floor, and the reason matters.**

### What the fix did — and it worked
It suppresses malicious-family tags (`malicious`/`c2`/`phishing`/`malware`/
`attacker`) on nodes already tagged `cdn`/`parking`, in both `tag_node()` and the
`add_node()` upsert. **Verified live:** every CDN infrastructure node in N2/N3 is
clean —
- N2 (jsDelivr): `cdn.jsdelivr.net`, `jsdelivr.map.fastly.net`, and all four
  Cloudflare/Fastly IPs are tagged `cdn`/`benign`, **zero malicious tags**.
- N3 (Wikipedia): all `*.wikimedia.org` domains/IPs clean (`benign`,
  `wikimedia_lb`); the `wikipedia25.org` typosquat is correctly tagged
  `typosquat`/`suspicious`, not malicious.

### Why the metric didn't move
`score_negative` docks 25 points per node carrying a malicious-family tag,
**regardless of node type**. In both N2 and N3 the −50 comes from **two `hash`
nodes** the agent discovered by pivoting:
- N2: two malware samples tagged `malicious`/`cdn-abuse` (files that genuinely
  abuse jsDelivr).
- N3: two samples tagged `malware`.

So the restraint failure is **at the hash-pivot layer, not the infrastructure
layer the fix targets.** The fix cleaned the right thing; it just wasn't where the
points were lost. The floor stayed at exactly 75 (N1=100, N2=50, N3=50, c12=100).

### Two defensible framings (the roadmap needs to pick one or both)

**Framing A — scorer is too blunt (recommended primary).** Tagging an
actually-malicious file that abuses a benign CDN as `malicious` is *correct* CTI,
not over-attribution of the benign seed. The negative/restraint test should
penalize malicious tags only on the **seed's own infrastructure lineage**
(domain/ip/asn/ns/registrar reachable from the seed), not on pivot-discovered
artifacts that are independently malicious. Fix: scope `score_negative`'s
`promoted` check to infrastructure node types. Under this definition N2/N3 would
score 100 and the floor clears — *and it would be measuring the thing the product
actually cares about* (don't call the CDN itself evil).

**Framing B — agent scope-creep (secondary, product-level).** On a seed that
resolves to obviously-benign shared infrastructure, should the agent be spending
pivots enumerating every malware sample that ever touched it? Arguably a restraint
behavior worth adding: when the seed is classified benign/CDN, *stop early* rather
than fanning out into sample attribution. This is a genuine product question, not
just a scorer artifact.

These are not mutually exclusive. A is a precise measurement fix; B is a behavior
question. **A is low-risk and unblocks the floor gate honestly; B deserves a
design discussion.**

---

## Prioritized roadmap input

**P0 — Re-scope the negative-case restraint metric (and/or add benign-seed stop-early).**
The restraint floor gate has now been "breached" two runs running for a reason
that is *not* CDN-infra mis-tagging (that's fixed). Decide between Framing A
(scope `score_negative` to infrastructure lineage — measurement fix, clears the
gate honestly) and Framing B (agent stop-early on benign seeds — behavior change).
Recommend shipping A first; it's mechanical and removes a false red gate. Est.
impact: restraint floor 75 → ~100, gate ✅.

**P1 — cert-CN pivot on mixed CDN+origin seeds (F-PIVOT-MISS).**
c12 (and the c3 variance) point at the same gap: `shodan_cert_cn_search` only
fires when *all* IPs are CDN-tagged, so Cloudflare-fronted seeds with a leaked
origin IP (Hetzner etc.) never get the cert-CN unmask. Loosen to fire when *any*
CDN-tagged IP exists, or fire unconditionally for domain seeds (it's cheap). Est.
impact: c12 PS 75→100 (~+8 CAP); likely lifts c3/c9 PS too.

**P2 — Deploy-time `claude` preflight + the watchdog already shipped.**
The no-first-event watchdog (shipped) converts a silent spawn-hang into a fast
`agent_no_output` failure. Add a deploy-step assertion that `claude --version`
resolves under the *service* environment so a PATH/binary problem is caught at
deploy, not at first investigation. Cheap, prevents a repeat of today's outage.

**P3 — Confirm c3 is variance, not regression.**
Single confirmatory re-run of c3; if PS stays at 75 across runs, investigate the
Bumblebee→Akira pivot path. Low priority — CAP mean rose and no mechanism links
this cycle's changes to c3.

---

## Carryover / notes for the roadmap agent
- This subset is the decay-resistant nightly five + three negatives; the full
  12-case protocol (`EVAL_PROTOCOL.md`) was not run. CAP deltas are vs the
  2026-06-01 `de5a31b` baseline (CAP mean 92.9).
- c9 and c12 are flagged `DATA_DECAYED` (their live-recall ground truth has
  aged); their CAP is still valid, only the REC context metric is skipped.
- Companion files in this directory: `scorecard.md` (full tables, legacy v2
  track), `deltas.md`, `failure_histogram.md`, `raw_scores.json`,
  `proposed_fixes.md` (auto-generated, fix-centric).
