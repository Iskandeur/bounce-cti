# Deltas — 2026-06-17 (90c516b) vs 2026-06-01 (de5a31b)

> **Run BLOCKED — no comparable scores produced.** Zero cases completed, so
> there are no per-case CAP/Overall deltas to report. See `scorecard.md` for the
> root-cause diagnosis.

## v3 CAP baseline (de5a31b, 2026-06-01) — for reference only

| Case | Prior CAP | This run | ΔCAP |
|-----:|----------:|:--------:|:----:|
| c02  | 100.0 | — (blocked) | n/a |
| c03  | 100.0 | — (blocked) | n/a |
| c08  | 84.5  | — (blocked) | n/a |
| c09  | 90.0  | — (blocked) | n/a |
| c12  | 90.0  | — (blocked) | n/a |
| **mean** | **92.9** | **—** | **n/a** |

| Negative | Prior RST | This run | ΔRST |
|---------:|----------:|:--------:|:----:|
| N1 (Cloudflare anycast) | 100 | — (blocked) | n/a |
| N2 (jsDelivr CDN)       | 50  | — (blocked) | n/a |
| N3 (Wikipedia)          | 50  | — (blocked) | n/a |

The `c127a80` CDN/parking tag-suppression fix was expected to lift N2/N3 from
RST=50 → 100 and clear the restraint-floor gate (prior breach: 75 < 80). That
expectation is **unverified** — the run never executed.

## Gate status

| Gate | Target | This run |
|---|---|---|
| CAP mean | ≥75 → 85 | **N/A (blocked)** |
| Restraint floor | ≥80 | **N/A (blocked)** |
| Hallucination | 0 (hard) | N/A (no output) |
| CAP regressions | none | N/A |

## Infra delta vs prior run

The decisive change between the last green run (2026-06-01) and tonight is the
**2026-06-15 removal of the `claude -p` subscription subsidy**. No eval
infrastructure or agent-prompt change explains the blocker; the environment
changed underneath a working harness.
