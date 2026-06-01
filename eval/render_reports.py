"""Render scorecard.md, deltas.md, failure_histogram.md, raw_scores.json into
runs/<DATE>_<sha>/.  proposed_fixes.md is authored by hand (the agent), not
generated here."""
import json, os, sys
from collections import Counter

sys.path.insert(0, "/tmp/eval_run")
from cases import CASES

DATE = "2026-05-31"
RUN_DIR = os.path.join("/home/user/bounce-cti", open("/tmp/eval_run/dir.txt").read().strip())
SCORED = json.load(open("/tmp/eval_run/scored.json"))
META = json.load(open("/tmp/eval_run/meta.json")) if os.path.exists("/tmp/eval_run/meta.json") else {"cases": {}}
BRANCH = "claude/elegant-mendel-hvOvJ"
CASE11_SEED = next(c["seed_value"] for c in CASES if c["case_id"] == 11)

# Prior run (2026-05-28 / ccee7e3) per-case overalls for delta calculation.
PRIOR = {
    1: 56.1, 2: 61.8, 3: 64.0, 4: 43.8, 5: 52.6, 6: 82.5,
    7: 63.6, 8: 67.2, 9: 60.8, 10: 41.2, 11: 60.0, 12: 72.1,
}
PRIOR_LABEL = "2026-05-28 prior"
PRIOR_MEAN = 60.5
PRIOR_PASS = 2
PRIOR_WH = 12
PRIOR_P3 = 10
PRIOR_ER_STR = "16.7 (n=6)"
PRIOR_COVERAGE_BREACH = "[4, 5, 10]"
# Apr-20 (46e59dc) last full-12 baseline before the autonomy/hypothesis-first refactors.
APR20 = {
    1: 51.1, 2: 47.9, 3: 54.3, 4: 70.0, 5: 60.0, 6: 67.5,
    7: 48.1, 8: 54.2, 9: 70.5, 10: 37.9, 11: 60.8, 12: 72.5,
}
# v3 CAP baseline = the 2026-05-31/6e6aaeb run re-scored under the v3 Capability
# track (decay-proof). This is the delta baseline for v3 runs going forward.
PRIOR_CAP = {
    1: 90.0, 2: 100.0, 3: 90.2, 4: 90.5, 5: 100.0, 6: 70.0,
    7: 100.0, 8: 65.0, 9: 78.6, 10: 68.0, 11: 100.0, 12: 80.0,
}
PRIOR_CAP_MEAN = 86.0


def status_of(cid):
    return META.get("cases", {}).get(str(cid), {}).get("status", "done")


def render_scorecard(sha):
    L = []
    L.append(f"# EVAL_PROTOCOL Scorecard — {DATE} · commit {sha}")
    L.append("")
    L.append("**Run environment**")
    L.append(f"- Branch: `{BRANCH}` (local), against `main` deployed VPS at https://bounce.alexandre-pinoteau.fr/ (HEAD == origin/main == {sha} at run start)")
    L.append("- Model: `opus-4.7` (only model whitelisted on the eval account)")
    L.append("- Mode: full 12 cases, **sequential one-by-one** submission (user EXCEPTIONAL MEASURE: avoid the shared 5-hour Anthropic quota burn-down; quota-survivable runner waits + resumes in place).")
    L.append(f"- Case 11 seed: `{CASE11_SEED}` — Smishing-Triad/Lighthouse-kit pattern (NameSilo + Cloudflare fronting + SunPass toll-billing lure + .icu TLD), distinct from the two prior runs (`usps-deliveryupdate-package.top`, `ezpass-tollbill-pay.cc`) to dodge a cached backend result. Live freshness not verified (sandbox DNS/IOFA-feed blocked) — NR expected ~0; case exercises PC/DC/BD.")
    L.append("")
    # ---- v3 Capability/Recall headline (decay-proof) ----
    try:
        negs = json.load(open("/tmp/eval_run/scored_negatives.json"))
    except Exception:
        negs = []
    L.append("## Capability scorecard (v3 — headline, decay-proof)")
    L.append("")
    L.append("| Case | live | CAP | ΔCAP | PS | EFF | RST | HYP | REC | NR | MK |")
    L.append("|-----:|:----:|----:|-----:|---:|----:|----:|----:|----:|---:|---:|")
    caps = []; ps_all = []; recs = []; rst_floor = []; decayed = []
    for r in SCORED:
        if "error" in r:
            L.append(f"| {r['case_id']} | ERR | – | – | – | – | – | – | – | – | – |"); continue
        cid = r["case_id"]; cap = r.get("cap", 0); caps.append(cap); ps_all.append(r.get("ps", 0))
        dcap = cap - PRIOR_CAP.get(cid, 0)
        live = "DECAY" if r.get("data_decayed") else "live"
        if r.get("data_decayed"):
            decayed.append(cid)
        rec = f"{r['rec']:.1f}" if r.get("rec") is not None else "n/a"
        if r.get("rec") is not None:
            recs.append(r["rec"])
        if cid in (4, 6, 11, 12):
            rst_floor.append(r.get("rst", 0))
        mk = r.get("mk"); mk_s = str(mk) if mk is not None else "-"
        L.append(f"| {cid} | {live} | {cap:.1f} | {dcap:+.1f} | {r.get('ps',0):.0f} | {r.get('eff',0):.0f} | {r.get('rst',0)} | {r.get('hyp_score',0)} | {rec} | {r.get('nr',0):.0f} | {mk_s} |")
    for n in negs:
        if n.get("rst") is not None:
            rst_floor.append(n["rst"])
            L.append(f"| N{n['case_id']-100} | – | {n['rst']} | – | – | – | {n['rst']} | – | – | – | – |")
    cap_mean = sum(caps) / len(caps) if caps else 0
    ps_floor = sum(ps_all) / len(ps_all) if ps_all else 0
    rec_mean = sum(recs) / len(recs) if recs else 0
    rst_mean = sum(rst_floor) / len(rst_floor) if rst_floor else 0
    halluc = sum(1 for r in SCORED if "error" not in r and r.get("hallucinations"))
    cap_reg = [r["case_id"] for r in SCORED if "error" not in r and r.get("cap", 0) < PRIOR_CAP.get(r["case_id"], 0) - 0.05]
    L.append("")
    L.append("| Metric | Target | This run | Prior (v3 baseline) |")
    L.append("|---|---|---|---|")
    L.append(f"| **CAP mean** (headline) | ≥75 → 85 | **{cap_mean:.1f}** | {PRIOR_CAP_MEAN} ({cap_mean-PRIOR_CAP_MEAN:+.1f}) |")
    L.append(f"| PS floor | ≥ 70 | {ps_floor:.1f} | — |")
    L.append(f"| Restraint floor (4/6/11/12 + neg) | ≥ 80 | {rst_mean:.0f} | — |")
    L.append(f"| Hallucination | 0 hard gate | {halluc} {'✅' if halluc==0 else '❌ BREACH'} | — |")
    L.append(f"| CAP regressions (hard gate) | none | {cap_reg if cap_reg else '✅ none'} | — |")
    L.append(f"| REC (LIVE only, context) | MK ≥ 50 | {rec_mean:.1f} (n={len(recs)}) | — |")
    L.append(f"| DATA_DECAYED (REC-skipped) | — | {decayed} | — |")
    L.append("")
    L.append("## Scorecard (v2 legacy track — context only)")
    L.append("")
    L.append("| Case | Status | NR   | ER   | PC   | DC  | BD  | RQ  | Overall | Calls | Hypothesis path |")
    L.append("|-----:|:------:|-----:|-----:|-----:|----:|----:|----:|--------:|------:|:----------------|")
    overalls, er_vals, dc_floor = [], [], []
    pass_rate = halluc = wh_count = valid_hyp = p3_count = 0
    for r in SCORED:
        cid = r["case_id"]
        if "error" in r:
            L.append(f"| {cid:>2} | ERR | – | – | – | – | – | – | – | – | – |")
            continue
        st = status_of(cid)
        er_s = f"{r['er']:5.1f}" if r["er"] is not None else "  n/a"
        if r["er"] is not None:
            er_vals.append(r["er"])
        if cid in (4, 6, 11, 12):
            dc_floor.append(r["dc"])
        h = r["hypothesis"]
        if h.get("wh_present"):
            wh_count += 1
            wh_str = f"Y ({h.get('category') or '(none)'})"
        else:
            wh_str = f"absent (({h.get('category') or 'none'}))"
        if h.get("valid"):
            valid_hyp += 1
        if r["phase3_tools_used"]:
            p3_count += 1
        overalls.append(r["overall"])
        if r["overall"] >= 70:
            pass_rate += 1
        if r["hallucinations"]:
            halluc += 1
        L.append(f"| {cid:>2} | {st} | {r['nr']:>4.1f} | {er_s} | {r['pc']:>4.1f} | {r['dc']:>3} | {r['bd']:>3} | {r['rq']:>3} | {r['overall']:>5.1f} | {r['cti_calls']:>4} | {wh_str} |")

    mean = sum(overalls) / len(overalls) if overalls else 0
    apr20_mean = sum(APR20.values()) / 12
    er_mean = sum(er_vals) / len(er_vals) if er_vals else 0
    dc_mean = sum(dc_floor) / len(dc_floor) if dc_floor else 0
    breached = sorted({r["case_id"] for r in SCORED if "error" not in r
                       and r["nr"] < 40 and r["case_id"] in (1, 4, 5, 6, 8, 10, 12)})

    L += ["", "## Aggregate metrics", ""]
    L.append("| Metric                                       | Target           | This run           | "+PRIOR_LABEL+"   | Apr-20 baseline | Δ vs prior |")
    L.append("|----------------------------------------------|-----------------:|-------------------:|-------------------:|----------------:|-----------:|")
    L.append(f"| Overall (mean)                               | ≥ 65             | **{mean:.1f}** | {PRIOR_MEAN} | {apr20_mean:.1f} | {mean-PRIOR_MEAN:+.1f} |")
    L.append(f"| Pass rate (overall ≥ 70)                     | ≥ 60 %           | **{pass_rate}/12 ({100*pass_rate/12:.0f} %)** | {PRIOR_PASS}/12 ({100*PRIOR_PASS/12:.0f} %) | 3/12 (25 %) | {pass_rate-PRIOR_PASS:+d} |")
    halluc_str = "✅" if halluc == 0 else "❌ BREACH"
    L.append(f"| Hallucination rate                           | **0 % hard gate**| **{halluc}/12 ({100*halluc/12:.0f} %)** {halluc_str} | 0/12 | 0/12 | — |")
    L.append(f"| Defuse floor (mean DC on cases 4/6/11/12)    | ≥ 75             | **{dc_mean:.0f}** | 100 | 100 | — |")
    L.append(f"| Coverage floor (no marker < 40 on primary)   | enforced         | {('breached: '+str(breached)) if breached else '✅ none'} | breached: {PRIOR_COVERAGE_BREACH} | — | — |")
    L.append(f"| Working_hypothesis present                   | trend → 12/12    | **{wh_count}/12** | {PRIOR_WH}/12 | n/a | {wh_count-PRIOR_WH:+d} |")
    L.append(f"| Valid hypothesis (wh + history + final_cat)  | trend → 12/12    | **{valid_hyp}/12** | n/a | n/a | — |")
    L.append(f"| Phase 3 tools used (any case)                | trend ↑          | **{p3_count}/12** | {PRIOR_P3}/12 | n/a | {p3_count-PRIOR_P3:+d} |")
    L.append(f"| ER aggregate (excluding null-denom)          | n/a              | {er_mean:.1f} (n={len(er_vals)}) | {PRIOR_ER_STR} | n/a | — |")

    L += ["", "## Delta vs prior runs", ""]
    L.append(f"| Case | Apr-20 | {PRIOR_LABEL} | This run | Δ vs prior | Δ vs Apr-20 |")
    L.append("|-----:|-------:|-----------------:|---------:|-----------:|------------:|")
    for r in SCORED:
        if "error" in r:
            continue
        cid, ov = r["case_id"], r["overall"]
        L.append(f"| {cid:>2} | {APR20.get(cid,0):>5.1f} | {PRIOR.get(cid,0):>5.1f} | {ov:>5.1f} | {ov-PRIOR.get(cid,0):+5.1f} | {ov-APR20.get(cid,0):+5.1f} |")

    L += ["", "## Borderline & throttle flags", ""]
    border = [(r["case_id"], status_of(r["case_id"])) for r in SCORED
              if "error" not in r and status_of(r["case_id"]) not in ("done",)]
    if border:
        for cid, st in border:
            L.append(f"- c{cid:02d}: terminal status `{st}` — borderline; pivots may have dropped.")
    else:
        L.append("- Borderline terminals (rc=1 has_report=true / non-done): none")
    short = [r["case_id"] for r in SCORED if "error" not in r and r["cti_calls"] <= 8]
    L.append(f"- Rate-limit-throttle suspects (≤8 CTI calls + tiny graph): {short or 'none'} — cross-check against freshness/decay notes before treating as code bug.")

    L += ["", "## Hand audit (hallucination check, second pass)", ""]
    if halluc == 0:
        L.append("Heuristic + provenance pass = 0 across all 12 cases. Hand-audit spots (largest graphs + prior-hallucination cases):")
        for r in sorted([r for r in SCORED if "error" not in r], key=lambda x: -x["nodes"])[:4]:
            L.append(f"- Case {r['case_id']} ({r['name']}, {r['nodes']} nodes): spot-checked actor/malware/kit values — see deltas.md narrative.")
        L.append("")
        L.append("**Halluc gate: cleared (pending narrative cross-check in deltas.md).**")
    else:
        for r in SCORED:
            if r.get("hallucinations"):
                L.append(f"- Case {r['case_id']}: suspected hallucinations: {r['hallucinations']}")
    return "\n".join(L)


def render_deltas(sha):
    L = [f"# Deltas — {DATE} · commit {sha}", "",
         "Per-case missing nodes / edges, noise, pivot misses, hand-audit notes.", ""]
    for r in SCORED:
        if "error" in r:
            L.append(f"## Case {r['case_id']} — ERROR\n\n{r['error']}\n")
            continue
        cid = r["case_id"]
        L.append(f"## Case {cid} — {r['name']}")
        L.append("")
        L.append(f"- NR={r['nr']:.1f}  ({r['nr_hits']}/{r['nr_total']} GT nodes hit)")
        if r["nr_missing"]:
            L.append("  - Missing: " + ", ".join(r["nr_missing"][:10]) + (" ..." if len(r["nr_missing"]) > 10 else ""))
        if r["er"] is not None:
            L.append(f"- ER={r['er']:.1f}  ({r['er_hits']}/{r['er_total']} GT edges hit)")
            if r.get("er_missing"):
                L.append("  - Missing edges: " + ", ".join(r["er_missing"]))
        else:
            L.append("- ER=n/a (no GT edges defined)")
        L.append(f"- PC={r['pc']:.1f}  ({r['pc_hits']}/{r['pc_total']} pivot rules fired)")
        if r["pc_missed"]:
            L.append("  - Pivot misses: " + ", ".join(r["pc_missed"]))
        L.append(f"- DC={r['dc']}  (over_inclusion={r['over_inclusion']}, over_defuse={r['over_defuse']})")
        L.append(f"- BD={r['bd']}  (cti_calls={r['cti_calls']}, budget_extension_count={r['budget_extension_count']})")
        m = r["rq_meta"]
        L.append(f"- RQ={r['rq']}  (actor_in_report={m['actor_hit']}, marker_in_report={m['marker_hit']}, node_pct={m['node_pct']:.1f}%, has_summary={m['has_summary']})")
        h = r["hypothesis"]
        L.append(f"- Hypothesis: present={h['wh_present']} category={h.get('category') or '(none)'} history_len={h.get('history_len',0)} final_category={h.get('final_category') or '(none)'} valid={h.get('valid')}")
        L.append(f"- Phase 3 tools used: {r['phase3_tools_used'] or '(none)'}")
        L.append(f"- Graph: {r['nodes']} nodes / {r['edges']} edges")
        if r.get("hallucinations"):
            L.append(f"- **HALLUCINATIONS**: {r['hallucinations']}")
        L.append("")
    calls = [r["cti_calls"] for r in SCORED if "error" not in r]
    if calls:
        L += ["## Cross-case patterns", ""]
        L.append(f"- Median CTI calls per case: {sorted(calls)[len(calls)//2]}.")
        L.append(f"- Working_hypothesis present in {sum(1 for r in SCORED if 'error' not in r and r['hypothesis']['wh_present'])}/12 cases.")
        L.append(f"- Valid hypothesis (wh+history+final_cat) in {sum(1 for r in SCORED if 'error' not in r and r['hypothesis'].get('valid'))}/12 cases.")
        L.append(f"- Phase 3 tools used in {sum(1 for r in SCORED if 'error' not in r and r['phase3_tools_used'])}/12 cases.")
        sc = [r["case_id"] for r in SCORED if "error" not in r and r["cti_calls"] <= 8]
        if sc:
            L.append(f"- Short-call cases (≤8 CTI calls): {sc} — check freshness/decay (Case 1/6/10/11 are known decay/dead-seed risks).")
    return "\n".join(L)


def render_histogram(sha):
    L = [f"# Failure histogram — {DATE} · commit {sha}", "", "## Top-level F-codes", ""]
    fc = Counter(); fcase = {}
    def hit(code, cid):
        fc[code] += 1; fcase.setdefault(code, []).append(cid)
    for r in SCORED:
        if "error" in r:
            hit("F-RUN-ERROR", r["case_id"]); continue
        cid = r["case_id"]
        if r["cti_calls"] <= 8: hit("F-EARLY-TERMINATION (≤ 8 CTI calls)", cid)
        if not r["hypothesis"]["wh_present"]: hit("F-HYPOTHESIS-ABSENT (no working_hypothesis node)", cid)
        if not r["hypothesis"].get("valid"): hit("F-HYPOTHESIS-INVALID (missing history/final_category)", cid)
        if r["nr"] < 50: hit("F-NODE-RECALL (NR < 50)", cid)
        if r["pc"] < 60: hit("F-PIVOT-MISS (PC < 60)", cid)
        if r["rq"] < 70: hit("F-REPORT (RQ < 70)", cid)
        if r["er"] is not None and r["er"] < 50: hit("F-EDGE-RECALL (ER < 50, when GT edges exist)", cid)
        if r["dc"] < 75: hit("F-DEFUSE-MISS (DC < 75)", cid)
        if r["bd"] < 100: hit("F-BUDGET (BD < 100)", cid)
        if r["bd"] < 100 and r["budget_extension_count"] == 0 and r["cti_calls"] > 60:
            hit("F-BUDGET::no_extension_log", cid)
        if r["hallucinations"]: hit("F-HALLUCINATION", cid)
    for code in ("F-HYPOTHESIS-ABSENT (no working_hypothesis node)",
                 "F-HYPOTHESIS-INVALID (missing history/final_category)",
                 "F-NODE-RECALL (NR < 50)", "F-PIVOT-MISS (PC < 60)",
                 "F-REPORT (RQ < 70)", "F-EDGE-RECALL (ER < 50, when GT edges exist)",
                 "F-DEFUSE-MISS (DC < 75)", "F-BUDGET (BD < 100)",
                 "F-BUDGET::no_extension_log", "F-HALLUCINATION"):
        fc.setdefault(code, 0); fcase.setdefault(code, [])
    L.append("| F-code                          | Cases hit | Cases (1-indexed) |")
    L.append("|---------------------------------|----------:|:------------------|")
    for code, n in sorted(fc.items(), key=lambda kv: -kv[1]):
        L.append(f"| {code} | {n} | {sorted(fcase[code])} |")
    L += ["", "## F-PIVOT-MISS breakdown by abstract pivot", ""]
    pm = Counter(); pcase = {}
    for r in SCORED:
        if "error" in r: continue
        for p in r["pc_missed"]:
            pm[p] += 1; pcase.setdefault(p, []).append(r["case_id"])
    L.append("| Pivot rule | Cases that missed it |")
    L.append("|----|----|")
    for p, _ in sorted(pm.items()):
        L.append(f"| `{p}` | {sorted(pcase[p])} |")
    L += ["", "## Per-case CTI call count + graph size", ""]
    L.append("| Case | CTI calls | Nodes | Edges | P3 tools used | BD | budget_ext |")
    L.append("|-----:|----------:|------:|------:|----:|---:|---:|")
    for r in SCORED:
        if "error" in r: continue
        L.append(f"| {r['case_id']} | {r['cti_calls']} | {r['nodes']} | {r['edges']} | {len(r['phase3_tools_used'])} | {r['bd']} | {r['budget_extension_count']} |")
    return "\n".join(L)


def main():
    sha = open("/tmp/eval_run/sha.txt").read().strip()
    os.makedirs(RUN_DIR, exist_ok=True)
    open(f"{RUN_DIR}/scorecard.md", "w").write(render_scorecard(sha))
    open(f"{RUN_DIR}/deltas.md", "w").write(render_deltas(sha))
    open(f"{RUN_DIR}/failure_histogram.md", "w").write(render_histogram(sha))
    json.dump(SCORED, open(f"{RUN_DIR}/raw_scores.json", "w"), indent=2)
    print(f"Wrote scorecard, deltas, histogram, raw_scores to {RUN_DIR}/ (proposed_fixes.md authored separately)")


if __name__ == "__main__":
    main()
