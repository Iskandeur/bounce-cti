"""Score per-case based on saved graph.json + transcript.json.

Mechanical only — no LLM in the loop. Build rules incrementally from observed
tool-call shapes.
"""
import json, os, re, sys
sys.path.insert(0, "/tmp/eval_run")
from cases import CASES

CASES_BY_ID = {c["case_id"]: c for c in CASES}

# Pivot rules keyed on case-specific rule name.
# Each value: callable(tools, nodes, seed_value) -> bool
def _has_tool(tools, name_substr, arg_re=None, **arg_eq):
    for t in tools:
        n = t.get("name", "")
        if name_substr not in n:
            continue
        inp = t.get("input", {}) or {}
        ok = True
        if arg_re is not None:
            ok = False
            for v in inp.values():
                if isinstance(v, str) and re.search(arg_re, v, re.IGNORECASE):
                    ok = True
                    break
        if not ok:
            continue
        for k, v in arg_eq.items():
            iv = inp.get(k)
            if iv is None or str(iv).lower() != str(v).lower():
                ok = False
                break
        if ok:
            return True
    return False


PIVOT_RULES = {
    # Generic ones
    "rdap_seed": lambda tools, nodes, seed: _has_tool(tools, "rdap_domain") or _has_tool(tools, "rdap_ip") or _has_tool(tools, "whois_domain"),
    "dns_resolve_seed": lambda tools, nodes, seed: _has_tool(tools, "dns_resolve") or _has_tool(tools, "reverse_dns"),
    "reverse_dns_seed": lambda tools, nodes, seed: _has_tool(tools, "reverse_dns") or _has_tool(tools, "vt_resolutions_ip") or _has_tool(tools, "virustotal_resolutions"),
    "reverse_whois_email": lambda tools, nodes, seed: _has_tool(tools, "whoxy_reverse") or _has_tool(tools, "whoxy_history"),
    "soa_mname_pivot": lambda tools, nodes, seed: _has_tool(tools, "dns_resolve", arg_re=r"SOA") or any("soa" in str(n.get("metadata") or {}).lower() for n in nodes),
    "vt_pdns_cluster": lambda tools, nodes, seed: _has_tool(tools, "virustotal_resolutions") or _has_tool(tools, "virustotal_domain"),
    "vt_pdns_ip": lambda tools, nodes, seed: _has_tool(tools, "virustotal_resolutions") or _has_tool(tools, "vt_resolutions_ip"),
    "vt_pdns_seed": lambda tools, nodes, seed: _has_tool(tools, "virustotal_domain") or _has_tool(tools, "virustotal_resolutions"),
    "vt_pdns_domain": lambda tools, nodes, seed: _has_tool(tools, "virustotal_domain"),
    "vt_pdns_stage2": lambda tools, nodes, seed: _has_tool(tools, "virustotal_domain") and len([n for n in nodes if n["type"]=="domain"]) >= 4,
    "virustotal_file": lambda tools, nodes, seed: _has_tool(tools, "virustotal_file") or _has_tool(tools, "malwarebazaar_hash"),
    "rdap_ip": lambda tools, nodes, seed: _has_tool(tools, "rdap_ip"),
    "shodan_or_onyphe_banner": lambda tools, nodes, seed: _has_tool(tools, "shodan_host") or _has_tool(tools, "onyphe_ip") or _has_tool(tools, "shodan_search") or _has_tool(tools, "onyphe_datascan"),
    "shodan_banner": lambda tools, nodes, seed: _has_tool(tools, "shodan_host") or _has_tool(tools, "onyphe_ip") or _has_tool(tools, "shodan_search"),
    "jarm_search": lambda tools, nodes, seed: any("jarm" in (t.get("name","") + json.dumps(t.get("input",{})).lower()) for t in tools) or _has_tool(tools, "netlas_jarm") or _has_tool(tools, "zoomeye_jarm"),
    "banner_sibling_search": lambda tools, nodes, seed: _has_tool(tools, "shodan_search") or _has_tool(tools, "onyphe_datascan") or _has_tool(tools, "netlas_search") or _has_tool(tools, "zoomeye_search"),
    "threatfox_ip": lambda tools, nodes, seed: _has_tool(tools, "threatfox"),
    "threatfox_multi": lambda tools, nodes, seed: _has_tool(tools, "threatfox"),
    "threatfox_asn": lambda tools, nodes, seed: _has_tool(tools, "threatfox") or _has_tool(tools, "abuseipdb_check"),
    "threatfox_stage2": lambda tools, nodes, seed: _has_tool(tools, "threatfox"),
    "urlscan_path_keyword": lambda tools, nodes, seed: _has_tool(tools, "urlscan_search"),
    "urlscan_kit_pivot": lambda tools, nodes, seed: _has_tool(tools, "urlscan_search") or _has_tool(tools, "urlscan_result"),
    "urlscan_or_wayback_seed": lambda tools, nodes, seed: _has_tool(tools, "urlscan_search") or _has_tool(tools, "wayback") or _has_tool(tools, "urlscan_result") or _has_tool(tools, "urlscan_domain"),
    "wayback_or_urlscan_seed": lambda tools, nodes, seed: _has_tool(tools, "wayback") or _has_tool(tools, "urlscan_search") or _has_tool(tools, "urlscan_result") or _has_tool(tools, "urlscan_domain"),
    "wayback_seized": lambda tools, nodes, seed: _has_tool(tools, "wayback"),
    "content_fingerprint_pivot": lambda tools, nodes, seed: _has_tool(tools, "dom_fingerprints") or _has_tool(tools, "urlscan_result") or any(n["type"] in ("favicon_hash", "title_hash", "tracking_id") for n in nodes),
    "crtsh_seed": lambda tools, nodes, seed: _has_tool(tools, "crtsh") or _has_tool(tools, "certspotter"),
    "crtsh_blocknovas": lambda tools, nodes, seed: _has_tool(tools, "crtsh") or _has_tool(tools, "certspotter"),
    "ct_burst_window": lambda tools, nodes, seed: (_has_tool(tools, "crtsh") or _has_tool(tools, "certspotter_issuances")) and any(("burst" in str(n.get("metadata") or {}).lower() or "issuance_date" in str(n.get("metadata") or {}).lower()) for n in nodes),
    "shodan_cert_cn_search": lambda tools, nodes, seed: _has_tool(tools, "shodan_search", arg_re=r"cert.*CN|subject.CN|ssl\.cert\.subject") or _has_tool(tools, "shodan_search", arg_re=r"cert"),
    "historical_origin_pivot": lambda tools, nodes, seed: _has_tool(tools, "virustotal_resolutions") or _has_tool(tools, "virustotal_domain") or _has_tool(tools, "onyphe_domain") or _has_tool(tools, "netlas_search") or _has_tool(tools, "zoomeye_search"),
    "urlscan_dom_pivot": lambda tools, nodes, seed: _has_tool(tools, "dom_fingerprints") or _has_tool(tools, "urlscan_result") or _has_tool(tools, "urlscan_search"),
    "rdap_origin": lambda tools, nodes, seed: _has_tool(tools, "rdap_ip"),
    "reverse_ip_seo_decoy": lambda tools, nodes, seed: _has_tool(tools, "shodan_host") or _has_tool(tools, "onyphe_ip") or _has_tool(tools, "vt_resolutions_ip") or _has_tool(tools, "virustotal_resolutions"),
    "cert_san_apex": lambda tools, nodes, seed: _has_tool(tools, "crtsh") or _has_tool(tools, "certspotter"),
    "dns_txt_mx_cross_ref": lambda tools, nodes, seed: _has_tool(tools, "dns_resolve", arg_re=r"TXT|MX") or _has_tool(tools, "dns_resolve", record_type="TXT") or _has_tool(tools, "dns_resolve", record_type="MX"),
    "urlscan_front_companies": lambda tools, nodes, seed: _has_tool(tools, "urlscan_search") or _has_tool(tools, "wayback"),
}


def load(case):
    cid = case["case_id"]
    # Sync inv_id from meta.json if available (runner may have re-submitted).
    try:
        meta = json.load(open("/tmp/eval_run/meta.json"))
        recorded = meta.get("cases", {}).get(str(cid), {}).get("inv_id")
        if recorded:
            case["inv_id"] = recorded
    except Exception:
        pass
    out_dir = f"/tmp/eval_run/c{cid:02d}"
    try:
        g = json.load(open(f"{out_dir}/graph.json"))
    except Exception:
        g = {"nodes": [], "edges": []}
    try:
        tx = json.load(open(f"{out_dir}/transcript.json"))
    except Exception:
        tx = {"entries": []}
    return g, tx


def extract_tools(tx):
    return [e for e in tx.get("entries", []) if e.get("kind") == "tool"]


def event_corpus_text(tx):
    """Lower-case concatenated text of all tool results + reasoning blocks."""
    out = []
    for e in tx.get("entries", []):
        if e.get("kind") == "tool_result":
            out.append((e.get("result_preview") or "").lower())
        elif e.get("kind") == "reasoning":
            out.append((e.get("text") or "").lower())
        elif e.get("kind") == "tool":
            out.append(json.dumps(e.get("input", {})).lower())
    return " ".join(out)


def cti_call_count(tools):
    return sum(1 for t in tools if t.get("name", "").startswith("mcp__cti__"))


def phase3_tools_used(tools):
    PHASE3 = {
        "abuseipdb_check", "certspotter_issuances", "certspotter_serial",
        "netlas_search", "netlas_jarm", "netlas_favicon",
        "whoxy_reverse", "whoxy_history",
        "zoomeye_search", "zoomeye_jarm", "zoomeye_favicon",
        "criminalip_ip", "criminalip_domain",
        "openphish_check", "dom_fingerprints",
    }
    used = set()
    for t in tools:
        n = t.get("name", "")
        for p in PHASE3:
            if p in n:
                used.add(p)
    return sorted(used)


# Loose type aliasing for ground-truth matching. A GT entry of type X is allowed
# to match a graph node whose type is in the set below. The lookup is symmetric
# on tags / metadata, so "actor:muddywater" matches a hash node tagged
# "muddywater" too.
_TYPE_ALIASES = {
    "actor": {"actor", "person", "threat_actor", "intrusion_set", "group", "campaign", "kit", "phishing_kit"},
    "malware": {"malware", "malware_family", "ransomware", "framework", "tool", "kit", "phishing_kit"},
    "ransomware": {"ransomware", "malware", "malware_family"},
    "framework": {"framework", "malware", "tool"},
    "kit": {"kit", "phishing_kit", "framework", "tool", "malware"},
    "phishing_kit": {"phishing_kit", "kit", "framework", "tool", "malware"},
    "kit_fingerprint": {"kit_fingerprint", "favicon_hash", "title_hash", "tracking_id", "form_action", "css_hash", "js_hash", "kit", "phishing_kit"},
    "tool": {"tool", "framework", "malware"},
    "ttp": {"ttp", "tag", "tactic", "technique"},
    "ip": {"ip", "ipv4", "ipv6"},
    "domain": {"domain", "subdomain", "host", "fqdn"},
    "subdomain": {"subdomain", "domain", "host", "fqdn"},
    "hash": {"hash", "sha256", "sha1", "md5", "imphash"},
    "url": {"url", "domain", "subdomain"},
    "asn": {"asn", "as"},
    "email": {"email", "registrant_email", "contact"},
    "registrar": {"registrar"},
    "cert_sha1": {"cert_sha1", "certificate", "cert_serial", "cert_fingerprint", "cert"},
    "cert_serial": {"cert_serial", "cert_sha1", "certificate", "cert"},
    "cert_cn": {"cert_cn", "cert_subject", "certificate", "cert"},
    "country": {"country", "geo"},
}


def has_node(nodes, ntype, value):
    """Match a ground-truth node against the graph. Case-insensitive substring on value.
    Loose: also matches nodes whose tags / metadata reference the GT value, and
    accepts type aliases (e.g. actor → person, malware → ransomware)."""
    if value.startswith("*"):
        # category placeholder - check via tags
        cat = value[1:]
        for n in nodes:
            tagstr = " ".join((n.get("tags") or []) + [str(n.get("metadata") or {})]).lower()
            if cat in tagstr:
                return True
        return False
    v = value.lower()
    alias = _TYPE_ALIASES.get(ntype.lower(), {ntype.lower()})
    for n in nodes:
        nt = n["type"].lower()
        nv = (n.get("value") or "").lower()
        md = n.get("metadata") or {}
        mds = json.dumps(md).lower()
        tags = [t.lower() for t in (n.get("tags") or [])]
        # Tag/metadata match works irrespective of node type — a hash tagged
        # "muddywater" satisfies the actor GT.
        if v in mds or any(v in t for t in tags):
            if ntype.lower() in {"actor", "malware", "ransomware", "framework", "kit", "phishing_kit", "tool", "kit_fingerprint", "ttp"}:
                return True
        if nt not in alias:
            continue
        if v in nv or nv in v:
            return True
        if v in mds:
            return True
        if any(v in t for t in tags):
            return True
    return False


def has_node_loose(nodes, ntype_options, value):
    """Find a node whose value contains the GT value but may have flexible type."""
    v = value.lower()
    for n in nodes:
        nt = n["type"].lower()
        if any(o in nt for o in ntype_options):
            nv = (n.get("value") or "").lower()
            if v in nv or nv in v:
                return True
    return False


def find_node_by_substr(nodes, ntypes, substr):
    s = substr.lower()
    for n in nodes:
        nt = n["type"].lower()
        if any(t in nt for t in ntypes):
            nv = (n.get("value") or "").lower()
            if s in nv:
                return n
    return None


def score_nr(case, nodes):
    gt = case["gt_nodes"]
    hits = 0
    missing = []
    for ntype, val in gt:
        if has_node(nodes, ntype, val):
            hits += 1
        else:
            missing.append(f"{ntype}:{val[:30]}")
    nr = 100.0 * hits / max(len(gt), 1)
    return nr, hits, len(gt), missing


def score_er(case, edges, nodes):
    """Loose match: edge between nodes whose values match the GT pair (substr each side)."""
    gt = case["gt_edges"]
    if not gt:
        return None, 0, 0, []
    hits = 0
    missing = []
    nodes_by_id = {n["id"]: n for n in nodes}
    for src_v, rel, dst_v in gt:
        sv, dv = src_v.lower(), dst_v.lower()
        found = False
        for e in edges:
            sn = nodes_by_id.get(e.get("src"))
            dn = nodes_by_id.get(e.get("dst"))
            if not sn or not dn:
                continue
            s_val = (sn.get("value") or "").lower()
            d_val = (dn.get("value") or "").lower()
            if (sv in s_val or s_val in sv) and (dv in d_val or d_val in dv):
                found = True
                break
            if (sv in d_val or d_val in sv) and (dv in s_val or s_val in dv):
                found = True
                break
        if found:
            hits += 1
        else:
            missing.append(f"{src_v[:18]}--{rel}-->{dst_v[:18]}")
    er = 100.0 * hits / len(gt)
    return er, hits, len(gt), missing


def score_pc(case, tools, nodes):
    rules = case["pivot_rules"]
    seed = case["seed_value"]
    hits = 0
    missed = []
    for r in rules:
        fn = PIVOT_RULES.get(r)
        if fn is None:
            continue
        if fn(tools, nodes, seed):
            hits += 1
        else:
            missed.append(r)
    pc = 100.0 * hits / max(len(rules), 1)
    return pc, hits, len(rules), missed


def score_dc(case, nodes):
    """Count over-inclusion / over-defuse vs defuse targets in the case description.
    Simplified: count nodes tagged 'defused' but ALSO matching a GT-node value (over-defuse)."""
    over_inc = 0
    over_def = 0
    for n in nodes:
        tags = n.get("tags") or []
        if "defused" in tags:
            # check if it's a GT node
            for _, gtv in case["gt_nodes"]:
                if gtv.startswith("*"):
                    continue
                nv = (n.get("value") or "").lower()
                if gtv.lower() in nv:
                    over_def += 1
                    break
    dc = max(0, 100 - 10 * over_inc - 15 * over_def)
    return dc, over_inc, over_def


def score_bd(case, tools, nodes, tx):
    calls = cti_call_count(tools)
    # budget_extension count
    be = sum(1 for n in nodes if n["type"] == "report" and "budget_extension" in (n.get("value") or "").lower())
    if calls <= 60:
        bd = 100
    elif calls <= 90:
        bd = 75 if be >= 1 else 50
    else:
        bd = 0
    return bd, calls, be


def score_rq(case, nodes, tx):
    summary_node = next((n for n in nodes if n["type"] == "report" and n["value"] in ("investigation_summary", "summary")), None)
    if not summary_node:
        # fall back to any report with summary text
        for n in nodes:
            if n["type"] == "report":
                md = n.get("metadata") or {}
                if md.get("summary") or md.get("text"):
                    summary_node = n
                    break
    text_blob = ""
    if summary_node:
        md = summary_node.get("metadata") or {}
        text_blob = " ".join(str(v) for v in md.values()).lower()
    else:
        # also use reasoning blocks as fallback report text
        text_blob = event_corpus_text(tx)[:5000]

    actor_hit = any(a.lower() in text_blob for a in case["expected_actor"])
    marker_hit = case["primary_marker"].lower() in text_blob
    # node coverage in report: count GT nodes whose value substring appears in text_blob
    gt_count = 0
    gt_total = 0
    for ntype, val in case["gt_nodes"]:
        if val.startswith("*"):
            continue
        gt_total += 1
        if val.lower() in text_blob:
            gt_count += 1
    node_pct = 100.0 * gt_count / max(gt_total, 1)
    threshold = node_pct >= 70

    hits = sum([actor_hit, threshold, marker_hit])
    rq = {3: 100, 2: 70, 1: 40, 0: 0}[hits]
    return rq, {"actor_hit": actor_hit, "marker_hit": marker_hit, "node_pct": node_pct, "has_summary": summary_node is not None}


def hypothesis_audit(nodes):
    wh = next((n for n in nodes if n["type"] == "report" and n["value"] == "working_hypothesis"), None)
    summary = next((n for n in nodes if n["type"] == "report" and n["value"] == "investigation_summary"), None)
    history = []
    final_category = None
    if summary:
        md = summary.get("metadata") or {}
        history = md.get("hypothesis_history") or []
        final_category = md.get("final_category")
    category = None
    if wh:
        md = wh.get("metadata") or {}
        category = md.get("category") or md.get("candidate_category")
    return {
        "wh_present": wh is not None,
        "category": category,
        "history_len": len(history),
        "final_category": final_category,
    }


def _has_provenance(n):
    """A node is traceable to a tool call (per protocol §4.6 hallucination
    definition) if its metadata carries explicit provenance — an evidence
    citation, a source/sources_seen field, or a provenance/origin tag. RDAP
    registrant vcards (person nodes) land their name in metadata.evidence
    rather than in the truncated transcript result_preview, so a corpus-only
    check false-positives on them. Provenance metadata clears the suspect."""
    md = n.get("metadata") or {}
    for k in ("evidence", "source", "sources_seen", "provenance", "origin", "tool"):
        v = md.get(k)
        if v:  # non-empty string or non-empty list
            return True
    return False


def hallucination_check(nodes, tx):
    """Heuristic + provenance pass: actor/malware/family/person node values that
    appear in NEITHER the tool-result/reasoning corpus NOR carry provenance
    metadata citing a source tool. A node with metadata.evidence='RIPE RDAP ...'
    or source='rdap' is traceable to a tool call and is NOT a hallucination."""
    corpus = event_corpus_text(tx)
    suspects = []
    for n in nodes:
        if n["type"] in ("actor", "malware", "ransomware", "framework", "phishing_kit", "kit", "person"):
            v = (n.get("value") or "").lower()
            if v and v not in corpus and len(v) >= 3:
                # also try simpler tokens
                tokens = re.findall(r"[a-z0-9]{4,}", v)
                if not any(t in corpus for t in tokens):
                    # Final clearance: provenance metadata makes it traceable.
                    if _has_provenance(n):
                        continue
                    suspects.append((n["type"], n["value"]))
    return suspects


def score_case(case):
    g, tx = load(case)
    nodes = g.get("nodes", [])
    edges = g.get("edges", [])
    tools = extract_tools(tx)

    nr, nr_h, nr_t, nr_miss = score_nr(case, nodes)
    er, er_h, er_t, er_miss = score_er(case, edges, nodes)
    pc, pc_h, pc_t, pc_miss = score_pc(case, tools, nodes)
    dc, over_inc, over_def = score_dc(case, nodes)
    bd, calls, be = score_bd(case, tools, nodes, tx)
    rq, rq_meta = score_rq(case, nodes, tx)
    hyp = hypothesis_audit(nodes)
    halluc = hallucination_check(nodes, tx)
    p3 = phase3_tools_used(tools)

    # overall: mean of NR/ER/PC/DC/BD/RQ; ER null is excluded
    dims = [nr, pc, dc, bd, rq]
    if er is not None:
        dims.append(er)
    overall = sum(dims) / len(dims)
    overall -= 15 * len(halluc)

    return {
        "case_id": case["case_id"],
        "name": case["name"],
        "inv_id": case["inv_id"],
        "nodes": len(nodes),
        "edges": len(edges),
        "cti_calls": calls,
        "phase3_tools_used": p3,
        "nr": round(nr, 1), "nr_hits": nr_h, "nr_total": nr_t, "nr_missing": nr_miss,
        "er": round(er, 1) if er is not None else None, "er_hits": er_h, "er_total": er_t, "er_missing": er_miss,
        "pc": round(pc, 1), "pc_hits": pc_h, "pc_total": pc_t, "pc_missed": pc_miss,
        "dc": dc, "over_inclusion": over_inc, "over_defuse": over_def,
        "bd": bd, "budget_extension_count": be,
        "rq": rq, "rq_meta": rq_meta,
        "hypothesis": hyp,
        "hallucinations": [list(x) for x in halluc],
        "overall": round(overall, 1),
    }


def main():
    results = []
    for case in CASES:
        try:
            r = score_case(case)
        except Exception as e:
            r = {"case_id": case["case_id"], "name": case["name"], "error": str(e)}
        results.append(r)
    json.dump(results, open("/tmp/eval_run/scored.json", "w"), indent=2)
    # quick print
    print(f"{'C':>2} {'NR':>5} {'ER':>5} {'PC':>5} {'DC':>4} {'BD':>4} {'RQ':>4} {'OV':>5} {'CTI':>4} WH P3")
    for r in results:
        if "error" in r:
            print(f"{r['case_id']:>2} ERR  {r['error']}")
            continue
        er = f"{r['er']:>5.1f}" if r['er'] is not None else "  n/a"
        wh = "Y" if r["hypothesis"]["wh_present"] else "."
        p3n = len(r["phase3_tools_used"])
        print(f"{r['case_id']:>2} {r['nr']:>5.1f} {er} {r['pc']:>5.1f} {r['dc']:>4} {r['bd']:>4} {r['rq']:>4} {r['overall']:>5.1f} {r['cti_calls']:>4}  {wh}  {p3n}")


if __name__ == "__main__":
    main()
