"""Fetch graph + transcript per investigation, save to /tmp/eval_run/<case>/."""
import json, os, sys, time, urllib.request, urllib.error, http.cookiejar
sys.path.insert(0, "/tmp/eval_run")
from cases import CASES

BASE = "https://bounce.alexandre-pinoteau.fr"
CJ = http.cookiejar.MozillaCookieJar("/tmp/cookies.txt")
CJ.load(ignore_discard=True, ignore_expires=True)
OPENER = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CJ))


def get(path):
    req = urllib.request.Request(BASE + path)
    for _ in range(3):
        try:
            with OPENER.open(req, timeout=60) as r:
                return json.loads(r.read())
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as e:
            print(f"  retry {path}: {e}")
            time.sleep(2)
    return None


def fetch_case(case):
    cid = case["case_id"]
    inv_id = case["inv_id"]
    # Prefer the inv_id recorded in meta.json (the runner may have re-submitted
    # with a fresh inv_id when the cached one was a quota-fail empty graph).
    try:
        meta = json.load(open("/tmp/eval_run/meta.json"))
        recorded = meta.get("cases", {}).get(str(cid), {}).get("inv_id")
        if recorded:
            inv_id = recorded
            case["inv_id"] = recorded
    except Exception:
        pass
    out_dir = f"/tmp/eval_run/c{cid:02d}"
    os.makedirs(out_dir, exist_ok=True)
    g = get(f"/api/investigations/{inv_id}/graph")
    tx = get(f"/api/investigations/{inv_id}/transcript")
    if g:
        json.dump(g, open(f"{out_dir}/graph.json", "w"))
    if tx:
        json.dump(tx, open(f"{out_dir}/transcript.json", "w"))
    n = len((g or {}).get("nodes", []))
    e = len((g or {}).get("edges", []))
    t = len((tx or {}).get("entries", []))
    print(f"Case {cid:02d} inv={inv_id}: {n} nodes, {e} edges, {t} transcript entries")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        only = set(int(x) for x in sys.argv[1].split(","))
        cases = [c for c in CASES if c["case_id"] in only]
    else:
        cases = CASES
    for case in cases:
        fetch_case(case)
