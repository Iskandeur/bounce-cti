"""Sequential one-by-one runner. Submit a case, wait for terminal, log to file, next.

User mandated: NO PARALLELISM. Run each case fully before launching the next.
"""
import json, os, sys, time, urllib.request, urllib.error, http.cookiejar
sys.path.insert(0, "/tmp/eval_run")
from cases import CASES

BASE = "https://bounce.alexandre-pinoteau.fr"
CJ = http.cookiejar.MozillaCookieJar("/tmp/cookies.txt")
CJ.load(ignore_discard=True, ignore_expires=True)
OPENER = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CJ))
TERMINAL = {"done", "failed", "stopped", "error", "cleared", "quota_exceeded"}

LOG_FILE = "/tmp/eval_run/runner.log"
META_FILE = "/tmp/eval_run/meta.json"


def log(msg):
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


def req(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"} if body is not None else {}
    r = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    for attempt in range(4):
        try:
            with OPENER.open(r, timeout=60) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            try:
                body_text = e.read().decode()[:200]
            except Exception:
                body_text = ""
            return e.code, {"error": body_text}
        except (urllib.error.URLError, TimeoutError) as e:
            log(f"  net retry {path}: {e}")
            time.sleep(2 ** attempt)
    return 0, {"error": "timeout"}


def get_status(inv_id):
    status, data = req("GET", "/api/investigations")
    if status != 200 or not isinstance(data, list):
        return None
    for inv in data:
        if inv["id"] == inv_id:
            return inv.get("status")
    return None


def wait_for_terminal(inv_id, label, max_minutes=60, hard_cap_minutes=120):
    """Poll until terminal, then save graph+transcript.

    Critical for one-by-one discipline: if we hit the soft deadline but the
    backend still reports `running`, KEEP WAITING (up to hard_cap). Abandoning
    a still-running investigation to submit the next case causes accidental
    parallelism on the VPS — which burned quota on the prior partial run.
    Only give up if status reads keep failing (None) past the soft deadline,
    which indicates the inv genuinely stalled or the API is unreachable.
    """
    soft_deadline = time.time() + max_minutes * 60
    hard_deadline = time.time() + hard_cap_minutes * 60
    last = None
    consec_none_after_soft = 0
    while time.time() < hard_deadline:
        s = get_status(inv_id)
        if s != last:
            log(f"  [{label}] status={s}")
            last = s
        if s in TERMINAL:
            return s
        if time.time() >= soft_deadline:
            if s == "running":
                consec_none_after_soft = 0  # genuinely still working
            elif s is None:
                consec_none_after_soft += 1
                # 10 consecutive failed status reads (~3+ min) past soft
                # deadline → API unreachable, give up gracefully.
                if consec_none_after_soft >= 10:
                    log(f"  [{label}] status unreadable past soft deadline — giving up")
                    return "timeout"
        time.sleep(20)
    log(f"  [{label}] HARD TIMEOUT after {hard_cap_minutes} min (backend still running)")
    return "timeout"


def fetch_and_save(case, status):
    cid = case["case_id"]
    inv_id = case["inv_id"]
    out_dir = f"/tmp/eval_run/c{cid:02d}"
    os.makedirs(out_dir, exist_ok=True)
    _, g = req("GET", f"/api/investigations/{inv_id}/graph")
    _, tx = req("GET", f"/api/investigations/{inv_id}/transcript")
    if g:
        json.dump(g, open(f"{out_dir}/graph.json", "w"))
    if tx:
        json.dump(tx, open(f"{out_dir}/transcript.json", "w"))
    n = len((g or {}).get("nodes", []))
    e = len((g or {}).get("edges", []))
    t = len((tx or {}).get("entries", []))
    log(f"  [c{cid:02d}] saved: {n} nodes, {e} edges, {t} entries, status={status}")


def has_useful_data(case):
    """Determine if previously-fetched data is meaningful (not just empty quota-fail)."""
    cid = case["case_id"]
    gf = f"/tmp/eval_run/c{cid:02d}/graph.json"
    tf = f"/tmp/eval_run/c{cid:02d}/transcript.json"
    if not (os.path.exists(gf) and os.path.exists(tf)):
        return False
    try:
        g = json.load(open(gf))
        tx = json.load(open(tf))
    except Exception:
        return False
    n = len(g.get("nodes", []))
    e = len(g.get("edges", []))
    tools = sum(1 for x in tx.get("entries", []) if x.get("kind") == "tool")
    return n >= 3 and tools >= 3


def submit_new(case):
    """Submit a fresh investigation (returns new inv_id)."""
    body = {"seed_type": case["seed_type"], "seed_value": case["seed_value"], "model": "opus-4.7"}
    status, data = req("POST", "/api/investigations", body)
    if status != 200:
        log(f"  [c{case['case_id']:02d}] submit failed: HTTP {status} {data}")
        return None
    new_id = data.get("id")
    log(f"  [c{case['case_id']:02d}] submitted new inv_id={new_id}")
    return new_id


def run_one(case, force_new=False):
    """Run a single case end-to-end. Returns status."""
    cid = case["case_id"]
    inv_id = case["inv_id"]
    label = f"c{cid:02d}"
    log(f"[c{cid:02d}] === {case['name']} (seed_type={case['seed_type']}) ===")

    cur_status = get_status(inv_id) if inv_id and inv_id != "NEW" else None
    log(f"  [{label}] existing status={cur_status}")

    needs_rerun = force_new or cur_status not in ("running", "done") or not has_useful_data(case)
    if force_new:
        # Fresh-iteration mode: always submit a new investigation so we measure
        # the currently-deployed code, not a cached prior-run graph.
        needs_rerun = True
    elif cur_status == "quota_exceeded":
        # Try resume first
        log(f"  [{label}] resuming quota_exceeded inv")
        s, d = req("POST", f"/api/investigations/{inv_id}/resume")
        if s == 200:
            needs_rerun = False
        else:
            log(f"  [{label}] resume failed: {s} {d} → submitting new")
            needs_rerun = True
    elif cur_status == "running":
        needs_rerun = False

    if needs_rerun:
        new_id = submit_new(case)
        if new_id is None:
            return "submit_failed"
        case["inv_id"] = new_id
        inv_id = new_id

    status = wait_for_terminal(inv_id, label)
    fetch_and_save(case, status)
    return status


def main():
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, "w").close()

    # Persist meta
    if os.path.exists(META_FILE):
        meta = json.load(open(META_FILE))
    else:
        meta = {"started": time.time(), "cases": {}}

    case_ids = sys.argv[1:] if len(sys.argv) > 1 else [str(c["case_id"]) for c in CASES]
    target_ids = set()
    for x in case_ids:
        if "-" in x:
            a, b = x.split("-")
            target_ids.update(range(int(a), int(b) + 1))
        else:
            target_ids.add(int(x))

    for case in CASES:
        if case["case_id"] not in target_ids:
            continue
        force = os.environ.get("FORCE_NEW") == "1"
        if case["case_id"] in meta["cases"] and meta["cases"][str(case["case_id"])].get("status") in ("done",):
            # already complete
            log(f"[c{case['case_id']:02d}] already done in meta, skipping")
            continue
        status = run_one(case, force_new=force)
        meta["cases"][str(case["case_id"])] = {
            "inv_id": case["inv_id"],
            "status": status,
            "completed_at": time.time(),
        }
        json.dump(meta, open(META_FILE, "w"), indent=2)
        log(f"[c{case['case_id']:02d}] DONE status={status}")

    log("ALL DONE")


if __name__ == "__main__":
    main()
