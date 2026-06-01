"""Sequential one-by-one runner. Submit a case, wait for terminal, log, next.

User-mandated (EXCEPTIONAL MEASURE): NO PARALLELISM — run each case fully
before launching the next, to avoid burning the shared Anthropic 5-hour
window. The backend's `claude -p` investigations consume the SAME subscription
quota as the eval-driver session, so a parallel burst exhausts it fast.

Quota-survival design (the whole point of this rewrite):
  * The shared subscription quota WILL be hit on a full-12 sequential run
    (prior run spanned 3 windows). When it is, the in-flight investigation
    flips to `quota_exceeded` and `POST /api/investigations` starts returning
    429. This runner DETECTS that, reads the reset epoch from `/api/quota`,
    SLEEPS until it passes, then `POST /resume`s the quota_exceeded inv in
    place (graph preserved) and keeps going. Submits also retry through 429.
  * Restart safety: the eval-driver session itself halts when quota dies and
    is restarted manually. meta.json records each case's inv_id THE MOMENT it
    is submitted (before waiting), so a mid-wait death is recoverable — on
    restart a tracked inv is RESUMED/continued, never blindly re-submitted
    (even in FORCE_NEW mode), so we never spawn duplicate investigations.
  * If the container was reclaimed (fresh /tmp), reconstruct meta.json from the
    dev-branch-committed copy before launching; the runner then re-attaches to
    the recorded inv_ids and re-fetches their graphs.
"""
import json, os, sys, time, urllib.request, urllib.error, http.cookiejar
sys.path.insert(0, "/tmp/eval_run")
from cases import CASES
try:
    from cases import NEGATIVE_CASES
except ImportError:
    NEGATIVE_CASES = []

MODEL = "opus-4.8"

BASE = "https://bounce.alexandre-pinoteau.fr"
CJ = http.cookiejar.MozillaCookieJar("/tmp/cookies.txt")
CJ.load(ignore_discard=True, ignore_expires=True)
OPENER = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CJ))

# `quota_exceeded` is intentionally NOT in the "stop and move on" terminal set
# here — it is handled specially (wait + resume). The genuinely-final statuses:
FINAL = {"done", "failed", "stopped", "error", "cleared"}

LOG_FILE = "/tmp/eval_run/runner.log"
META_FILE = "/tmp/eval_run/meta.json"

# Bounded per-iteration sleep while waiting for the quota window to refill, so
# the log shows liveness and we re-probe for an early reset. Hard cap protects
# against a stuck `exhausted_until`.
QUOTA_POLL_MAX_SLEEP = 1500     # ≤25 min between probes
QUOTA_HARD_CAP_SECONDS = 8 * 3600  # give up waiting after 8h


def log(msg):
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


def req(method, path, body=None):
    """Return (http_status:int, parsed_json_or_error_dict). 0 = network failure."""
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"} if body is not None else {}
    r = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    for attempt in range(4):
        try:
            with OPENER.open(r, timeout=60) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            try:
                raw = e.read().decode()
            except Exception:
                raw = ""
            try:
                parsed = json.loads(raw)
            except Exception:
                parsed = {"error": raw[:300]}
            return e.code, parsed
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            log(f"  net retry {path}: {e}")
            time.sleep(2 ** attempt)
    return 0, {"error": "timeout"}


def save_meta(meta):
    meta["updated"] = time.time()
    json.dump(meta, open(META_FILE, "w"), indent=2)


# ---------------------------------------------------------------- quota ----

def quota_state():
    """(exhausted: bool, reset_epoch: float|None)."""
    s, d = req("GET", "/api/quota")
    if s != 200 or not isinstance(d, dict):
        return False, None
    return bool(d.get("exhausted")), d.get("exhausted_until")


def reset_from_detail(detail):
    """Pull a reset epoch out of a 429/425 error body if present."""
    if isinstance(detail, dict):
        d2 = detail.get("detail") if isinstance(detail.get("detail"), dict) else detail
        for k in ("reset_at", "exhausted_until"):
            v = d2.get(k) if isinstance(d2, dict) else None
            if v:
                return v
    return None


def wait_for_quota(reason="", reset_hint=None):
    """Block until the subscription quota window refills. Returns True if it
    cleared, False if the hard cap elapsed. Survives a stuck epoch by re-probing
    /api/quota every iteration (the gate may clear before the stated reset)."""
    started = time.time()
    log(f"  QUOTA WAIT ({reason}) — entering wait loop")
    while time.time() - started < QUOTA_HARD_CAP_SECONDS:
        exhausted, reset = quota_state()
        if not exhausted:
            log(f"  QUOTA CLEARED ({reason}) after {int(time.time()-started)}s")
            return True
        reset = reset or reset_hint
        now = time.time()
        if reset and reset > now:
            sleep = min(QUOTA_POLL_MAX_SLEEP, int(reset - now) + 30)
        else:
            sleep = 600  # no epoch known → re-probe every 10 min
        eta = time.strftime('%H:%M:%S', time.gmtime(reset)) if reset else "unknown"
        log(f"  QUOTA still exhausted; reset≈{eta} UTC; sleeping {sleep}s")
        time.sleep(max(30, sleep))
    log(f"  QUOTA WAIT ({reason}) HARD-CAP {QUOTA_HARD_CAP_SECONDS}s elapsed — giving up")
    return False


# --------------------------------------------------------------- status ----

def get_status(inv_id):
    status, data = req("GET", "/api/investigations")
    if status != 200 or not isinstance(data, list):
        return None
    for inv in data:
        if inv.get("id") == inv_id:
            return inv.get("status")
    return None


def wait_for_terminal(inv_id, label, max_minutes=75, hard_cap_minutes=150):
    """Poll until a FINAL or quota_exceeded status. KEEP WAITING past the soft
    deadline while the backend still reports `running` (abandoning a live inv to
    launch the next case causes accidental parallelism on the VPS)."""
    soft = time.time() + max_minutes * 60
    hard = time.time() + hard_cap_minutes * 60
    last = None
    consec_none_after_soft = 0
    while time.time() < hard:
        s = get_status(inv_id)
        if s != last:
            log(f"  [{label}] status={s}")
            last = s
        if s in FINAL or s == "quota_exceeded":
            return s
        if time.time() >= soft:
            if s == "running":
                consec_none_after_soft = 0
            elif s is None:
                consec_none_after_soft += 1
                if consec_none_after_soft >= 10:
                    log(f"  [{label}] status unreadable past soft deadline — giving up")
                    return "timeout"
        time.sleep(20)
    log(f"  [{label}] HARD TIMEOUT after {hard_cap_minutes} min (still running)")
    return "timeout"


def drive_to_final(inv_id, label, meta, cid):
    """wait_for_terminal, but transparently survive quota_exceeded: wait for the
    window, resume in place, and keep waiting. Returns a FINAL status (or
    quota_exceeded/timeout if we exhaust resume attempts / the hard cap)."""
    attempts = 0
    while True:
        status = wait_for_terminal(inv_id, label)
        if status != "quota_exceeded":
            return status
        attempts += 1
        log(f"  [{label}] hit quota_exceeded (resume attempt {attempts})")
        meta["cases"][str(cid)] = {"inv_id": inv_id, "status": "quota_exceeded",
                                   "updated_at": time.time()}
        save_meta(meta)
        if attempts > 15:
            log(f"  [{label}] too many quota resumes — leaving as quota_exceeded")
            return "quota_exceeded"
        if not wait_for_quota(reason=f"{label} resume"):
            return "quota_exceeded"
        s, d = req("POST", f"/api/investigations/{inv_id}/resume")
        if s == 425:
            # still cooling (race) — loop back, wait_for_quota again
            log(f"  [{label}] resume 425 (still cooling); re-waiting")
            time.sleep(60)
            continue
        if s != 200:
            log(f"  [{label}] resume failed HTTP {s} {d}")
            return "quota_exceeded"
        log(f"  [{label}] resumed; continuing to wait")


def fetch_and_save(cid, inv_id, status, out_dir=None):
    if out_dir is None:
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
    log(f"  [{os.path.basename(out_dir)}] saved: {n} nodes, {e} edges, {t} entries, status={status}")


def has_useful_data(cid, out_dir=None):
    if out_dir is None:
        out_dir = f"/tmp/eval_run/c{cid:02d}"
    gf = f"{out_dir}/graph.json"
    tf = f"{out_dir}/transcript.json"
    if not (os.path.exists(gf) and os.path.exists(tf)):
        return False
    try:
        g = json.load(open(gf)); tx = json.load(open(tf))
    except Exception:
        return False
    n = len(g.get("nodes", []))
    tools = sum(1 for x in tx.get("entries", []) if x.get("kind") == "tool")
    return n >= 3 and tools >= 3


def submit_with_quota_retry(case, meta):
    """Submit a fresh investigation; if the quota gate (429) fires, wait and
    retry. Records the new inv_id into meta IMMEDIATELY (restart-safety)."""
    cid = case["case_id"]
    body = {"seed_type": case["seed_type"], "seed_value": case["seed_value"], "model": MODEL}
    for _ in range(20):
        status, data = req("POST", "/api/investigations", body)
        if status == 200:
            new_id = data.get("id")
            log(f"  [c{cid:02d}] submitted new inv_id={new_id}")
            meta["cases"][str(cid)] = {"inv_id": new_id, "status": "submitted",
                                       "updated_at": time.time()}
            save_meta(meta)
            return new_id
        if status == 429:
            log(f"  [c{cid:02d}] submit gated by quota (429); waiting")
            if not wait_for_quota(reason=f"c{cid:02d} submit",
                                  reset_hint=reset_from_detail(data)):
                return None
            continue
        log(f"  [c{cid:02d}] submit failed: HTTP {status} {data}")
        return None
    return None


def run_one(case, meta, force_new=False):
    cid = case["case_id"]
    label = f"c{cid:02d}"
    log(f"[c{cid:02d}] === {case['name']} (seed_type={case['seed_type']}, seed={case['seed_value']}) ===")

    # 1. Resolve which inv_id to act on. A meta-tracked inv (from this run, even
    #    a prior crashed session) ALWAYS wins over force_new — never resubmit a
    #    case we've already launched.
    tracked = meta["cases"].get(str(cid), {})
    inv_id = tracked.get("inv_id")
    if not inv_id and not force_new:
        inv_id = case["inv_id"] if case["inv_id"] not in (None, "NEW") else None

    if inv_id:
        cur = get_status(inv_id)
        log(f"  [{label}] tracked inv_id={inv_id} status={cur}")
        if cur == "done" and has_useful_data(cid):
            log(f"  [{label}] already done with useful data — skipping re-run")
            return "done", inv_id
        if cur in ("running",):
            status = drive_to_final(inv_id, label, meta, cid)
            fetch_and_save(cid, inv_id, status)
            return status, inv_id
        if cur == "quota_exceeded":
            # resume in place
            if wait_for_quota(reason=f"{label} startup-resume"):
                s, d = req("POST", f"/api/investigations/{inv_id}/resume")
                if s in (200, 425):
                    status = drive_to_final(inv_id, label, meta, cid)
                    fetch_and_save(cid, inv_id, status)
                    return status, inv_id
            log(f"  [{label}] could not resume tracked quota inv → will submit fresh")
            inv_id = None
        elif cur == "done":
            # done but no local data (fresh container) — just fetch it
            fetch_and_save(cid, inv_id, cur)
            if has_useful_data(cid):
                return "done", inv_id
            inv_id = None  # empty → resubmit
        elif cur in FINAL:
            # failed/stopped/error/cleared → resubmit fresh
            inv_id = None
        elif cur is None:
            # inv vanished from list → resubmit
            inv_id = None

    # 2. No usable tracked inv → submit fresh (with quota retry).
    if not inv_id:
        inv_id = submit_with_quota_retry(case, meta)
        if inv_id is None:
            return "submit_failed", None

    status = drive_to_final(inv_id, label, meta, cid)
    fetch_and_save(cid, inv_id, status)
    return status, inv_id


def run_one_negative(neg, meta, force_new=False):
    """Run a negative/restraint case (§9b). Uses the same inv logic as run_one
    but saves data to the neg's own directory (n01/n02/n03) and uses a distinct
    meta key (neg_<cid>) so case IDs 101-103 don't collide with positives."""
    cid = neg["case_id"]
    out_dir = f"/tmp/eval_run/{neg.get('dir') or ('n%02d' % (cid - 100))}"
    meta_key = f"neg_{cid}"
    label = neg.get("dir") or f"n{cid - 100:02d}"
    log(f"[{label}] === {neg['name']} (seed_type={neg['seed_type']}, seed={neg['seed_value']}) ===")

    tracked = meta["cases"].get(meta_key, {})
    inv_id = tracked.get("inv_id")

    if inv_id:
        cur = get_status(inv_id)
        log(f"  [{label}] tracked inv_id={inv_id} status={cur}")
        if cur == "done" and has_useful_data(cid, out_dir):
            log(f"  [{label}] already done — skipping")
            return "done", inv_id
        if cur in ("running",):
            status = drive_to_final(inv_id, label, meta, meta_key)
            fetch_and_save(cid, inv_id, status, out_dir)
            return status, inv_id
        if cur == "quota_exceeded":
            if wait_for_quota(reason=f"{label} startup-resume"):
                s, d = req("POST", f"/api/investigations/{inv_id}/resume")
                if s in (200, 425):
                    status = drive_to_final(inv_id, label, meta, meta_key)
                    fetch_and_save(cid, inv_id, status, out_dir)
                    return status, inv_id
            inv_id = None
        elif cur == "done":
            fetch_and_save(cid, inv_id, cur, out_dir)
            if has_useful_data(cid, out_dir):
                return "done", inv_id
            inv_id = None
        elif cur is None or cur in FINAL:
            inv_id = None

    if not inv_id:
        body = {"seed_type": neg["seed_type"], "seed_value": neg["seed_value"], "model": MODEL}
        for _ in range(20):
            s, d = req("POST", "/api/investigations", body)
            if s == 200:
                inv_id = d.get("id")
                log(f"  [{label}] submitted inv_id={inv_id}")
                meta["cases"][meta_key] = {"inv_id": inv_id, "status": "submitted",
                                           "updated_at": time.time()}
                save_meta(meta)
                break
            if s == 429:
                log(f"  [{label}] submit gated by quota (429); waiting")
                if not wait_for_quota(reason=f"{label} submit",
                                      reset_hint=reset_from_detail(d)):
                    return "submit_failed", None
                continue
            log(f"  [{label}] submit failed: HTTP {s} {d}")
            return "submit_failed", None
        if not inv_id:
            return "submit_failed", None

    status = drive_to_final(inv_id, label, meta, meta_key)
    fetch_and_save(cid, inv_id, status, out_dir)
    return status, inv_id


def main():
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, "w").close()
    log("=== sequential_runner START (one-by-one, quota-survivable) ===")

    if os.path.exists(META_FILE):
        meta = json.load(open(META_FILE))
    else:
        meta = {"started": time.time(), "cases": {}}
    meta.setdefault("cases", {})

    # Accept: plain case IDs (2, 3, 8 ...), ranges (2-9), "N1"/"N2"/"N3" for
    # negative cases, and the numeric IDs of negatives (101, 102, 103).
    raw_args = sys.argv[1:] if len(sys.argv) > 1 else \
        [str(c["case_id"]) for c in CASES] + [f"N{n['case_id']-100}" for n in NEGATIVE_CASES]
    target_pos_ids = set()
    run_negatives = False
    neg_ids = set()
    for x in raw_args:
        xu = x.upper()
        if xu.startswith("N") and xu[1:].isdigit():
            neg_ids.add(int(xu[1:]))   # N1 → 1, N2 → 2, N3 → 3
            run_negatives = True
        elif x.isdigit() and int(x) >= 100:
            neg_ids.add(int(x) - 100)  # 101 → 1, 102 → 2
            run_negatives = True
        elif "-" in x:
            a, b = x.split("-")
            target_pos_ids.update(range(int(a), int(b) + 1))
        else:
            target_pos_ids.add(int(x))

    force = os.environ.get("FORCE_NEW") == "1"
    log(f"pos_targets={sorted(target_pos_ids)} neg_targets={sorted(neg_ids)} force_new={force}")

    for case in CASES:
        if case["case_id"] not in target_pos_ids:
            continue
        cid = case["case_id"]
        tracked = meta["cases"].get(str(cid), {})
        if tracked.get("status") == "done" and has_useful_data(cid):
            log(f"[c{cid:02d}] already done in meta + data present — skipping")
            continue
        status, inv_id = run_one(case, meta, force_new=force)
        meta["cases"][str(cid)] = {"inv_id": inv_id, "status": status,
                                   "completed_at": time.time()}
        save_meta(meta)
        log(f"[c{cid:02d}] DONE status={status} inv_id={inv_id}")

    for neg in NEGATIVE_CASES:
        rel_id = neg["case_id"] - 100  # 101 → 1
        if neg_ids and rel_id not in neg_ids:
            continue
        if not (run_negatives or neg_ids):
            continue
        meta_key = f"neg_{neg['case_id']}"
        out_dir = f"/tmp/eval_run/{neg.get('dir') or ('n%02d' % rel_id)}"
        tracked = meta["cases"].get(meta_key, {})
        if tracked.get("status") == "done" and has_useful_data(neg["case_id"], out_dir):
            log(f"[{neg.get('dir')}] already done in meta + data present — skipping")
            continue
        status, inv_id = run_one_negative(neg, meta, force_new=force)
        meta["cases"][meta_key] = {"inv_id": inv_id, "status": status,
                                   "completed_at": time.time()}
        save_meta(meta)
        log(f"[{neg.get('dir')}] DONE status={status} inv_id={inv_id}")

    log("ALL DONE")


if __name__ == "__main__":
    main()
