# Demo snapshots

Each `<name>.json` here is one investigation frozen for the static demo
(`cd frontend && npm run build:demo` → `frontend/dist-demo/`, `?case=<name>`
picks one, otherwise the first by name). What a snapshot holds and leaves out:
`backend/demo_snapshot.py`. To look at it, serve the build:
`python3 -m http.server 8000 --bind 127.0.0.1 --directory frontend/dist-demo`,
then http://127.0.0.1:8000/. A double-clicked `index.html` stays on a hint:
browsers refuse its scripts and the snapshot fetch on `file://`.

## Making one

From the running app, as the investigation's owner (checked against the
server's own secrets):

```bash
curl -s -b cookies.txt \
  "https://<host>/api/investigations/<inv_id>/demo_snapshot?label=Eval%20case%202&forbid=<name>" \
  | python3 -c 'import json,sys; json.dump(json.load(sys.stdin)["snapshot"], sys.stdout, ensure_ascii=False)' \
  > eval/demo/case02.json
```

Or from a database file, with the `.env` of the instance that ran the
investigation (on the production host, as the user that can read it):

```bash
python3 eval/demo_export.py <inv_id> case02 --db data/bounce.db --dotenv .env \
  --label "Eval case 2: one malware hash, no other input" --forbid <name>
```

`--forbid` (repeatable, case-insensitive) is for names that must never appear
on a public page. Read every warning before committing: a credential shape in
threat data is usually a phishing URL's own token, but look.

## Which investigation

A run made after 2026-10-15 21:45 UTC (#63): before that, the event log lost
the rest of a phase after the first tool result over 64 KiB, so the timeline of
an older run has holes. `python3 eval/stream_audit.py --db data/bounce.db
--since <run start>` must exit 0 on it.

## Publishing

This repository is public: a committed snapshot is readable by anyone, so run
the checks above before committing, not after. CI re-checks every committed
file (`backend/tests/test_committed_demo_snapshots.py`): a name the demo build
would skip, a field `from_view` strips, an event not in its reduced form, an
edge pointing outside the graph, or a secret of the CI environment fails the
gate. With several snapshots, the page shows a case picker. The page itself goes up only
when `.github/workflows/demo-pages.yml` is run by hand (GitHub Pages).
