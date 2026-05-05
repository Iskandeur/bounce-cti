# Bounce-CTI — Agent Guide

## What this is

Autonomous CTI (Cyber Threat Intelligence) investigation platform. A user submits a seed (domain / IP / hash / URL / JARM / ASN), the backend spawns a headless `claude -p` agent that queries ~40 public CTI source tools via MCP, builds an infrastructure graph in SQLite, and streams it live to a React + Cytoscape frontend over WebSocket. Investigations are scoped to PIN-authenticated users, can be shared via signed links, and can be exported as PDF or STIX 2.1.

## Project layout

```
backend/
  main.py               # FastAPI app (REST + WebSocket + static file serving)
  agent_runner.py       # Spawns claude -p with MCP config, multi-phase workflow
                        #   (main → hypothesis_write → followup → report_write), pumps events
  graph_store.py        # SQLite schema + CRUD (investigations, nodes, edges, events,
                        #   cache, users, sessions, shares, pivot_tasks)
  config.py             # Env var loading (API keys, paths)
  auth.py               # PIN-based auth, sessions, admin bootstrap + impersonation
  defuse_lists.py       # CDN/parking/sinkhole/dyndns noise filters
  refang.py             # Defang→fang IOC normalisation (evil[.]com → evil.com)
  pdf_import.py         # Extract IOCs from an uploaded CTI report PDF
  pdf_report.py         # Render an investigation as a downloadable PDF
  stix_export.py        # Render an investigation as a STIX 2.1 bundle
  key_pool.py           # API key rotation pool: round-robin, cooldown on 429,
                        #   per-day quota tracking, graceful degradation
  pivot_mapping.py      # Per-node-type pivot rules + fan-out caps + cloud ASN
                        #   list + discriminating_marker() for convergence
  mcp_servers/
    graph_mcp.py        # MCP server: graph CRUD (add_node, add_edge, tag_node,
                        #   get_graph, get_node, get_report, defuse) +
                        #   autonomy engine (next_pivot, mark_pivot_done,
                        #   queue_status, coverage_matrix, requeue_missing,
                        #   gaps_report, quota_status). add_node auto-enqueues
                        #   pivots into pivot_tasks per pivot_mapping rules.
    cti_mcp.py          # MCP server: ~50 async CTI source tools
  sources/              # One file per CTI source (all async, all cached):
                        #   Existing: crtsh, rdap, dns_tools, virustotal,
                        #     urlscan, onyphe, shodan, otx, threatfox, wayback,
                        #     ip_api, mnemonic, abusech (URLhaus+MalwareBazaar)
                        #   Phase 2: fingerprints (favicon mmh3 hash, title
                        #     SHA1, tracking IDs, form actions, wallets, JS hashes)
                        #   Phase 3: abuseipdb, certspotter, netlas, whoxy,
                        #     zoomeye, criminalip, openphish
                        #   Shared: http_client
frontend/
  src/
    main.jsx            # React entrypoint
    App.jsx             # Main app (Cytoscape graph, sidebar, report/chat/node panels)
    Login.jsx           # PIN login screen
    AdminPanel.jsx      # Admin dashboard (users, models, impersonation)
    ShareModal.jsx      # Build a share link (sections + expiry)
    SharedView.jsx      # Public/share-link viewer (read-only graph + import button)
    styles.css
  vite.config.js        # Dev proxy: /api→:8001, /ws→ws://:8001
data/                   # Runtime data (gitignored)
  bounce.db             # SQLite database
  secret.key            # HMAC key for PIN auth
  mcp-{id}.json         # Per-investigation MCP configs (temporary)
  mcp-launcher-*.log    # Per-server launcher trace logs (debug)
runs/                   # Archived eval-protocol scorecards (one folder per run)
deploy.sh               # Auto-deploy script (callable on the VPS)
run_mcp.py              # MCP server launcher (referenced by generated mcp.json configs)
mcp.json                # Template MCP config (rendered per investigation at runtime)
EVAL_PROTOCOL.md        # Active eval protocol (run on every non-trivial agent change)
PIVOT_MAPPING.md        # Architecture spec for the autonomy engine refactor
```

## Development

```bash
# Backend
source .venv/bin/activate
uvicorn backend.main:app --host 127.0.0.1 --port 8001 --reload

# Frontend (separate terminal)
cd frontend && npm run dev    # Vite dev server on :5173, proxies to :8001
```

Production: frontend is built (`npm run build`) and served as static files by FastAPI.

## Deployment & CI/CD

This repo has **automatic deployment via GitHub Actions**.

**Every push to `main` triggers a deploy to the production VPS:**

1. GitHub Actions SSHes into the VPS (secrets: `VPS_HOST`, `VPS_USER`, `VPS_SSH_KEY`)
2. Runs inline deploy commands (defined in `.github/workflows/deploy.yml`): git pull, install deps if changed, rebuild frontend if changed, restart systemd service
3. The service runs behind Caddy (reverse proxy, automatic HTTPS)

**WARNING: any commit pushed to `main` goes live immediately.** There is no staging environment, no review gate, no rollback automation. Before pushing:
- Make sure the Python backend starts without errors
- Make sure the frontend builds (`cd frontend && npm run build`)
- Do not push commits that break imports, syntax, or database schema without migration

### If you need to change the deploy pipeline

- Deploy script: `deploy.sh` (runs on the VPS)
- GitHub Actions workflow: `.github/workflows/deploy.yml`
- Systemd service: `bounce-cti.service` (managed on the VPS, not in this repo)
- Reverse proxy: Caddy with automatic HTTPS (managed on the VPS)

## Key conventions

- **Frontend is React + Vite, no router**: a handful of components in `frontend/src/`
  (`App.jsx` is the bulk; `Login`, `AdminPanel`, `ShareModal`, `SharedView` are separate files).
  View switching is done with local state, not URLs.
- **Backend serves the frontend**: In production, FastAPI mounts `frontend/dist/` at `/` as static files.
- **MCP tools only**: The investigation agent communicates exclusively via MCP tools
  (graph + cti servers). Bash/Edit/Write/Read/Glob/Grep/Web* are explicitly disallowed.
- **Multi-phase agent loop**: `agent_runner.py` runs the main investigation
  (`phase_main`), then mechanically enforces a `working_hypothesis` report node
  if the main phase skipped one (`phase_hypothesis_write`, added 2026-05),
  then injects a follow-up phase that fills mandatory tools and surfaces
  graph-state-aware Phase 3 gaps (`phase_followup`), then ensures a final
  `investigation_summary` report node (`phase_report_write`), then runs an
  autonomous pivot-drain loop (`phase_pivot_drain_<N>`, added 2026-05) that
  reads the report's own `pivot_suggestions` and the pivot queue, executes
  them, and recurses for up to `BOUNCE_PIVOT_DRAIN_ROUNDS` rounds (default 3,
  set to 0 to disable). Each round caps at `BOUNCE_PIVOT_DRAIN_MAX_TURNS`
  (default 60) and stops early when a round adds fewer than
  `BOUNCE_PIVOT_DRAIN_CONVERGENCE` (default 3) new nodes. The state
  machine in `PIVOT_MAPPING.md` informs the adaptive logic.
- **Pivot queue** (`pivot_tasks` table): every `add_node` call auto-enqueues all
  applicable pivots via `pivot_mapping.pivots_for()`. Defused nodes (CDN/parking/
  sinkhole/dyndns) only enqueue documentation pivots (rdap/dns_resolve); the rest
  are inserted as `skipped` with `skip_reason='defused'` for later visibility in
  `gaps_report`. Per-node fan-out cap: 8 high-priority + 4 low-priority pivots.
  The agent drains the queue via `next_pivot()` / `mark_pivot_done()`.
- **Key rotation**: `backend/key_pool.py` lets each source accept either
  `<SRC>_API_KEY=k1` (single) or `<SRC>_API_KEYS=k1,k2,k3` (multi, takes precedence).
  Cooldown on 429 (60s default), full-day cooldown on quota exhausted. Sources call
  `key_pool.acquire(src)` and degrade gracefully when None is returned.
- **Node IDs are deterministic**: SHA1 of `(investigation_id, type, value)` — upserts are idempotent.
- **Auth is PIN + session cookie**: Set `ADMIN_PIN=<6-digit>` in the env before the first start
  so the bootstrap promotes that PIN to admin (idempotent; no auto-generation if unset).
  Each investigation is owned by a user; the WebSocket and every `/api/*` route check ownership.
- **Per-user model whitelist**: Admins can restrict which Claude models a user can spawn.
  Admin accounts are unrestricted.
- **SQLite is the only datastore**: No external database. The `data/` directory must persist across deploys.
- **Environment variables**: API keys and config are in `.env` (not in git). See `.env.example` for the full list.

## Testing

**Always test features against the live app before considering them done.** Don't just check syntax and imports — actually use the feature:
- For UI changes: open the app, navigate to the feature, verify it renders and behaves correctly.
- For API endpoints: curl them or open them in a browser to verify the response.
- For investigation features: use an existing investigation or start a lightweight one (e.g. a parked domain) to test end-to-end.
- Avoid `.extension` in API route paths (e.g. `/report.pdf`) — Caddy or FastAPI static file mounts can interfere. Use clean paths (e.g. `/pdf`).

## Documentation upkeep — MANDATORY

**Documentation MUST stay in sync with the code at every commit.** This is not optional.

Whenever a commit changes any of the following, the corresponding docs must be updated in the **same commit** (not a follow-up):

| If you change…                                              | Update at minimum…                                    |
|-------------------------------------------------------------|-------------------------------------------------------|
| Project layout (new/renamed/removed files in `backend/`, `frontend/src/`, root) | `CLAUDE.md` "Project layout", `ARCHITECTURE.md`       |
| MCP tools (`backend/mcp_servers/*.py`)                      | `CLAUDE.md`, `ARCHITECTURE.md`                        |
| HTTP / WebSocket routes (`backend/main.py`)                 | `ARCHITECTURE.md` route list, `README.md` if user-visible |
| SQLite schema (`backend/graph_store.py`)                    | `ARCHITECTURE.md` schema section                      |
| Auth, sharing, admin model                                  | `CLAUDE.md` "Key conventions", `ARCHITECTURE.md`      |
| User-visible features (UI, exports, imports, sharing)       | `README.md`, `PURPOSE.md` if scope shifts             |
| Deploy pipeline (`.github/workflows/`, `deploy.sh`)         | `CLAUDE.md` "Deployment & CI/CD", `ARCHITECTURE.md`   |
| `.env.example` keys                                         | `README.md` setup, `ARCHITECTURE.md` configuration    |
| Agent system prompt / workflow (`agent_runner.py`)          | `EVAL_PROTOCOL.md` may need a re-run; note in commit message |

**Before every commit**, scan the staged diff and ask: *"Does this commit invalidate any
claim in `README.md`, `CLAUDE.md`, `ARCHITECTURE.md`, `PURPOSE.md`, or `.env.example`?"*
If yes, fix it in the same commit. A commit that ships code without the matching doc
update is considered incomplete.

If a doc-only follow-up is unavoidable (e.g. you're correcting a stale claim discovered
later), prefix the commit subject with `docs:` so the intent is obvious in `git log`.

## Gotchas

- The `claude` CLI must be installed and authenticated on any machine running investigations.
- VirusTotal free tier: 4 req/min. Investigations may be slow.
- The `data/` directory is gitignored but must survive deploys (SQLite DB, auth key).
- WebSocket endpoint is `/ws/{investigation_id}` — reverse proxy must support upgrade headers.
- Every push to `main` deploys to production (see "Deployment & CI/CD"). There is no staging.
