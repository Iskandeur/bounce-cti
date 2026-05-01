# Bounce-CTI — Agent Guide

## What this is

Autonomous CTI (Cyber Threat Intelligence) investigation platform. A user submits a seed (domain / IP / hash / URL / JARM / ASN), the backend spawns a headless `claude -p` agent that queries ~40 public CTI source tools via MCP, builds an infrastructure graph in SQLite, and streams it live to a React + Cytoscape frontend over WebSocket. Investigations are scoped to PIN-authenticated users, can be shared via signed links, and can be exported as PDF or STIX 2.1.

## Project layout

```
backend/
  main.py               # FastAPI app (REST + WebSocket + static file serving)
  agent_runner.py       # Spawns claude -p with MCP config, two-phase workflow, pumps events
  graph_store.py        # SQLite schema + CRUD (investigations, nodes, edges, events,
                        #   cache, users, sessions, shares)
  config.py             # Env var loading (API keys, paths)
  auth.py               # PIN-based auth, sessions, admin bootstrap + impersonation
  defuse_lists.py       # CDN/parking/sinkhole/dyndns noise filters
  refang.py             # Defang→fang IOC normalisation (evil[.]com → evil.com)
  pdf_import.py         # Extract IOCs from an uploaded CTI report PDF
  pdf_report.py         # Render an investigation as a downloadable PDF
  stix_export.py        # Render an investigation as a STIX 2.1 bundle
  mcp_servers/
    graph_mcp.py        # MCP server: add_node, add_edge, tag_node, get_graph,
                        #   get_node, get_report, defuse
    cti_mcp.py          # MCP server: ~40 async CTI source tools
  sources/              # One file per CTI source (all async, all cached):
                        #   crtsh, rdap, dns_tools, virustotal, urlscan, onyphe,
                        #   shodan, otx, threatfox, wayback, ip_api, mnemonic,
                        #   abusech (URLhaus + MalwareBazaar), http_client (shared)
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
EVAL_PROTOCOL_V1.md     # Legacy eval protocol
EVAL_PROTOCOL_V2.md     # Active eval protocol (run on every non-trivial agent change)
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
- **Two-phase agent loop**: `agent_runner.py` runs the main investigation, then injects a
  follow-up phase that fills mandatory tools the agent skipped (e.g. `rdap_ip`, `reverse_dns`)
  and forces a final report node.
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
| Agent system prompt / workflow (`agent_runner.py`)          | `EVAL_PROTOCOL_V2.md` may need a re-run; note in commit message |

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
