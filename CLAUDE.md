# Bounce-CTI — Agent Guide

## What this is

Autonomous CTI (Cyber Threat Intelligence) investigation platform. A user submits a seed (domain/IP/hash), the backend spawns a headless `claude -p` agent that queries 20+ public CTI sources via MCP tools, builds an infrastructure graph in SQLite, and streams it live to a React+Cytoscape frontend over WebSocket.

## Project layout

```
backend/
  main.py              # FastAPI app (REST + WebSocket + static file serving)
  agent_runner.py       # Spawns claude -p with MCP config, pumps events
  graph_store.py        # SQLite schema + CRUD (nodes, edges, events, cache, users)
  config.py             # Env var loading (API keys, paths)
  auth.py               # PIN-based auth, sessions, admin impersonation
  defuse_lists.py       # CDN/parking/sinkhole/dyndns noise filters
  mcp_servers/
    graph_mcp.py        # MCP server: add_node, add_edge, tag_node, get_graph, defuse
    cti_mcp.py          # MCP server: 20+ async CTI source tools
  sources/              # One file per CTI source (all async, all cached)
frontend/
  src/App.jsx           # Single-file React app (Cytoscape graph, panels, WebSocket)
  vite.config.js        # Dev proxy: /api→:8001, /ws→ws://:8001
data/                   # Runtime data (gitignored)
  bounce.db             # SQLite database
  secret.key            # HMAC key for PIN auth
  mcp-{id}.json         # Per-investigation MCP configs (temporary)
deploy.sh               # Auto-deploy script (called by CI)
run_mcp.py              # MCP server launcher (used in generated mcp.json configs)
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

- **Frontend is a single file**: `frontend/src/App.jsx` contains all components. No routing.
- **Backend serves the frontend**: In production, FastAPI serves `frontend/dist/` as static files.
- **MCP tools only**: The investigation agent communicates exclusively via MCP tools (graph + cti servers). It has no filesystem or shell access.
- **Node IDs are deterministic**: SHA1 of `(investigation_id, type, value)` — upserts are idempotent.
- **SQLite is the only datastore**: No external database. The `data/` directory must persist across deploys.
- **Environment variables**: API keys and config are in `.env` (not in git). See `.env.example` for the full list.

## Gotchas

- The `claude` CLI must be installed and authenticated on any machine running investigations.
- VirusTotal free tier: 4 req/min. Investigations may be slow.
- The `data/` directory is gitignored but must survive deploys (SQLite DB, auth key).
- WebSocket endpoint is `/ws/{investigation_id}` — reverse proxy must support upgrade headers.
