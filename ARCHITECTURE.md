# Bounce-CTI — Architecture

## High-level diagram

```
Browser (React + Cytoscape)
  │  WebSocket (live events)
  │  REST API (session-cookie auth)
  ▼
FastAPI backend (uvicorn, default :8001)
  │  asyncio.create_task
  ▼
agent_runner.py  ──spawn──►  claude -p (headless)
                                 │  two-phase loop:
                                 │   1. main investigation
                                 │   2. follow-up to fill mandatory tools
                                 │      and force a final report node
                    ┌────────────┴────────────┐
                    ▼                         ▼
            MCP: graph server          MCP: cti server
            (graph_mcp.py)             (cti_mcp.py)
            add_node, add_edge,        ~40 async tools across:
            tag_node, get_graph,       DNS / RDAP, crt.sh, VirusTotal,
            get_node, get_report,      URLScan, Onyphe, Shodan, OTX,
            defuse                     ThreatFox, Wayback, ip-api,
                    │                  Mnemonic pDNS, abuse.ch
                    ▼                  (URLhaus + MalwareBazaar)
              SQLite (data/bounce.db)
              investigations / nodes / edges / events / cache /
              users / sessions / shares
```

## Components

### `backend/main.py`
FastAPI app. All `/api/*` and `/ws/*` are gated by a session cookie except
`/api/auth/login`, `/api/auth/logout`, and the public share viewer.

**Auth & admin**

- `POST /api/auth/login` — exchange a PIN for a session cookie (rate-limited per IP)
- `POST /api/auth/logout`
- `GET  /api/auth/me`
- `GET  /api/admin/users`
- `POST /api/admin/users` — create a user (returns generated PIN)
- `PATCH /api/admin/users/{id}` — update label / allowed-models
- `DELETE /api/admin/users/{id}`
- `POST /api/admin/impersonate/{id}` — admin-only; swaps the session to the target user
- `GET  /api/models` — models the caller is allowed to spawn

**Investigations**

- `POST   /api/investigations` — start (auto-detects seed type from value if `seed_type=auto`)
- `POST   /api/investigations/batch` — start many at once; `combined=true` chains them on one graph
- `GET    /api/investigations` — list (caller-owned only)
- `GET    /api/investigations/{id}/graph`
- `POST   /api/investigations/{id}/stop` — kill the running agent
- `DELETE /api/investigations/{id}`
- `POST   /api/investigations/{id}/rerun`
- `POST   /api/investigations/{id}/add_seed` — add a peer-seed to an existing investigation
- `POST   /api/investigations/{id}/enrich` — run a pivot from an existing node
- `POST   /api/investigations/{id}/prompt` — custom prompt on top of the current graph
- `GET    /api/investigations/{id}/pdf` — render PDF report
- `GET    /api/investigations/{id}/stix` — render STIX 2.1 bundle
- `GET    /api/investigations/{id}/nodes/{node_id}/evidence`
- `POST   /api/investigations/{id}/nodes/{node_id}/tag` — toggle a tag (e.g. `pinned`)
- `POST   /api/investigations/{id}/nodes/{node_id}/note` — set/clear analyst note

**PDF import (bootstrap from a CTI report)**

- `POST /api/investigations/from_pdf` — extract IOCs from PDF, seed a new investigation
- `POST /api/investigations/{id}/from_pdf` — append IOCs from a PDF as add-seeds

**Sharing**

- `POST   /api/investigations/{id}/shares` — create signed share link
  (sections: any subset of `graph`/`report`/`timeline`/`evidence`/`chats`,
  optional expiry, optional label)
- `GET    /api/investigations/{id}/shares`
- `GET    /api/shares` — list shares created by the caller
- `DELETE /api/shares/{token}`
- `POST   /api/shares/{token}/revoke`
- `GET    /api/share/{token}` — **public** (no auth) — filtered investigation payload
- `POST   /api/share/{token}/import` — clone the share, or merge it into one of the caller's investigations

**Live events**

- `WS /ws/{id}` — snapshot on connect, then incremental events
  (`node_added`, `node_updated`, `edge_added`, `node_tagged`, `agent_*`,
  `status_change`, `server_shutdown` on graceful restart)

### `backend/agent_runner.py`
Spawns `claude -p` (Claude Code headless) with:
- A detailed step-by-step CTI system prompt (see `SYSTEM_PROMPT*` constants —
  there are seed-type-specific variants, and the prompt switches based on
  whether the seed is parked / sinkholed)
- Per-investigation `mcp.json` (rendered from the `mcp.json` template, with
  `${BOUNCE_PYTHON}` / `${BOUNCE_INV_ID}` / `${PYTHONPATH}` substituted)
- `--allowedTools` restricted to MCP tools only (graph + cti)
- `--disallowedTools` blocking `Bash,Edit,Write,MultiEdit,Read,Glob,Grep,NotebookEdit,WebSearch,WebFetch,Task,TodoWrite`
- `--permission-mode bypassPermissions`
- Configurable `--model` (`sonnet` / `opus` / `opus-4.7` / `haiku`); the
  `opus-4.7` alias maps to `claude-opus-4-7`
- `--max-turns` cap

After the main run, a **second phase** is injected automatically when needed:
it inspects which mandatory tools the agent skipped (e.g. `rdap_ip`,
`reverse_dns`, `virustotal_communicating_files`) and asks the agent to fill
them, then ensures a final `report` node exists.

The runner also exposes:
- `run_pivot(...)` — pivot from an existing node (used by `/enrich`)
- `run_add_seed(...)` — chain a peer seed onto the same graph
- `run_custom_prompt(...)` — analyst-authored prompt with optional selected nodes
- `stop_investigation(inv_id)` — SIGTERM the spawned process group

stdout/stderr are pumped into the SQLite `events` table; the WebSocket handler
polls events and streams them to the browser.

**Path conversion**: On Windows (`os.name == 'nt'`), Python paths and project
paths are converted from `C:\…` to `/mnt/c/…` so WSL `claude` can invoke them
via Windows interop. A separate `mcp-launcher-{module}.log` is written under
`data/` for each MCP server start to debug timeouts.

### `backend/graph_store.py`
SQLite-backed store. Tables:

| Table            | Columns (essentials)                                                                                                          |
|------------------|-------------------------------------------------------------------------------------------------------------------------------|
| `investigations` | `id`, `seed_type`, `seed_value`, `created_at`, `status`, `user_id`, `model`                                                   |
| `nodes`          | `id`, `investigation_id`, `type`, `value`, `metadata` (JSON), `tags` (JSON), `confidence`, `source`, `created_at`, UNIQUE(inv,type,value) |
| `edges`          | `id`, `investigation_id`, `src`, `dst`, `relation`, `evidence`, `source`, `confidence`, `created_at`, UNIQUE(inv,src,dst,relation) |
| `events`         | `id` AUTOINCREMENT, `investigation_id`, `kind`, `payload` (JSON), `created_at` — full agent stream + state changes            |
| `cache`          | `key`, `value` (JSON), `created_at` — HTTP response cache (TTL per source)                                                    |
| `users`          | `id`, `pin_hmac` (UNIQUE), `created_at`, `is_admin`, `allowed_models` (JSON or NULL), `label`                                 |
| `sessions`       | `token` (PK), `user_id`, `expires_at`                                                                                         |
| `shares`         | `token` (PK), `investigation_id`, `created_by`, `created_at`, `sections` (JSON), `expires_at`, `revoked`, `label`             |

Node IDs are SHA1 hashes of `(investigation_id, type, value)` (lower-cased) —
so upserts are idempotent.

`init_db()` runs idempotent migrations: it `_ensure_column`s `user_id`/`model`/
`is_admin`/`allowed_models`/`label` for upgrades from earlier schemas.

### `backend/auth.py`
- HMAC-SHA256 of the PIN with a per-deploy secret stored in `data/secret.key`
  (auto-generated on first run, mode `0600`)
- 6-digit PIN, 30-day session cookie
- IP-keyed rate limit on `POST /api/auth/login` (5 attempts / 15 min)
- `bootstrap_admin()` runs at FastAPI `startup`: if `ADMIN_PIN` env var is set
  to a 6-digit PIN, ensures a user with that PIN exists and is flagged
  `is_admin=1` (idempotent — it'll also re-promote that user if their admin
  flag was cleared). If `ADMIN_PIN` is unset, it does nothing.

### `backend/mcp_servers/graph_mcp.py`
MCP server exposing graph write/read tools to the agent:
- `add_node(type, value, metadata, confidence, source, tags)`
- `add_edge(src_type, src_value, dst_type, dst_value, relation, evidence, source, confidence)`
- `tag_node(type, value, tag)`
- `get_graph(compact: bool = False)` — full or compact (slim metadata) snapshot
- `get_node(type, value)` — fetch one node's full metadata
- `get_report()` — fetch the current `report` node payload (if any)
- `defuse(kind, value)` — CDN/parking/sinkhole/dyndns check; returns
  `should_stop_pivot` + a tag suggestion

`BOUNCE_INV_ID` env var selects which investigation the agent is writing to.

### `backend/mcp_servers/cti_mcp.py`
MCP server exposing ~40 async CTI source tools:

- DNS / pDNS: `dns_resolve`, `reverse_dns`, `mnemonic_pdns`,
  `onyphe_resolver_forward`, `onyphe_resolver_reverse`
- RDAP / WHOIS: `rdap_domain`, `rdap_ip`
- Certificates: `crtsh_subdomains`, `crtsh_serial`, `crtsh_query`, `onyphe_ctl`
- VirusTotal: `virustotal_domain`, `virustotal_ip`, `virustotal_file`,
  `virustotal_resolutions_domain`, `virustotal_resolutions_ip`,
  `virustotal_subdomains`, `virustotal_communicating_files`
- URLScan: `urlscan_search`, `urlscan_result`
- Onyphe Griffin (datascan / threatlist / pastries / geoloc / domain / ip)
- Shodan: `shodan_host`, `shodan_search`
- OTX: `otx_domain`, `otx_ip`, `otx_file`
- ThreatFox: `threatfox_search`
- abuse.ch: `urlhaus_host`, `malwarebazaar_hash`, `malwarebazaar_signature`
- ip-api: `ip_api_lookup`, `ip_api_batch_lookup`, `ip_api_edns`
- Wayback: `wayback`

### `backend/sources/`
One file per source. All async, all cached via `graph_store.cache_get/cache_set`.
Files: `crtsh`, `rdap`, `dns_tools`, `virustotal`, `urlscan`, `onyphe`,
`shodan`, `otx`, `threatfox`, `wayback`, `ip_api`, `mnemonic`, `abusech`
(URLhaus + MalwareBazaar), and `http_client` (shared HTTPX client + retry).

### `backend/defuse_lists.py`
Hardcoded lists for noise filtering:
- CDN IP ranges (Cloudflare, Fastly, Akamai, CloudFront, GCP)
- Parking nameservers (Sedo, Bodis, DAN, ParkingCrew…)
- DynDNS TLDs (DuckDNS, No-IP, DDNS.net…)
- Known sinkhole IPs

### `backend/refang.py`
Defang→fang IOC normalisation (`evil[.]com` → `evil.com`,
`hxxps://bad(.)site` → `https://bad.site`, `user[at]evil[dot]com` →
`user@evil.com`). Used at the API boundary so the rest of the codebase only
ever sees live values.

### `backend/pdf_import.py`
Extracts text + IOCs from a CTI report PDF (regex + refang). Used by the
`/api/investigations/from_pdf` endpoints to bootstrap an investigation from
a vendor write-up.

### `backend/pdf_report.py`
Renders an investigation as a downloadable PDF (DejaVu Sans TTF for full
Unicode support).

### `backend/stix_export.py`
Renders an investigation as a STIX 2.1 bundle (JSON).

### `run_mcp.py`
Standalone MCP launcher (at project root). Used as `command` in generated
`data/mcp-{id}.json` configs. Adds the project root to `sys.path` and runs the
specified MCP server module. Cross-platform: works whether invoked by Windows
Python or WSL Python. Writes a startup trace to `data/mcp-launcher-*.log`.

### `frontend/`
React 18 + Vite + Cytoscape.js (cose-bilkent layout). No router — view
switching is local state.

| File              | Responsibility                                                                            |
|-------------------|-------------------------------------------------------------------------------------------|
| `main.jsx`        | React entrypoint                                                                          |
| `App.jsx`         | Main app: Cytoscape canvas, sidebar (investigations + new-seed form), report/chat/node panels, agent event log, mobile drawers |
| `Login.jsx`       | PIN login                                                                                 |
| `AdminPanel.jsx`  | Admin dashboard: users, allowed-models per user, impersonation                            |
| `ShareModal.jsx`  | Build a share link (section opt-in + expiry + label)                                      |
| `SharedView.jsx`  | Public viewer for a `/?share=<token>` link, with import-into-account button               |
| `styles.css`      | All styling                                                                               |

Key in-app helpers:
- `HighlightedText` — tokenises text, matches IOC values against the graph node
  map, wraps matches in clickable spans that call `focusNode(id)`
- `focusNode(id)` — selects a node in Cytoscape + animates fit to its neighborhood
- `applyFilters(ft)` — hides/shows node types and their incident edges
- WebSocket handler — dispatches `snapshot/node_added/edge_added/node_tagged/...`
  events to Cytoscape

UI panels:
1. **Left sidebar**: new investigation form (single seed or batch, PDF upload,
   model selector), investigation history, agent event log, share manager.
2. **Center graph**: Cytoscape canvas + floating toolbar (Fit / Relayout /
   Labels / Export / Copy-to-Maltego / STIX / PDF) + node-type filter chips +
   edge-relation filter.
3. **Right panel**: tabs — Report (investigation summary with clickable IOCs,
   finding cards with source chips, pivot suggestions), Chat (free-form
   custom-prompt history), Node (metadata, copy JSON, pivot/enrich, pin,
   note), Timeline (chronological agent activity).

## Data flow (investigation lifecycle)

```
1. User submits seed (type+value, or auto-detect; or batch; or PDF) via UI
2. POST /api/investigations → create_investigation() → returns inv_id
3. asyncio.create_task(run_investigation(inv_id, ...))
4. agent_runner writes per-inv mcp.json (path-aware for WSL/Windows)
5. Spawns: claude -p "Seed: domain diia.me\nInvestigate now."
           --model sonnet
           --append-system-prompt "<seed-type-specific workflow>"
           --mcp-config data/mcp-{inv_id}.json
           --strict-mcp-config
           --output-format stream-json
           --allowedTools mcp__graph__* mcp__cti__*
           --disallowedTools Bash,Edit,Write,...
           --max-turns 120
6. Claude reads system prompt, executes the workflow via MCP tools
7. Each add_node/add_edge call → SQLite write + event insert
8. pump_stdout() streams agent JSON events → events table
9. Follow-up phase: if mandatory tools were skipped or no report node exists,
   a second claude -p invocation is launched with a targeted prompt
10. WS /ws/{inv_id} polls events table every 0.5s → pushes to browser
11. Browser handles:
    - node_added/updated → cy.add() / cy.data() + relayout
    - edge_added → cy.add() + relayout
    - agent_assistant → extract tool_use name → event log line
    - agent_exit → refresh investigation status
12. Agent writes report node → browser shows Report tab
13. Optional: user exports PDF or STIX, or creates a share link
```

## Configuration

All keys in `.env` (copy from `.env.example`):

```
VIRUSTOTAL_API_KEY=    # 4 req/min free tier
URLSCAN_API_KEY=       # free
ONYPHE_API_KEY=        # free community tier
SHODAN_API_KEY=        # paid, optional
OTX_API_KEY=           # free
ABUSECH_AUTH_KEY=      # free, register at https://auth.abuse.ch/  (URLhaus + MalwareBazaar)
CLAUDE_BIN=claude      # path to claude CLI if not in PATH
ADMIN_PIN=             # optional; if unset, an admin PIN is generated on first start
```

## Development setup

```bash
# Backend
python -m venv .venv
source .venv/bin/activate            # or .venv\Scripts\activate on Windows
pip install -r requirements.txt
cp .env.example .env                 # fill in API keys
uvicorn backend.main:app --host 127.0.0.1 --port 8001 --reload

# Frontend (separate terminal)
cd frontend
npm install
npm run dev     # dev server with HMR on :5173, proxies /api + /ws to :8001
# OR: npm run build  # for production, served by FastAPI at :8001
```

## Deployment (CI/CD)

The project uses **GitHub Actions** for continuous deployment. Every push to
`main` triggers an automatic deploy to the production VPS.

### How it works

```
Push on main
  │
  ▼
GitHub Actions (.github/workflows/deploy.yml)
  │  SSH into VPS using secrets (VPS_HOST, VPS_USER, VPS_SSH_KEY)
  ▼
Inline script (defined in deploy.yml, runs on VPS via SSH)
  ├─ git fetch + reset to origin/main
  ├─ pip install (only if requirements.txt changed)
  ├─ npm ci + npm run build (only if frontend/ changed)
  ├─ sudo systemctl restart bounce-cti
  └─ health check (verify service is running)
```

### Production stack

- **Reverse proxy**: Caddy (automatic HTTPS via Let's Encrypt)
- **App server**: uvicorn behind systemd (`bounce-cti.service`)
- **Database**: SQLite in `data/bounce.db` (persistent, not in git)
- **Auth secrets**: `data/secret.key` (generated on first run, not in git)

On a graceful restart, the backend broadcasts a `server_shutdown` frame on
every connected WebSocket so the UI can show a banner and reconnect when the
service comes back up.

### GitHub secrets required

Three secrets must be configured in **Settings > Secrets > Actions**:

| Secret | Description |
|--------|-------------|
| `VPS_HOST` | IP address of the production server |
| `VPS_USER` | SSH username on the VPS |
| `VPS_SSH_KEY` | Private SSH key (ed25519) authorized on the VPS |

### Manual deploy

To deploy manually on the VPS (e.g. to test before pushing):

```bash
/opt/bounce-cti/deploy.sh
```

### Rollback

```bash
# On the VPS
cd /opt/bounce-cti
git log --oneline -5          # find the good commit
git reset --hard <commit-sha>
sudo systemctl restart bounce-cti
```

## Adding a new source

1. Create `backend/sources/newsource.py` with an `async def` function. Use
   `backend/sources/http_client.py` for the shared HTTPX client.
2. Call `cache_get/cache_set` from `graph_store` for caching.
3. Add an `@mcp.tool()` async function in `backend/mcp_servers/cti_mcp.py`.
4. Add the tool name to `_ALLOWED_TOOLS` in `backend/agent_runner.py`.
5. Document the tool's use case in the relevant `SYSTEM_PROMPT*` if it should
   be called for a specific seed type or pivot.
6. Update the source list in `CLAUDE.md` and this file in the same commit
   (see the "Documentation upkeep" rule in `CLAUDE.md`).

## Known issues / limitations

- **WSL/Windows path duality**: `run_mcp.py` launcher solves the cross-environment
  path issue. If MCP servers show as `pending` in the agent log, check that
  `claude` is authenticated and that the Python path in the generated
  `data/mcp-{id}.json` is accessible. Inspect `data/mcp-launcher-*.log` for
  the per-server startup trace.
- **VT rate limits**: Free tier = 4 req/min. The agent respects
  `rate_limit_event` and waits, but heavy investigations may be slow.
- **Cache TTL**: Default 1h for most sources, 24h for RDAP/Wayback. Delete
  `data/bounce.db` to clear the cache (this will also wipe investigations
  and users).
- **Graph relayout**: cose-bilkent reruns on every node/edge addition (can
  be slow on large graphs). Use the "Labels off" toggle to improve readability
  on dense graphs.
- **No staging environment**: every commit on `main` deploys live. Make sure
  imports, syntax, the frontend build, and the SQLite schema are clean before
  pushing.
