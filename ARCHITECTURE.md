# Bounce-CTI — Architecture

## High-level diagram

```
Browser (React + Cytoscape)
  │  WebSocket (live events)
  │  REST API
  ▼
FastAPI backend (uvicorn)
  │  asyncio.create_task
  ▼
agent_runner.py  ──spawn──►  claude -p (headless, WSL)
                                 │
                    ┌────────────┴────────────┐
                    ▼                         ▼
            MCP: graph server          MCP: cti server
            (graph_mcp.py)             (cti_mcp.py)
            add_node/add_edge          dns_resolve, crtsh,
            tag_node, defuse           virustotal, rdap,
                    │                  urlscan, onyphe,
                    ▼                  shodan, otx, ...
              SQLite (bounce.db)
              nodes / edges / events / cache
```

## Components

### `backend/main.py`
FastAPI app. Exposes:
- `POST /api/investigations` — start a new investigation (seed_type, seed_value, model)
- `GET /api/investigations` — list all
- `GET /api/investigations/{id}/graph` — full graph JSON
- `DELETE /api/investigations/{id}` — delete
- `POST /api/investigations/{id}/rerun` — clear + restart
- `WS /ws/{id}` — stream graph events (node_added, edge_added, agent_*)

### `backend/agent_runner.py`
Spawns `claude -p` (Claude Code headless) with:
- A detailed step-by-step CTI system prompt (see `SYSTEM_PROMPT` constant)
- Per-investigation `mcp.json` (generated dynamically, WSL-path-aware)
- `--allowedTools` restricted to MCP tools only
- `--disallowedTools` blocking Bash/Edit/Write/Read etc.
- `--permission-mode bypassPermissions`
- Configurable `--model` (sonnet/opus/haiku)

Pumps stdout/stderr into the SQLite events table. The WebSocket handler polls events and streams them to the browser.

**Path conversion**: On Windows (`os.name=='nt'`), Python paths and project paths are converted from `C:\...` to `/mnt/c/...` so WSL claude can invoke them via Windows interop.

### `backend/graph_store.py`
SQLite-backed graph. Tables:
- `investigations(id, seed_type, seed_value, created_at, status)`
- `nodes(id, investigation_id, type, value, metadata, tags, confidence, source, created_at)`
- `edges(id, investigation_id, src, dst, relation, evidence, source, confidence, created_at)`
- `events(id, investigation_id, kind, payload, created_at)` — all state changes + agent stream
- `cache(key, value, created_at)` — HTTP response cache (TTL per-source)

Node IDs are SHA1 hashes of `(investigation_id, type, value)` — idempotent upserts.

### `backend/mcp_servers/graph_mcp.py`
MCP server exposing graph write/read tools to the agent:
- `add_node(type, value, metadata, confidence, source, tags)`
- `add_edge(src_type, src_value, dst_type, dst_value, relation, evidence, source, confidence)`
- `tag_node(type, value, tag)`
- `get_graph()` — returns full current graph
- `defuse(kind, value)` — CDN/parking/sinkhole/dyndns check

`BOUNCE_INV_ID` env var selects which investigation to write to.

### `backend/mcp_servers/cti_mcp.py`
MCP server exposing 20 async CTI source tools:
`dns_resolve`, `reverse_dns`, `crtsh_subdomains`, `rdap_domain`, `rdap_ip`,
`virustotal_domain/ip/file`, `virustotal_resolutions_domain/ip`,
`urlscan_search`, `onyphe_domain/ip`, `shodan_host/search`,
`otx_domain/ip/file`, `threatfox_search`, `wayback`

### `backend/sources/`
One file per source. All async, all cached via `graph_store.cache_get/set`.
Sources: `dns_tools`, `crtsh`, `rdap`, `virustotal`, `urlscan`, `onyphe`, `shodan`, `otx`, `threatfox`, `wayback`.

### `backend/defuse_lists.py`
Hardcoded lists for noise filtering:
- CDN IP ranges (Cloudflare, Fastly, Akamai, CloudFront, GCP)
- Parking nameservers (Sedo, Bodis, DAN, ParkingCrew...)
- DynDNS TLDs (DuckDNS, No-IP, DDNS.net...)
- Known sinkhole IPs

### `run_mcp.py`
Standalone MCP launcher (at project root). Used as `command` in generated mcp.json configs. Adds the project root to `sys.path` and runs the specified MCP server module. Cross-platform: works whether invoked by Windows Python or WSL Python.

### `frontend/`
React + Vite + Cytoscape.js (cose-bilkent layout).

Key components in `App.jsx`:
- `HighlightedText` — tokenizes text, matches IOC values against the graph node map, wraps matches in clickable spans that call `focusNode(id)`
- `focusNode(id)` — selects a node in Cytoscape + animates fit to its neighborhood
- `applyFilters(ft)` — hides/shows node types and their incident edges
- WebSocket handler — dispatches `snapshot/node_added/edge_added/node_tagged` events to Cytoscape

UI panels:
1. **Left sidebar**: new investigation form (seed type/value + model selector), history list, agent event log
2. **Center graph**: Cytoscape canvas + floating toolbar (Fit/Relayout/Labels/Export) + node type filter chips
3. **Right panel**: two tabs — Report (investigation summary with clickable IOCs, finding cards with source chips, pivot suggestions) and Node (node metadata, copy JSON, pivot button)

## Data flow (investigation lifecycle)

```
1. User submits seed (domain/ip/hash + model) via UI
2. POST /api/investigations → create_investigation() → returns inv_id
3. asyncio.create_task(run_investigation(inv_id, ...))
4. agent_runner writes per-inv mcp.json (WSL-path-aware)
5. Spawns: claude -p "Seed: domain diia.me\nInvestigate now."
           --model sonnet
           --mcp-config data/mcp-{inv_id}.json
           --strict-mcp-config
           --output-format stream-json
           --allowedTools mcp__graph__* mcp__cti__*
           --disallowedTools Bash,Edit,Write,...
6. Claude reads system prompt, executes 8-step workflow via MCP tools
7. Each add_node/add_edge call → SQLite write + event insert
8. pump_stdout() streams agent JSON events → events table
9. WS /ws/{inv_id} polls events table every 0.5s → pushes to browser
10. Browser handles:
    - node_added/updated → cy.add() / cy.data() + relayout
    - edge_added → cy.add() + relayout
    - agent_assistant → extract tool_use name → event log line
    - agent_exit → refresh investigation status
11. Agent writes report node (STEP 8) → browser shows Report tab
```

## Configuration

All keys in `.env` (copy from `.env.example`):
```
VIRUSTOTAL_API_KEY=    # 4 req/min free tier
URLSCAN_API_KEY=       # free
ONYPHE_API_KEY=        # free community tier
SHODAN_API_KEY=        # paid, optional
OTX_API_KEY=           # free
CLAUDE_BIN=claude      # path to claude CLI if not in PATH
```

## Development setup

```bash
# Backend
python -m venv .venv
source .venv/bin/activate   # or .venv\Scripts\activate on Windows
pip install -r requirements.txt
cp .env.example .env        # fill in API keys
uvicorn backend.main:app --reload

# Frontend (separate terminal)
cd frontend
npm install
npm run dev     # dev server with HMR on :5173, proxies API to :8000
# OR: npm run build  # for production, served by FastAPI at :8000
```

## Deployment (CI/CD)

The project uses **GitHub Actions** for continuous deployment. Every push to `main` triggers an automatic deploy to the production VPS.

### How it works

```
Push on main
  │
  ▼
GitHub Actions (.github/workflows/deploy.yml)
  │  SSH into VPS using secrets (VPS_HOST, VPS_USER, VPS_SSH_KEY)
  ▼
deploy.sh (on VPS)
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

1. Create `backend/sources/newsource.py` with an `async def` function
2. Call `cache_get/cache_set` from `graph_store` for caching
3. Add an `@mcp.tool()` async function in `backend/mcp_servers/cti_mcp.py`
4. Add the tool name to `--allowedTools` in `backend/agent_runner.py`
5. Document the tool's use case in the system prompt if relevant

## Known issues / limitations

- **WSL/Windows path duality**: `run_mcp.py` launcher solves the cross-environment path issue. If MCP servers show as `pending` in the agent log, check that `claude` is authenticated and that the Python path in the generated `data/mcp-{id}.json` is accessible.
- **VT rate limits**: Free tier = 4 req/min. The agent respects `rate_limit_event` and waits, but heavy investigations may be slow.
- **Cache TTL**: Default 1h for most sources, 24h for RDAP/Wayback. Delete `data/bounce.db` to clear the cache.
- **Graph relayout**: cose-bilkent reruns on every node/edge addition (can be slow on large graphs). Use the "Labels off" toggle to improve readability on dense graphs.
