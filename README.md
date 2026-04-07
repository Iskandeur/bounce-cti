# bounce-cti

Autonomous CTI investigation tool. Feed it a domain / IP / file hash, and a
Claude Code agent pivots through public sources (crt.sh, RDAP, DNS, VirusTotal,
URLScan, Onyphe, Shodan, OTX, ThreatFox, Wayback) building a live infrastructure
graph in your browser.

## Architecture

```
React + Cytoscape  <--WS-->  FastAPI  <--spawn-->  claude -p (headless)
                                |                       |
                                |                       +-- MCP: graph (write nodes/edges)
                                |                       +-- MCP: cti   (call sources)
                                +-- SQLite (graph + cache + events)
```

The agent never returns findings via stdout — it writes them to the graph via
MCP tools. The frontend streams those writes over WebSocket.

## Setup

```bash
python -m venv .venv
# Windows:  .venv\Scripts\activate
# Unix:     source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env  # fill in your keys

cd frontend
npm install
npm run build  # or `npm run dev` in another terminal
cd ..
```

Make sure `claude` (Claude Code CLI) is on your PATH, or set `CLAUDE_BIN` in `.env`.

## Run

```bash
uvicorn backend.main:app --reload
```

Open http://localhost:8000 (prod build) or http://localhost:5173 (vite dev).

## Defusing

`backend/defuse_lists.py` contains hardcoded CDN ranges, parking NS, dyndns
TLDs and known sinkholes. The agent MUST call `graph.defuse()` before pivoting
on an IP or NS — see the system prompt in `backend/agent_runner.py`.

## Adding a source

1. Create `backend/sources/myapi.py` with an `async def` function.
2. Expose it as a `@mcp.tool()` in `backend/mcp_servers/cti_mcp.py`.
3. Whitelist it in `--allowedTools` inside `backend/agent_runner.py`.
