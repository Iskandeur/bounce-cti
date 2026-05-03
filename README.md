# bounce-cti

> **Copyright (c) 2026 Alexandre Pinoteau · All rights reserved.**
> Licensed under the [PolyForm Noncommercial License 1.0.0](./LICENSE).
> You may use, study, and modify this project for **non-commercial** purposes
> (personal, academic, research, hobby). **Any commercial use — including
> internal use at a for-profit company — requires a separate commercial
> license from the author.** Please open a GitHub issue or reach out to
> arrange one.

Autonomous CTI investigation tool. Feed it a domain, IP, file hash, URL, JARM
fingerprint, or ASN, and a Claude Code agent pivots through ~50 public-source
tools (DNS / RDAP, crt.sh, CertSpotter, VirusTotal, URLScan, Onyphe, Shodan,
Netlas, ZoomEye, CriminalIP, OTX, ThreatFox, AbuseIPDB, abuse.ch URLhaus &
MalwareBazaar, Mnemonic pDNS, ip-api, Wayback, Whoxy reverse-WHOIS, OpenPhish,
DOM fingerprints) building a live infrastructure graph in your browser.

## Features

- **Live graph**: Cytoscape canvas updated over WebSocket as the agent pivots.
- **PIN auth + admin dashboard**: per-user model whitelist, account labels,
  one-click impersonation. Admin PIN is bootstrapped from `ADMIN_PIN` env var
  on first start (see "First login" below).
- **Shareable investigations**: signed share links with section opt-in
  (graph / report / timeline / evidence / chats), expiry, and import-into-account flow.
- **PDF in / PDF out**: bootstrap an investigation from a vendor write-up
  (server-side IOC extraction + refanging) and export the finished
  investigation as a PDF report or a STIX 2.1 bundle.
- **Mobile-friendly**: drawer layout, touch-sized targets, single-finger pan.
- **Custom prompts on top of an existing graph**: ask the agent to dig further
  with the current graph (and a selection) as context.
- **Noise defusing**: built-in CDN ranges, parking nameservers, sinkhole IPs
  and DynDNS TLDs — agent must call `defuse()` before pivoting on infrastructure.

## Architecture

```
React + Cytoscape  ⇄ WebSocket ⇄  FastAPI  ⇄ spawn ⇄  claude -p (headless)
                                      │                       │
                                      │                       ├─ MCP: graph (write nodes/edges/tags)
                                      │                       └─ MCP: cti   (call sources)
                                      └─ SQLite (investigations + graph + cache + events + auth + shares)
```

The agent never returns findings via stdout — it writes them to the graph via
MCP tools. The frontend streams those writes over WebSocket.

See [`ARCHITECTURE.md`](./ARCHITECTURE.md) for the full breakdown and
[`PURPOSE.md`](./PURPOSE.md) for scope and intent.

## Setup

```bash
python -m venv .venv
# Windows:  .venv\Scripts\activate
# Unix:     source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env  # fill in your API keys (see below)

cd frontend
npm install
npm run build  # or `npm run dev` in another terminal
cd ..
```

Make sure `claude` (Claude Code CLI) is on your `PATH`, or set `CLAUDE_BIN` in
`.env`. The CLI must already be authenticated.

### API keys (in `.env`)

All free-tier or community keys; everything except VirusTotal is optional but
strongly recommended for full coverage. See `.env.example` for the full list
including the Phase 3 sources (AbuseIPDB, CertSpotter, Netlas, Whoxy, ZoomEye,
CriminalIP).

```
# Core
VIRUSTOTAL_API_KEY=    # 4 req/min on free tier
URLSCAN_API_KEY=       # free
ONYPHE_API_KEY=        # free community tier
SHODAN_API_KEY=        # paid; optional
OTX_API_KEY=           # free
ABUSECH_AUTH_KEY=      # free, register at https://auth.abuse.ch/  (URLhaus + MalwareBazaar)

# Phase 3 (added 2026-05-03; all optional, free tiers)
ABUSEIPDB_API_KEY=     # 1000 req/day  https://www.abuseipdb.com
CERTSPOTTER_API_KEY=   #  100 req/day  https://sslmate.com (SSLMate)
NETLAS_API_KEY=        #   50 req/day  https://app.netlas.io
WHOXY_API_KEY=         # 1500 lifetime https://www.whoxy.com (reverse WHOIS)
ZOOMEYE_API_KEY=       #  10k /month   https://www.zoomeye.org
CRIMINALIP_API_KEY=    #  ~50/day      https://www.criminalip.io

# Multi-key rotation (optional). Supersedes the single-key form per source.
# VIRUSTOTAL_API_KEYS=k1,k2,k3
# NETLAS_API_KEYS=...

CLAUDE_BIN=claude      # path to claude CLI if not in PATH
```

## Run

```bash
# Production-style: backend serves the built frontend
uvicorn backend.main:app --host 127.0.0.1 --port 8001

# Dev: HMR frontend in another terminal
cd frontend && npm run dev    # http://localhost:5173
```

Open **http://localhost:8001** for the production build, or
**http://localhost:5173** for the Vite dev server (which proxies `/api` and
`/ws` to `:8001`).

### First login

Set `ADMIN_PIN=<6-digit PIN>` in the environment before the first start so the
backend bootstraps an admin user with that PIN. The bootstrap is idempotent:
on subsequent starts it re-promotes the same PIN to admin if you ever lose
admin rights, but it does **not** auto-generate a PIN — the env var is
required. Once logged in as admin, use the admin dashboard to issue PINs to
additional users (with optional model whitelists).

## Defusing

`backend/defuse_lists.py` contains hardcoded CDN ranges, parking nameservers,
DynDNS TLDs and known sinkholes. The agent MUST call `graph.defuse()` before
pivoting on an IP or NS — the system prompt in `backend/agent_runner.py`
enforces this and adds an early-exit when a domain looks parked or sinkholed.

## Adding a CTI source

1. Create `backend/sources/myapi.py` with an `async def` function. Use
   `backend/sources/http_client.py` for the shared HTTPX client and
   `graph_store.cache_get/cache_set` for response caching.
2. Expose it as a `@mcp.tool()` in `backend/mcp_servers/cti_mcp.py`.
3. Whitelist the tool name in `_ALLOWED_TOOLS` inside `backend/agent_runner.py`.
4. If it's signal-rich, mention it in the relevant `SYSTEM_PROMPT_*` so the
   agent knows when to call it.
5. Update `CLAUDE.md` and `ARCHITECTURE.md` source lists in the same commit
   (see "Documentation upkeep" in `CLAUDE.md` — docs must stay in sync with
   the code at every commit).

## Deployment

Every push to `main` auto-deploys to the production VPS via GitHub Actions.
There is no staging environment — see `CLAUDE.md` and `ARCHITECTURE.md` for
the deploy pipeline, required GitHub secrets, and rollback procedure.

## Eval

`EVAL_PROTOCOL_V2.md` is the active scoring rubric for the agent. Re-run it
against a new commit whenever you touch the agent system prompt, MCP tool set,
defuse lists, or source integrations. Past runs live under `runs/`.
