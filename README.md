# bounce-cti

> **Copyright (c) 2026 Alexandre Pinoteau · All rights reserved.**
> Source-available for personal study and non-commercial individual use.
> Any organizational, institutional, governmental, or commercial use
> requires a written license — see [LICENSE](./LICENSE) and
> [COMMERCIAL.md](./COMMERCIAL.md).

Autonomous CTI investigation tool. Feed it a domain, IP, file hash, URL, JARM
fingerprint, ASN, malicious command line, or just the **filename** of a
malicious binary (e.g. `dropper.exe`, no upload needed), and a Claude Code
agent pivots through ~50 public-source
tools (DNS / RDAP, crt.sh, CertSpotter, VirusTotal, URLScan, Onyphe, Shodan,
Netlas, ZoomEye, CriminalIP, OTX, ThreatFox, AbuseIPDB, abuse.ch URLhaus &
MalwareBazaar, Mnemonic pDNS, ip-api, Wayback, Whoxy reverse-WHOIS, OpenPhish,
DOM fingerprints) building a live infrastructure graph in your browser.

## Features

- **Live graph**: Cytoscape canvas updated over WebSocket as the agent pivots.
- **PIN auth + admin dashboard**: per-user model whitelist, account labels,
  one-click impersonation. Admin PIN is bootstrapped from `ADMIN_PIN` env var
  on first start (see "First login" below).
- **Model + thinking-effort selection**: pick the Claude model (Sonnet 4.6,
  Opus 4.6 / 4.7 / 4.8, Haiku 4.5) and an extended-thinking effort level
  (low → max, or the model default) per investigation. Admins gate which
  models each user may spawn.
- **Investigation vertical**: choose the lens for a new investigation — **CTI**
  (threat-infrastructure attribution, the default), **OSINT** (identity /
  entity footprint correlation), or **Due Diligence / KYB** (company identity +
  corporate hierarchy from authoritative registries — v1 seeds a `company` and
  resolves it via GLEIF, incl. Level-2 "who owns whom", pulls UK officers / PSC
  from Companies House and US-issuer identity from SEC EDGAR, and screens the
  company and its directors against the OFAC / EU / UK sanctions lists; ownership
  is shown as *estimated*, never as authoritative beneficial ownership). OSINT adds people/identity seeds — a free
  no-key **username** sweep across ~54 public platforms, **email**→public
  profile (Gravatar) and GitHub-profile enrichment, a **phone** lookup (offline
  carrier / line-type / country), and **wallet** on-chain activity (BTC free,
  ETH with a key). The selector appears in the new-investigation form; bare
  handles are seeded as usernames under OSINT (including when adding a seed to
  an existing OSINT investigation). OSINT investigations are badged in the list.
- **Shareable investigations**: signed share links with section opt-in
  (graph / report / timeline / evidence / chats), expiry, and import-into-account flow.
- **PDF in / PDF out**: bootstrap an investigation from a vendor write-up
  (server-side IOC extraction + refanging) and export the finished
  investigation as a PDF report or a STIX 2.1 bundle. OSINT investigations can
  also be exported as a Markdown **identity dossier** (accounts, identifiers,
  connections, provenance), and Due-Diligence investigations as a **KYB dossier**
  (sanctions exposure, company identity, corporate hierarchy, officers/PSC).
- **Mobile-friendly**: drawer layout, touch-sized targets, single-finger pan.
- **Light / dark theme**: toggle in the sidebar header (☀ / ☾); the choice is
  persisted per browser and applied before first paint.
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
CriminalIP) and the Tier 1/2 sources (DNSDumpster, HackerTarget, LeakIX,
Pulsedive, Censys, EmailRep, Project Honey Pot).

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

# Community knowledge graph (read-only). Demo at https://demo.opencti.io
# exposes a generous 10k/window quota; the token format is `flgrn_octi_tkn_…`.
OPENCTI_URL=https://demo.opencti.io
OPENCTI_API_KEY=

# Tier 1/2 (added 2026-05-21). Required ones error out without a key;
# HackerTarget / LeakIX / EmailRep also work anonymously (key lifts the cap).
DNSDUMPSTER_API_KEY=     #   50 req/day  https://dnsdumpster.com/developer/  (required)
PULSEDIVE_API_KEY=       #  500 req/mo   https://pulsedive.com/api/          (required)
CENSYS_API_KEY=          #  250 req/mo   https://search.censys.io/account/api (required; `id:secret` or `censys_<id>_<secret>`)
PROJECTHONEYPOT_API_KEY= #  free http:BL https://www.projecthoneypot.org/httpbl_configure.php (required, IPv4 only)
HACKERTARGET_API_KEY=    #  ~50/day anon https://hackertarget.com            (optional)
LEAKIX_API_KEY=          #  works anon   https://leakix.net                  (optional)
EMAILREP_API_KEY=        #  10/day anon  https://emailrep.io/key             (optional)

# No-auth sources (no key needed): CIRCL hashlookup + vuln-lookup, AlienVault
# reputation feed, PhishTank, Tor exit-relay list, dnstwist (local binary —
# `pip install dnstwist`, already in requirements.txt).

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

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](./CONTRIBUTING.md). Because
Bounce-CTI is source-available and may also be offered commercially, your first
pull request must sign the [Contributor License Agreement](./CLA.md) (handled
automatically by a bot). A CI merge-gate (`backend imports` + `frontend builds`)
must pass before any PR is merged, since `main` deploys straight to production.

## Deployment

Every push to `main` auto-deploys to the production VPS via GitHub Actions.
There is no staging environment — see `CLAUDE.md` and `ARCHITECTURE.md` for
the deploy pipeline, required GitHub secrets, and rollback procedure.

## Eval

`EVAL_PROTOCOL.md` is the active scoring rubric for the agent. Re-run it
against a new commit whenever you touch the agent system prompt, MCP tool set,
defuse lists, or source integrations. Past runs live under `runs/`.
