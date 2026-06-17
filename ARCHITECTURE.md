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
- `GET  /api/models` — models the caller is allowed to spawn, plus the list
  of extended-thinking `efforts` (`low`/`medium`/`high`/`xhigh`/`max`)

**Investigations**

> All spawn endpoints (`start`, `batch`, `rerun`, `add_seed`, `enrich`,
> `prompt`, `from_pdf`, `from_sample`) accept an optional `model` and an
> optional `effort` (extended-thinking level). The chosen `effort` is persisted
> on the investigation row and reused by `resume` / subsequent phases.

- `POST   /api/investigations` — start (auto-detects seed type from value if `seed_type=auto`; supported types: `domain`, `ip`, `hash`, `url`, `jarm`, `asn`, `command_line`, `executable_name` — the last being a bare filename of a malicious binary such as `dropper.exe`, pivoted via MalwareBazaar's `get_filename` — and `email` / `wallet_address` / `username` for actor-level seeds: an email triggers Whoxy reverse-WHOIS + EmailRep + Pulsedive + OpenCTI; a wallet (ETH `0x…`, BTC bech32 / legacy, XMR — auto-detected by address format) cross-references ThreatFox + Pulsedive + OpenCTI; a forum / Telegram handle is graphed as an opaque identifier and probed against ThreatFox / Pulsedive / OpenCTI / URLScan). Optional `vertical` field (default `cti`; normalised via `backend/verticals.py`, unknown → `cti`) stored on the investigation.
- `POST   /api/investigations/batch` — start many at once; `combined=true` chains them on one graph
- `GET    /api/investigations` — list (caller-owned only)
- `GET    /api/investigations/{id}/graph`
- `GET    /api/investigations/{id}/transcript` — agent's reasoning + tool-call
  transcript ordered by event time. Used by the UI to rebuild the timeline
  after page reload (live WebSocket events only cover the current session).
  Entries are tagged `reasoning` / `tool` / `tool_result` / `phase` so the
  client can render the audit trail with full agent text and per-tool inputs.
- `GET    /api/investigations/{id}/nodes/{node_id}/cross_investigations` —
  list every prior investigation owned by the caller where the same
  `(type, value)` IOC already appeared. Powers the Node-tab "Also seen in
  N prior investigations" panel; the same data is exposed to the agent as
  the `cross_investigation_lookup` MCP tool so it can record
  `seen_in_prior_investigation` evidence on repeat infrastructure during
  the autonomous run.
- `GET    /api/investigations/{id}/actions/blocklist?fmt=...` — render the
  network IOCs as a drop-list. `fmt`: `plain` (default), `hosts`,
  `unbound`, `rpz`, `palo_edl`, `cisco_acl`, `csv`. Defused nodes
  (CDN/parking/sinkhole/Tor/...) excluded unless `include_defused=1`.
- `GET    /api/investigations/{id}/actions/detection?fmt=...` — starter
  detection rule. `fmt`: `sigma` (default), `snort`, `yara`. Hashes
  flagged `nsrl_known` and defused indicators are excluded.
- `GET    /api/investigations/{id}/actions/takedown` — list of
  takedown-ready abuse-email bundles, one per malicious host/IP with a
  known `abuse_email` in its metadata. Each item carries To/Subject/Body
  + mailto link so the Actions UI can offer one-click open in the
  analyst's mail client; bounce-cti never sends anything itself.
- `POST   /api/investigations/{id}/stop` — kill the running agent
- `DELETE /api/investigations/{id}`
- `PATCH  /api/investigations/{id}` — rename (`{title}`); empty/omitted title clears it, falling back to the seed value in the UI
- `POST   /api/investigations/{id}/rerun`
- `POST   /api/investigations/{id}/resume` — pick up an investigation halted by a Claude-subscription quota error (425 while still in cooldown)
- `GET    /api/quota` — Claude-subscription quota state for the host account (`{exhausted, exhausted_until, message, last_seen}`); the frontend polls it to render a global banner + per-investigation Resume button
- `POST   /api/investigations/{src}/merge_into/{dst}` — merge `src` into `dst`
  (both owned by caller; nodes deduped on `(type, value)`, edges on `(src, dst, relation)`,
  metadata/tags/sources_seen unioned; `delete_source=true` to consume the source)
- `POST   /api/investigations/{id}/add_seed` — add a peer-seed to an existing investigation
- `POST   /api/investigations/{id}/enrich` — run a pivot from an existing node
- `POST   /api/investigations/{id}/prompt` — custom prompt on top of the current graph
- `GET    /api/investigations/{id}/pdf` — render PDF report
- `GET    /api/investigations/{id}/stix` — render STIX 2.1 bundle
- `GET    /api/investigations/{id}/csv`  — render STIX-flavoured CSV of observables
  (OpenCTI workbench-ready: `stix_type`, `entity_type`, `value`, hash columns,
  `labels`, `confidence`, `sources`, `description`, `first_seen`, `last_seen`)
- `GET    /api/investigations/{id}/nodes/{node_id}/evidence`
- `POST   /api/investigations/{id}/nodes/{node_id}/tag` — toggle a tag (e.g. `pinned`)
- `POST   /api/investigations/{id}/nodes/{node_id}/note` — set/clear analyst note

**PDF import (bootstrap from a CTI report)**

- `POST /api/investigations/from_pdf` — extract IOCs from PDF, seed a new investigation
- `POST /api/investigations/{id}/from_pdf` — append IOCs from a PDF as add-seeds
- `POST /api/investigations/from_sample` — multipart: either `file` (executable
  / dropper / archive / script — hashed locally, sha256 becomes the seed
  IOC) or `text` (a malicious command line / script — IOCs extracted as
  seeds, raw text graphed as a `command_line` context node + fed to the
  agent as `report_context`). Exactly one of the two must be supplied.
- `GET /api/admin/lessons_learned?limit=N` — admin-only feed of agent
  retrospectives backed by `data/lessons_learned.jsonl`

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
- Configurable `--model` (`sonnet` / `opus` / `opus-4.7` / `opus-4.8` /
  `haiku`); the `opus-4.7` / `opus-4.8` aliases map to `claude-opus-4-7` /
  `claude-opus-4-8`
- Configurable extended-thinking effort: the per-investigation `effort` level
  (`low` / `medium` / `high` / `xhigh` / `max`, or unset = model default) is
  stored on the `investigations` row and applied to every phase spawn via the
  `CLAUDE_CODE_EFFORT_LEVEL` env var (equivalent to the CLI `--effort` flag),
  set in `agent_runner._build_env`
- `--max-turns` cap

After the main run, additional phases run automatically:

- **Phase 1.5 — `phase_hypothesis_write`** (added 2026-05): if the main phase
  did not write a `working_hypothesis` report node, runs a tiny dedicated
  prompt that forces the agent to commit to a hypothesis category (apt_targeted,
  commodity_malware, traffer_or_tds, …) before phase 2. Mechanical enforcement
  of the hypothesis-first arc described in `SYSTEM_PROMPT`.
- **Phase 2 — `phase_followup`**: inspects which mandatory tools the agent
  skipped (e.g. `rdap_ip`, `reverse_dns`, `virustotal_communicating_files`),
  appends graph-state-aware adaptive Phase 3 targets from
  `_adaptive_followup_targets`, surfaces the chosen working_hypothesis to
  anchor pivot decisions, and runs the agent again.
- **Phase 3 — `phase_report_write`**: if no `investigation_summary` report
  node exists, runs a single-purpose phase to write one (with mechanically-
  extracted discriminating-marker candidates pre-injected as MUST INCLUDE
  VERBATIM lines).
- **Phase 4 — `phase_pivot_drain_<N>`**: autonomous pivot-drain loop (see
  CLAUDE.md "Multi-phase agent loop"). Up to `BOUNCE_PIVOT_DRAIN_ROUNDS`
  rounds, each capped at `BOUNCE_PIVOT_DRAIN_MAX_TURNS`, with a
  convergence stop when a round adds < `BOUNCE_PIVOT_DRAIN_CONVERGENCE`
  net-new nodes. A global ceiling `BOUNCE_TOTAL_CTI_BUDGET` (default 82)
  caps cumulative `mcp__cti__*` calls across all phases — the loop counts
  raw CTI calls (`_count_cti_calls`) before each round, stops when <8 calls
  of headroom remain, and clamps the round's turn budget to the remainder.
- **Phase 5 — `phase_lessons_learned`**: short retrospective. The agent
  reads the graph + `gaps_report()` + `queue_status()` and writes a
  single hidden `lessons_learned` report node listing blockers, missing
  capabilities, suggestions, noteworthy patterns, and a one-paragraph
  self-critique. The runner then appends that entry to
  `data/lessons_learned.jsonl` (the project-wide ledger surfaced through
  `GET /api/admin/lessons_learned`).

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

### `backend/seeds.py`
Seed registry — the single source of truth for per-seed-type behaviour. Replaces
the five `if seed_type == …` ladders that used to live in `agent_runner.py`
(now fully eliminated). Exposes:
- `mandatory_tools(seed_type, seed_value)` — the ordered `(tool_name,
  call_example)` pairs the agent must call before reporting;
- `investigation_prompt(seed_type, seed_value)` — the main-phase user prompt
  (`domain`/`hash`/unknown fall through to the generic domain-style branch);
- `add_seed_block(seed_type, seed_value)` / `pivot_block(seed_type, seed_value)`
  — the per-type body of the `run_add_seed` / `run_pivot` prompts (shared
  preamble/suffix stay in agent_runner); `""` for unknown types;
- `followup_extra_steps(seed_type)` — the per-type follow-up steps for the
  `run_investigation` follow-up phase;
- `KNOWN_SEED_TYPES`.

This is the foundation for the multi-vertical (cti/osint/dd) refactor: adding a
seed type becomes a one-place change. Golden-locked by
`backend/tests/test_seeds.py` (+ `golden_investigation_prompts.json`,
`golden_seed_blocks.json`).

### `backend/verticals.py`
The multi-vertical (CTI / OSINT / DD) abstraction. A `Vertical` dataclass
captures the per-vertical knobs — `name`, `label`, `agent_name` (for the
system-prompt builder), `seed_types` (accepted seeds, referencing the seed
registry), `source_pool` (which MCP pool to mount), and `prompt_block` (the
vertical-specific system-prompt addendum, empty for CTI). `VERTICALS` registers
the active verticals: `cti` (byte-for-byte the existing behaviour) and `osint`
(Phase 2, slice 1 — an OSINT *lens*: reuses the CTI source pool/namespace for v1,
differs only by `agent_name=Bounce-OSINT` + an OSINT `prompt_block` that reframes
the goal from threat-infra attribution to identity/entity footprint correlation;
a dedicated `mcp__osint__*` source pool is a later slice). `get_vertical()` /
`normalise()` resolve a name and fall back to `cti` for unknown/empty input, so
bad input never breaks the platform. `POST /api/investigations` accepts an
optional `vertical` field (default `cti`), normalised here and stored on
`investigations.vertical`.

`SOURCE_POOL_MODULES` / `source_pool_module()` map a vertical's `source_pool`
id to the MCP server module that exposes that pool's source tools. The pool id
doubles as the MCP server *key*, so it sets the tool namespace
(`mcp__<pool>__*`). For CTI: `cti` → `cti_mcp` (the historical `mcp__cti__*`
namespace). `agent_runner._write_mcp_config` reads the investigation's vertical
and mounts the resolved pool — so the generated `mcp-{id}.json` is per-vertical
(CTI byte-for-byte unchanged; OSINT v1 reuses the `cti` pool). DD gets registered
as its pool and prompt block land (Phase 3). Tested by
`backend/tests/test_verticals.py`.

The `{core}+{vertical}` system-prompt builder lives in
`agent_runner.build_system_prompt(template, vertical)`: it composes a phase
system prompt from the shared `{core}` template (written in the CTI voice,
`SYSTEM_PROMPT` / `_FOLLOWUP_SYSTEM_PROMPT` / …) by swapping the `agent_name`
throughout and appending the vertical's `prompt_block`. It is applied once,
centrally, inside `_run_claude_phase` (so all phases — main, hypothesis,
followup, report, pivot-drain, lessons, pivot, add-seed, custom — inherit it)
and is a byte-for-byte identity for CTI (`agent_name='Bounce-CTI'`,
`prompt_block=''`; roadmap invariant 4.4). Tested by
`backend/tests/test_prompt_builder.py`.

### `backend/graph_store.py`
SQLite-backed store. Tables:

| Table            | Columns (essentials)                                                                                                          |
|------------------|-------------------------------------------------------------------------------------------------------------------------------|
| `investigations` | `id`, `seed_type`, `seed_value`, `created_at`, `status`, `user_id`, `model`, `effort` (extended-thinking level, or NULL = model default), `quota_reset_at` (epoch when a Claude-subscription cooldown lifts), `title` (optional analyst-supplied rename; falls back to `seed_value` in the UI), `vertical` (`cti`\|`osint`\|`dd`, default `cti` — which product vertical the investigation belongs to) |
| `nodes`          | `id`, `investigation_id`, `type`, `value`, `metadata` (JSON), `tags` (JSON), `confidence`, `source`, `created_at`, UNIQUE(inv,type,value) |
| `edges`          | `id`, `investigation_id`, `src`, `dst`, `relation`, `evidence`, `source`, `confidence`, `created_at`, UNIQUE(inv,src,dst,relation) |
| `events`         | `id` AUTOINCREMENT, `investigation_id`, `kind`, `payload` (JSON), `created_at` — full agent stream + state changes            |
| `cache`          | `key`, `value` (JSON), `created_at` — HTTP response cache (TTL per source)                                                    |
| `users`          | `id`, `pin_hmac` (UNIQUE), `created_at`, `is_admin`, `allowed_models` (JSON or NULL), `label`                                 |
| `sessions`       | `token` (PK), `user_id`, `expires_at`                                                                                         |
| `shares`         | `token` (PK), `investigation_id`, `created_by`, `created_at`, `sections` (JSON), `expires_at`, `revoked`, `label`             |
| `pivot_tasks`    | `id`, `investigation_id`, `node_type`, `node_value`, `pivot_op`, `priority`, `status` (pending\|running\|done\|skipped\|failed\|deferred), `skip_reason` (defused\|no_api_key\|noise_filter\|queue_ceiling), `result_summary`, `attempts`, `enqueued_at`, `started_at`, `completed_at`, UNIQUE(inv,node_type,node_value,pivot_op). Direct CTI tool calls are auto-reconciled to `done` against the event log (`reconcile_pivots_from_events`); a global `BOUNCE_PIVOT_QUEUE_MAX` ceiling parks new enqueues as `deferred`. |
| `quota_state`    | single-row table (`id=1`): `exhausted_until` (epoch), `message`, `last_seen` — Claude-subscription cooldown shared across the host account |

Node IDs are SHA1 hashes of `(investigation_id, type, value)` (lower-cased) —
so upserts are idempotent.

`canonical_node_type(type, value, metadata)` disambiguates the TLS-fingerprint
node types agents tend to conflate: `jarm` (62-hex active server fingerprint)
vs `ja3` (32-hex client MD5) vs `ja3s` (32-hex server MD5). It resolves from
`metadata.type` ("JA3 client fingerprint" → `ja3`, "JA3S server fingerprint" →
`ja3s`) then value shape, and is applied inside `add_node` (and mirrored in
`add_edge`/`tag_node` via `_canonical_edge_endpoint_type`, which prefers the
type of an already-stored fingerprint node with that value) so edges and tags
land on the corrected node id instead of a phantom `jarm` one. JARM is never
inferred merely because a value is a TLS fingerprint.

`init_db()` runs idempotent migrations: it `_ensure_column`s `user_id`/`model`/
`effort`/`quota_reset_at`/`title`/`vertical` on `investigations` and
`is_admin`/`allowed_models`/`label` on `users` for upgrades from earlier
schemas. `vertical` defaults to `'cti'`, so legacy rows and any caller that
doesn't pass one keep the original CTI behaviour (`graph_store.get_vertical()`
also falls back to `'cti'`).

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
MCP server exposing graph write/read tools + the autonomy engine to the agent:

**Graph CRUD**
- `add_node(type, value, metadata, confidence, source, tags)` — also
  auto-enqueues all applicable pivots for this node into `pivot_tasks`
  (defuse-aware, noise-filter-aware, fan-out capped at 8 high + 4 low priority
  per node, queue-ceiling deferral). Auto-tags documented known-bad tool
  defaults (`pivot_mapping.KNOWN_BAD_MARKERS`) and promotes a known
  actor-handle tag (`ACTOR_HANDLES`) to a first-class `threat_actor` node +
  `attributed_to` edge, and likewise a known phishing-kit tag (`KIT_HANDLES`)
  to a `phishing_kit` node + `uses_kit` edge (provenance preserved).
- `add_edge(src_type, src_value, dst_type, dst_value, relation, evidence, source, confidence)`
  — auto-creates a `phantom_autostub`-tagged stub for any missing endpoint so
  edges never dangle (the analyst can spot the unresolved reference)
- `tag_node(type, value, tag)`
- `get_graph(compact: bool = False, stats_only: bool = False)` — full, compact
  (slim metadata), or stats-only (shape + tag counts, no node/edge lists)
- `get_node(type, value)` — fetch one node's full metadata
- `get_report()` — fetch the current `report` node payload (if any)
- `defuse(kind, value, registrant?, registrar?)` — CDN / parking / sinkhole /
  blackhole / dyndns check. Returns `{tags, reasons, sinkhole_kind, should_stop_pivot}`.
  `sinkhole_kind` is one of `blackhole` (null-routed reserved IPs — 0.0.0.0,
  127/8, 240/4, TEST-NET), `monitoring` (vendor / academic sinkhole IPs and NS
  patterns: Shadowserver, Spamhaus, abuse.ch, Microsoft DCU, …), or `le_seized`
  (RDAP registrant / registrar string matches a law-enforcement / vendor
  takedown handler such as `@fbi.gov`, `@microsoft.com`, `ROLR`). LE-seized
  domains return `should_stop_pivot=false` on purpose so the agent keeps
  mining historical residue. Lists live in `backend/defuse_lists.py`.

**Autonomy engine** (drains `pivot_tasks`, drives convergence)
- `next_pivot()` — pop highest-priority pending task, atomically marks `running`;
  attaches `source_state` (key-pool/quota state for the pivot's source) so the
  agent can skip a tool it has no working key for
- `mark_pivot_done(task_id, summary, status)` — close a task
- `queue_status()` — counts: pending/running/done/skipped/failed/deferred + by-op
  (reconciles directly-invoked CTI calls into `done` first)
- `coverage_matrix(only_with_gaps: bool = False)` — per-node pivot coverage
- `requeue_missing()` — close coverage gaps idempotently; also promotes
  queue-ceiling-`deferred` tasks back to `pending`
- `gaps_report()` — group skipped/failed pivots by reason (no_api_key, defused,
  noise_filter, queue_ceiling, ...)
- `quota_status()` — per-source key pool snapshot + `dead_sources` (sources
  flagged systemically non-functional this run via `source_health`, e.g.
  OpenCTI `AUTH_REQUIRED`; auto-skipped at enqueue with
  `skip_reason='source_dead:<status>'`)

`BOUNCE_INV_ID` env var selects which investigation the agent is writing to.

### `backend/mcp_servers/cti_mcp.py`
MCP server exposing ~50 async CTI source tools:

- DNS / pDNS: `dns_resolve`, `reverse_dns`, `mnemonic_pdns`,
  `onyphe_resolver_forward`, `onyphe_resolver_reverse`
- RDAP / WHOIS: `rdap_domain`, `rdap_ip`, `whois_domain`, `whois_ip`
  (classic RFC 3912 TCP/43 client; complements RDAP for fields some
  registries don't yet publish over RDAP — registrar abuse mailbox,
  full registrant org on thin TLDs, OrgAbuseEmail for IP/ASN ranges)
- Certificates: `crtsh_subdomains`, `crtsh_serial`, `crtsh_query`, `onyphe_ctl`,
  `certspotter_issuances`, `certspotter_serial`
- VirusTotal: `virustotal_domain`, `virustotal_ip`, `virustotal_file`,
  `virustotal_resolutions_domain`, `virustotal_resolutions_ip`,
  `virustotal_subdomains`, `virustotal_communicating_files`
- URLScan: `urlscan_search`, `urlscan_result`
- Onyphe Griffin (datascan / threatlist / pastries / geoloc / domain / ip)
- Shodan: `shodan_host`, `shodan_search`
- OTX: `otx_domain`, `otx_ip`, `otx_file`
- ThreatFox: `threatfox_search`
- abuse.ch: `urlhaus_host`, `malwarebazaar_hash`, `malwarebazaar_signature`, `malwarebazaar_filename` (filename-only pivot — returns sample hashes ever reported under that name, used as the primary pivot for `executable_name` seeds), `malwarebazaar_imphash` (PE imphash → sibling-sample cluster, one-call loader-family expansion)
- ip-api: `ip_api_lookup`, `ip_api_batch_lookup`, `ip_api_edns`
- Wayback: `wayback`
- **Phase 3 (added 2026-05-03)**:
  - `abuseipdb_check` — IP reputation (1000 req/day free)
  - `netlas_search` / `netlas_jarm` / `netlas_favicon` — scanner DB (50 req/day)
  - `whoxy_reverse` — reverse WHOIS by email/name/keyword (1500 lifetime)
  - `zoomeye_search` / `zoomeye_jarm` / `zoomeye_favicon` — scanner DB (10k/mo)
  - `criminalip_ip` / `criminalip_domain` — IP/domain intel (~50/day)
  - `openphish_check` — community phishing feed corroboration (no auth)
- **Community knowledge graph (added 2026-05-20)**:
  - `opencti_lookup_indicator` — exact-match IOC enrichment via OpenCTI's
    GraphQL API. Returns score, curated labels (often malware-family names
    like "socgholish", "mintsloader"), and walks `stixCoreRelationships` to
    surface attribution: linked Malware, IntrusionSet, ThreatActor, Campaign,
    AttackPattern (MITRE ATT&CK). Sparse coverage — best-effort enrichment.
  - `opencti_search_actor` — fuzzy intrusion-set / threat-actor lookup with
    aliases + description (for cross-referencing surfaced actor names).
  - `opencti_search_report` — fuzzy report lookup with external_references
    (for chasing the source analysis when a report title appears in the
    indicator response).
- **Phase 2 fingerprint extractor**:
  - `dom_fingerprints(url|urlscan_uuid)` — favicon mmh3 hash (Shodan-compat),
    title SHA1, marketing tracking IDs (GA, GA4, GTM, FB Pixel, Yandex,
    Hotjar, Adobe DTM, MS Clarity, TikTok), form action URLs, inline-script
    SHA1s, crypto wallet addresses (BTC bech32, ETH, XMR)

### `backend/sources/`
One file per source. All async, all cached via `graph_store.cache_get/cache_set`.

Existing: `crtsh`, `rdap`, `dns_tools`, `virustotal`, `urlscan`, `onyphe`,
`shodan`, `otx`, `threatfox`, `wayback`, `ip_api`, `mnemonic`, `abusech`
(URLhaus + MalwareBazaar), and `http_client` (shared HTTPX client + retry).

Phase 2 (DOM fingerprinting): `fingerprints` — extracts favicon mmh3 hash
(Shodan-compat), title SHA1, marketing tracking IDs, form actions, inline
scripts, crypto wallet addresses from a page's HTML or a urlscan UUID.

Phase 3 (added 2026-05-03): `abuseipdb`, `certspotter`, `netlas`, `whoxy`,
`zoomeye`, `criminalip`, `openphish`. Each goes through `key_pool.acquire()`
for rotation/cooldown and degrades gracefully when no key is configured.

Community knowledge graph (added 2026-05-20): `opencti` — single GraphQL
endpoint at `$OPENCTI_URL/graphql` (defaults to `https://demo.opencti.io`)
with bearer-token auth via `key_pool.acquire("opencti")`. Three tools wired
into `cti_mcp` (`opencti_lookup_indicator`, `opencti_search_actor`,
`opencti_search_report`). Auto-enqueued as a priority-3 enrichment for
`domain` / `ip` / `hash` / `url` nodes; falls back to `skip_reason='no_api_key'`
when no token is configured. GraphQL `errors[].extensions.code = AUTH_REQUIRED`
triggers a 10-minute cooldown to stop hot-loop retries on bad tokens.

Phase 4 (added 2026-05-21): broad source-coverage expansion.
- `dnsdumpster` — passive subdomain enum (free 50/day, key required)
- `hackertarget` — reverse-IP, host search, geoip (free anonymous, key
  recommended); fallback for VT/Shodan reverse and ip_api
- `leakix` — exposed services + data-leak events on a host (key optional)
- `pulsedive` — risk-scored IOC enrichment with threat-cluster pivots
  (free 500/month)
- `phishtank` — phishing URL verdict, independent of OpenPhish (no auth)
- `circl_lu` — CIRCL Luxembourg hashlookup (NSRL known-good defuse) + CVE
  vulnerability-lookup (both no-auth)
- `alienvault_rep` — AlienVault IP reputation feed, mirrored locally
  every 6h (no auth)
- `censys` — Censys Platform v3 (Bearer PAT) with auto-fallback to legacy
  Search v2 when the key looks like `id:secret`
- `emailrep` — registrant-email reputation grading (10/day anonymous,
  250/month with key)
- `project_honeypot` — http:BL DNS-based blacklist (IPv4 only, key
  required, sync via `socket.gethostbyname`)
- `tor_exits` — live Tor exit-relay set (no auth, 30 min cache);
  `defuse_lists.is_tor_exit()` queries the in-process set so `add_node`
  auto-tags Tor exits with `tor_exit` and skips infrastructure pivots
- `dnstwist` — local CLI (`pip install dnstwist`) for typosquat /
  IDN-homoglyph / bitsquat permutation discovery; strictly passive
- `takeover` — subdomain-takeover heuristic (curated cloud-provider
  fingerprint list, HTTP GET on the host's own root page)

These add 20 MCP tools, taking the total to ~77. The `circl_hash_lookup`,
`tor_exit_check`, `dnstwist_permutations`, `leakix_host`, and
`pulsedive_indicator` wrappers attach `_pivot_hints` (see `backend/hints.py`)
that steer the agent into NSRL defusion, tor-exit defusion, typosquat
add-nodes, leak triage, and threat-cluster expansion respectively.

### `backend/key_pool.py`
In-process API key pool with round-robin rotation, cooldown on 429
(`mark_rate_limited(src, key, cooldown_seconds)`) and full-day cooldown on
quota exhaustion (`mark_quota_exhausted(src, key)`). Reads keys from env in
two formats per source: `<PREFIX>_API_KEYS=k1,k2,k3` (multi, takes
precedence) or `<PREFIX>_API_KEY=k1` (single, legacy). Per-source short
names: `vt`, `urlscan`, `onyphe`, `shodan`, `otx`, `abusech`, `abuseipdb`,
`certspotter`, `netlas`, `whoxy`, `zoomeye`, `criminalip`, `opencti`. Sources call
`acquire(src)` and degrade gracefully when None is returned.

### `backend/pivot_mapping.py`
Per-node-type pivot rules. `pivots_for(type, value, has_key, defused)`
returns `[(pivot_op, priority, skip_reason_or_None)]`. Defused nodes only
receive doc-only pivots (rdap, dns_resolve); the rest are inserted as
`skipped` with `skip_reason='defused'`. No-key sources are inserted as
`skipped` with `skip_reason='no_api_key'` so they surface in `gaps_report`.
Unregistered node types return `[]`. The rule table is keyed by canonical type
and shared across verticals; `register_pivots(type, rules, replace=False)` is
the cross-vertical extension point (OSINT/DD source modules add their node-type
pivots at import time instead of editing the monolith), and
`known_pivot_types()` lists the registered types.

Also exports `CLOUD_ASNS` (multi-tenant cloud/CDN ASN list, used by the
convergence check), per-node fan-out caps (`MAX_HIGH_PRIO_PER_NODE=8`,
`MAX_LOW_PRIO_PER_NODE=4`), per-hop cap (`MAX_NEW_NODES_PER_HOP=30`), and
`discriminating_marker(type, tags, metadata)` — the predicate used by the
convergence criterion (jarm, ja3, ja3s, favicon_hash, cert_serial, tracking_id,
wallet_address, email, **person**, plus non-CDN/non-blackhole ip/domain/ns/asn).

### `backend/defuse_lists.py`
Hardcoded lists for noise filtering:
- CDN IP ranges (Cloudflare, Fastly, Akamai, CloudFront, GCP)
- Parking nameservers + parking CNAMEs + parking registrant orgs
- DynDNS TLDs (DuckDNS, No-IP, DDNS.net…)
- Known sinkhole IPs (Shadowserver, Microsoft DCU, OpenDNS, Spamhaus,
  abuse.ch, Team Cymru, FBI/DoJ historical landings)
- Known sinkhole NS substrings (`.shadowserver.org`, `.spamhaus.org`,
  `.abuse.ch`, `sinkhole.*`, `rpz.*`, `blackhole.*`, Microsoft DCU NS, …)
- Blackhole IPs + ranges (`0.0.0.0`, `127/8`, `240/4`, TEST-NET-1/2/3, …)
  — distinct from monitoring sinkholes: these mean the domain has been
  intentionally null-routed rather than handed to a monitoring vendor.
- LE registrant patterns (`@fbi.gov`, `@microsoft.com`, `@shadowserver.org`,
  `Registrar of Last Resort`, …) — when present in the RDAP registrant /
  registrar field, `defuse_check(..., registrant=…, registrar=…)` flags
  `sinkhole_kind="le_seized"`, keeping the historical workflow active.

### `backend/refang.py`
Defang→fang IOC normalisation (`evil[.]com` → `evil.com`,
`hxxps://bad(.)site` → `https://bad.site`, `user[at]evil[dot]com` →
`user@evil.com`). Used at the API boundary so the rest of the codebase only
ever sees live values.

### `backend/pdf_import.py`
Extracts text + IOCs from a CTI report PDF (regex + refang). Used by the
`/api/investigations/from_pdf` endpoints to bootstrap an investigation from
a vendor write-up.

### `backend/sample_import.py`
Handles the malware-sample / command-line ingestion path
(`/api/investigations/from_sample`). Two flavours:

- ``handle_file_upload(blob, filename)`` — hashes the uploaded binary
  (SHA256/SHA1/MD5 + size), sniffs the container type (PE/ELF/Mach-O/zip/
  pdf/gzip/7z/rar/script/text via magic bytes + filename heuristics), and
  when the file decodes as text, also extracts embedded IOCs and produces
  a `command_line` context node. The SHA256 is the primary seed; embedded
  IOCs are queued as add-seeds.
- ``handle_text_paste(text)`` — refangs + IOC-extracts the pasted snippet
  (reuses ``pdf_import.extract_iocs``), graphs the raw text on a
  `command_line` node, and seeds the investigation with the strongest
  extracted IOC. If no IOCs are present, the `command_line` node IS the
  seed and the raw text is passed to the agent as ``report_context``.

Neither helper persists the binary on disk — only hashes, metadata, and up
to ``SCRIPT_TEXT_MAX`` of decoded text are retained.

### `backend/pdf_report.py`
Renders an investigation as a downloadable PDF (DejaVu Sans TTF for full
Unicode support).

### `backend/stix_export.py`
Renders an investigation as a STIX 2.1 bundle (JSON) via `generate_stix_bundle`,
or as a STIX-flavoured CSV of observables via `generate_csv` (one row per
observable, columns map onto OpenCTI's CSV mapper for direct workbench import).

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
# Core sources (existing)
VIRUSTOTAL_API_KEY=    # 4 req/min free tier
URLSCAN_API_KEY=       # free
ONYPHE_API_KEY=        # free community tier
SHODAN_API_KEY=        # paid, optional
OTX_API_KEY=           # free
ABUSECH_AUTH_KEY=      # free, register at https://auth.abuse.ch/  (URLhaus + MalwareBazaar)

# Phase 3 sources (added 2026-05-03)
ABUSEIPDB_API_KEY=     # free 1000 req/day
CERTSPOTTER_API_KEY=   # free 100 req/day (SSLMate)
NETLAS_API_KEY=        # free 50 req/day
WHOXY_API_KEY=         # free 1500 lifetime
ZOOMEYE_API_KEY=       # free 10k/month
CRIMINALIP_API_KEY=    # free ~50/day

# Phase 4 sources (added 2026-05-21)
DNSDUMPSTER_API_KEY=        # free 50 req/day
HACKERTARGET_API_KEY=       # optional — lifts the anonymous ~50/day cap
LEAKIX_API_KEY=             # optional — gives 1k/day vs ~50/day anonymous
PULSEDIVE_API_KEY=          # free 500 req/month
CENSYS_API_KEY=             # PAT format `censys_<id>_<secret>` (Platform v3) or `id:secret` (legacy Search v2)
EMAILREP_API_KEY=           # optional — 250/month vs 10/day anonymous
PROJECTHONEYPOT_API_KEY=    # http:BL access key, free
# No-auth sources (no env var): whois (RFC 3912, TCP/43), circl_lu, alienvault_rep, phishtank, tor_exits, dnstwist (local), takeover

# Multi-key rotation (optional; if set, takes precedence over the single-key form)
# Useful for free tiers (VT, Netlas, CertSpotter, CriminalIP).
# VIRUSTOTAL_API_KEYS=k1,k2,k3
# NETLAS_API_KEYS=...
# CERTSPOTTER_API_KEYS=...

CLAUDE_BIN=claude      # path to claude CLI if not in PATH
ADMIN_PIN=             # optional 6-digit PIN; the matching user is promoted to admin on startup (idempotent). No auto-generation if unset.
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

### Merge-gate (`.github/workflows/ci.yml`)

Because `main` deploys straight to prod with no staging, a CI merge-gate runs
on every PR targeting `main` (and as a backstop on push to `main`):

```
Pull request → main
  │
  ▼
GitHub Actions (.github/workflows/ci.yml)
  ├─ backend-import : pip install -r requirements.txt
  │                   → python -m compileall backend
  │                   → import backend.main
  ├─ backend-tests  : pip install -r requirements-dev.txt
  │                   → pytest backend/tests   (golden/regression tests)
  └─ frontend-build : npm ci → npm run build
```

A failing gate must be fixed before merge. Combine with branch protection on
`main` (require PR + passing checks) so a broken commit cannot reach prod.

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
  ├─ preflight: claude CLI resolves (fatal if CLAUDE_BIN in .env not executable)
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
