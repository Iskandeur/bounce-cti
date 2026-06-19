# Bounce-CTI — Agent Guide

## What this is

Autonomous CTI (Cyber Threat Intelligence) investigation platform. A user submits a seed (domain / IP / hash / URL / JARM / ASN / command_line / executable_name / email / wallet_address / username / phone), the backend spawns a headless `claude -p` agent that queries ~50 public CTI source tools via MCP (commercial scanners + abuse feeds + the OpenCTI community knowledge graph), builds an infrastructure graph in SQLite, and streams it live to a React + Cytoscape frontend over WebSocket. Investigations are scoped to PIN-authenticated users, can be shared via signed links, and can be exported as PDF or STIX 2.1.

The `executable_name` seed type lets the analyst paste just the basename of a malicious binary (e.g. `dropper.exe`) without uploading the file or knowing its hash — the agent pivots via MalwareBazaar's `get_filename` query to recover sample hashes and then runs the standard hash workflow on the top hits for family attribution.

The `email`, `wallet_address`, and `username` seed types let the analyst start from an actor signal: a registrant / phishing-contact email triggers reverse-WHOIS over Whoxy + EmailRep reputation; a cryptocurrency wallet (auto-detected for ETH `0x…`, BTC bech32, BTC legacy, XMR) cross-references ransomware IOC feeds; a forum / Telegram handle is graphed as an opaque identifier and probed against the community KG. None of these require dedicated chain-tracing — the value is graph-level correlation across the existing source pool.

## Project layout

```
backend/
  main.py               # FastAPI app (REST + WebSocket + static file serving)
  agent_runner.py       # Spawns claude -p with MCP config, multi-phase workflow
                        #   (main → hypothesis_write → followup → report_write), pumps events
  graph_store.py        # SQLite schema + CRUD (investigations, nodes, edges, events,
                        #   cache, users, sessions, shares, pivot_tasks, quota_state)
  config.py             # Env var loading (API keys, paths)
  seeds.py              # Seed registry: single source of truth for per-seed-type
                        #   behaviour (mandatory_tools + investigation_prompt +
                        #   add_seed_block + pivot_block + followup_extra_steps +
                        #   KNOWN_SEED_TYPES). Replaces the five seed_type if/elif
                        #   ladders in agent_runner (now eliminated). Multi-
                        #   vertical foundation (Phase 1).
  verticals.py          # Vertical registry: the CTI/OSINT/DD abstraction.
                        #   Vertical{name,label,agent_name,seed_types,
                        #   source_pool,prompt_block} + VERTICALS (cti + osint
                        #   lens; osint reuses the cti pool for v1, differs by
                        #   agent_name + prompt_block) + get_vertical/normalise
                        #   (unknown → cti fallback) + source pool selection
                        #   (SOURCE_POOL_MODULES, consumed by
                        #   agent_runner._write_mcp_config). {core}+{vertical}
                        #   system-prompt builder (agent_runner.build_system_prompt)
                        #   swaps agent_name + appends prompt_block — iso-
                        #   functional for CTI. Multi-vertical foundation (Phase 1).
  auth.py               # PIN-based auth, sessions, admin bootstrap + impersonation
  defuse_lists.py       # CDN/parking/sinkhole/blackhole/dyndns noise filters
                        #   + LE-takedown registrant markers (sinkhole_kind)
  refang.py             # Defang→fang IOC normalisation (evil[.]com → evil.com)
  pdf_import.py         # Extract IOCs from an uploaded CTI report PDF
  sample_import.py      # Handle uploaded malware sample (any binary or script)
                        #   + pasted command-line / script — hashes binaries,
                        #   extracts IOCs from scripts, builds the command_line
                        #   context node + report_context for the agent
  action_exports.py     # Operational deliverables for the Actions tab:
                        #   render_blocklist (plain/hosts/unbound/rpz/palo_edl/
                        #     cisco_acl/csv), render_detection (sigma/snort/
                        #     yara), render_takedown (per-host abuse email
                        #     bundle: To/Subject/Body + mailto link). Filters
                        #     out defused indicators by default so accidental
                        #     CDN / Tor / sinkhole blocks don't leak into
                        #     production drop-lists.
  mitre_mapping.py      # Heuristic MITRE ATT&CK technique mapper:
                        #   TECHNIQUES catalog (44 enterprise techniques),
                        #   _TAG_MAP (node-tag → technique candidates with
                        #   rationale), _IMPORT_MAP (PE-import → technique).
                        #   map_graph(graph) returns ranked candidates with
                        #   merged rationales / evidence node IDs / confidence
                        #   (low/medium/high based on signal count). Exposed
                        #   to the agent as the mitre_attack_candidates MCP
                        #   tool — the agent validates each candidate and
                        #   writes the final report.metadata.mitre_attack_mapping.
  sample_analysis.py    # Pure-Python static-analysis pass run on uploaded
                        #   binaries: Shannon entropy (overall + per-section),
                        #   printable string extraction (ASCII + UTF-16LE,
                        #   ≥6/≥4 chars, deduped + ranked + capped at 500),
                        #   IOC harvesting from those strings, PE walker
                        #   (machine, compile_timestamp, sections w/ entropy,
                        #   import-DLL list, imphash-lite), ELF walker
                        #   (ei_class, machine, entry). Zero new deps; runs
                        #   in-process so the binary never leaves the host.
                        #   Output lands on hash_node.metadata.static_analysis
  osint_export.py       # Render an OSINT investigation as a Markdown identity
                        #   dossier (subject + accounts/handles + identifiers
                        #   [emails/phones/wallets] + connections + provenance);
                        #   identity-centric counterpart to action_exports.
                        #   Pure render_dossier(graph, inv); served at
                        #   GET /api/investigations/{id}/osint_dossier
  pdf_report.py         # Render an investigation as a downloadable PDF
  stix_export.py        # Render an investigation as a STIX 2.1 bundle
  key_pool.py           # API key rotation pool: round-robin, cooldown on 429,
                        #   per-day quota tracking, graceful degradation
  source_health.py      # Short-TTL dead-source cache (auth_required /
                        #   tier_restricted / quota_exhausted / zero_balance)
                        #   backed by the cache table so both MCP processes see
                        #   it; auto-enqueue skips pivots needing a dead source
  pivot_mapping.py      # Per-node-type pivot rules + fan-out caps + global
                        #   pending-queue ceiling (MAX_PENDING_QUEUE) + cloud
                        #   ASN list + discriminating_marker() for convergence
                        #   + noise pre-filters (cloud_platform_domain,
                        #   is_role_mailbox, is_hex_serial) + KNOWN_BAD_MARKERS
                        #   (positive default-fingerprint table) + ACTOR_HANDLES
                        #   (tag→threat_actor promotion) + KIT_HANDLES
                        #   (tag→phishing_kit promotion) + key_source_for_op +
                        #   register_pivots()/known_pivot_types() (cross-vertical
                        #   extension point: OSINT/DD modules add node-type pivots
                        #   without editing the rules monolith)
  mcp_servers/
    graph_mcp.py        # MCP server: graph CRUD (add_node, add_edge, tag_node,
                        #   get_graph[+stats_only], get_node, get_report, defuse)
                        #   + autonomy engine (next_pivot[+source_state],
                        #   mark_pivot_done, queue_status, coverage_matrix,
                        #   requeue_missing[+promote_deferred], gaps_report,
                        #   quota_status). add_node auto-enqueues pivots per
                        #   pivot_mapping rules (with noise-filter suppression +
                        #   queue-ceiling deferral), auto-tags known-bad
                        #   defaults, and promotes known actor-handle tags to
                        #   threat_actor nodes (+ kit-handle tags to phishing_kit
                        #   nodes). add_edge auto-stubs missing
                        #   endpoints (phantom_autostub).
    cti_mcp.py          # MCP server: ~84 async CTI source tools
                        #   (incl. malwarebazaar_imphash — PE imphash cluster,
                        #   username_enumerate — Sherlock-style profile sweep,
                        #   gravatar_email — email→public profile / accounts,
                        #   github_profile — GitHub user identity enrichment,
                        #   wallet_enrich — crypto wallet on-chain activity,
                        #   phone_lookup — offline phone metadata,
                        #   website_extract — page links/emails/social profiles)
  sources/              # One file per CTI source (all async, all cached):
                        #   Existing: crtsh, rdap, whois (RFC 3912 / port-43),
                        #     dns_tools, virustotal,
                        #     urlscan, onyphe, shodan, otx, threatfox, wayback,
                        #     ip_api, mnemonic, abusech (URLhaus+MalwareBazaar)
                        #   Phase 2: fingerprints (favicon mmh3 hash, title
                        #     SHA1, tracking IDs, form actions, wallets, JS hashes)
                        #   Phase 3: abuseipdb, certspotter, netlas, whoxy,
                        #     zoomeye, criminalip, openphish
                        #   Community KG: opencti (GraphQL, read-only —
                        #     score, malware-family labels, actor/campaign
                        #     attribution, ATT&CK + linked report titles)
                        #   Phase 4 (2026-05-21): dnsdumpster (passive subdomain),
                        #     hackertarget (rev-IP / host search / geoip — free),
                        #     leakix (exposed services + leak detection),
                        #     pulsedive (risk-scored IOC enrichment),
                        #     phishtank (URL verdict — independent of OpenPhish),
                        #     circl_lu (CIRCL hashlookup NSRL + vuln-lookup),
                        #     alienvault_rep (IP reputation feed, no auth),
                        #     censys (Platform v3, JARM + cert search),
                        #     emailrep (registrant-email reputation),
                        #     project_honeypot (http:BL DNS lookup),
                        #     tor_exits (live exit-relay list — auto-defuse),
                        #     dnstwist (local typosquat enumeration),
                        #     takeover (subdomain-takeover heuristic)
                        #   OSINT (Phase 2): username_enum (free, no-key
                        #     Sherlock-style profile sweep across ~30 public
                        #     platforms; e_code/e_string/m_string detection
                        #     manifest adapted COPY-DATA from blackbird +
                        #     Sherlock, MIT — see THIRD_PARTY_LICENSES; anti-bot
                        #     platforms (Instagram/TikTok/X/LinkedIn/Facebook)
                        #     surfaced as `deferred` behind an Apify scraping
                        #     seam, paid/not enabled). Shared into the cti pool
                        #     so both the OSINT username seed and CTI actor-
                        #     handle pivots use it.
                        #     gravatar (free, no-key email→public profile:
                        #     MD5(email)→display name + linked social accounts +
                        #     URLs; email pivot, shared into the cti pool).
                        #     github_profile (free, no-key GitHub user→identity
                        #     enrichment: name/company/blog/twitter handle;
                        #     username pivot, shared into the cti pool).
                        #     phone_enrich (offline, no-key phone metadata via
                        #     libphonenumber/phonenumbers Apache-2.0: validity,
                        #     country/region, carrier, line type, timezones;
                        #     powers the new `phone` OSINT seed + phone pivot,
                        #     shared into the cti pool).
                        #     wallet_enrich (crypto wallet on-chain activity:
                        #     BTC via blockstream.info no-key, ETH via Etherscan
                        #     w/ optional ETHERSCAN_API_KEY — balance, volume,
                        #     tx count, activity window, counterparty sample;
                        #     concept ported from flowsint Apache-2.0, see
                        #     THIRD_PARTY_LICENSES; wallet_address pivot, shared
                        #     into the cti pool).
                        #     website_enrich (free, no-key page extraction:
                        #     title/text + outbound links/external domains +
                        #     emails + social-profile handles via stdlib regex;
                        #     concept ported from flowsint to_text/to_links
                        #     Apache-2.0; url pivot, shared into the cti pool).
                        #   Shared: http_client
  tests/                # pytest suite (golden / regression tests, e.g.
                        #   test_seeds.py locks the seed-registry output).
                        #   Run: pytest backend/tests (deps: requirements-dev.txt)
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
2. Runs inline deploy commands (defined in `.github/workflows/deploy.yml`): git pull, install deps if changed, rebuild frontend if changed, **preflight that the `claude` CLI resolves** (fatal if `CLAUDE_BIN` in `.env` is set but not executable — the 2026-06-17 outage was a binary-off-PATH move that only surfaced at the first investigation; best-effort warning otherwise), restart systemd service
3. The service runs behind Caddy (reverse proxy, automatic HTTPS)

**WARNING: any commit pushed to `main` goes live immediately.** There is no staging environment, no rollback automation. Before pushing:
- Make sure the Python backend starts without errors
- Make sure the frontend builds (`cd frontend && npm run build`)
- Do not push commits that break imports, syntax, or database schema without migration

### CI merge-gate (`.github/workflows/ci.yml`)

Because `main` deploys straight to prod, a merge-gate runs on every PR to `main`
(and as a backstop on push to `main`):
- **`backend-import`** — installs `requirements.txt`, byte-compiles `backend/`,
  and imports `backend.main` (catches syntax errors and broken imports).
- **`backend-tests`** — installs `requirements-dev.txt` and runs
  `pytest backend/tests` (golden/regression tests, e.g. the seed-registry lock).
- **`frontend-build`** — `npm ci` + `npm run build` (catches a broken frontend).

A red gate must be fixed before merge. Pair this with branch protection on
`main` (PR + passing checks required) so a broken commit cannot reach prod.

### If you need to change the deploy pipeline

- Deploy script: `deploy.sh` (runs on the VPS)
- GitHub Actions workflows: `.github/workflows/deploy.yml` (deploy),
  `.github/workflows/ci.yml` (merge-gate)
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
  graph-state-aware Phase 3 gaps (`phase_followup`; CDN cert-CN unmask pivots
  promoted from adaptive hints to mandatory — `shodan_search("ssl.cert.subject.CN:...")`
  fires whenever the graph has ANY CDN-tagged IP, covering both the all-CDN front
  and the mixed CDN+leaked-origin case (2026-06-17 eval F-PIVOT-MISS: the old
  all-IPs-must-be-CDN check skipped Cloudflare-fronted seeds that also exposed a
  real origin IP), even when the agent would otherwise skip the adaptive
  suggestion; CT burst-window cohort hint fires when `crtsh_subdomains` was called
  on the seed domain but no node carries `issuance_date` or `burst` in metadata —
  the agent is prompted to re-examine CT `not_before` dates and add a
  `ct_burst_cohort` report node with `metadata.issuance_date`, satisfying the
  EVAL_PROTOCOL scorer's `ct_burst_window` pivot rule and unblocking Case 9
  Tycoon-2FA PS 75→100 (2026-06-17 fix)), then ensures a final
  `investigation_summary` report node (`phase_report_write`), then runs an
  autonomous pivot-drain loop (`phase_pivot_drain_<N>`, added 2026-05) that
  reads the report's own `pivot_suggestions` and the pivot queue, executes
  them, and recurses for up to `BOUNCE_PIVOT_DRAIN_ROUNDS` rounds (default 3,
  set to 0 to disable). Each round caps at `BOUNCE_PIVOT_DRAIN_MAX_TURNS`
  (default 60) and stops early when a round adds fewer than
  `BOUNCE_PIVOT_DRAIN_CONVERGENCE` (default 3) new nodes. A global
  CTI-call ceiling `BOUNCE_TOTAL_CTI_BUDGET` (default 82) caps cumulative
  `mcp__cti__*` calls across all phases: before each drain round the loop
  counts raw CTI calls so far (`_count_cti_calls`), stops draining when
  fewer than 8 calls of headroom remain, and clamps the round's turn budget
  to what's left. Because one agent turn emits several *parallel* `tool_use`
  blocks (~2-3 CTI calls/turn), a near-ceiling round is additionally
  re-budgeted in calls (`remaining // 3`) once `remaining ≤ 24`, so a parallel
  burst can't blow past the §4.5 `>90 ⇒ BD=0` cliff (Case 8 overshot to 98 on
  2026-05-31 before this). This keeps fast-triage runs inside the
  EVAL_PROTOCOL §4.5 budget bands instead of overshooting to 115-127 calls on
  complex hubs. The state machine in `PIVOT_MAPPING.md` informs the adaptive
  logic.
  Finally, a short **lessons-learned retrospective** phase
  (`phase_lessons_learned`) asks the agent to enumerate blockers, missing
  capabilities, and concrete codebase improvements it would make. The
  result lands on a hidden `lessons_learned` report node and is appended
  to `data/lessons_learned.jsonl`, exposed via
  `GET /api/admin/lessons_learned` for review.
- **Pivot queue** (`pivot_tasks` table): every `add_node` call auto-enqueues all
  applicable pivots via `pivot_mapping.pivots_for()`. Defused nodes (CDN/parking/
  sinkhole/dyndns) only enqueue documentation pivots (rdap/dns_resolve); the rest
  are inserted as `skipped` with `skip_reason='defused'` for later visibility in
  `gaps_report`. Per-node fan-out cap: 8 high-priority + 4 low-priority pivots.
  The agent drains the queue via `next_pivot()` / `mark_pivot_done()`.
  **Queue reconciliation** (`graph_store.reconcile_pivots_from_events`, called
  on every `queue_status`/`coverage_matrix`/`gaps_report`/`next_pivot`): agents
  drive most enrichment with direct `mcp__cti__*` calls and rarely call
  `mark_pivot_done`, which left the queue stuck at hundreds-pending / 0-done on
  every eval case. Reconciliation mechanically marks a pending/running/deferred
  task `done` when the event log shows its tool was invoked with the matching
  node value — so `queue_status`/`gaps_report` reflect reality. **Queue governor**:
  a global ceiling `BOUNCE_PIVOT_QUEUE_MAX` (default 300) parks new auto-enqueues
  as `deferred` (`skip_reason='queue_ceiling'`) once the pending backlog is large,
  so drain budget goes to queued work rather than an exploding backlog;
  `requeue_missing()` promotes deferred→pending. **Noise pre-filters** suppress
  structurally-doomed pivots at enqueue (subdomain/whois on shared-SaaS parents
  like `*.azurewebsites.net`; reverse-WHOIS on role mailboxes like `abuse@`;
  serial lookups on non-hex cert serials) — surfaced as `skipped`
  (`skip_reason='noise_filter'`), not silently dropped. **Source-health
  cache** (`backend/source_health.py`, backed by the `cache` table so both MCP
  processes see it): when a source returns a systemic failure (e.g. OpenCTI
  GraphQL `AUTH_REQUIRED`, indicating the token is expired/invalid), it gets
  marked dead with a short TTL (1h for auth, 4h for daily-quota, 2h for
  zero-balance). New pivots needing that source are then skipped at enqueue
  with `skip_reason='source_dead:<status>'` — eliminating the per-node
  rediscovery cost. `quota_status` surfaces the dead-sources dict.
- **Claude-subscription quota tracking**: `agent_runner` scans every
  `claude -p` stream-json event + stderr line for quota exhaustion two ways:
  the structured `rate_limit_event` (a non-`allowed` `status`, with `resetsAt`
  read for the reset epoch — `status: allowed`/`allowed_warning` are
  informational and ignored, see `_scan_event_for_quota`), and human-readable
  variants — the legacy `Claude AI usage limit reached|<epoch>` marker plus
  newer phrasings like `You've hit your limit · resets 1:50pm (UTC)` (see
  `_detect_quota_error`). When the phrasing carries a human-readable wall-clock
  reset time instead of an epoch, `_parse_reset_clock` resolves it to the next
  future occurrence of that `HH:MM` **in UTC** (the referential the CLI reports
  in) — anchoring to UTC rather than the server's local timezone is what keeps
  the UI countdown (`reset_epoch − now`) correct for any viewer. When no reset
  epoch is recoverable at all, a fallback cooldown
  (`BOUNCE_QUOTA_FALLBACK_COOLDOWN_S`, default 3600s) is applied so the global
  gate still engages. On a hit, the agent is killed, the
  investigation flips to status `quota_exceeded` with `quota_reset_at` stored,
  the global `quota_state` row is updated, and a `quota_exceeded` event +
  `status_change` event are emitted so the WebSocket clients refresh live.
  New spawns
  (`/api/investigations`, `/batch`, `/rerun`, `/enrich`, `/add_seed`,
  `/prompt`, `/from_pdf`) are gated by `_require_quota_available()` and
  return HTTP 429 until the reset epoch passes. `POST /api/investigations/{id}/resume`
  re-runs `run_investigation` without clearing the graph — phases are
  idempotent (`_has_working_hypothesis`, `_has_investigation_summary`,
  pivot-drain convergence) so already-finished work is skipped. The frontend
  polls `GET /api/quota` for the global banner + per-inv countdown.
- **No-first-event watchdog**: a healthy `claude -p` emits its `system` init
  event within seconds; the per-phase `watchdog()` in `_run_claude_phase` kills
  a spawn that emits *no* stream-json for `BOUNCE_AGENT_FIRST_EVENT_TIMEOUT_S`
  (default 120s, 0 disables) and logs an `agent_no_output` event so a wedged
  spawn (bad binary, broken MCP launch) fails fast with a terminal error
  instead of hanging to the 20-min ceiling. This is the guardrail for the kind
  of silent-spawn failure behind the 2026-06-17 outage (the `claude` binary was
  off the systemd service PATH → `FileNotFoundError` → zero output).
- **Key rotation**: `backend/key_pool.py` lets each source accept either
  `<SRC>_API_KEY=k1` (single) or `<SRC>_API_KEYS=k1,k2,k3` (multi, takes precedence).
  Cooldown on 429 (60s default), full-day cooldown on quota exhausted. Sources call
  `key_pool.acquire(src)` and degrade gracefully when None is returned.
- **Node IDs are deterministic**: SHA1 of `(investigation_id, type, value)` — upserts are idempotent.
  `graph_store.canonical_node_type()` first corrects the TLS-fingerprint types agents
  conflate — `jarm` (62-hex server) vs `ja3` (32-hex client) vs `ja3s` (32-hex server),
  resolved from `metadata.type` then value shape — and `add_edge`/`tag_node` mirror it so
  edges/tags target the corrected node id, not a phantom `jarm`.
- **Theme**: light/dark is toggled in the sidebar header and persisted in `localStorage`
  (`bounce-theme`); `main.jsx` sets `<html data-theme>` before first paint. The UI is
  CSS-variable-driven, so the theme lives almost entirely in `styles.css` `:root`
  overrides. The Cytoscape canvas is theme-agnostic (dark label chips read on both).
- **Auth is PIN + session cookie**: Set `ADMIN_PIN=<6-digit>` in the env before the first start
  so the bootstrap promotes that PIN to admin (idempotent; no auto-generation if unset).
  Each investigation is owned by a user; the WebSocket and every `/api/*` route check ownership.
- **Per-user model whitelist**: Admins can restrict which Claude models a user can spawn
  (`sonnet`, `opus`, `opus-4.7`, `opus-4.8`, `haiku` — `ALLOWED_MODELS` in `main.py`;
  the `opus-4.7`/`opus-4.8` aliases map to `claude-opus-4-7`/`claude-opus-4-8` in
  `agent_runner._MODEL_ALIASES`). Admin accounts are unrestricted.
- **Per-investigation thinking effort**: the analyst can pick an extended-thinking
  effort level (`low`/`medium`/`high`/`xhigh`/`max`, or unset = model default). It's
  stored in the `investigations.effort` column at create time and applied to every
  phase spawn via the `CLAUDE_CODE_EFFORT_LEVEL` env var (the CLI `--effort` flag),
  set in `agent_runner._build_env` by reading the row — so resume / rerun / pivot all
  inherit the choice. `ALLOWED_EFFORTS` lives in `main.py`; `_VALID_EFFORTS` in
  `agent_runner.py`.
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
  `agent_runner._resolve_claude_bin()` resolves the binary via PATH and then probes
  `~/.local/bin` (native-installer location), `~/.npm-global/bin`, `/usr/local/bin`,
  `/usr/bin`. Under systemd the service PATH often omits `~/.local/bin`, so if spawns
  fail with `claude CLI not found`, set `CLAUDE_BIN` to the absolute path in `.env`
  and restart. (A PATH gap here was the 2026-06-17 production outage: the bare-name
  lookup returned None, the spawn raised `FileNotFoundError`, and every investigation
  produced zero nodes.)
- VirusTotal free tier: 4 req/min. Investigations may be slow.
- The `data/` directory is gitignored but must survive deploys (SQLite DB, auth key).
- WebSocket endpoint is `/ws/{investigation_id}` — reverse proxy must support upgrade headers.
- Every push to `main` deploys to production (see "Deployment & CI/CD"). There is no staging.
