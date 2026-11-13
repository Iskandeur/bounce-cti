# Bounce-CTI — Agent Guide

## What this is

Autonomous CTI (Cyber Threat Intelligence) investigation platform. A user submits a seed (domain / IP / hash / URL / JARM / ASN / command_line / executable_name / email / wallet_address / username / phone / company), the backend spawns a headless `claude -p` agent that queries ~50 public CTI source tools via MCP (commercial scanners + abuse feeds + the OpenCTI community knowledge graph), builds an infrastructure graph in SQLite, and streams it live to a React + Cytoscape frontend over WebSocket. Investigations are scoped to PIN-authenticated users, can be shared via signed links, and can be exported as PDF or STIX 2.1.

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
                        #   + per-investigation counters (get_counter/bump_counter,
                        #   backed by the cache table so they survive the per-phase
                        #   agent respawns), list_nodes_of_type, and
                        #   set_node_tags_exclusive (the lead lifecycle is a state
                        #   machine, not an accumulating tag bag)
  config.py             # Env var loading (API keys, paths)
  seeds.py              # Seed registry: single source of truth for per-seed-type
                        #   behaviour (mandatory_tools + investigation_prompt +
                        #   add_seed_block + pivot_block + followup_extra_steps +
                        #   KNOWN_SEED_TYPES). Replaces the five seed_type if/elif
                        #   ladders in agent_runner (now eliminated). Multi-
                        #   vertical foundation (Phase 1).
  verticals.py          # Vertical registry: the CTI/OSINT/DD abstraction.
                        #   Also CONTEXT_POOL_KEY/MODULE + CONTEXT_POOL_PROMPT_BLOCK
                        #   (the lead-discipline rules C1-C6, appended by
                        #   build_system_prompt only when the pool is mounted;
                        #   explicitly AMENDS rule R3's "do not search the web").
                        #   Vertical{name,label,agent_name,seed_types,
                        #   source_pool,prompt_block} + VERTICALS (cti + osint
                        #   lens [reuses cti pool] + dd [Due Diligence/KYB, own
                        #   dedicated pool mcp__dd__*, company seed, GLEIF v1;
                        #   legal guardrails baked in the prompt: ownership =
                        #   ESTIMATED not authoritative UBO/RBE, no adverse-media])
                        #   + get_vertical/normalise (unknown → cti fallback) +
                        #   source pool selection (SOURCE_POOL_MODULES: cti→cti_mcp,
                        #   dd→dd_mcp, consumed by agent_runner._write_mcp_config).
                        #   {core}+{vertical} system-prompt builder
                        #   (agent_runner.build_system_prompt)
                        #   swaps agent_name + appends prompt_block — iso-
                        #   functional for CTI. Multi-vertical foundation (Phase 1).
  context_pool.py       # The SECOND EPISTEMIC TIER: model parametric memory +
                        #   open-web text. Everything entering through it becomes
                        #   a `lead` node — never a typed IOC — with source=
                        #   parametric_memory / web:<host>, confidence clamped to
                        #   LEAD_CONFIDENCE_CAP (0.35) SERVER-SIDE, and a
                        #   lifecycle tag (unverified → corroborated | refuted |
                        #   unverifiable). A lead is excluded from every
                        #   actionable export until a PRIMARY source tool
                        #   ratifies it (is_actionable). Also holds the
                        #   mechanical legal guardrails (claim_type_denied: DD
                        #   adverse-media + special-category claims refused at
                        #   the tool boundary, not by prompt), the anti-circular
                        #   rule (is_primary_evidence_tool — memory may not
                        #   corroborate memory), the SSRF guard (check_fetch_url
                        #   / check_fetch_host_address), corroboration_stats (the
                        #   measurable hallucination thermometer), the shared
                        #   dossier renderers (split_leads /
                        #   leads_markdown_section) and the enablement policy
                        #   (context_pool_enabled — default ON for osint + dd,
                        #   OFF for cti). Pure module, no I/O; locked by
                        #   tests/test_context_pool.py.
  sources/web_context.py# Open-web source behind mcp__ctx__web_search / web_fetch.
                        #   Search backends: Brave → Serper → keyless DuckDuckGo
                        #   HTML fallback. Everything cached in the `cache` table
                        #   so an eval re-run replays byte-identical content
                        #   instead of that hour's SERP. Fetch is SSRF-guarded
                        #   (scheme allowlist + pre-DNS host check + post-DNS
                        #   check on every resolved address + redirect re-check)
                        #   and byte-capped.
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
                        #   NB: context-pool leads and any node still tagged
                        #   unverified/refuted/unverifiable are excluded with NO
                        #   analyst override (unlike include_defused) — a defused
                        #   node is real-but-noisy, an unverified one may not exist.
                        #   render_blocklist (plain/hosts/unbound/rpz/palo_edl/
                        #     cisco_acl/csv), render_detection (sigma/snort/
                        #     yara), render_takedown (per-host abuse email
                        #     bundle: To/Subject/Body + mailto link). Filters
                        #     out defused indicators by default so accidental
                        #     CDN / Tor / sinkhole blocks don't leak into
                        #     production drop-lists. _DEFUSED_TAGS holds every
                        #     tag defuse_check can emit ("parking" included):
                        #     tests/test_action_exports_defused.py ties them.
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
  dd_export.py          # Render a DD investigation as a Markdown KYB dossier
                        #   (sanctions exposure headline + company identity +
                        #   corporate hierarchy + officers/PSC + provenance,
                        #   with estimated-ownership + candidate-match
                        #   disclaimers). Pure render_kyb_dossier(graph, inv);
                        #   served at GET /api/investigations/{id}/kyb_dossier
  pdf_report.py         # Render an investigation as a downloadable PDF
  stix_export.py        # Render an investigation as a STIX 2.1 bundle.
                        #   Pure build_stix_bundle(nodes,edges,inv,id,tlp=) +
                        #   DB wrapper generate_stix_bundle. Conformance-hardened:
                        #   no SDO-only common props on SCOs (confidence/labels/
                        #   created/created_by_ref), RFC-valid email-addr only
                        #   (invalid WHOIS hashes → report.x_bounce_unmodelled_
                        #   observables), TLP marking on every object (default
                        #   AMBER), spec-validated relationship pairs (reversed
                        #   resolves-to flipped, out-of-spec → related-to keeping
                        #   x_bounce_relation), malicious observables promoted to
                        #   indicator SDOs w/ STIX patterns, report_types set.
                        #   Locked by tests/test_stix_export.py
  evidence_match.py     # Evidence → Load: which cached source answers are about a
                        #   node's value. like_pattern (SQL prefilter, wildcards
                        #   escaped) + key_mentions (the value as a whole token of
                        #   the cache key: no longer hostname / IP / hash, API host
                        #   skipped, percent-decoded, case-insensitive, nothing
                        #   under 3 characters). Pure; used by
                        #   graph_store.get_evidence_for_value; locked by
                        #   tests/test_evidence_match.py
  key_pool.py           # API key rotation pool: round-robin, cooldown on 429,
                        #   per-day quota tracking, graceful degradation
  source_health.py      # Short-TTL dead-source cache (auth_required /
                        #   tier_restricted / quota_exhausted / zero_balance)
                        #   backed by the cache table so both MCP processes see
                        #   it; auto-enqueue skips pivots needing a dead source
  fixtures.py           # EVAL_PROTOCOL §4.C fixture capture + OFFLINE replay of
                        #   source responses. Hooks graph_store.cache_get/
                        #   cache_set (every source memoises there) + dns_tools
                        #   (the one uncached source, via through()). Capture:
                        #   BOUNCE_FIXTURE_CAPTURE_DIR (set per investigation by
                        #   agent_runner from BOUNCE_FIXTURE_CAPTURE=1, or from
                        #   investigations.fixture_capture = an admin's
                        #   "capture": true at creation). Replay:
                        #   BOUNCE_FIXTURE_DIR, served whatever the TTL, never
                        #   written to the DB, network refused in the MCP
                        #   process (install_offline_guard), misses logged per
                        #   investigation. Secrets redacted to <secret:SOURCE>
                        #   in key AND value before any write. Bookkeeping keys
                        #   (BOOKKEEPING_PREFIXES: counter|, source_health|, …)
                        #   are never captured. Stdlib only; off by default
  demo_snapshot.py      # Static demo snapshots (roadmap J3): from_view() turns
                        #   graph_store.share_view(inv, graph+report+timeline)
                        #   into the JSON the static demo renders, minus agent
                        #   session/request ids, usage, local paths, thinking
                        #   blocks, report chats; check() refuses a secret value
                        #   or a forbidden word (named, never printed). Used by
                        #   GET /api/investigations/{id}/demo_snapshot (owner)
                        #   and eval/demo_export.py. Stdlib only
  pivot_arm.py          # The mechanical arm pivot-1 (EVAL_PROTOCOL §4.E rule 1): a seed's
                        #   mandatory tools run on the seed alone, NO model, results read
                        #   as nodes through the exports' own neutralisation. Behind
                        #   POST /api/admin/eval/pivot; eval/prospective.py `pivot` fills
                        #   the arm, `seal --arm pivot-1=<dir>` takes it (same hour)
  eval_judge.py         # Prospective cases, server side (EVAL_PROTOCOL §4.E):
                        #   fresh_iocs (ThreatFox get_iocs → candidate seeds +
                        #   the §4.E rules each breaks) and judge v2
                        #   (otx+abusech/2: OTX keyed + ThreatFox + URLhaus +
                        #   MalwareBazaar, exact match, live — never the cache —
                        #   each listing's id/date/author) + entries (a seed's
                        #   ThreatFox entry read by id, then searched back
                        #   wildcard and exact_match: gone vs not returned yet).
                        #   Behind the admin routes /api/admin/eval/fresh_iocs
                        #   and /judge (+ "entries"), which use the server's own
                        #   keys. Stdlib only
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
    ctx_mcp.py          # MCP server: the CONTEXT POOL (mcp__ctx__*), mounted
                        #   ALONGSIDE the vertical's source pool so its calls are
                        #   counted/budgeted separately from BOUNCE_TOTAL_CTI_BUDGET.
                        #   recall_prior_knowledge (NO network, no cost — forces
                        #   the model's prior knowledge out of the report prose
                        #   and into an auditable, falsifiable, queued-for-
                        #   verification lead; requires verifiable_by + falsifier),
                        #   web_search / web_fetch (cached, budgeted, SSRF-guarded,
                        #   returned with an untrusted-content warning),
                        #   context_budget. Budget enforced server-side via a
                        #   persisted counter so it survives per-phase respawns.
    cti_mcp.py          # MCP server: ~90 async CTI source tools
                        #   (incl. internetdb_ip — keyless/creditless IP exposure,
                        #   shodan_host_count — free cluster size + facets (the
                        #     credit-free replacement for shodan_search),
                        #   shodan_api_info — plan + remaining credits + policy,
                        #   malwarebazaar_imphash — PE imphash cluster,
                        #   username_enumerate — Sherlock-style profile sweep,
                        #   gravatar_email — email→public profile / accounts,
                        #   github_profile — GitHub user identity enrichment,
                        #   github_commit_emails — handle→author email harvest,
                        #   wallet_enrich — crypto wallet on-chain activity,
                        #   phone_lookup — offline phone metadata,
                        #   website_extract — page links/emails/social profiles)
    dd_mcp.py           # MCP server: Due-Diligence (KYB) source pool
                        #   (mcp__dd__*), mounted for the `dd` vertical. Tools:
                        #   gleif_lookup (company identity + Level-2 hierarchy),
                        #   sanctions_screen (+ sanctions_screen_batch: OFAC +
                        #   EU FSF + UK UKSL name screen, batch = one call/graph),
                        #   companies_house_lookup (UK profile + officers + PSC),
                        #   edgar_lookup (SEC EDGAR US-listed issuer identity),
                        #   recherche_entreprises_lookup (FR company + dirigeants).
                        #   Separate pool from cti (different domain + the
                        #   monetisation boundary). Legal guardrails: ownership =
                        #   ESTIMATED (not UBO/RBE), no adverse-media here.
  sources/              # One file per CTI source (all async, all cached):
                        #   Existing: crtsh, rdap, whois (RFC 3912 / port-43),
                        #     dns_tools, virustotal,
                        #     urlscan, onyphe, shodan (free-first + credit guard;
                        #     see "Shodan is free-first" in Key conventions),
                        #     internetdb (Shodan InternetDB — NO key, NO credits;
                        #     ports/CPEs/CVEs/hostnames, ~weekly, no banners),
                        #     otx, threatfox, wayback,
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
                        #     Sherlock-style profile sweep across ~49 public
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
                        #     wikidata (free, no-key, CC0 identity anchor:
                        #     name→QID + description + official site + social
                        #     handles [twitter/github/mastodon/…] with a citable
                        #     QID URL; username pivot, shared into the cti pool).
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
                        #   DD (Phase 3): gleif (GLEIF/LEI company identity +
                        #     Level-2 "who owns whom" hierarchy; free, no-key,
                        #     CC0; powers the `company` seed via the dd pool. NB:
                        #     Level-2 = ESTIMATED corporate ownership, NOT
                        #     authoritative UBO/RBE).
                        #     sanctions (name screening vs OFAC SDN + EU FSF +
                        #     UK UKSL consolidated lists; free, no-key, all
                        #     commercial-OK licences; header-tolerant parsers +
                        #     normalised matcher; hits = candidates for review,
                        #     not determinations. dd pool).
                        #     companies_house (UK company profile + officers + PSC;
                        #     free key, OGL v3.0; officers/PSC → person nodes →
                        #     sanctions-screened. Graceful w/o key. dd pool).
                        #     edgar (SEC EDGAR US-listed issuer identity: CIK,
                        #     tickers/exchanges, SIC, state of incorp, former
                        #     names; free, no key, public domain. dd pool).
                        #     recherche_entreprises (FR company + dirigeants via
                        #     gouv API; free, no key, Licence Ouverte 2.0;
                        #     dirigeants → person nodes → sanctions. dd pool).
                        #   Shared: http_client
  run_progress.py       # Where a run stands, for GET /api/investigations/{id}/progress
                        #   (polled by the UI): the run = events since the last
                        #   agent_starting; phase in flight and finished phases from
                        #   phase_<name>_starting/_exit; source calls counted as
                        #   agent_runner._count_cti_calls counts them; ceiling =
                        #   BOUNCE_TOTAL_CTI_BUDGET, null for a run with no drain
                        #   loop. Pure compute() + a thin DB reader that never
                        #   loads tool results. Locked by tests/test_run_progress.py
  tests/                # pytest suite (golden / regression tests, e.g.
                        #   test_seeds.py locks the seed-registry output).
                        #   Run: pytest backend/tests (deps: requirements-dev.txt)
frontend/
  src/
    main.jsx            # React entrypoint
    App.jsx             # MainApp: owns the graph state, the Cytoscape instance, the
                        #   WebSocket event pump and the investigation actions, and
                        #   composes the panels below; AppRoot (auth / share routing)
    components/         # Presentational panels, fed by MainApp through props:
                        #   Sidebar (NewInvestigationForm, InvestigationHistory,
                        #   AddSeedPanel, RunProgress [the progress line + its
                        #   live region], AgentLog), GraphPane (canvas + toolbar +
                        #   filter chips), GraphLegend (on-demand key of the canvas:
                        #   the node types and border meanings present in the
                        #   graph), ReportTab (LeadsCard, HypothesisCard,
                        #   BudgetLog), NodeTab (StaticAnalysis), TimelineTab,
                        #   ActionsPanel, ChatTab, PromptBox, PickedChips,
                        #   HighlightedText, CopyLabel (a copy button's label, fixed width)
    hooks/              # State slices used by MainApp: useRunSettings (model /
                        #   vertical / effort), useNewInvestigation (IOC / sample /
                        #   PDF form + submits), useNodeData (lead stats, cross-
                        #   investigation hits, node note), useQuota, usePanelResize,
                        #   useTheme, useIsMobile, useServerReconnect,
                        #   useGraphSummary (types / border meanings / defused
                        #   count of the graph, for the legend and the toolbar),
                        #   useRunProgress (progress of the open investigation:
                        #   fetch on open, on run-level WebSocket events via
                        #   poke(), every 10 s while live)
    lib/                # Pure modules, no React: constants (node colors / shapes,
                        #   Maltego types), ioc (refang, detectIOCType,
                        #   verticalFromLocation, parseSeedInput), graph (Cytoscape
                        #   stylesheet + layout options, toCyNodeData,
                        #   isAuxReportNode, readCanvasColors, isDefused), legend
                        #   (shape glyphs, border meanings, summariseGraph),
                        #   timeline, reportMarkdown, format, runProgress (phase
                        #   labels + the words of the progress line;
                        #   runProgress.test.js, node --test, run in CI)
    invUrl.js           # Pure ?inv=<id> URL-sync helper (+ invUrl.test.js, node --test, run in CI)
    Login.jsx           # PIN login screen
    AdminPanel.jsx      # Admin dashboard (users, models, impersonation)
    ShareModal.jsx      # Build a share link (sections + expiry)
    SharedView.jsx      # Public/share-link viewer (read-only graph + import button);
                        #   with demoSrc, the static demo viewer (no backend;
                        #   demoCases adds a case picker when >1 snapshot)
    demo.jsx            # Entry of the static demo build
    styles.css
  demo/index.html       # Static demo page (vite.demo.config.js). Opened from
                        #   disk (file://) its module script never runs: a hint
                        #   in #root, unhidden on file: only, says to serve it;
                        #   a <noscript> if JS is off (test_demo_page_offline.py)
  e2e/                  # Browser suite (Playwright, Chromium), no backend: mockApi.js
                        #   answers /api/ and the /ws/<id> WebSocket from the
                        #   hand-written, synthetic fixtures/data.js. harness.js fails
                        #   a test on an /api/ call with no mock and on an uncaught
                        #   page error. a11y.spec.js fails on any axe rule violated;
                        #   a11y-baseline.js, the tolerated ones, is empty. `npm run test:e2e`;
                        #   what it leaves out is in e2e/README.md
  playwright.config.js  # Starts the Vite dev server for the suite (127.0.0.1:5199,
                        #   --strictPort, never an already-running one)
  vite.config.js        # Dev proxy: /api→:8001, /ws→ws://:8001
  vite.demo.config.js   # `npm run build:demo` → dist-demo/: SharedView + every
                        #   eval/demo/*.json copied to data/, relative base (any
                        #   static host). The app build is untouched by it.
                        #   Open it served (python3 -m http.server --bind
                        #   127.0.0.1 --directory dist-demo), never from disk
data/                   # Runtime data (gitignored)
  bounce.db             # SQLite database
  secret.key            # HMAC key for PIN auth
  mcp-{id}.json         # Per-investigation MCP configs (temporary)
  mcp-launcher-*.log    # Per-server launcher trace logs (debug)
  fixtures/             # capture/<inv_id>/ (BOUNCE_FIXTURE_CAPTURE=1 or capture: true) and
                        #   replay-misses/<inv_id>.jsonl (BOUNCE_FIXTURE_DIR)
runs/                   # Archived eval-protocol scorecards (one folder per run)
eval/results_digest.py  # Renders EVAL_RESULTS.md from runs/*/scorecard.md (stdlib,
                        #   offline). Like-for-like trend on the fresh subset only;
                        #   v2 Overall and v3 CAP never averaged together.
                        #   `--check` exits 1 when the page is stale (also enforced
                        #   by backend/tests/test_eval_results_digest.py).
EVAL_RESULTS.md         # GENERATED published eval digest — re-run the script after
                        #   adding a run under runs/ or eval/baseline/, never edit by hand
eval/baseline.py        # Bare-model baseline (EVAL_PROTOCOL §4.D): run --arm memory|web
                        #   gives each seed to the same model with no Bounce-CTI tool
                        #   (empty cwd, no MCP, filtered env); compare scores every side
                        #   with eval/scorer.py itself (score_case(case, out_dir)).
                        #   run --seeds <batch>/seeds.json runs a prospective batch
                        #   (each run.json says started_at / finished_at, UTC: seal
                        #   checks rule 1 on it).
                        #   Stdlib only
eval/baseline/<date>/   # Committed baseline results: results.json (scores, models,
                        #   hosts the web arm read) + results.md. No raw answers
eval/prospective.py     # Prospective cases (EVAL_PROTOCOL §4.E): seal <batch> freezes
                        #   every arm's claims (what action_exports would ship, minus
                        #   the seed) + the judge's answer at T into manifest.json, and
                        #   commitment.json (sha256 + counts, no value: commit it at T);
                        #   check after the horizon (exit 3 before, --early = provisional);
                        #   score: known/ahead/unconfirmed/benign/undetermined per arm,
                        #   pooled recall. Judge v1 = OTX pulses, keyless, a domain asked
                        #   under hostname AND domain. Manifest not the committed one = exit 1;
                        #   a lookup failed at T seals nothing (exit 4; OTX_API_KEY for a batch).
                        #   --server/--cookies (admin session): `seeds` picks a batch from
                        #   /api/admin/eval/fresh_iocs (pick/1, one per family, once),
                        #   `preflight`, and seal/check under judge v2 via /judge, with a
                        #   positive control (a seed must be listed in its own feed at T,
                        #   else exit 4; one its search misses is read by id: still in the
                        #   feed = late, accepted at T; gone = refused; strict at the check,
                        #   where score refuses a blind search). An abuse.ch listing dated
                        #   before the seal scores known (known_late), not ahead.
                        #   Secondary horizon 30 days pre-registered.
                        #   `bounce` fills the Bounce-CTI arm through the server: one
                        #   investigation per seed (opus-5), ONE AT A TIME, resumed (≤2)
                        #   after quota_exceeded / error: interrupted, graph written only
                        #   when done, bounce.json recording each run at submission (rerun
                        #   = pick up, never resubmit; exit 5 while a run is not done).
                        #   seal reads each run's start (bounce.json, pivot-1.json, the
                        #   web arm's run.json started_at) and refuses a start > 48 h after
                        #   the seed's first_seen (rule 1 at run time), a run not done, a
                        #   web run with no answer, an arm with no start times (unless
                        #   --allow-unstamped, listed in the commitment). --drop
                        #   LABEL=reason leaves a contaminated seed out at the seal:
                        #   never edit seeds.json (its sha256 ties the stamped arms)
                        #   backend/tests/test_sources_read_only.py: sources only read
deploy.sh               # Manual deploy, callable on the VPS. The automatic deploy is
                        #   the inline script of .github/workflows/deploy.yml, which
                        #   backend/tests/test_deploy_script.py runs in a sandbox
Dockerfile              # Local one-image run (not used by prod): frontend build
                        #   stage, then backend + claude CLI as non-root `bounce`
docker-compose.yml      # `docker compose up -d --build`: .env bind-mounted read-only
                        #   (never created), data/ in a volume, 127.0.0.1:8001 only
.dockerignore           # .env, data/, .git stay out of every image. These three
                        #   promises are pinned by backend/tests/test_docker_packaging.py
run_mcp.py              # MCP server launcher (referenced by generated mcp.json configs)
mcp.json                # Template MCP config (rendered per investigation at runtime)
EVAL_PROTOCOL.md        # Active eval protocol (run on every non-trivial agent change)
PIVOT_MAPPING.md        # Architecture spec for the autonomy engine refactor
eval/fixture_tool.py    # promote <inv_id> <case> (a capture → eval/fixtures/<case>/
                        #   + MANIFEST.md), verify (integrity + no secret: .env
                        #   values and credential shapes; exit 1), stats
eval/fixtures/<case>/   # Committed fixture sets, one per eval case, one JSON
                        #   file per source response (name = sha256 of the key)
eval/demo_export.py     # <inv_id> <name> --db … --dotenv …: one investigation →
                        #   eval/demo/<name>.json (backend/demo_snapshot.py rules).
                        #   Source DB opened read-only, rows copied to a throwaway
                        #   DB; exit 1 on a secret or --forbid word (nothing
                        #   written), 2 if the --dotenv can't be read
eval/demo/              # Committed demo snapshots + README (how to make one, which
                        #   run to pick). PUBLIC repo: check before committing
eval/drain_gate_replay.py # --db … [--seeds]: replays the pivot-drain gate
                        #   (_concluded_benign) on every drain of a database, each
                        #   graph rebuilt from its events as it stood at drain start.
                        #   Read-only; seed values only with --seeds
.github/workflows/demo-pages.yml  # Publishes dist-demo/ to GitHub Pages, by hand only
.github/dependabot.yml  # Monthly grouped update PRs: actions, frontend, pip (never mcp>=2).
                        #   Workflow invariants pinned by backend/tests/test_ci_workflows.py
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
2. Runs inline deploy commands (defined in `.github/workflows/deploy.yml`): **preflight that the `claude` CLI resolves** (fatal if `CLAUDE_BIN` in `.env` is set but not executable — the 2026-06-17 outage was a binary-off-PATH move that only surfaced at the first investigation; best-effort warning otherwise), git pull, install deps if changed, rebuild frontend if changed, restart systemd service **if something it loads changed, or if it is not running**
3. The service runs behind Caddy (reverse proxy, automatic HTTPS)

Four rules of that script. `backend/tests/test_deploy_script.py` takes the script
out of the workflow and runs it in a sandbox (a throwaway clone, `sudo` / `npm` /
`pip` stubbed) for each of them:
- **One deploy at a time** (`concurrency: deploy-production`). A push that lands
  during a deploy waits for it; a later push replaces the one that waits (shown as
  cancelled), which loses nothing: a run deploys `origin/main` as it stands.
- **A restart only for what the service loads.** A restart ends every
  investigation in flight. A commit that touches only the paths of the script's
  `INERT` list restarts nothing: top-level `*.md`, `media/`, `backend/tests/`,
  `frontend/`, `eval/`, `runs/`, `.github/`, `requirements-dev.txt`,
  `.env.example`, the ignore files, the Docker files, the licence files. Any other
  path restarts, a new top-level file or a doc in a new directory included. The
  test checks the list against `git ls-files`: **a new top-level file fails it
  until it is classified**, in `INERT` or in the test's `code` set. To restart by
  hand: `sudo systemctl restart bounce-cti` on the VPS.
- **The bundle is rebuilt, not restarted for.** A change under `frontend/` (other
  than `frontend/e2e/`, `frontend/playwright.config.js` and `.md` files) runs
  `npm ci` + `npm run build`, and the running process serves the new files from
  disk. A tab that is already open keeps the old bundle until it is reloaded (a
  restart used to reload every open tab).
- **A deploy that stops before its restart puts the checkout back.** A failed
  `npm ci`, build or `pip install` fails the run and resets the checkout to where
  it was, so the service keeps running code that is still on disk (the MCP
  processes it spawns read `backend/` from disk) and the next run, or a re-run of
  the failed job, starts again from the same place. `.git/bounce-deploy-pending`
  on the VPS exists only while a deploy is unfinished: it holds the commit the run
  started from, for the case where the run is killed outright.

**WARNING: any commit pushed to `main` goes live immediately.** There is no staging environment, no rollback automation. Before pushing:
- Make sure the Python backend starts without errors
- Make sure the frontend builds (`cd frontend && npm run build`)
- Do not push commits that break imports, syntax, or database schema without migration

### CI merge-gate (`.github/workflows/ci.yml`)

Because `main` deploys straight to prod, a merge-gate runs on every PR to `main`
(and as a backstop on push to `main`):
- **`backend-import`** — on Python 3.12 (production's), installs
  `requirements.txt`, byte-compiles `backend/`, and imports `backend.main`
  (catches syntax errors and broken imports).
- **`backend-tests`** — on Python 3.11 and 3.12, installs `requirements-dev.txt`
  and runs `pytest backend/tests` (golden/regression tests, e.g. the seed-registry lock).
- **`frontend-build`** — on Node 22 (the image's), `npm ci`, the front-end unit
  tests (`node --test "src/**/*.test.js"`: every `*.test.js` under `src/`),
  `npm run build` (catches a broken frontend), then `npm run build:demo` (the
  static demo still builds, snapshots or not).
- **`frontend-e2e`** ("Frontend end-to-end") — on Node 22, `npm ci`,
  `npx playwright install --with-deps chromium`, `npm run test:e2e`: the browser
  suite of `frontend/e2e/` against the Vite dev server, API and WebSocket mocked
  (no backend). A new `/api/` call in the frontend needs a fixture there, and a
  axe rule violation fails it (no rule is tolerated: `e2e/a11y-baseline.js` is empty).
- **`docker-image`** — builds the image and boots it with no `.env`: the app
  answers, the bootstrap admin (a random `ADMIN_PIN`) logs in, the process runs
  as uid 10001 and the `claude` CLI is on its PATH. It proves packaging, not
  that an investigation can run (no Claude credentials in CI).

A red gate must be fixed before merge. The repository ruleset on `main` requires
the checks **Backend imports** and **Frontend builds** by name: never rename those
two jobs or give them a matrix (GitHub appends the matrix values to the check
name, and the required check then stays pending forever, blocking every PR).
`backend/tests/test_ci_workflows.py` pins this, ties the CI Python and Node to the
Dockerfile's, and fails on any action not pinned to a full commit SHA with its
release in a comment (`deploy.yml` hands the production SSH key to
`appleboy/ssh-action`). A new runtime version moves the Dockerfile, the CI and
production together.

`.github/dependabot.yml` proposes updates monthly, grouped, at most two open per
ecosystem: actions (it moves the SHA and the comment together), frontend minor and
patch, and `requirements.txt` only when a floor or cap must move. `mcp>=2.0` is
ignored there as long as `requirements.txt` caps it (the test checks every cap is
mirrored). Merging a Dependabot PR deploys to production like any other commit.

### If you need to change the deploy pipeline

- Automatic deploy: the inline script of `.github/workflows/deploy.yml` (change it
  together with `backend/tests/test_deploy_script.py`, which runs it)
- Manual deploy: `deploy.sh` (runs on the VPS; it has none of the rules above: it
  restarts on every change and leaves the checkout moved when it fails)
- GitHub Actions workflows: `.github/workflows/deploy.yml` (deploy),
  `.github/workflows/ci.yml` (merge-gate), `.github/dependabot.yml` (update proposals)
- Systemd service: `bounce-cti.service` (managed on the VPS, not in this repo)
- Reverse proxy: Caddy with automatic HTTPS (managed on the VPS)

## Key conventions

- **Frontend is React + Vite, no router**: `App.jsx` holds `MainApp`, which owns the
  graph state and the Cytoscape instance and passes them down as props; the panels live in
  `frontend/src/components/`, the state slices in `hooks/`, the pure helpers in `lib/`
  (`Login`, `AdminPanel`, `ShareModal`, `SharedView` stay at the top of `src/`).
  View switching is done with local state, not URLs.
  The desktop grid columns come from `panelColumns` (`hooks/usePanelResize.js`): each
  side panel has the width it was dragged to, and in a window too narrow for both
  (769 to about 1100px at the default widths) they share what is left once the graph
  has 340px, never under the minimum of their handle (180 / 220px).
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
  `investigation_summary` report node (`phase_report_write`), then — when the
  context pool is mounted and leads are still unverified — resolves them in
  `phase_corroborate_leads` (placed BEFORE the report write so the report
  describes leads by verdict instead of asserting them), then runs an
  autonomous pivot-drain loop (`phase_pivot_drain_<N>`, added 2026-05) that
  reads the report's own `pivot_suggestions` and the pivot queue, executes
  them, and recurses for up to `BOUNCE_PIVOT_DRAIN_ROUNDS` rounds (default 3,
  set to 0 to disable). A CTI seed the run itself concluded legitimate is NOT
  drained (`_concluded_benign`: every `working_hypothesis` says `legitimate`,
  the summary's `threat_assessment` reads as benign, no seed tag is malicious;
  logged as `phase_pivot_drain_skipped`). The drain had been chasing the abuse a
  shared service hosts into unrelated clusters: N2 `cdn.jsdelivr.net` went from
  a benign verdict at 31 nodes to an ACRStealer/ClearFake graph, RST 100 → 0.
  osint/dd keep their drain (a legitimate subject is their normal case);
  `BOUNCE_PIVOT_DRAIN_ON_BENIGN=1` restores it for CTI. Each round caps at `BOUNCE_PIVOT_DRAIN_MAX_TURNS`
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
  **Vertical scoping** (`pivots_for(..., vertical=)`, 2026-06-19): DD-pool ops
  (`gleif_lookup`/`sanctions_screen`/`companies_house_lookup`/`edgar_lookup`/
  `recherche_entreprises_lookup`) only enqueue in the `dd` vertical, and
  threat-CTI noise ops (`threatfox`/`pulsedive`/`phishtank`/`urlhaus`/`tor_exit`/
  `abuseipdb`/`criminalip`/`dom_fingerprints`/…) are suppressed in the `osint`
  lens — both surfaced as `skipped` (`skip_reason='vertical_scope'`). This stops
  a benign OSINT identity run from auto-enqueuing abuse-feed fan-out, and keeps
  `sanctions_screen` (a criminal/legal-data axis) from firing outside DD. CTI is
  unchanged (EVAL invariant). `graph_mcp` reads the investigation's vertical
  (`gs.get_vertical`) and passes it to `pivots_for`. **`add_edge` is also
  vertical-guarded**: in `dd`, CTI-only relations (`known_ioc`/`attributed_to`/
  `communicates_with`/`resolves_to`/… in `_DD_FORBIDDEN_RELATIONS`) are rejected
  so a KYB graph stays corporate instead of leaking phantom threat-infra edges.
  **Queue reconciliation** (`graph_store.reconcile_pivots_from_events`, called
  on every `queue_status`/`coverage_matrix`/`gaps_report`/`next_pivot`): agents
  drive most enrichment with direct `mcp__<pool>__*` calls and rarely call
  `mark_pivot_done`, which left the queue stuck at hundreds-pending / 0-done on
  every eval case. Reconciliation mechanically marks a pending/running/deferred
  task `done` when the event log shows its tool was invoked with the matching
  node value — matching across the `cti` / `dd` / `osint` pool prefixes (DD ops
  were previously invisible, leaving the DD queue stuck at 0-done) — so
  `queue_status`/`gaps_report` reflect reality. **Queue governor**:
  a global ceiling `BOUNCE_PIVOT_QUEUE_MAX` (default 300) parks new auto-enqueues
  as `deferred` (`skip_reason='queue_ceiling'`) once the pending backlog is large,
  so drain budget goes to queued work rather than an exploding backlog;
  `requeue_missing()` promotes deferred→pending. **Noise pre-filters** suppress
  structurally-doomed pivots at enqueue (subdomain/whois on shared-SaaS parents
  like `*.azurewebsites.net`; **shared mail-provider MX hosts** like
  `mx*.mail.ovh.net` / `*.protection.outlook.com` via `is_mail_host`;
  reverse-WHOIS on role mailboxes like `abuse@`; **reverse-WHOIS on privacy-mail
  registrants** (protonmail/tuta/… via `is_privacy_mail` — never resolves);
  serial lookups on non-hex cert serials; and **DD jurisdiction routing** — a
  `company` node's `metadata.jurisdiction` (or, when absent, one **inferred from
  its legal-form suffix** via `infer_jurisdiction`: GmbH/AG→DE, SAS/SARL→FR,
  LLC/Inc→US, K.K.→JP, Sdn Bhd→MY…) only enqueues the matching registry, so a
  FR/DE/… subsidiary doesn't auto-enqueue Companies House `no_api_key` noise) — surfaced as `skipped` (`skip_reason='noise_filter'`),
  not silently dropped. **Company dedup**: `graph_mcp.add_node` folds a `company`
  that matches an existing one by **LEI or canonical name**
  (`company_canonical_key`: HTML-unescape + lowercase + drop corp suffixes) into
  the first-seen canonical node (incoming name → `aliases`), fixing both the
  free-text-seed-vs-resolved-entity duplicate (`Danone` vs `DANONE SA`) and
  HTML-entity variants (`ERNST & YOUNG` vs `ERNST &amp; YOUNG`). **Sanctions in
  DD are screened via `sanctions_screen_batch`** (mandated in the prompt), NOT
  auto-enqueued per node (per-node exploded the queue to ~48); and as a guarantee
  independent of agent compliance, `agent_runner._dd_sanctions_sweep` runs a
  **mechanical OFAC/EU/UK screen of every company+person node at the end of a DD
  run**, tagging hits `sanctioned` and always emitting a `sanctions_screen`
  evidence report node (provenance even at zero hits — the agent skipped the
  screen on SAP 2026-06-19). **Source-health
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
- **Run progress has one source** (`backend/run_progress.py`,
  `GET /api/investigations/{id}/progress`): the UI's progress line reads the
  phase, the elapsed time and the source calls from that route alone. The run
  is everything since the last `agent_starting` (a resume, an added seed, a
  manual pivot and a custom prompt are runs of their own). A new phase needs no change there: any
  `phase_<name>_starting` / `_exit` pair logged by `_run_claude_phase` shows up,
  and the client words an unknown name from the name itself (add its label to
  `PHASE_LABELS` in `frontend/src/lib/runProgress.js`). The ceiling shown is
  `BOUNCE_TOTAL_CTI_BUDGET` and only for a full investigation: the drain loop
  alone enforces it, so the count can end above it and the UI says "budget".
  The WebSocket replays every past event on connect, which is why the client
  debounces its refresh.
- **No-first-event watchdog**: a healthy `claude -p` emits its `system` init
  event within seconds; the per-phase `watchdog()` in `_run_claude_phase` kills
  a spawn that emits *no* stream-json for `BOUNCE_AGENT_FIRST_EVENT_TIMEOUT_S`
  (default 120s, 0 disables) and logs an `agent_no_output` event so a wedged
  spawn (bad binary, broken MCP launch) fails fast with a terminal error
  instead of hanging to the 20-min ceiling. This is the guardrail for the kind
  of silent-spawn failure behind the 2026-06-17 outage (the `claude` binary was
  off the systemd service PATH → `FileNotFoundError` → zero output).
- **Stream lines of any length**: one stream-json line is one event, and a
  `user` event carries a tool's whole output, so lines of 100-300 KB are normal
  (VirusTotal, Onyphe). Both pumps read through `_iter_stream_lines`, which puts
  back together a line longer than asyncio's 64 KiB reader limit. A line past
  `_STREAM_LINE_MAX` (8 MiB) is logged as `agent_stdout_oversize` (size + first
  2,000 chars), and a pump that dies logs `agent_stream_error` instead of being
  swallowed by `gather(return_exceptions=True)`. Never go back to
  `async for line in proc.stdout`. Until 2026-10-15 that loop raised on the
  first long line, and the rest of the phase went unlogged with no error:
  172 of 372 production investigations lost part of their log, and the event
  log is what `_count_cti_calls`, quota detection, pivot reconciliation and the
  eval scorer read (EVAL_PROTOCOL §4.A note). `eval/stream_audit.py` measures
  it from the database; with `--since <day or UTC time>` it exits 1 if a phase
  exited rc=0 without its `result` event, or if `agent_stream_error` /
  `agent_stdout_oversize` was logged, and 3 (undetermined) when no phase ran in
  the window. `--prove-fix` (after a deploy, `--since` = deploy time) also
  exits 3 until a line of 64 KiB or more has been logged in full.
- **Auth-failure detection** (`_detect_auth_error`, distinct from quota): when
  the host's `claude` CLI credential is expired/invalid, every phase emits
  `Failed to authenticate. API Error: 401 …` yet the process exits 0, so the run
  produced zero nodes but was marked `done` (observed 2026-06-19). The stdout/
  stderr pumps scan for 401/"invalid authentication credentials"/"oauth token
  has expired"; on a hit `_note_auth` kills the spawn, `run_investigation` aborts
  after the first phase and `_finalise_auth_halt` flips the status to
  `error: auth` with an actionable message + `status_change` event. This is an
  **ops failure** (re-authenticate the CLI), surfaced loud instead of a silent
  empty `done`; unlike quota it sets **no** global cooldown.
- **Model-refusal detection** (`_detect_model_unsupported`): a CLI older than
  the model id it is given answers `API Error: 400 Claude Code 2.1.149 does not
  support this model; version 2.1.280 or newer is required`, exits 1 and still
  prints a `result` event (`is_error`), which the phase logic read as "the agent
  ran": all 7 phases spawned and the run ended `done` with zero nodes (real
  CLI 2.1.149 asked for `claude-opus-5-5`, 2026-10-23). Read only from an
  is_error `result` event or stderr (never a tool result), it stops the run
  after that phase as `error: model` with an actionable message
  (`_finalise_model_halt`). Auth and model halts share `_halt_on_ops_error`,
  which `run_investigation`, `run_add_seed`, `run_pivot` and
  `run_custom_prompt` all call before reporting `done`.
- **A user stop ends the whole run** (`stop_investigation`,
  `_halt_on_user_stop`): `POST /api/investigations/{id}/stop` used to kill the
  `claude -p` process in flight and write `done`, and nothing told the workflow.
  A killed phase returns like a failed one (rc=-15, no `result` event), so
  `run_investigation` went on to spawn the report-write and lessons-learned
  phases (plus follow-up and drain when a report node existed) and ended
  `error rc=-15` over the route's `done` (reproduced 2026-11-11 with a fake CLI).
  Now each stop is counted per investigation (`_stop_count`), every run entry
  point records the count it started with (`_begin_run`, a ContextVar), and a run
  whose count has moved returns at its next check: after every phase, before the
  quota / ops halts, and inside `_run_claude_phase` before a spawn. The route
  writes the status (`done` + `status_change` with `stopped_by_user`) in the
  request, for any `running` investigation, because the run only notices when
  its killed phase returns (up to a watchdog poll, 10 s); the run writes no
  status, only one `agent_exit` with `stopped_by_user`. It is a count because a
  flag cleared at the next run would lose a stop followed by a quick rerun. The
  chains in `main.py` (batch combined, from PDF, add seeds, from sample) read
  `stop_count` and do not start the next seed (`_chain_stopped`). **A new phase,
  or a new run entry point, needs its `_halt_on_user_stop` check / `_begin_run`
  call**; `tests/test_user_stop.py` covers the existing ones.
- **Shodan is free-first, credits are guarded**: a Membership grants only 100 query
  credits/month for the whole instance, but nearly the entire API is free — `internetdb_ip`
  (no key at all), `shodan_host`, `shodan_host_count` (count + facets for *any* query,
  filters included), `shodan_api_info`, and the DNS endpoints all cost 0 credits. Only
  `shodan_search` bills (1 credit per 100 results, whenever the query carries a filter or
  pages past page 1 — i.e. every useful CTI pivot), so it is **disabled by default**: it
  returns a structured refusal *without making any HTTP request* and names the free
  alternatives. Opt in with `BOUNCE_SHODAN_ALLOW_CREDITS=1`, cap with
  `BOUNCE_SHODAN_CREDIT_BUDGET=N` (policy in `config.shodan_credits_allowed()`).
  Consequently the cluster pivots (`jarm`/`favicon_hash`/`asn`) enqueue
  `shodan_host_count` for sizing + facets and graph member hosts via the free scanners
  (netlas/zoomeye/urlscan/crt.sh); `shodan_search` is parked as
  `skipped(skip_reason='credit_metered')`. **No seed type may mandate a credit-metered
  tool** — a mandatory call the guard refuses can never be satisfied, so the follow-up
  phase would nag forever (locked by a test). `/shodan/scan` and Network Alerts are
  deliberately not implemented (active probing + account-state mutation).
- **Context pool = hypotheses, source pool = jury** (`backend/context_pool.py`,
  `mcp__ctx__*`): the agent's parametric memory and open-web text are a **second,
  weaker epistemic tier**, not another source. They were already leaking into
  report prose untraced (that is why R11 and the "do not invent" rules exist);
  the pool channels them instead. Everything entering through it becomes a
  **`lead`** node — never a typed IOC — `source=parametric_memory` / `web:<host>`,
  confidence clamped to **0.35 in `graph_mcp.add_node`** (server-side: a prompt
  rule is a suggestion, this is an invariant), tagged `unverified`, and
  **excluded from every actionable export** (blocklist / detection / takedown /
  STIX; dossiers + PDF show them under a separate labelled heading). A lead
  becomes a finding ONLY via `mcp__graph__corroborate_lead`, which requires a
  **primary** source tool as evidence — a `mcp__ctx__*` tool is rejected, since
  memory corroborating memory is circular. On `corroborated` + `promote_as_*` the
  real typed node is minted with the *primary tool* as provenance and linked by a
  `corroborated_by` edge. `verdict=refuted` / `unverifiable` are **success
  states**, not failures. Because a lead is capped, tagged and non-exportable,
  the same mechanism is also the **prompt-injection defence**: text injected into
  a fetched page can only ever mint a lead a real source must ratify.
  Dedicated phase `phase_corroborate_leads` runs *before* the report is written.
  Metric: `corroboration_rate` (`GET /api/investigations/{id}/leads`) — the
  measurable hallucination thermometer, per run / vertical / model.
  **Enablement is deliberately asymmetric** (`BOUNCE_CTX_ENABLED`, default
  `auto`): ON for `osint` + `dd`, **OFF for `cti`**. CTI carries the byte-for-byte
  prompt invariant (roadmap 4.4) and the EVAL §4.5 budget cliff, so enable it
  there only after an eval run (`BOUNCE_CTX_ENABLED=all`). To run that eval
  without flipping the pool for every user, an admin creates ONE investigation
  with `"context_pool": true` on `POST /api/investigations` (stored in
  `investigations.context_pool`, read on every spawn through
  `agent_runner._context_pool_on`, which the MCP config, the tool whitelist,
  the system prompt and the corroboration phase all ask, so they never
  disagree; 403 for a non-admin, 409 under the kill switch, which still wins).
  `eval/sequential_runner.py` asks for it with `BOUNCE_EVAL_CONTEXT_POOL=1` and
  stops any run the server did not acknowledge with both `context_pool` and
  `context_pool_web`. Every other investigation keeps the CTI default, prompt
  byte-identical. `BOUNCE_CTX_WEB=0`
  keeps the free, network-less `recall_prior_knowledge` while removing the
  injection surface entirely; `BOUNCE_CTX_BUDGET` (default 12) caps calls per
  investigation. The native `WebSearch` / `WebFetch` stay in `_DISALLOWED_TOOLS`
  even when the pool is on — they would bypass the cache (eval determinism), the
  budget, the SSRF guard and the lead tier.
- **Fixture capture / replay (EVAL_PROTOCOL §4.C)** (`backend/fixtures.py`): the
  `cache` table is the one place every source's answer passes through, so that
  is where it hooks. `BOUNCE_FIXTURE_CAPTURE=1` (env or `.env`; `.env` is re-read
  per investigation, so no restart) records every source response an
  investigation reads, cache hits included, into `data/fixtures/capture/<inv_id>/`.
  To capture ONE investigation without touching `.env`, an admin creates it with
  `"capture": true` on `POST /api/investigations` (stored in
  `investigations.fixture_capture`, read on every spawn, so resume/pivot/add-seed
  keep capturing; a non-admin gets 403 before anything starts; a rerun deletes
  the previous capture, and so does deleting the investigation).
  `eval/sequential_runner.py` asks for it with `BOUNCE_EVAL_CAPTURE=1` and stops
  any run the server did not acknowledge as captured.
  `python eval/fixture_tool.py promote <inv_id> case02` turns that into the
  committed set `eval/fixtures/case02/`. `BOUNCE_FIXTURE_DIR=eval/fixtures/case02`
  replays it: source keys are served from the set whatever the TTL, nothing is
  written to the DB, the MCP processes refuse DNS and outbound sockets, and a
  request the capture never made fails as `fixture replay: no recorded response
  for …` and is appended to `data/fixtures/replay-misses/<inv_id>.jsonl` (the
  miss count is how far the replayed agent strayed). Replay pins the **data**,
  not the model's sampling. A replay box needs no API key: the names of the keys
  present at capture are recorded (`_env.json`, names only) and stood in with
  placeholders, which redact to the same `<secret:SOURCE>` as the real keys did.
  Run replay on a dev instance, never on the production service (the main
  process is not network-guarded). **A new kind of bookkeeping key in the cache**
  (anything that is not a source's answer) must be added to
  `fixtures.BOOKKEEPING_PREFIXES`; `test_every_cache_user_outside_sources_is_classified`
  fails until it is.
- **Demo snapshots** (`backend/demo_snapshot.py`, roadmap J3): a static,
  read-only page of real investigations (`npm run build:demo`), for readers
  with no PIN. A snapshot is exactly what a share link with graph + report +
  timeline shows (`graph_store.share_view`, which `get_share_payload` wraps:
  change one, you change both), minus agent session ids, usage and local paths.
  It is refused when it holds a secret of the instance that ran the
  investigation, so it is made where those secrets are readable: the owner
  route `GET /api/investigations/{id}/demo_snapshot` (server env) or
  `eval/demo_export.py --dotenv <that .env>`, which will not run against a
  `.env` it can't read. The repo is public: a committed snapshot is published.
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
  overrides. Text tokens hold 4.5:1 on every surface token of their theme (`--on-dim`,
  `--primary`, `--warning`, `--success`, `--error` on `--bg` to `--surface-3`): dim a
  text with `--on-dim`, never with `opacity`, and take a status colour from a token,
  never a fixed hex (`STATUS_COLOR` in `lib/constants.js`). The Cytoscape canvas follows the theme too: Cytoscape cannot read CSS
  variables, so `readCanvasColors()` (`lib/graph.js`) reads `--on-bg` (node label, seed
  border, selection ring), `--on-dim` / `--bg` (edge label and its chip), `--error` /
  `--success` and the `--graph-*` variables defined next to `.graph` in `styles.css`
  (default border and edge, pinned border, the blue and orange of rings and edges, the
  opacity factor of coloured edges) into a ref the stylesheet functions read, and `MainApp`
  re-reads them and calls `cy.style().update()` when the theme changes. Type colours
  (`NODE_COLORS`) are the same in both themes.
- **Cytoscape drops a style value it cannot parse** (a console warning, then the rule
  does nothing): `shadow-*` does not exist in 3.x, and a colour takes 3- or 6-digit hex,
  `rgb()` or a name, never 8-digit hex, `var()` or `color-mix()`. Transparency goes in
  `line-opacity` (line and arrow together), `outline-opacity`, `underlay-opacity`. On the
  canvas the border says what a node is (seed, tag, lead state, pinned); what the analyst
  is doing with it never touches the border: a ring (`outline-*`) in the text colour for
  the selected node and in blue for picked ones, a flat backdrop (`underlay-*`) for a
  search match.
- **One rule decides what the canvas draws**: the `display` function of the `node` rule
  in `buildCyStylesheet` hides a node whose type chip is off, or a defused node while the
  toolbar's "Defused" toggle is off (`isDefused`: a tag of `DEFUSE_TAGS`, seeds and pinned
  nodes excepted); the `edge` rule carries the relation filter, and Cytoscape does not draw
  the edges of a hidden node. All three read refs, so a toggle is a `cy.style().update()`.
  Never set `display` with `ele.style()`: a bypass wins over the stylesheet, and one filter
  then shows what another hides. Hidden nodes stay in `cy.nodes()`, so the JSON / Maltego
  copies and the counts still include them. `DEFUSE_TAGS` (`lib/constants.js`) is the union
  of the tags `defuse_check` emits and of `action_exports._DEFUSED_TAGS`
  (`backend/tests/test_defuse_tags_in_sync.py`).
- **Auth is PIN + session cookie**: Set `ADMIN_PIN=<6-digit>` in the env before the first start
  so the bootstrap promotes that PIN to admin (idempotent; no auto-generation if unset).
  Each investigation is owned by a user; the WebSocket and every `/api/*` route check ownership.
  The session cookie is host-only by default; set `BOUNCE_COOKIE_DOMAIN=.<parent>` (e.g.
  `.alexandre-pinoteau.fr`) so it's shared across the D3 deep-link subdomains
  (`cti./osint./dd.`) — one login covers all verticals.
- **D3 subdomain routing** (Phase 4): the SPA reads its hostname's first label
  (`cti./osint./dd.`, or a `?vertical=` param for dev/shareable links) via
  `verticalFromLocation()` in `lib/ioc.js` and pre-selects that vertical (shown as a
  fixed "from subdomain" badge instead of the selector). Topology: `bounce.` =
  showcase, `cti./osint./dd.` = the app with the vertical pinned. Cloudflare DNS
  + the reverse proxy route every app subdomain to the same backend; pair with
  `BOUNCE_COOKIE_DOMAIN` for cross-subdomain SSO.
- **Per-user model whitelist**: Admins can restrict which Claude models a user can spawn
  (`ALLOWED_MODELS` in `main.py`). Every alias maps to an exact model id in
  `agent_runner._MODEL_ALIASES`. The bare tier aliases are the *current* model of their
  tier, pinned to the newest one the production CLI runs (`sonnet`→`claude-sonnet-5-5`,
  `opus`→`claude-opus-5`, `haiku`→`claude-haiku-5-5`). They used to be left to the CLI's
  own aliasing, which follows the age of the installed CLI: on 2026-10-23 production
  (CLI 2.1.149) ran them as `claude-sonnet-4-6`, `claude-opus-4-7` and `claude-haiku-4-5`
  under a "latest" label. `claude-opus-5-5` needs CLI ≥ 2.1.280, so `opus` moves to it
  only after the service user's CLI is updated (a pin newer than the CLI fails as
  `error: model`, see Model-refusal detection). The labels name the version they run
  ("Opus (current: 5)"), and `test_model_lists_in_sync.py` fails when the table, the
  labels or "newest of its tier" part ways. Versioned aliases never move: the Claude 5
  family (`sonnet-5`→`claude-sonnet-5`, `opus-5`→`claude-opus-5`, `fable-5`→`claude-fable-5`)
  and previous Opus generations (`opus-4.8`→`claude-opus-4-8`, `opus-4.7`→`claude-opus-4-7`).
  NB: Fable 5's safety classifiers target offensive-cyber content, so malware-heavy
  investigations may hit refusals on it — prefer `opus-5` when that matters. Admin
  accounts are unrestricted.
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
- **CLI auth under systemd ≠ interactive auth.** `claude auth status` in an
  interactive shell can read OK while the service-spawned `claude -p` still gets
  `401 Invalid authentication credentials` — because the systemd service runs
  with a different `HOME` (so it reads a different `~/.claude`) or because creds
  live in a keyring the headless service can't reach (observed 2026-06-19). The
  robust fix for a service is a **headless token**: run `claude setup-token` as
  the service user, then set `CLAUDE_CODE_OAUTH_TOKEN` (or `ANTHROPIC_API_KEY`)
  in the service env. `agent_runner._build_env` passes these (+ `CLAUDE_CONFIG_DIR`
  / XDG vars) through to the spawn — the minimal env used to drop them, so a
  token set in `.env` was silently ignored. Failures now surface as
  `error: auth` (see Auth-failure detection) instead of an empty `done`.
- VirusTotal free tier: 4 req/min. Investigations may be slow.
- The `data/` directory is gitignored but must survive deploys (SQLite DB, auth key).
- WebSocket endpoint is `/ws/{investigation_id}` — reverse proxy must support upgrade headers.
- Every push to `main` deploys to production (see "Deployment & CI/CD"). There is no staging.
