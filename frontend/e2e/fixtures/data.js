// What the mocked backend answers. Everything here is written by hand and
// synthetic: reserved documentation names only (example.com, 192.0.2.0/24,
// 198.51.100.0/24, AS64496), made-up ids and hashes. The shapes follow
// backend/main.py and backend/graph_store.py.

const T0 = 1767225600 // 2026-01-01T00:00:00Z

export const INV_DOMAIN = 'e2e000000001'
export const INV_IP = 'e2e000000002'

// GET /api/auth/me
export const ME = { user_id: 1, is_admin: false, allowed_models: null }

// GET /api/verticals
export const VERTICALS = [
  { name: 'cti', label: 'CTI', seed_types: ['domain', 'ip', 'hash', 'url'] },
  { name: 'osint', label: 'OSINT', seed_types: ['username', 'email', 'domain'] },
  { name: 'dd', label: 'Due Diligence', seed_types: ['company'] },
]

// GET /api/quota
export const QUOTA = { exhausted: false, exhausted_until: null, message: null, last_seen: null }

// GET /api/investigations (newest first, like the backend)
export const INVESTIGATIONS = [
  {
    id: INV_DOMAIN, seed_type: 'domain', seed_value: 'example.com', created_at: T0 + 3600,
    status: 'done', user_id: 1, model: 'sonnet', effort: null, title: null, vertical: 'cti',
    fixture_capture: 0, context_pool: 0, quota_reset_at: null,
    seeds: [{ type: 'domain', value: 'example.com', added_at: T0 + 3600 }],
  },
  {
    id: INV_IP, seed_type: 'ip', seed_value: '192.0.2.10', created_at: T0,
    status: 'done', user_id: 1, model: 'sonnet', effort: null, title: null, vertical: 'cti',
    fixture_capture: 0, context_pool: 0, quota_reset_at: null,
    seeds: [{ type: 'ip', value: '192.0.2.10', added_at: T0 }],
  },
]

const node = (inv, n, type, value, extra = {}) => ({
  id: `${inv.slice(-4)}00000000${String(n).padStart(4, '0')}`,
  investigation_id: inv, type, value,
  metadata: {}, tags: [], confidence: 0.8, source: 'agent', created_at: T0 + 3600 + n,
  ...extra,
})

const edge = (inv, n, src, dst, relation) => ({
  id: `${inv.slice(-4)}0000eeee${String(n).padStart(4, '0')}`,
  investigation_id: inv, src: src.id, dst: dst.id, relation,
  evidence: '', source: 'agent', confidence: 0.8, created_at: T0 + 3700 + n,
})

// The investigation_summary report node's metadata is the report the Report tab renders.
export const REPORT = {
  threat_assessment: 'suspicious',
  summary: 'The seed example.com resolves to 192.0.2.10 and shares that address with a made-up sample.',
  key_findings: [
    { text: 'example.com resolves to 192.0.2.10, announced by AS64496.', sources: ['dns_resolve', 'ip_api'] },
    { text: 'mail.example.com sits behind a CDN address (198.51.100.7).', sources: ['crtsh'] },
  ],
  mitre_attack_mapping: [{
    technique_id: 'T1583.001', technique_name: 'Acquire Infrastructure: Domains',
    tactics: ['resource-development'], confidence: 'low', evidence: 'A registered domain is in use.',
  }],
  pivot_suggestions: ['Check other names on 192.0.2.10'],
  ioc_list: ['example.com', 'mail.example.com', '192.0.2.10'],
  sources_used: ['rdap', 'crtsh', 'dns_resolve', 'ip_api'],
  prompt_history: [],
}

const d = {
  seed: node(INV_DOMAIN, 1, 'domain', 'example.com', {
    tags: ['seed'], source: 'user', metadata: { sources_seen: ['rdap', 'crtsh'] },
  }),
  mail: node(INV_DOMAIN, 2, 'domain', 'mail.example.com', { source: 'crtsh' }),
  ip: node(INV_DOMAIN, 3, 'ip', '192.0.2.10', { tags: ['suspicious'], source: 'dns_resolve' }),
  cdnIp: node(INV_DOMAIN, 4, 'ip', '198.51.100.7', { tags: ['cdn'], source: 'dns_resolve' }),
  asn: node(INV_DOMAIN, 5, 'asn', 'AS64496', { source: 'ip_api' }),
  hash: node(INV_DOMAIN, 6, 'hash', 'e2e0'.repeat(16), {
    source: 'malwarebazaar', metadata: { file_name: 'sample.example.bin' },
  }),
  summary: node(INV_DOMAIN, 7, 'report', 'investigation_summary', { metadata: REPORT }),
  // The three kinds of report node the canvas leaves out (lib/graph.js isAuxReportNode).
  hypothesis: node(INV_DOMAIN, 8, 'report', 'working_hypothesis', {
    metadata: {
      category: 'phishing_infrastructure', confidence: 'medium',
      reason: 'A fresh mail subdomain next to the seed.', evidence: ['mail.example.com'],
    },
  }),
  budget: node(INV_DOMAIN, 9, 'report', 'budget_extension_1', {
    metadata: { calls_so_far: 61, reason: 'One more pivot on the shared address.' },
  }),
  lessons: node(INV_DOMAIN, 10, 'report', 'lessons_learned', { metadata: { blockers: [] } }),
}

const i = {
  seed: node(INV_IP, 1, 'ip', '192.0.2.10', { tags: ['seed'], source: 'user' }),
  asn: node(INV_IP, 2, 'asn', 'AS64496', { source: 'ip_api' }),
}

// What the WebSocket sends first on /ws/<inv_id>: {kind: 'snapshot', graph}.
export const GRAPHS = {
  [INV_DOMAIN]: {
    nodes: Object.values(d),
    edges: [
      edge(INV_DOMAIN, 1, d.seed, d.mail, 'has_subdomain'),
      edge(INV_DOMAIN, 2, d.seed, d.ip, 'resolves_to'),
      edge(INV_DOMAIN, 3, d.mail, d.cdnIp, 'resolves_to'),
      edge(INV_DOMAIN, 4, d.ip, d.asn, 'hosted_on_asn'),
      edge(INV_DOMAIN, 5, d.hash, d.ip, 'communicates_with'),
    ],
  },
  [INV_IP]: {
    nodes: Object.values(i),
    edges: [edge(INV_IP, 1, i.seed, i.asn, 'hosted_on_asn')],
  },
}

// Nodes the canvas draws: every node of the snapshot minus the three aux
// report nodes. The toolbar shows this number in "↓ JSON (N)".
export const DRAWN_NODES = { [INV_DOMAIN]: 7, [INV_IP]: 2 }

// GET /api/investigations/<id>/transcript
export const TRANSCRIPTS = {
  [INV_DOMAIN]: {
    investigation_id: INV_DOMAIN,
    entries: [
      { kind: 'phase', ts: T0 + 3600, phase: 'main', stage: 'starting' },
      { kind: 'reasoning', ts: T0 + 3601, text: 'Starting from the seed domain example.com.' },
      { kind: 'tool', ts: T0 + 3602, name: 'mcp__cti__dns_resolve', input: { domain: 'example.com' } },
      {
        kind: 'tool_result', ts: T0 + 3603, name: 'mcp__cti__dns_resolve',
        result_preview: '{"a": ["192.0.2.10"]}', is_error: false,
      },
    ],
  },
  [INV_IP]: { investigation_id: INV_IP, entries: [] },
}

// GET /api/investigations/<id>/leads, as a CTI run answers it (context pool off).
export const LEADS = {
  total_leads: 0, corroborated: 0, refuted: 0, unverifiable: 0, unverified: 0,
  corroboration_rate: null, by_claim_type: {},
  vertical: 'cti', context_pool_enabled: false, ctx_calls_used: 0, ctx_budget: 12,
  leads: [],
}

// GET /api/investigations/<id>/progress (backend/run_progress.py). By default
// the run of each investigation is over: 12 minutes 4 seconds, 61 source calls
// against the pivot-drain budget of 82.
const runOver = (inv, started) => ({
  investigation_id: inv, status: 'done', running: false, vertical: 'cti', now: started + 86400,
  run: {
    kind: 'investigation', started_at: started, ended_at: started + 724,
    end_status: 'done', stopped_by_user: false,
  },
  phase: null,
  phases: [{ name: 'main', started_at: started, ended_at: started + 724 }],
  drain: null, source_calls: 61, source_calls_run: 61, ceiling: 82,
})
export const PROGRESS = {
  [INV_DOMAIN]: runOver(INV_DOMAIN, T0 + 3600),
  [INV_IP]: runOver(INV_IP, T0),
}

// The same endpoint while a run is live, for the tests that override the
// route: 2 minutes 5 seconds in, the phase named by `phase` in flight.
export const runningProgress = (inv, phase) => ({
  investigation_id: inv, status: 'running', running: true, vertical: 'cti', now: T0 + 7325,
  run: {
    kind: 'investigation', started_at: T0 + 7200, ended_at: null,
    end_status: null, stopped_by_user: false,
  },
  phase: { name: phase, started_at: T0 + 7300 },
  phases: [{ name: 'main', started_at: T0 + 7200, ended_at: T0 + 7300 }],
  drain: { round: 2, max_rounds: 3 }, source_calls: 61, source_calls_run: 61, ceiling: 82,
})

// GET /api/investigations/<id>/nodes/<node_id>/cross_investigations:
// 192.0.2.10 is in both investigations, nothing else is.
export const crossInvestigations = (invId, nodeId) => {
  const n = GRAPHS[invId]?.nodes.find(x => x.id === nodeId)
  if (!n) return null
  const hits = invId === INV_DOMAIN && n.value === '192.0.2.10'
    ? [{
        investigation_id: INV_IP, seed_type: 'ip', seed_value: '192.0.2.10', title: null,
        node_tags: ['seed'], node_first_seen: T0 + 1, node_metadata_keys: [],
        investigation_created_at: T0,
      }]
    : []
  return { type: n.type, value: n.value, hits, count: hits.length }
}

// GET /api/investigations/<id>/nodes/<node_id>/evidence: one cached source answer.
export const evidence = (invId, nodeId) => {
  const n = GRAPHS[invId]?.nodes.find(x => x.id === nodeId)
  if (!n) return null
  return {
    node_id: nodeId, value: n.value,
    evidence: [{
      cache_key: `rdap|https://rdap.example.com/ip/${n.value}`,
      data: { handle: 'NET-192-0-2-0-1', name: 'TEST-NET-1' },
      cached_at: T0 + 3605,
    }],
  }
}
