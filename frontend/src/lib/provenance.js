import { LEAD_STATES } from './constants.js'

// Provenance of one node, as plain data for the Node tab: where the node came
// from (nodeOrigin) and which edges tie it to the graph (edgesOf + nodeTies).

// Ties listed before the "show the others" control.
export const TIES_SHOWN = 12

// The edges touching one node, read from a Cytoscape instance as plain objects.
// Aux report nodes never reach Cytoscape, so their edges are absent here.
export function edgesOf(cy, nodeId) {
  if (!cy || !nodeId) return []
  const end = n => ({ id: n.id(), type: n.data('type') || '', value: n.data('value') || '' })
  return cy.$id(nodeId).connectedEdges().map(e => ({
    id: e.id(),
    relation: e.data('relation') || '',
    evidence: e.data('evidence') || '',
    source: end(e.source()),
    target: end(e.target()),
  }))
}

// One entry per edge touching `nodeId`: the direction, the relation, the node
// at the other end and the reason written on the edge. Ties that carry a
// reason come first (they answer "why is this here"), then outgoing before
// incoming, then by relation and neighbour so the order is stable while edges
// stream in.
export function nodeTies(nodeId, edges) {
  const ties = (edges || [])
    .filter(e => e && (e.source?.id === nodeId || e.target?.id === nodeId))
    .map(e => {
      const outgoing = e.source.id === nodeId
      const other = outgoing ? e.target : e.source
      return {
        id: e.id,
        outgoing,
        relation: e.relation || 'related',
        evidence: String(e.evidence || '').trim(),
        neighbour: { id: other.id, type: other.type || '', value: String(other.value ?? '') },
        self: e.source.id === e.target.id,
      }
    })
  // Numbers inside a value sort as numbers: host2 before host10.
  const byText = (x, y) => x.localeCompare(y, 'en', { numeric: true })
  return ties.sort((a, b) =>
    (b.evidence ? 1 : 0) - (a.evidence ? 1 : 0)
    || (b.outgoing ? 1 : 0) - (a.outgoing ? 1 : 0)
    || byText(a.relation, b.relation)
    || byText(a.neighbour.type, b.neighbour.type)
    || byText(a.neighbour.value, b.neighbour.value)
    || byText(String(a.id), String(b.id)))
}

// A value short enough for one line of the panel: the start and the end are
// kept (the end tells two long URLs or digests apart). The full value goes in
// the element's `title`.
export function shortValue(value, max = 48) {
  const s = String(value ?? '')
  if (s.length <= max) return s
  const tail = Math.floor(max / 4)
  return s.slice(0, max - tail - 1) + '…' + s.slice(-tail)
}

// Which source a cached answer came from, read from its cache key: the API's
// host and first path segment for http_client's default keys
// (`GET|https://rdap.org/domain/evil.example|None` → `rdap.org/domain`), the
// head of a source's own key otherwise (`whois|domain|evil.example` → `whois`).
export function evidenceSource(cacheKey) {
  const [head, rest = ''] = String(cacheKey ?? '').split('|')
  if (!['GET', 'POST', 'TXT', 'FORM'].includes(head)) return head
  return rest.replace(/^[a-z]+:\/\//i, '').split(/[/?#]/).filter(Boolean).slice(0, 2).join('/') || head
}

// The agent sometimes passes several source names in one string
// ("virustotal,rdap"): each name counts once, whatever the order.
const sourceNames = s => (typeof s === 'string' ? s : '')
  .split(/[,;]/).map(x => x.trim()).filter(Boolean)

// Values of `source` that say how a node was created and name no source: they
// get their own sentence and are left out of the source names and their count.
const NOT_A_SOURCE = new Set(['agent', 'edge_autostub', 'tag_promotion'])

// Where a node came from, read from the fields the backend writes once
// (`source`, `confidence`, `created_at`) and from `metadata.sources_seen`,
// which grows with every later report. `sources` are the names given when the
// node was added, `others` the names recorded since. `kind` says which
// sentence is true:
//   'lead'   a context-pool hypothesis (the agent's memory or open-web text)
//   'agent'  added by the agent with no source tool named
//   'stub'   created because an edge named it (edge_autostub)
//   'tag'    created from a tag on another node (tag_promotion)
//   'source' added with one or more source names
//   'none'   no source recorded
export function nodeOrigin(node) {
  const n = node || {}
  const md = n.metadata || {}
  const source = typeof n.source === 'string' ? n.source.trim() : ''
  const sources = [...new Set(sourceNames(source))].filter(s => !NOT_A_SOURCE.has(s))
  const seen = Array.isArray(md.sources_seen) ? md.sources_seen.flatMap(sourceNames) : []
  const others = [...new Set(seen)].filter(s => !sources.includes(s) && !NOT_A_SOURCE.has(s)).sort()
  const origin = {
    kind: 'source',
    source,
    sources,
    others,
    sourceCount: sources.length + others.length,
    createdAt: Number(n.created_at) > 0 ? Number(n.created_at) : null,
    confidence: typeof n.confidence === 'number' ? n.confidence : null,
    tagEvidence: '',
    lead: null,
    promotedFrom: null,
  }
  if (n.type === 'lead') {
    origin.kind = 'lead'
    const tags = n.tags || []
    origin.lead = {
      basis: source === 'parametric_memory' ? 'memory' : source.startsWith('web:') ? 'web' : 'other',
      state: LEAD_STATES.find(s => tags.includes(s)) || 'unverified',
      tool: md.verdict_evidence_tool || '',
      value: md.verdict_evidence_value || '',
      note: md.verdict_note || '',
      verifiableBy: Array.isArray(md.verifiable_by) ? md.verifiable_by.map(String) : [],
      falsifier: md.falsifier || '',
    }
  } else if (source === 'agent') {
    origin.kind = 'agent'
  } else if (source === 'edge_autostub') {
    origin.kind = 'stub'
  } else if (source === 'tag_promotion') {
    origin.kind = 'tag'
    origin.tagEvidence = typeof md.evidence === 'string' ? md.evidence : ''
  } else if (sources.length === 0) {
    origin.kind = source ? 'agent' : 'none'   // e.g. "agent,agent": still no source named
  }
  if (n.type !== 'lead' && md.promoted_from_lead) {
    origin.promotedFrom = {
      lead: String(md.promoted_from_lead),
      tool: md.corroborating_tool || '',
      value: md.corroborating_value || '',
    }
  }
  return origin
}
