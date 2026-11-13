export const NODE_COLORS = {
  domain: '#79c0ff', ip: '#ffa657', hash: '#d2a8ff', url: '#56d364',
  cert: '#3fb950', asn: '#e3b341', email: '#f78166', registrar: '#8b949e',
  ns: '#58a6ff', favicon: '#e3b341', jarm: '#bc8cff', report: '#f5a623',
  country: '#ff7b72', person: '#ff80b3', command_line: '#f0883e',
  executable_name: '#ffb86b', wallet_address: '#f1c40f',
  username: '#a371f7', ja3: '#caa6ff', ja3s: '#9d7fe0',
  phone: '#2dd4bf', company: '#6ee7b7', threat_actor: '#ff5c8a',
  // Context-pool lead: deliberately desaturated grey-violet so it never reads
  // as a confirmed indicator at a glance. Paired with a dashed border below.
  lead: '#9a8cb8'
}
export const NODE_SHAPES = {
  domain: 'ellipse', ip: 'rectangle', ns: 'diamond', registrar: 'hexagon',
  cert: 'round-rectangle', asn: 'barrel', hash: 'triangle', report: 'concave-hexagon',
  jarm: 'pentagon', url: 'cut-rectangle', country: 'tag', person: 'star',
  command_line: 'rhomboid', executable_name: 'vee',
  email: 'round-tag', wallet_address: 'rhomboid', username: 'star',
  phone: 'round-diamond', company: 'round-rectangle',
  ja3: 'heptagon', ja3s: 'octagon', threat_actor: 'star',
  lead: 'round-tag'
}
// Theme tokens, so a status reads on the light theme too (the fixed greens and
// ambers of the dark theme were at 1.7:1 on a light surface).
export const STATUS_COLOR = { running: 'var(--warning)', done: 'var(--success)', cleared: 'var(--on-dim)',
                       error: 'var(--error)', quota_exceeded: 'var(--warning)' }

// Context-pool lead lifecycle (backend/context_pool.py), in precedence order:
// a resolved verdict wins over the initial `unverified`.
export const LEAD_STATES = ['corroborated', 'refuted', 'unverifiable', 'unverified']
export const LEAD_STATE_COLOR = {
  corroborated: '#56d364', refuted: '#f85149',
  unverifiable: '#8b949e', unverified: '#9a8cb8',
}

// Tags that mark a node as defused: it exists, and it says nothing about the
// operator (a CDN address, a parking nameserver, a sinkhole…). The backend
// keeps two lists: the tags defuse_check() emits (backend/defuse_lists.py) and
// the tags the Actions exports leave out (backend/action_exports.py
// _DEFUSED_TAGS). This is their union, so "defused" means the same nodes on
// the canvas and in the Actions tab.
// backend/tests/test_defuse_tags_in_sync.py fails when the lists part ways.
export const DEFUSE_TAGS = [
  'cdn', 'parking', 'parked_domain', 'sinkhole', 'blackhole', 'dyndns',
  'tor_exit', 'nsrl_known', 'legit_service', 'shared_hosting',
]

// ── Maltego entity type mapping ──────────────────────────────────────────────
// Maps bounce-cti node.type -> Maltego entity type string. The paste format is
// `<maltego_entity_type>#<value>` (one per line). Falsy return = skip this type.
export const MALTEGO_TYPES = {
  domain:    () => 'maltego.Domain',
  ip:        v  => v.includes(':') ? 'maltego.IPv6Address' : 'maltego.IPv4Address',
  hash:      () => 'maltego.Hash',
  url:       () => 'maltego.URL',
  cert:      () => 'maltego.X509Certificate',
  asn:       () => 'maltego.AS',
  email:     () => 'maltego.EmailAddress',
  ns:        () => 'maltego.NSRecord',
  registrar: () => 'maltego.Organization',
  favicon:   () => 'maltego.Phrase',
  jarm:      () => 'maltego.Phrase',
  ja3:       () => 'maltego.Phrase',
  ja3s:      () => 'maltego.Phrase',
  country:   () => 'maltego.Location.Country',
  person:    () => 'maltego.Person',
  command_line: () => 'maltego.Phrase',
  executable_name: () => 'maltego.File',
  wallet_address: () => 'maltego.Phrase',
  username:  () => 'maltego.Alias',
  phone:     () => 'maltego.PhoneNumber',
  company:   () => 'maltego.Company',
  report:    () => null,
}

// Node types an analyst can pivot from (enrich in place or seed a new graph).
export const PIVOTABLE = ['domain', 'ip', 'hash', 'url', 'jarm', 'asn']
