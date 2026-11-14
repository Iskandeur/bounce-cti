import test from 'node:test'
import assert from 'node:assert/strict'
import { edgesOf, evidenceSource, nodeOrigin, nodeTies, shortValue } from './provenance.js'

const D = { id: 'd', type: 'domain', value: 'evil.example' }
const IP = { id: 'i', type: 'ip', value: '203.0.113.7' }
const NS = { id: 'n', type: 'ns', value: 'ns1.evil.example' }
const SUB = { id: 's', type: 'domain', value: 'cdn.evil.example' }
const edge = (id, source, relation, target, evidence = '') => ({ id, source, relation, target, evidence })

test('a tie says which way the edge goes and who is at the other end', () => {
  const [out] = nodeTies('d', [edge('e1', D, 'resolves_to', IP, 'A record')])
  assert.deepEqual(out, {
    id: 'e1', outgoing: true, relation: 'resolves_to', evidence: 'A record',
    neighbour: IP, self: false,
  })
  const [inc] = nodeTies('i', [edge('e1', D, 'resolves_to', IP, 'A record')])
  assert.equal(inc.outgoing, false)
  assert.deepEqual(inc.neighbour, D)
})

test('ties with a reason come first, then outgoing, then by relation and neighbour', () => {
  const ties = nodeTies('d', [
    edge('e1', D, 'uses_ns', NS),
    edge('e2', SUB, 'has_parent', D),
    edge('e3', D, 'has_subdomain', SUB),
    edge('e4', IP, 'hosts', D, 'passive DNS'),
    edge('e5', D, 'resolves_to', IP, 'A record'),
  ])
  assert.deepEqual(ties.map(t => t.id), ['e5', 'e4', 'e3', 'e1', 'e2'])
})

test('numbers inside a neighbour value sort as numbers', () => {
  const host = i => ({ id: `h${i}`, type: 'domain', value: `host${i}.evil.example` })
  const ties = nodeTies('d', [10, 2, 1].map(i => edge(`e${i}`, D, 'has_subdomain', host(i))))
  assert.deepEqual(ties.map(t => t.neighbour.value),
    ['host1.evil.example', 'host2.evil.example', 'host10.evil.example'])
})

test('the order does not depend on the order edges arrived in', () => {
  const edges = [
    edge('e1', D, 'uses_ns', NS), edge('e3', D, 'has_subdomain', SUB),
    edge('e5', D, 'resolves_to', IP, 'A record'),
  ]
  assert.deepEqual(nodeTies('d', edges).map(t => t.id),
    nodeTies('d', [...edges].reverse()).map(t => t.id))
})

test('edges that do not touch the node are left out, blank reasons count as none', () => {
  const ties = nodeTies('d', [
    edge('e1', IP, 'located_in', { id: 'c', type: 'country', value: 'FR' }, 'geo'),
    edge('e2', D, 'resolves_to', IP, '   '),
  ])
  assert.deepEqual(ties.map(t => [t.id, t.evidence]), [['e2', '']])
})

test('an edge from a node to itself is one tie, flagged', () => {
  const [t] = nodeTies('d', [edge('e1', D, 'redirects_to', D)])
  assert.equal(t.self, true)
  assert.equal(t.outgoing, true)
})

test('edgesOf reads plain data from a Cytoscape-like instance', () => {
  const node = d => ({ id: () => d.id, data: k => d[k] })
  const cyEdge = { id: () => 'e1', data: k => ({ relation: 'resolves_to', evidence: 'A record' })[k],
                   source: () => node(D), target: () => node(IP) }
  const cy = { $id: id => ({ connectedEdges: () => (id === 'd' ? [cyEdge] : []) }) }
  assert.deepEqual(edgesOf(cy, 'd'), [edge('e1', D, 'resolves_to', IP, 'A record')])
  assert.deepEqual(edgesOf(cy, 'zz'), [])
  assert.deepEqual(edgesOf(null, 'd'), [])
})

test('shortValue keeps the start and the end of a long value', () => {
  assert.equal(shortValue('evil.example'), 'evil.example')
  const sha256 = 'a'.repeat(32) + 'b'.repeat(32)
  assert.equal(shortValue(sha256), 'a'.repeat(32) + 'bbb' + '…' + 'b'.repeat(12))   // 35 + … + 12
  assert.equal(shortValue(sha256, 64), sha256)
  const url = 'http://evil.example/' + 'p'.repeat(100) + '/login.php'
  const short = shortValue(url)
  assert.equal(short.length, 48)
  assert.ok(short.startsWith('http://evil.example/') && short.endsWith('/login.php'))
  assert.ok(short.includes('…'))
})

test('origin of a node added with a source name', () => {
  const o = nodeOrigin({
    type: 'domain', source: 'crtsh', confidence: 0.8, created_at: 1762870325.4,
    metadata: { sources_seen: ['urlscan', 'crtsh', 'rdap', 'urlscan'] },
  })
  assert.equal(o.kind, 'source')
  assert.deepEqual(o.sources, ['crtsh'])
  assert.deepEqual(o.others, ['rdap', 'urlscan'])     // first source left out, no duplicate
  assert.equal(o.sourceCount, 3)
  assert.equal(o.createdAt, 1762870325.4)
  assert.equal(o.confidence, 0.8)
})

test('several names passed in one string count once each, whatever the order', () => {
  const o = nodeOrigin({
    type: 'hash', source: 'virustotal,rdap',
    metadata: { sources_seen: ['virustotal,rdap', 'rdap, virustotal', 'otx,virustotal,malwarebazaar'] },
  })
  assert.equal(o.kind, 'source')
  assert.deepEqual(o.sources, ['virustotal', 'rdap'])
  assert.deepEqual(o.others, ['malwarebazaar', 'otx'])
  assert.equal(o.sourceCount, 4)
})

test('origin tells an agent-only node, an edge stub and a tag promotion apart', () => {
  const agent = nodeOrigin({ type: 'ip', source: 'agent', metadata: { sources_seen: ['agent', 'rdap'] } })
  // "agent" names no source: it is neither listed nor counted.
  assert.deepEqual([agent.kind, agent.sources, agent.others, agent.sourceCount], ['agent', [], ['rdap'], 1])
  const later = nodeOrigin({ type: 'ip', source: 'rdap', metadata: { sources_seen: ['rdap', 'agent'] } })
  assert.deepEqual([later.kind, later.others, later.sourceCount], ['source', [], 1])
  assert.equal(nodeOrigin({ type: 'ip', source: 'edge_autostub' }).kind, 'stub')
  const tag = nodeOrigin({ type: 'threat_actor', source: 'tag_promotion',
                           metadata: { evidence: "tag 'apt28' on domain:evil.example" } })
  assert.deepEqual([tag.kind, tag.tagEvidence], ['tag', "tag 'apt28' on domain:evil.example"])
  const none = nodeOrigin({ type: 'ip' })
  assert.deepEqual([none.kind, none.sourceCount, none.createdAt, none.confidence], ['none', 0, null, null])
})

test('a lead is a hypothesis, with its verdict when the metadata carries one', () => {
  const fresh = nodeOrigin({
    type: 'lead', source: 'parametric_memory', confidence: 0.35, tags: ['unverified'],
    metadata: { verifiable_by: ['mcp__cti__rdap_domain'], falsifier: 'registered after 2024' },
  })
  assert.equal(fresh.kind, 'lead')
  assert.deepEqual(fresh.lead, {
    basis: 'memory', state: 'unverified', tool: '', value: '', note: '',
    verifiableBy: ['mcp__cti__rdap_domain'], falsifier: 'registered after 2024',
  })
  const done = nodeOrigin({
    type: 'lead', source: 'web:blog.example', tags: ['unverified', 'corroborated'],
    metadata: { verdict_evidence_tool: 'mcp__cti__dns_resolve', verdict_evidence_value: '203.0.113.7',
                verdict_note: 'A record matches' },
  })
  assert.deepEqual([done.lead.basis, done.lead.state, done.lead.tool, done.lead.value, done.lead.note],
    ['web', 'corroborated', 'mcp__cti__dns_resolve', '203.0.113.7', 'A record matches'])
})

test('a node promoted from a lead says which tool confirmed it', () => {
  const o = nodeOrigin({
    type: 'ip', source: 'mcp__cti__dns_resolve', tags: ['corroborated'],
    metadata: { promoted_from_lead: 'evil.example resolves to 203.0.113.7',
                corroborating_tool: 'mcp__cti__dns_resolve', corroborating_value: '203.0.113.7' },
  })
  assert.equal(o.kind, 'source')
  assert.deepEqual(o.promotedFrom, {
    lead: 'evil.example resolves to 203.0.113.7',
    tool: 'mcp__cti__dns_resolve', value: '203.0.113.7',
  })
})

test('a cached answer is labelled by the source that gave it', () => {
  assert.equal(evidenceSource('GET|https://rdap.org/domain/evil.example|None'), 'rdap.org/domain')
  assert.equal(evidenceSource("GET|https://crt.sh/|{'q': '%.evil.example', 'output': 'json'}"), 'crt.sh')
  assert.equal(evidenceSource("FORM|https://urlhaus-api.abuse.ch/v1/host/|{'host': 'evil.example'}"), 'urlhaus-api.abuse.ch/v1')
  assert.equal(evidenceSource('whois|domain|evil.example'), 'whois')
  assert.equal(evidenceSource('internetdb|203.0.113.7'), 'internetdb')
  assert.equal(evidenceSource('GET'), 'GET')
})
