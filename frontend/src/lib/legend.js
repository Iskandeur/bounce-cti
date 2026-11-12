import { NODE_COLORS, NODE_SHAPES } from './constants.js'
import { isDefused } from './graph.js'

// What the canvas legend shows (components/GraphLegend.jsx): the Cytoscape node
// shapes as small SVG outlines, the meaning of each node border, and a summary
// of what a graph holds so the legend lists only what is on screen.

// ── Shape glyphs ─────────────────────────────────────────────────────────────
// Every glyph is a path in a 16 × 16 box, built from the same unit points
// (-1..1, y down) Cytoscape uses for the shape of that name.
const HALF = 6.5
const at = ([x, y]) => [8 + x * HALF, 8 + y * HALF]
const fmt = ([x, y]) => `${+x.toFixed(2)} ${+y.toFixed(2)}`

function polygon(points, radius = 0) {
  const pts = points.map(at)
  if (!radius) return 'M' + pts.map(fmt).join('L') + 'Z'
  // Rounded corners: stop `radius` short of each corner and curve through it.
  const toward = (from, to) => {
    const dx = to[0] - from[0], dy = to[1] - from[1]
    const k = Math.min(radius / Math.hypot(dx, dy), 0.5)
    return [from[0] + dx * k, from[1] + dy * k]
  }
  return pts.map((p, i) => {
    const prev = pts[(i + pts.length - 1) % pts.length]
    const next = pts[(i + 1) % pts.length]
    return `${i ? 'L' : 'M'}${fmt(toward(p, prev))}Q${fmt(p)} ${fmt(toward(p, next))}`
  }).join('') + 'Z'
}

// Stretch a point list to fill the unit square, as Cytoscape does.
function fit(points) {
  const xs = points.map(p => p[0]), ys = points.map(p => p[1])
  const minX = Math.min(...xs), maxX = Math.max(...xs)
  const minY = Math.min(...ys), maxY = Math.max(...ys)
  return points.map(([x, y]) => [
    (x - minX) / (maxX - minX) * 2 - 1,
    (y - minY) / (maxY - minY) * 2 - 1,
  ])
}

function ngon(sides, turn = 0, scale = 1) {
  const step = 2 * Math.PI / sides
  const start = Math.PI / 2 + (sides % 2 === 0 ? step / 2 : 0) + turn
  return Array.from({ length: sides }, (_, i) => {
    const a = start + i * step
    return [Math.cos(a) * scale, -Math.sin(a) * scale]
  })
}

const DIAMOND = [[0, 1], [1, 0], [0, -1], [-1, 0]]
const TAG = [[-1, -1], [0.25, -1], [1, 0], [0.25, 1], [-1, 1]]
const SQUARE = [[-1, -1], [1, -1], [1, 1], [-1, 1]]
// Five outer points and five inner ones, alternating.
const STAR = fit(ngon(5).flatMap((p, i) => [p, ngon(5, Math.PI / 5, 0.6)[i]]))
// Corners cut by 8 px on a 22 px node.
const CUT = 1 - 16 / 22

export const SHAPE_PATHS = {
  ellipse: 'M8 1.5A6.5 6.5 0 1 1 8 14.5A6.5 6.5 0 1 1 8 1.5Z',
  rectangle: polygon(SQUARE),
  'round-rectangle': polygon(SQUARE, 3.25),
  'cut-rectangle': polygon([
    [-CUT, -1], [CUT, -1], [1, -CUT], [1, CUT], [CUT, 1], [-CUT, 1], [-1, CUT], [-1, -CUT],
  ]),
  // A rectangle whose top and bottom edges fall away at the corners.
  barrel: 'M1.5 2.15V13.85Q1.66 14.5 4.75 14.5H11.25Q14.34 14.5 14.5 13.85'
    + 'V2.15Q14.34 1.5 11.25 1.5H4.75Q1.66 1.5 1.5 2.15Z',
  diamond: polygon(DIAMOND),
  'round-diamond': polygon(DIAMOND, 1.5),
  triangle: polygon(fit(ngon(3))),
  pentagon: polygon(fit(ngon(5))),
  hexagon: polygon(fit(ngon(6))),
  heptagon: polygon(fit(ngon(7))),
  octagon: polygon(fit(ngon(8))),
  star: polygon(STAR),
  vee: polygon([[-1, -1], [0, -0.333], [1, -1], [0, 1]]),
  rhomboid: polygon([[-1, -1], [0.333, -1], [1, 1], [-0.333, 1]]),
  'concave-hexagon': polygon([
    [-1, -0.95], [-0.75, 0], [-1, 0.95], [1, 0.95], [0.75, 0], [1, -0.95],
  ]),
  tag: polygon(TAG),
  'round-tag': polygon(TAG, 1.5),
}

// A shape with no glyph here is drawn as an ellipse, Cytoscape's own default.
export const shapePath = shape => SHAPE_PATHS[shape] || SHAPE_PATHS.ellipse

// ── Border meanings ──────────────────────────────────────────────────────────
// One entry per border the stylesheet of lib/graph.js draws for a tag or a
// lead state, in the order of its rules. Colours and dashes repeat those
// rules: change both together. A var() is a colour the canvas reads from
// the theme (readCanvasColors).
export const BORDER_MARKS = [
  { id: 'seed', test: d => d.seed, color: 'var(--on-bg)', width: 2.5,
    text: 'Seed, where the investigation started' },
  { id: 'lead', test: d => d.leadState === 'unverified' || d.leadState === 'unverifiable',
    color: '#9a8cb8', dash: 'dashed',
    text: 'Lead from memory or the web, no source has confirmed it' },
  { id: 'corroborated', test: d => d.leadState === 'corroborated', color: '#56d364',
    text: 'Lead a source confirmed' },
  { id: 'refuted', test: d => d.leadState === 'refuted', color: '#f85149', dash: 'dotted',
    text: 'Lead a source refuted' },
  { id: 'pinned', test: d => d.pinned, color: 'var(--graph-pin)', width: 2.5,
    text: 'Pinned by an analyst' },
  { id: 'suspicious', test: d => d.suspicious || d.phishing, color: '#f85149',
    text: 'Tagged suspicious or phishing' },
  { id: 'cdn', test: d => d.cdn, color: '#1f6feb', dash: 'dashed',
    text: 'CDN address, shared by many sites' },
  { id: 'parking', test: d => d.parking, color: '#8b949e', dash: 'dashed',
    text: 'Parked domain or parking nameserver' },
  { id: 'sinkhole', test: d => d.sinkhole, color: '#f85149', dash: 'dashed',
    text: 'Sinkhole, taken over by a vendor or the police' },
]

// ── Summary of a graph ───────────────────────────────────────────────────────
// The investigation summary is a report node the stylesheet draws as a star.
const SUMMARY = { key: 'investigation_summary', label: 'investigation summary', shape: 'star', color: '#f0a500' }

function kindOf(d) {
  if (d.type === 'report' && d.value === 'investigation_summary') return SUMMARY
  return {
    key: d.type, label: d.type,
    shape: NODE_SHAPES[d.type] || 'ellipse',
    color: NODE_COLORS[d.type] || '#8b949e',
  }
}

export const EMPTY_SUMMARY = { key: '', types: [], marks: [], defused: 0 }

// From the data objects of the nodes of a graph: the node types present
// (in the order of NODE_COLORS, unknown types last) with their count, the
// border meanings present, and how many nodes are defused. `key` changes
// only when one of those does.
export function summariseGraph(nodes) {
  const kinds = new Map()
  const seen = new Set()
  let defused = 0
  for (const d of nodes) {
    const kind = kindOf(d)
    const entry = kinds.get(kind.key) || { ...kind, count: 0 }
    entry.count += 1
    kinds.set(kind.key, entry)
    for (const mark of BORDER_MARKS) if (mark.test(d)) seen.add(mark.id)
    if (isDefused(d)) defused += 1
  }
  const order = Object.keys(NODE_COLORS)
  const rank = key => {
    if (key === SUMMARY.key) return order.indexOf('report') + 0.5
    const i = order.indexOf(key)
    return i < 0 ? order.length : i
  }
  const types = [...kinds.values()]
    .sort((a, b) => rank(a.key) - rank(b.key) || a.key.localeCompare(b.key))
  const marks = BORDER_MARKS.filter(m => seen.has(m.id))
  const key = [
    types.map(t => `${t.key}:${t.count}`).join(','),
    marks.map(m => m.id).join(','),
    defused,
  ].join('|')
  return { key, types, marks, defused }
}
