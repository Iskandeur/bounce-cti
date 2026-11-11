import { NODE_COLORS, NODE_SHAPES, LEAD_STATES, DEFUSE_TAGS } from './constants.js'

// The colours Cytoscape draws against the canvas, read from the theme
// variables of styles.css (the --graph-* ones sit next to .graph): the canvas
// is var(--bg), so whatever has to stand out on it changes with the theme.
// Cytoscape parses 3- or 6-digit hex, rgb() and colour names only: keep these
// variables free of var(), color-mix() and 8-digit hex.
export function readCanvasColors() {
  const css = getComputedStyle(document.documentElement)
  const read = (name, fallback) => css.getPropertyValue(name).trim() || fallback
  return {
    text: read('--on-bg', '#e6edf3'),        // node label, seed border, selection ring
    dimText: read('--on-dim', '#768390'),    // edge label
    canvas: read('--bg', '#0d1117'),         // chip behind an edge label
    line: read('--graph-line', '#30363d'),   // default node border and edge
    pin: read('--graph-pin', '#fbbf24'),     // border of a pinned node
    blue: read('--graph-blue', '#58a6ff'),   // picked ring, search match, resolves_to / has_subdomain
    orange: read('--graph-orange', '#ffa657'), // co_resolves
    red: read('--error', '#f85149'),         // known_ioc
    green: read('--success', '#56d364'),     // same_ns_set
    // Coloured edges are tints: this multiplies their opacity, so a tint
    // that is quiet on the dark canvas does not vanish on the white one.
    edgeTint: parseFloat(read('--graph-edge-tint', '1')) || 1,
  }
}

// A defused node, as the toolbar toggle and the legend count it. Reads the
// per-tag flags toCyNodeData sets, which a live node_tagged event sets too. A
// seed or a node the analyst pinned stays on the canvas whatever its tags.
export const isDefused = d => !d.seed && !d.pinned && DEFUSE_TAGS.some(t => d[t])

// Cytoscape stylesheet. The label / display / colour functions read the
// toolbar toggles, the filters and the theme colours through refs, so a change
// to any of them only needs a style().update().
export function buildCyStylesheet({
  showPinsRef, showNotesRef, showEdgeLabelsRef, filterTypesRef, filterRelationsRef,
  showDefusedRef, canvasColorsRef,
}) {
  const canvas = key => () => canvasColorsRef.current[key]
  // A relation's colour applies to its line and its arrow; line-opacity
  // covers both (Cytoscape has no opacity of its own for arrows, and rejects
  // a colour with an alpha channel).
  const tinted = (key, opacity, extra) => ({
    'line-color': canvas(key),
    'target-arrow-color': canvas(key),
    'line-opacity': () => Math.min(1, opacity * canvasColorsRef.current.edgeTint),
    ...extra,
  })
  return [
    {
      selector: 'node',
      style: {
        'background-color': ele => NODE_COLORS[ele.data('type')] || '#8b949e',
        'shape': ele => NODE_SHAPES[ele.data('type')] || 'ellipse',
        // Node label is composed live so the pin / note toolbar
        // toggles take effect without re-ingesting the graph:
        //   📌  if pinned and showPins is on
        //   <truncated value>
        //   · <user_note> if note exists and showNotes is on
        'label': ele => {
          const d = ele.data()
          const base = d.label || ''
          const pinned = d.pinned && showPinsRef.current ? '📌 ' : ''
          const note = (d.metadata?.user_note && showNotesRef.current)
            ? `\n· ${d.metadata.user_note}`
            : ''
          return pinned + base + note
        },
        'text-wrap': 'wrap',
        'color': canvas('text'),
        'font-size': 10,
        'text-valign': 'bottom',
        'text-margin-y': 5,
        'width': ele => ele.data('type') === 'report' ? 38 : 22,
        'height': ele => ele.data('type') === 'report' ? 38 : 22,
        'border-width': 2,
        'border-color': canvas('line'),
        // The one place that decides whether a node is drawn: its type chip
        // is off, or it is defused while the toolbar hides defused nodes.
        // Cytoscape does not draw the edges of a node that is not displayed,
        // so the edge rule below only carries the relation filter.
        'display': ele => (filterTypesRef.current.has(ele.data('type'))
          || (!showDefusedRef.current && isDefused(ele.data()))) ? 'none' : 'element',
      }
    },
    {
      selector: 'node[?seed]',
      style: { 'width': 32, 'height': 32, 'border-width': 3, 'border-color': canvas('text'), 'font-weight': 'bold' }
    },
    // Context-pool material: an unratified claim from the agent's prior
    // knowledge or from open-web text. Rendered dashed + translucent so it
    // is never mistaken on the canvas for an observed indicator. A lead that
    // gets corroborated is re-tagged and picked up by the rule below.
    {
      selector: 'node[leadState = "unverified"], node[leadState = "unverifiable"]',
      style: {
        'border-style': 'dashed',
        'border-color': '#9a8cb8',
        'border-width': 2,
        'opacity': 0.72,
      }
    },
    {
      selector: 'node[leadState = "corroborated"]',
      style: { 'border-style': 'solid', 'border-color': '#56d364', 'opacity': 1 }
    },
    {
      selector: 'node[leadState = "refuted"]',
      style: {
        'border-style': 'dotted',
        'border-color': '#f85149',
        'opacity': 0.4,
      }
    },
    // Analyst-pinned nodes: a thicker gold border, plus an emoji prefix in
    // the label (turned on/off via showPinsRef).
    {
      selector: 'node[?pinned]',
      style: { 'border-color': canvas('pin'), 'border-width': 4 },
    },
    {
      selector: 'node[?suspicious]',
      style: { 'border-color': '#f85149', 'border-width': 3 }
    },
    {
      selector: 'node[?phishing]',
      style: { 'border-color': '#f85149', 'border-width': 3 }
    },
    {
      selector: 'node[?cdn]',
      style: { 'border-color': '#1f6feb', 'border-width': 3, 'border-style': 'dashed' }
    },
    {
      selector: 'node[?parking]',
      style: { 'border-color': '#8b949e', 'border-style': 'dashed', 'opacity': 0.6 }
    },
    {
      selector: 'node[?sinkhole]',
      style: { 'border-color': '#f85149', 'border-style': 'dashed', 'opacity': 0.5 }
    },
    {
      selector: 'node[type="report"]',
      style: {
        'width': 34, 'height': 34,
        'shape': 'concave-hexagon',
        'background-color': '#f5a623',
        'border-color': '#d48806',
        'border-width': 2,
        'font-weight': 'bold',
        'font-size': 10,
      }
    },
    {
      selector: 'node[type="report"][value="investigation_summary"]',
      style: {
        'shape': 'star',
        'width': 46, 'height': 46,
        'background-color': '#f0a500',
        'border-color': '#c87800',
        'border-width': 3,
        'font-size': 11,
        'font-weight': 'bold',
      }
    },
    // The three rules below mark what the analyst is doing with a node, and
    // leave its border alone: the border keeps saying what the node is (seed,
    // tag, lead state, pinned). A search match sits on a flat backdrop; the
    // node shown in the right panel and the nodes picked for a copy or a
    // prompt get a ring outside the border, in the text colour and in blue.
    {
      selector: 'node.search-match',
      style: {
        'underlay-color': canvas('blue'),
        'underlay-opacity': 0.35,
        'underlay-padding': 6,
        'underlay-shape': 'ellipse',
      }
    },
    {
      selector: 'node.search-dim',
      style: { 'opacity': 0.25 }
    },
    {
      selector: 'node:selected',
      style: { 'outline-color': canvas('text'), 'outline-width': 3, 'outline-offset': 2 }
    },
    {
      selector: 'node.picked',
      style: { 'outline-color': canvas('blue'), 'outline-width': 3, 'outline-offset': 2 }
    },
    {
      selector: 'edge',
      style: {
        'width': 1.5,
        'line-color': canvas('line'),
        'target-arrow-color': canvas('line'),
        'target-arrow-shape': 'triangle',
        'curve-style': 'bezier',
        'label': ele => showEdgeLabelsRef.current ? (ele.data('relation') || '') : '',
        'font-size': 8,
        'color': canvas('dimText'),
        'text-rotation': 'autorotate',
        'text-background-color': canvas('canvas'),
        'text-background-opacity': 1,
        'text-background-padding': 2,
        // Per-relation visibility toggle (Quentin's request: hide
        // historical / co_resolves links to declutter dense graphs).
        'display': ele => filterRelationsRef.current.has(ele.data('relation')) ? 'none' : 'element',
      }
    },
    { selector: 'edge[relation="resolves_to"]', style: tinted('blue', 0.4) },
    { selector: 'edge[relation="co_resolves"]', style: tinted('orange', 0.4) },
    { selector: 'edge[relation="has_subdomain"]', style: tinted('blue', 0.27, { 'line-style': 'dashed' }) },
    { selector: 'edge[relation="known_ioc"]', style: tinted('red', 0.53, { 'width': 2 }) },
    { selector: 'edge[relation="same_ns_set"]', style: tinted('green', 0.4, { 'width': 2 }) },
  ]
}

export const INITIAL_LAYOUT = {
  name: 'cose-bilkent',
  animate: false,
  nodeRepulsion: 12000,
  idealEdgeLength: 140,
  edgeElasticity: 0.45,
  gravity: 0.15,
  gravityRangeCompound: 1.2,
  nestingFactor: 0.1,
  numIter: 2500,
  tile: true,
  randomize: true,
  nodeDimensionsIncludeLabels: true,
}

// Incremental relayout while nodes stream in: keeps current positions.
export const RELAYOUT_OPTIONS = {
  name: 'cose-bilkent',
  animate: true,
  animationDuration: 500,
  randomize: false,
  nodeRepulsion: 12000,
  idealEdgeLength: 140,
  edgeElasticity: 0.45,
  gravity: 0.15,
  gravityRangeCompound: 1.2,
  nestingFactor: 0.1,
  numIter: 2500,
  tile: true,
  nodeDimensionsIncludeLabels: true,
}

// Hard relayout (used by toolbar): always randomize so a stuck "line" graph
// breaks out of its bad local minimum.
export const HARD_RELAYOUT_OPTIONS = {
  name: 'cose-bilkent',
  animate: true,
  animationDuration: 600,
  randomize: true,
  nodeRepulsion: 14000,
  idealEdgeLength: 160,
  edgeElasticity: 0.45,
  gravity: 0.1,
  numIter: 4000,
  tile: true,
  nodeDimensionsIncludeLabels: true,
}

// The agent emits two flavours of internal "report" node that aren't
// meant for the graph canvas: working_hypothesis (phase-1.5 category
// commit) and budget_extension_<N> (R4 audit log). Both have useful
// metadata, but rendering them as separate graph nodes clutters the
// layout — they belong in the Report side-panel.
export const isAuxReportNode = (n) => {
  if (!n || n.type !== 'report') return false
  const v = String(n.value || '').toLowerCase()
  return v === 'working_hypothesis' || v.startsWith('working_hypothesis')
      || v.startsWith('budget_extension')
      || v === 'lessons_learned'
}

// Cytoscape data object for a graph node (label, tag flags, lead state).
export function toCyNodeData(n) {
  // For hash nodes, prefer a human-readable filename for the label;
  // a raw sha256 truncated to 28 chars is useless. Fall back to a short
  // hash prefix when no filename is available.
  const displayValue = (() => {
    if (n.type === 'hash') {
      const md = n.metadata || {}
      const name = md.file_name
        || (Array.isArray(md.names) && md.names[0])
        || (Array.isArray(md.file_names) && md.file_names[0])
        || md.meaningful_name
      if (name) return String(name)
      return n.value.slice(0, 10) + '…'
    }
    if (n.type === 'command_line') {
      // value is a 16-char sha256 prefix — useless as a label. Prefer
      // metadata.preview (first line up to 80 chars) so the analyst sees
      // what the snippet actually starts with on the graph.
      const md = n.metadata || {}
      const p = md.preview || md.file_name
      if (p) return String(p)
      return n.value.slice(0, 10) + '…'
    }
    return n.value
  })()
  const label = n.type === 'report' && n.value === 'investigation_summary'
    ? 'Investigation Summary'
    : (displayValue.length > 30 ? displayValue.slice(0, 28) + '…' : displayValue)
  const d = {
    id: n.id, type: n.type, label, value: n.value,
    metadata: n.metadata, tags: n.tags, source: n.source, confidence: n.confidence,
    created_at: n.created_at
  }
  // Boolean flags driven by tag presence — each MUST be set explicitly
  // (true OR false) on every update, otherwise an "unpin" or "untag"
  // leaves the previous true value lingering in cytoscape's data merge.
  const FLAG_TAGS = ['pinned', 'suspicious', 'phishing', 'seed', ...DEFUSE_TAGS]
  const tagSet = new Set(n.tags || [])
  FLAG_TAGS.forEach(t => { d[t] = tagSet.has(t) })
  // Context-pool lifecycle, flattened to a single data field so the cytoscape
  // stylesheet can select on it (cytoscape selectors can't test array
  // membership, and this codebase doesn't use classes). Always set explicitly
  // so a corroborated lead loses its dashed styling on re-ingest.
  d.leadState = LEAD_STATES.find(s => tagSet.has(s)) || ''
  return d
}
