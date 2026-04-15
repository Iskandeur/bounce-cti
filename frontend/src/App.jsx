import React, { useEffect, useRef, useState, useCallback } from 'react'
import Login from './Login.jsx'
import AdminPanel from './AdminPanel.jsx'
import cytoscape from 'cytoscape'
import coseBilkent from 'cytoscape-cose-bilkent'

cytoscape.use(coseBilkent)

const NODE_COLORS = {
  domain: '#79c0ff', ip: '#ffa657', hash: '#d2a8ff', url: '#56d364',
  cert: '#3fb950', asn: '#e3b341', email: '#f78166', registrar: '#8b949e',
  ns: '#58a6ff', favicon: '#e3b341', jarm: '#bc8cff', report: '#f5a623',
  country: '#ff7b72'
}
const NODE_SHAPES = {
  domain: 'ellipse', ip: 'rectangle', ns: 'diamond', registrar: 'hexagon',
  cert: 'round-rectangle', asn: 'barrel', hash: 'triangle', report: 'concave-hexagon',
  jarm: 'pentagon', url: 'cut-rectangle', country: 'tag'
}
const STATUS_COLOR = { running: '#e3b341', done: '#56d364', cleared: '#8b949e', error: '#f85149' }

// ── Maltego entity type mapping ──────────────────────────────────────────────
// Maps bounce-cti node.type -> Maltego entity type string. The paste format is
// `<maltego_entity_type>#<value>` (one per line). Falsy return = skip this type.
const MALTEGO_TYPES = {
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
  country:   () => 'maltego.Location.Country',
  report:    () => null,
}

const wsMap = {}

// ── HighlightedText ──────────────────────────────────────────────────────────
function HighlightedText({ text, nodeValues, onNodeClick }) {
  if (!text) return null
  const tokens = text.split(/(\s+)/)
  return (
    <span>
      {tokens.map((token, i) => {
        const stripped = token.replace(/^[.,;:!?()"']+|[.,;:!?()"']+$/g, '')
        const id = nodeValues.get(token) || nodeValues.get(stripped)
        if (id) {
          return (
            <span
              key={i}
              className="ioc-link"
              onClick={() => onNodeClick(id)}
            >
              {token}
            </span>
          )
        }
        return <React.Fragment key={i}>{token}</React.Fragment>
      })}
    </span>
  )
}

function MainApp({ onLogout, isAdmin, allowedModels, userId }) {
  const [seedType, setSeedType] = useState('domain')
  const [seedValue, setSeedValue] = useState('')
  const [batchMode, setBatchMode] = useState(false)
  const [batchText, setBatchText] = useState('')
  const [model, setModel] = useState('sonnet')
  const [adminOpen, setAdminOpen] = useState(false)
  useEffect(() => { /* model-coercion */
    if (allowedModels && allowedModels.length && !allowedModels.includes(model)) {
      setModel(allowedModels[0])
    }
  }, [allowedModels])
  const [invs, setInvs] = useState([])
  const [activeInv, setActiveInv] = useState(null)
  const [selected, setSelected] = useState(null)
  const [events, setEvents] = useState([])
  const [report, setReport] = useState(null)
  const [copied, setCopied] = useState(false)
  const [nodeValues, setNodeValues] = useState(new Map())
  const [filterTypes, setFilterTypes] = useState(new Set())
  const [showEdgeLabels, setShowEdgeLabels] = useState(true)
  const [rightTab, setRightTab] = useState('report')
  const [existingTypes, setExistingTypes] = useState(new Set())
  // Multi-selection for "copy / export" scope. Ctrl/Cmd/Shift + click toggles
  // a node into this set without touching the single-click details panel.
  // Empty set == "all nodes" (implicit select-all).
  const [pickedIds, setPickedIds] = useState(new Set())
  const [nodeCount, setNodeCount] = useState(0)
  const [graphSearch, setGraphSearch] = useState('')
  const [searchMatches, setSearchMatches] = useState(0)
  const [batchCombined, setBatchCombined] = useState(false)

  const cyRef = useRef(null)
  const containerRef = useRef(null)
  const activeInvRef = useRef(null)
  const showEdgeLabelsRef = useRef(showEdgeLabels)
  const filterTypesRef = useRef(filterTypes)

  useEffect(() => { activeInvRef.current = activeInv }, [activeInv])
  useEffect(() => { showEdgeLabelsRef.current = showEdgeLabels }, [showEdgeLabels])
  useEffect(() => { filterTypesRef.current = filterTypes }, [filterTypes])

  // ── Cytoscape init ───────────────────────────────────────────────────────
  useEffect(() => {
    cyRef.current = cytoscape({
      container: containerRef.current,
      style: [
        {
          selector: 'node',
          style: {
            'background-color': ele => NODE_COLORS[ele.data('type')] || '#8b949e',
            'shape': ele => NODE_SHAPES[ele.data('type')] || 'ellipse',
            'label': 'data(label)',
            'color': '#e6edf3',
            'font-size': 10,
            'text-valign': 'bottom',
            'text-margin-y': 5,
            'width': ele => ele.data('type') === 'report' ? 38 : 22,
            'height': ele => ele.data('type') === 'report' ? 38 : 22,
            'border-width': 2,
            'border-color': '#30363d',
          }
        },
        {
          selector: 'node[?seed]',
          style: { 'width': 32, 'height': 32, 'border-width': 3, 'border-color': '#f0f6fc', 'font-weight': 'bold' }
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
            'width': 38, 'height': 38,
            'shape': 'concave-hexagon',
            'background-color': '#f5a623',
            'border-color': '#d48806',
            'border-width': 3,
            'color': '#e6edf3',
            'font-weight': 'bold',
            'font-size': 11,
          }
        },
        {
          selector: 'node.search-match',
          style: {
            'border-color': '#58a6ff',
            'border-width': 4,
            'shadow-blur': 14,
            'shadow-color': '#58a6ffbb',
            'shadow-opacity': 0.9,
          }
        },
        {
          selector: 'node.search-dim',
          style: { 'opacity': 0.25 }
        },
        {
          selector: 'node:selected',
          style: {
            'border-color': '#ffffff',
            'border-width': 4,
            'shadow-blur': 18,
            'shadow-color': '#ffffff55',
            'shadow-offset-x': 0,
            'shadow-offset-y': 0,
            'shadow-opacity': 0.8
          }
        },
        {
          selector: 'node.picked',
          style: {
            'border-color': '#58a6ff',
            'border-width': 4,
            'shadow-blur': 14,
            'shadow-color': '#58a6ffaa',
            'shadow-opacity': 0.9,
          }
        },
        {
          selector: 'edge',
          style: {
            'width': 1.5,
            'line-color': '#30363d',
            'target-arrow-color': '#30363d',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'label': ele => showEdgeLabelsRef.current ? (ele.data('relation') || '') : '',
            'font-size': 8,
            'color': '#8b949e',
            'text-rotation': 'autorotate',
            'text-background-color': '#0d1117',
            'text-background-opacity': 1,
            'text-background-padding': 2,
          }
        },
        {
          selector: 'edge[relation="resolves_to"]',
          style: { 'line-color': '#58a6ff66', 'target-arrow-color': '#58a6ff66' }
        },
        {
          selector: 'edge[relation="co_resolves"]',
          style: { 'line-color': '#ffa65766', 'target-arrow-color': '#ffa65766' }
        },
        {
          selector: 'edge[relation="has_subdomain"]',
          style: { 'line-color': '#58a6ff44', 'target-arrow-color': '#58a6ff44', 'line-style': 'dashed' }
        },
        {
          selector: 'edge[relation="known_ioc"]',
          style: { 'line-color': '#f8514988', 'target-arrow-color': '#f8514988', 'width': 2 }
        },
        {
          selector: 'edge[relation="same_ns_set"]',
          style: { 'line-color': '#56d36466', 'target-arrow-color': '#56d36466', 'width': 2 }
        },
      ],
      layout: {
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
    })

    cyRef.current.on('tap', 'node', evt => {
      const d = evt.target.data()
      const oe = evt.originalEvent
      const multiKey = oe && (oe.ctrlKey || oe.metaKey || oe.shiftKey)
      if (multiKey) {
        // Multi-select toggle: don't change the details panel.
        setPickedIds(prev => {
          const next = new Set(prev)
          if (next.has(d.id)) next.delete(d.id); else next.add(d.id)
          return next
        })
        return
      }
      setSelected(d)
      if (d.type === 'report') {
        setReport(d.metadata)
        setRightTab('report')
      } else {
        setRightTab('node')
      }
    })
    cyRef.current.on('tap', evt => {
      if (evt.target === cyRef.current) {
        setSelected(null)
        // Clicking empty canvas also clears the multi-selection.
        setPickedIds(prev => (prev.size === 0 ? prev : new Set()))
      }
    })

    refreshInvs()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Update edge label visibility reactively
  useEffect(() => {
    if (!cyRef.current) return
    cyRef.current.style()
      .selector('edge')
      .style('label', ele => showEdgeLabels ? (ele.data('relation') || '') : '')
      .update()
  }, [showEdgeLabels])

  // Sync the `picked` CSS class on nodes whenever the selection set changes.
  useEffect(() => {
    const cy = cyRef.current
    if (!cy) return
    cy.nodes().forEach(n => n.toggleClass('picked', pickedIds.has(n.id())))
  }, [pickedIds])

  // Keep a reactive node count so toolbar labels (e.g. "all (N)") update live.
  useEffect(() => {
    const cy = cyRef.current
    if (!cy) return
    const update = () => setNodeCount(cy.nodes().length)
    cy.on('add remove', 'node', update)
    update()
    return () => cy.off('add remove', 'node', update)
  }, [])

  // ── focusNode ────────────────────────────────────────────────────────────
  const focusNode = useCallback((id) => {
    const cy = cyRef.current
    if (!cy) return
    const node = cy.$id(id)
    if (!node.length) return
    node.select()
    cy.animate({ fit: { eles: node.closedNeighborhood(), padding: 80 }, duration: 400 })
    setSelected(node.data())
    setRightTab('node')
  }, [])

  // ── applyFilters ─────────────────────────────────────────────────────────
  const applyFilters = useCallback((ft) => {
    const cy = cyRef.current
    if (!cy) return
    cy.nodes().forEach(n => {
      n.style('display', ft.has(n.data('type')) ? 'none' : 'element')
    })
    cy.edges().forEach(e => {
      const srcHidden = ft.has(e.source().data('type'))
      const tgtHidden = ft.has(e.target().data('type'))
      e.style('display', (srcHidden || tgtHidden) ? 'none' : 'element')
    })
  }, [])

  const toggleFilterType = (type) => {
    setFilterTypes(prev => {
      const next = new Set(prev)
      if (next.has(type)) next.delete(type); else next.add(type)
      applyFilters(next)
      return next
    })
  }

  // ── Graph helpers ────────────────────────────────────────────────────────
  const relayoutTimer = useRef(null)
  const relayout = useCallback(() => {
    const cy = cyRef.current
    if (!cy || cy.nodes().length === 0) return
    // Debounce: if many nodes are streaming in, do not run layout for every one
    if (relayoutTimer.current) clearTimeout(relayoutTimer.current)
    relayoutTimer.current = setTimeout(() => {
      cy.layout({
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
      }).run()
    }, 250)
  }, [])

  // Hard relayout (used by toolbar): always randomize so a stuck "line" graph
  // breaks out of its bad local minimum.
  const hardRelayout = useCallback(() => {
    const cy = cyRef.current
    if (!cy || cy.nodes().length === 0) return
    if (relayoutTimer.current) clearTimeout(relayoutTimer.current)
    cy.layout({
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
    }).run()
  }, [])

  const addCyNode = useCallback((n) => {
    const cy = cyRef.current
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
      return n.value
    })()
    const label = displayValue.length > 30 ? displayValue.slice(0, 28) + '…' : displayValue
    const d = {
      id: n.id, type: n.type, label, value: n.value,
      metadata: n.metadata, tags: n.tags, source: n.source, confidence: n.confidence
    }
    ;(n.tags || []).forEach(t => { d[t] = true })
    if (cy.$id(n.id).length) {
      cy.$id(n.id).data(d)
    } else {
      cy.add({ group: 'nodes', data: d })
    }
    setNodeValues(prev => new Map([...prev, [n.value, n.id]]))
    setExistingTypes(prev => new Set([...prev, n.type]))
  }, [])

  const addCyEdge = useCallback((e) => {
    const cy = cyRef.current
    if (cy.$id(e.id).length) return
    if (!cy.$id(e.src).length || !cy.$id(e.dst).length) return
    cy.add({ group: 'edges', data: { id: e.id, source: e.src, target: e.dst, relation: e.relation, evidence: e.evidence } })
  }, [])

  const handleEvent = useCallback((evt) => {
    if (evt.kind === 'snapshot') {
      evt.graph.nodes.forEach(n => addCyNode(n))
      evt.graph.edges.forEach(e => addCyEdge(e))
      relayout()
    } else if (evt.kind === 'node_added' || evt.kind === 'node_updated') {
      addCyNode(evt.node)
      relayout()
    } else if (evt.kind === 'edge_added') {
      addCyEdge(evt.edge)
      relayout()
    } else if (evt.kind === 'node_tagged') {
      const n = cyRef.current.$id(evt.node_id)
      if (n.length) n.data(evt.tag, true)
    }
  }, [addCyNode, addCyEdge, relayout])

  // ── refreshInvs ──────────────────────────────────────────────────────────
  const refreshInvs = async () => {
    const r = await fetch('/api/investigations')
    const data = await r.json()
    setInvs(data)
    return data
  }

  // ── openInv ───────────────────────────────────────────────────────────────
  const openInv = useCallback((id) => {
    Object.values(wsMap).forEach(ws => ws.close())
    Object.keys(wsMap).forEach(k => delete wsMap[k])
    setActiveInv(id)
    setSelected(null)
    setReport(null)
    setEvents([])
    setNodeValues(new Map())
    setExistingTypes(new Set())
    setFilterTypes(new Set())
    setPickedIds(new Set())
    cyRef.current.elements().remove()

    const wsProto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${wsProto}//${location.host}/ws/${id}`)
    wsMap[id] = ws
    ws.onmessage = (m) => {
      const evt = JSON.parse(m.data)
      handleEvent(evt)
      const label = (() => {
        if (!evt.kind.startsWith('agent_') && !['snapshot','node_added','node_updated','edge_added','node_tagged'].includes(evt.kind)) {
          return evt.kind
        }
        const msg = evt.msg || evt.data || {}
        if (evt.kind === 'agent_starting') {
          // Refresh sidebar so a pivot/rerun immediately shows "running"
          refreshInvs()
          return '▶ agent starting'
        }
        if (evt.kind === 'status_change') {
          // Backend flipped status (typically to "running" on pivot start)
          refreshInvs()
          return `● status: ${evt.status || '?'}`
        }
        if (evt.kind === 'agent_exit') {
          const rc = msg.rc ?? msg?.msg?.rc ?? '?'
          // Refresh sidebar status when the agent finishes
          refreshInvs()
          return `■ exit rc=${rc}`
        }
        if (evt.kind === 'agent_stderr') return `⚠ ${(msg.msg || msg || '').toString().slice(0, 80)}`
        if (evt.kind === 'agent_rate_limit_event') return '__ratelimit__'
        if (evt.kind === 'agent_assistant') {
          const content = msg?.message?.content || []
          const tool = content.find(b => b.type === 'tool_use')
          if (tool) return `__tool__${tool.name}(${JSON.stringify(tool.input || {}).slice(0, 60)})`
        }
        return null
      })()
      if (label) setEvents(e => [label, ...e].slice(0, 150))
    }
    ws.onerror = () => setEvents(e => ['__error__⚠ WS error', ...e])
  }, [handleEvent])

  // ── start ─────────────────────────────────────────────────────────────────
  const start = async () => {
    if (!seedValue.trim()) return
    const r = await fetch('/api/investigations', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ seed_type: seedType, seed_value: seedValue.trim(), model })
    })
    const { id } = await r.json()
    await refreshInvs()
    openInv(id)
  }

  // Launch a batch of investigations.
  // combined=false → one investigation per IOC (parallel).
  // combined=true  → single investigation graph with all IOCs as pivots (correlation mode).
  const startBatch = async () => {
    const items = batchText
      .split(/[\n,]+/)
      .map(s => s.trim())
      .filter(Boolean)
      .map(v => ({ seed_type: seedType, seed_value: v }))
    if (items.length === 0) return
    const r = await fetch('/api/investigations/batch', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ items, model, combined: batchCombined })
    })
    const d = await r.json()
    await refreshInvs()
    const first = (d.started || [])[0]
    if (first) openInv(first.id)
    setBatchText('')
  }

  // ── deleteInv / rerunInv ──────────────────────────────────────────────────
  const deleteInv = async (id, ev) => {
    ev.stopPropagation()
    if (!confirm('Delete this investigation?')) return
    await fetch(`/api/investigations/${id}`, { method: 'DELETE' })
    if (activeInvRef.current === id) {
      cyRef.current.elements().remove()
      setActiveInv(null)
      setSelected(null)
      setReport(null)
      setEvents([])
      setNodeValues(new Map())
      setExistingTypes(new Set())
    }
    await refreshInvs()
  }

  const rerunInv = async (id, ev) => {
    ev.stopPropagation()
    await fetch(`/api/investigations/${id}/rerun`, { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ model }) })
    await refreshInvs()
    openInv(id)
  }

  // ── copy helpers ─────────────────────────────────────────────────────────
  const copyNodeJson = (n) => {
    navigator.clipboard.writeText(JSON.stringify({
      type: n.type, value: n.value, tags: n.tags,
      source: n.source, confidence: n.confidence, metadata: n.metadata
    }, null, 2))
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  // Return the cytoscape node collection to export / copy:
  //   - if the user has explicitly picked nodes (ctrl+click), use exactly those;
  //   - otherwise, use every node currently on the graph (implicit select-all).
  const getTargetNodes = () => {
    const cy = cyRef.current
    if (!cy) return null
    return pickedIds.size > 0
      ? cy.nodes().filter(n => pickedIds.has(n.id()))
      : cy.nodes()
  }

  const copyGraphJson = () => {
    const targets = getTargetNodes()
    if (!targets || targets.length === 0) return
    const idSet = new Set(); targets.forEach(n => idSet.add(n.id()))
    const cy = cyRef.current
    const nodes = targets.map(n => {
      const d = n.data()
      return {
        id: d.id, type: d.type, value: d.value,
        tags: d.tags || [], source: d.source, confidence: d.confidence,
        metadata: d.metadata || {},
      }
    })
    // Only include edges that connect two nodes in the selection.
    const edges = cy.edges()
      .filter(e => idSet.has(e.source().id()) && idSet.has(e.target().id()))
      .map(e => ({
        id: e.id(), src: e.source().id(), dst: e.target().id(),
        relation: e.data('relation'), evidence: e.data('evidence'),
      }))
    navigator.clipboard.writeText(JSON.stringify({ nodes, edges }, null, 2))
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  // Build Maltego-paste text: one `<entity_type>#<value>` per line.
  // See https://docs.maltego.com/ (Pasting Data) for the format.
  const copyToMaltego = () => {
    const targets = getTargetNodes()
    if (!targets || targets.length === 0) return
    const lines = []
    targets.forEach(n => {
      const d = n.data()
      const mapper = MALTEGO_TYPES[d.type]
      const mtype = mapper ? mapper(d.value) : 'maltego.Phrase'
      if (!mtype) return // e.g. report
      lines.push(`${mtype}#${d.value}`)
    })
    if (lines.length === 0) return
    navigator.clipboard.writeText(lines.join('\n'))
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  // ── Event log line classifier ─────────────────────────────────────────────
  const eventClass = (e) => {
    if (e.startsWith('__tool__')) return 'event-line tool'
    if (e.startsWith('__error__')) return 'event-line error'
    if (e === '__ratelimit__') return 'event-line ratelimit'
    return 'event-line'
  }
  const eventLabel = (e) => {
    if (e.startsWith('__tool__')) return e.slice(8)
    if (e.startsWith('__error__')) return e.slice(9)
    if (e === '__ratelimit__') return '⏳ rate limit — waiting'
    return e
  }

  // ── pivot ─────────────────────────────────────────────────────────────────
  const PIVOTABLE = ['domain', 'ip', 'hash', 'url']
  const pivot = (n) => {
    if (!PIVOTABLE.includes(n.type)) return
    setBatchMode(false)
    setSeedType(n.type)
    setSeedValue(n.value)
  }

  // Pivot in-place: spawn another agent pass on the SAME investigation graph
  // (nodes/edges are merged via idempotent upserts).
  const pivotHere = async (n) => {
    if (!activeInv) return
    if (!PIVOTABLE.includes(n.type)) return
    await fetch(`/api/investigations/${activeInv}/enrich`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ seed_type: n.type, seed_value: n.value, model })
    })
    setEvents(e => [`▶ enrich pivot: ${n.type} ${n.value}`, ...e])
    refreshInvs()
  }

  // Build a markdown view of the current report for "Copy MD". Uses exact
  // IOC values so analysts can paste into a ticket / chat without losing the
  // auto-linking on the UI (IOCs will be rediscoverable via search there).
  const reportToMarkdown = (r) => {
    if (!r) return ''
    const lines = []
    lines.push(`# Investigation summary`)
    lines.push('')
    if (r.threat_assessment) lines.push(`**Threat assessment:** \`${r.threat_assessment}\``)
    if (r.summary) { lines.push(''); lines.push(r.summary) }
    if (r.key_findings?.length) {
      lines.push(''); lines.push('## Key findings')
      r.key_findings.forEach(f => {
        const text = typeof f === 'string' ? f : (f.text || '')
        const srcs = (typeof f === 'object' && Array.isArray(f.sources)) ? f.sources : []
        const srcStr = srcs.length ? `  *(${srcs.join(', ')})*` : ''
        lines.push(`- ${text}${srcStr}`)
      })
    }
    if (r.discriminating_markers?.length) {
      lines.push(''); lines.push('## Discriminating markers')
      r.discriminating_markers.forEach(m => lines.push(`- \`${m}\``))
    }
    if (r.pivot_suggestions?.length) {
      lines.push(''); lines.push('## Pivot suggestions')
      r.pivot_suggestions.forEach(p => lines.push(`- ${p}`))
    }
    if (r.ioc_list?.length) {
      lines.push(''); lines.push('## IOC list')
      r.ioc_list.forEach(i => lines.push(`- \`${i}\``))
    }
    if (r.sources_used?.length) {
      lines.push(''); lines.push(`**Sources used:** ${r.sources_used.map(s => `\`${s}\``).join(', ')}`)
    }
    return lines.join('\n')
  }

  const copyReportMarkdown = () => {
    if (!report) return
    navigator.clipboard.writeText(reportToMarkdown(report))
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  const copyText = (txt) => {
    if (!txt) return
    navigator.clipboard.writeText(String(txt))
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  // ── Graph IOC search ────────────────────────────────────────────────────
  const doGraphSearch = useCallback((q) => {
    setGraphSearch(q)
    const cy = cyRef.current
    if (!cy) return
    const lq = q.trim().toLowerCase()
    if (!lq) {
      cy.nodes().removeClass('search-match search-dim')
      setSearchMatches(0)
      return
    }
    let count = 0
    cy.nodes().forEach(n => {
      const d = n.data()
      const val = (d.value || '').toLowerCase()
      const label = (d.label || '').toLowerCase()
      const match = val.includes(lq) || label.includes(lq)
      n.toggleClass('search-match', match)
      n.toggleClass('search-dim', !match)
      if (match) count++
    })
    setSearchMatches(count)
  }, [])

  const selectAllSearchMatches = useCallback(() => {
    const cy = cyRef.current
    if (!cy) return
    const ids = new Set()
    cy.nodes('.search-match').forEach(n => ids.add(n.id()))
    if (ids.size > 0) setPickedIds(ids)
  }, [])

  const focusNextSearchMatch = useCallback(() => {
    const cy = cyRef.current
    if (!cy) return
    const matches = cy.nodes('.search-match')
    if (matches.length === 0) return
    // Find first match not currently selected, or wrap around
    const current = cy.$(':selected')
    let target = matches[0]
    if (current.length) {
      const idx = matches.indexOf(current[0])
      if (idx >= 0 && idx + 1 < matches.length) target = matches[idx + 1]
      else target = matches[0]
    }
    cy.nodes().unselect()
    target.select()
    cy.animate({ fit: { eles: target.closedNeighborhood(), padding: 80 }, duration: 300 })
    setSelected(target.data())
    setRightTab('node')
  }, [])

  // ── Render ────────────────────────────────────────────────────────────────
  const existingTypeList = [...existingTypes].filter(t => t !== 'report')

  return (
    <div className="app">
      {/* ── LEFT SIDEBAR ── */}
      <div className="sidebar">
        <div className="logo-row"><img className="logo-mark logo-mark-sidebar" src="/logo-256.png" alt="" /><div className="logo">BOUNCE<span>CTI</span></div>{isAdmin && <button className="admin-btn" title="Admin panel" onClick={() => setAdminOpen(true)}>⚙</button>}<button className="logout-btn" title="Log out" onClick={onLogout}>⎋</button></div>

        <div className="section-label">
          New investigation
          <button
            type="button"
            className={`batch-toggle${batchMode ? ' active' : ''}`}
            onClick={() => setBatchMode(v => !v)}
            title={batchMode ? 'Back to single IOC input' : 'Switch to batch mode (many IOCs at once)'}
          >
            {batchMode ? '↩ single' : '⧉ batch'}
          </button>
        </div>
        {!batchMode && (
          <>
            <select value={seedType} onChange={e => setSeedType(e.target.value)}>
              <option value="domain">Domain</option>
              <option value="ip">IP address</option>
              <option value="hash">File hash</option>
              <option value="url">URL</option>
            </select>
            <input
              value={seedValue}
              onChange={e => setSeedValue(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && start()}
              placeholder={
                seedType === 'domain' ? 'example.com' :
                seedType === 'ip'     ? '1.2.3.4' :
                seedType === 'url'    ? 'https://example.com/path' :
                                         'sha256...'
              }
            />
          </>
        )}
        {batchMode && (
          <>
            <select value={seedType} onChange={e => setSeedType(e.target.value)}>
              <option value="domain">Domain (one per line)</option>
              <option value="ip">IP address (one per line)</option>
              <option value="hash">File hash (one per line)</option>
              <option value="url">URL (one per line)</option>
            </select>
            <textarea
              className="batch-textarea"
              value={batchText}
              onChange={e => setBatchText(e.target.value)}
              placeholder={`Paste one IOC per line:\nexample.com\nbad.example.net\n…`}
              rows={6}
            />
            <label className="batch-combined-toggle" title="Combined: all IOCs on one graph (find cross-links). Separate: one investigation per IOC.">
              <input type="checkbox" checked={batchCombined} onChange={e => setBatchCombined(e.target.checked)} />
              <span>{batchCombined ? 'Combined (one graph)' : 'Separate investigations'}</span>
            </label>
          </>
        )}
        <div className="section-label">Model</div>
        <select value={model} onChange={e => setModel(e.target.value)}>
          {(!allowedModels || allowedModels.includes('sonnet')) && <option value="sonnet">Sonnet 4.6 (recommended)</option>}
          {(!allowedModels || allowedModels.includes('opus')) && <option value="opus">Opus 4.6 (smarter, slower)</option>}
          {(!allowedModels || allowedModels.includes('haiku')) && <option value="haiku">Haiku 4.5 (faster, lighter)</option>}
        </select>
        <button onClick={batchMode ? startBatch : start}>
          {batchMode ? 'Launch batch →' : 'Investigate →'}
        </button>

        <div className="section-label">History</div>
        <div className="inv-list">
          {invs.map(i => (
            <div
              key={i.id}
              className={`inv-item${activeInv === i.id ? ' active' : ''}`}
              onClick={() => openInv(i.id)}
            >
              <div className="inv-item-main">
                <span className="inv-seed">{i.seed_value}</span>
                <span className="inv-type">{i.seed_type}</span>
              </div>
              <div className="inv-item-meta">
                <span className="inv-status-dot" style={{ background: STATUS_COLOR[i.status] || '#8b949e' }} />
                <span className="inv-status-text" style={{ color: STATUS_COLOR[i.status] || '#8b949e' }}>{i.status}</span>
                {i.model && <span className="inv-model-badge">{i.model}</span>}
                <span className="inv-actions">
                  <button className="icon-btn" title="Rerun" onClick={e => rerunInv(i.id, e)}>↺</button>
                  <button className="icon-btn danger" title="Delete" onClick={e => deleteInv(i.id, e)}>✕</button>
                </span>
              </div>
            </div>
          ))}
        </div>

        <div className="section-label">Agent log</div>
        <div className="event-log">
          {events.length === 0 && <div className="event-line" style={{ color: 'var(--on-dim)' }}>No events yet</div>}
          {events.map((e, i) => (
            <div key={i} className={eventClass(e)}>{eventLabel(e)}</div>
          ))}
        </div>
      </div>

      {/* ── GRAPH ── */}
      <div className="graph">
        <div id="cy" ref={containerRef} style={{ position: 'absolute', inset: 0 }} />

        {/* IOC search bar */}
        <div className="graph-search-bar">
          <input
            className="graph-search-input"
            type="text"
            value={graphSearch}
            onChange={e => doGraphSearch(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Enter' && e.shiftKey) selectAllSearchMatches()
              else if (e.key === 'Enter') focusNextSearchMatch()
              else if (e.key === 'Escape') { doGraphSearch(''); e.target.blur() }
            }}
            placeholder="Search IOCs…"
          />
          {graphSearch && (
            <span className="graph-search-info">
              {searchMatches} match{searchMatches !== 1 ? 'es' : ''}
              {searchMatches > 0 && (
                <>
                  <button className="graph-search-action" onClick={focusNextSearchMatch} title="Focus next (Enter)">↵</button>
                  <button className="graph-search-action" onClick={selectAllSearchMatches} title="Select all matches (Shift+Enter)">☐⁺</button>
                </>
              )}
              <button className="graph-search-action" onClick={() => doGraphSearch('')} title="Clear search">✕</button>
            </span>
          )}
        </div>

        {/* Graph toolbar */}
        <div className="graph-toolbar">
          <button className="toolbar-btn" onClick={() => cyRef.current?.fit(undefined, 80)} title="Fit graph">
            ⊡ Fit
          </button>
          <button className="toolbar-btn" onClick={hardRelayout} title="Re-run layout (randomize)">
            ⟳ Relayout
          </button>
          <button
            className={`toolbar-btn${showEdgeLabels ? ' active' : ''}`}
            onClick={() => setShowEdgeLabels(v => !v)}
            title="Toggle edge labels"
          >
            {showEdgeLabels ? '⌗ Labels on' : '⌗ Labels off'}
          </button>
          <button
            className="toolbar-btn"
            onClick={copyGraphJson}
            disabled={nodeCount === 0}
            title={pickedIds.size > 0
              ? `Copy ${pickedIds.size} selected node(s) as JSON`
              : `Copy all ${nodeCount} node(s) as JSON — ctrl+click nodes to narrow`}
          >
            {copied ? '✓ copied' : `↓ JSON (${pickedIds.size > 0 ? pickedIds.size : nodeCount})`}
          </button>
          <button
            className="toolbar-btn"
            onClick={copyToMaltego}
            disabled={nodeCount === 0}
            title={pickedIds.size > 0
              ? `Copy ${pickedIds.size} selected node(s) in Maltego paste format`
              : `Copy all ${nodeCount} node(s) in Maltego paste format — ctrl+click nodes to narrow`}
          >
            {copied ? '✓ copied' : `⟶ Maltego (${pickedIds.size > 0 ? pickedIds.size : nodeCount})`}
          </button>
          {pickedIds.size > 0 && (
            <button
              className="toolbar-btn"
              onClick={() => setPickedIds(new Set())}
              title="Clear selection (back to all-nodes default)"
            >
              ✕ clear
            </button>
          )}
        </div>

        {/* Node type filter bar */}
        {existingTypeList.length > 0 && (
          <div className="filter-bar">
            {existingTypeList.map(type => {
              const active = !filterTypes.has(type)
              const color = NODE_COLORS[type] || '#8b949e'
              return (
                <button
                  key={type}
                  className="filter-chip"
                  onClick={() => toggleFilterType(type)}
                  style={active
                    ? { background: color + '33', borderColor: color, color }
                    : { background: 'transparent', borderColor: color + '66', color: color + '88' }
                  }
                >
                  {type}
                </button>
              )
            })}
          </div>
        )}

        {/* Legend */}
        <div className="legend">
          {Object.entries(NODE_COLORS).filter(([k]) => k !== 'report').map(([type, color]) => (
            <span key={type} className="legend-item">
              <span className="legend-dot" style={{ background: color }} />
              {type}
            </span>
          ))}
        </div>
      </div>

      {/* ── RIGHT PANEL ── */}
      <div className="details">
        {/* Tab bar */}
        <div className="panel-tabs">
          <button
            className={`panel-tab${rightTab === 'report' ? ' active' : ''}`}
            onClick={() => setRightTab('report')}
          >
            Report
          </button>
          <button
            className={`panel-tab${rightTab === 'node' ? ' active' : ''}`}
            onClick={() => setRightTab('node')}
          >
            Node
          </button>
        </div>

        <div className="panel-content">
          {/* ── Report tab ── */}
          {rightTab === 'report' && (
            <>
              {!report && (
                <p className="hint">Click the ★ report node for the full investigation summary.</p>
              )}
              {report && (
                <>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span className={`threat-badge threat-${(report.threat_assessment || 'unknown').replace(/\s+/g, '_')}`}>
                      {(report.threat_assessment || 'UNKNOWN').toUpperCase()}
                    </span>
                    <button
                      className="btn-sm secondary export-btn"
                      style={{ marginLeft: 'auto' }}
                      onClick={copyReportMarkdown}
                      title="Copy the full report as markdown (paste into ticket / chat)"
                    >
                      {copied ? '✓ copied' : '↓ Copy MD'}
                    </button>
                  </div>

                  {report.summary && (
                    <div style={{ fontSize: 13, lineHeight: 1.6, color: 'var(--on-surface)' }}>
                      <HighlightedText text={report.summary} nodeValues={nodeValues} onNodeClick={focusNode} />
                    </div>
                  )}

                  {report.key_findings?.length > 0 && (
                    <div>
                      <div className="section-label" style={{ margin: '8px 0 6px' }}>Key findings</div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                        {report.key_findings.map((f, i) => {
                          const text = typeof f === 'string' ? f : f.text
                          const sources = typeof f === 'object' ? (f.sources || []) : []
                          return (
                            <div key={i} className="finding-card">
                              <div className="finding-text">
                                <HighlightedText text={text} nodeValues={nodeValues} onNodeClick={focusNode} />
                              </div>
                              {sources.length > 0 && (
                                <div className="finding-sources">
                                  {sources.map((s, j) => (
                                    <span key={j} className="source-chip">{s}</span>
                                  ))}
                                </div>
                              )}
                            </div>
                          )
                        })}
                      </div>
                    </div>
                  )}

                  {report.pivot_suggestions?.length > 0 && (
                    <div>
                      <div className="section-label" style={{ margin: '8px 0 6px' }}>Pivot suggestions</div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                        {report.pivot_suggestions.map((p, i) => (
                          <div key={i} className="pivot-item">
                            <span style={{ color: 'var(--primary)', flexShrink: 0 }}>›</span>
                            <span>{p}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {report.ioc_list?.length > 0 && (
                    <div>
                      <div className="section-label" style={{ margin: '8px 0 6px' }}>IOC list</div>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                        {report.ioc_list.map((ioc, i) => {
                          const nodeId = nodeValues.get(ioc)
                          return (
                            <span
                              key={i}
                              className={`ioc-chip${nodeId ? ' clickable' : ''}`}
                              onClick={nodeId ? () => focusNode(nodeId) : undefined}
                            >
                              {ioc}
                            </span>
                          )
                        })}
                      </div>
                    </div>
                  )}

                  {report.sources_used?.length > 0 && (
                    <div>
                      <div className="section-label" style={{ margin: '8px 0 6px' }}>Sources used</div>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                        {report.sources_used.map((s, i) => (
                          <span key={i} className="source-chip">{s}</span>
                        ))}
                      </div>
                    </div>
                  )}
                </>
              )}
            </>
          )}

          {/* ── Node tab ── */}
          {rightTab === 'node' && (
            <>
              {!selected && (
                <p className="hint">Click a node in the graph to inspect it.</p>
              )}
              {selected && (
                <>
                  <div className="node-header">
                    <span
                      className="type-badge"
                      style={{
                        background: (NODE_COLORS[selected.type] || '#8b949e') + '2a',
                        borderColor: NODE_COLORS[selected.type] || '#8b949e',
                        color: NODE_COLORS[selected.type] || '#8b949e'
                      }}
                    >
                      {selected.type}
                    </span>
                    <span className="node-value">{selected.value}</span>
                  </div>

                  {(selected.tags || []).length > 0 && (
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                      {selected.tags.map(t => (
                        <span key={t} className={`tag-chip tag-${t}`}>{t}</span>
                      ))}
                    </div>
                  )}

                  <div style={{ display: 'flex', gap: 12, fontSize: 11, color: 'var(--on-dim)' }}>
                    {selected.source && <span>src: <b style={{ color: 'var(--on-surface)' }}>{selected.source}</b></span>}
                    {selected.confidence != null && (
                      <span>conf: <b style={{ color: 'var(--on-surface)' }}>{((selected.confidence || 0) * 100).toFixed(0)}%</b></span>
                    )}
                  </div>

                  <div style={{ display: 'flex', gap: 6 }}>
                    {PIVOTABLE.includes(selected.type) && (
                      <>
                        <button
                          className="btn-sm"
                          style={{ flex: 1 }}
                          onClick={() => pivotHere(selected)}
                          title="Run another agent pass on this graph from this node (enrich in place)"
                        >
                          ↳ Pivot here
                        </button>
                        <button
                          className="btn-sm secondary"
                          style={{ flex: 1 }}
                          onClick={() => pivot(selected)}
                          title="Send this IOC to the new-investigation form (creates a fresh graph)"
                        >
                          ⎘ New inv
                        </button>
                      </>
                    )}
                    <button
                      className="btn-sm secondary"
                      style={{ flex: 1 }}
                      onClick={() => copyNodeJson(selected)}
                    >
                      {copied ? '✓ copied' : '↓ Copy JSON'}
                    </button>
                  </div>

                  {/* Hash nodes: prominent filename block + copy-hash shortcut.
                      The graph label already shows file_name when present;
                      here we surface both fields explicitly so the analyst
                      can grab either one quickly. */}
                  {selected.type === 'hash' && (
                    <div className="hash-detail">
                      {(() => {
                        const md = selected.metadata || {}
                        const name = md.file_name
                          || (Array.isArray(md.names) && md.names[0])
                          || (Array.isArray(md.file_names) && md.file_names[0])
                          || md.meaningful_name
                        return name ? (
                          <div className="hash-detail-row">
                            <span className="hash-detail-label">filename</span>
                            <span className="hash-detail-value" title={String(name)}>{String(name)}</span>
                            <button
                              className="btn-sm secondary hash-copy-btn"
                              onClick={() => copyText(name)}
                              title="Copy filename"
                            >⧉</button>
                          </div>
                        ) : (
                          <div className="hash-detail-row muted">no filename in metadata</div>
                        )
                      })()}
                      <div className="hash-detail-row">
                        <span className="hash-detail-label">hash</span>
                        <span className="hash-detail-value mono" title={selected.value}>{selected.value}</span>
                        <button
                          className="btn-sm secondary hash-copy-btn"
                          onClick={() => copyText(selected.value)}
                          title="Copy hash"
                        >⧉</button>
                      </div>
                    </div>
                  )}

                  <div>
                    <div className="section-label" style={{ margin: '8px 0 6px' }}>Metadata</div>
                    <pre className="meta-pre">{JSON.stringify(selected.metadata, null, 2)}</pre>
                  </div>
                </>
              )}
            </>
          )}
        </div>
      {adminOpen && <AdminPanel onClose={() => setAdminOpen(false)} selfId={userId} />}
    </div>
    </div>
  )
}

export default function AppRoot() {
  const [authState, setAuthState] = useState('checking')
  const [me, setMe] = useState(null)
  useEffect(() => {
    fetch('/api/auth/me', { credentials: 'same-origin' })
      .then(r => r.ok ? r.json() : null)
      .then(data => { if (data) { setMe(data); setAuthState('authed') } else { setMe(null); setAuthState('needed') } })
      .catch(() => { setMe(null); setAuthState('needed') })
  }, [])
  const logout = async () => {
    try { await fetch('/api/auth/logout', { method: 'POST' }) } catch (e) { /* ignore */ }
    setMe(null)
    setAuthState('needed')
  }
  if (authState === 'checking') {
    return (
      <div className="auth-screen">
        <div className="auth-card">
          <img className="logo-mark logo-mark-auth" src="/logo-512.png" alt="Bounce-CTI" />
          <div className="logo">BOUNCE<span>CTI</span></div>
        </div>
      </div>
    )
  }
  if (authState === 'needed') {
    return <Login onAuth={() => fetch('/api/auth/me', { credentials: 'same-origin' }).then(r => r.ok ? r.json() : null).then(data => { if (data) { setMe(data); setAuthState('authed') } })} />
  }
  return <MainApp
    onLogout={logout}
    isAdmin={!!me?.is_admin}
    allowedModels={me?.allowed_models || null}
    userId={me?.user_id}
  />
}
