import React, { useEffect, useRef, useState, useCallback } from 'react'
import cytoscape from 'cytoscape'
import coseBilkent from 'cytoscape-cose-bilkent'

cytoscape.use(coseBilkent)

const NODE_COLORS = {
  domain: '#79c0ff', ip: '#ffa657', hash: '#d2a8ff', url: '#56d364',
  cert: '#3fb950', asn: '#e3b341', email: '#f78166', registrar: '#8b949e',
  ns: '#58a6ff', favicon: '#e3b341', jarm: '#bc8cff', report: '#f0f6fc'
}
const NODE_SHAPES = {
  domain: 'ellipse', ip: 'rectangle', ns: 'diamond', registrar: 'hexagon',
  cert: 'round-rectangle', asn: 'barrel', hash: 'triangle', report: 'star',
  jarm: 'pentagon', url: 'cut-rectangle'
}
const STATUS_COLOR = { running: '#e3b341', done: '#56d364', cleared: '#8b949e', error: '#f85149' }

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

export default function App() {
  const [seedType, setSeedType] = useState('domain')
  const [seedValue, setSeedValue] = useState('')
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
          style: { 'width': 38, 'height': 38, 'shape': 'star', 'background-color': '#f0f6fc' }
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
      layout: { name: 'cose-bilkent', animate: false }
    })

    cyRef.current.on('tap', 'node', evt => {
      const d = evt.target.data()
      setSelected(d)
      if (d.type === 'report') {
        setReport(d.metadata)
        setRightTab('report')
      } else {
        setRightTab('node')
      }
    })
    cyRef.current.on('tap', evt => {
      if (evt.target === cyRef.current) setSelected(null)
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
  const relayout = useCallback(() => {
    const cy = cyRef.current
    if (!cy || cy.nodes().length === 0) return
    cy.layout({ name: 'cose-bilkent', animate: true, animationDuration: 400, randomize: false }).run()
  }, [])

  const addCyNode = useCallback((n) => {
    const cy = cyRef.current
    const label = n.value.length > 30 ? n.value.slice(0, 28) + '…' : n.value
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
    cyRef.current.elements().remove()

    const ws = new WebSocket(`ws://${location.host}/ws/${id}`)
    wsMap[id] = ws
    ws.onmessage = (m) => {
      const evt = JSON.parse(m.data)
      handleEvent(evt)
      const label = (() => {
        if (!evt.kind.startsWith('agent_') && !['snapshot','node_added','node_updated','edge_added','node_tagged'].includes(evt.kind)) {
          return evt.kind
        }
        const msg = evt.msg || evt.data || {}
        if (evt.kind === 'agent_starting') return '▶ agent starting'
        if (evt.kind === 'agent_exit') {
          const rc = msg.rc ?? msg?.msg?.rc ?? '?'
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
      body: JSON.stringify({ seed_type: seedType, seed_value: seedValue.trim() })
    })
    const { id } = await r.json()
    await refreshInvs()
    openInv(id)
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
    await fetch(`/api/investigations/${id}/rerun`, { method: 'POST' })
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

  const copyGraphJson = async () => {
    if (!activeInv) return
    const r = await fetch(`/api/investigations/${activeInv}/graph`)
    const data = await r.json()
    navigator.clipboard.writeText(JSON.stringify(data, null, 2))
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
  const pivot = (n) => {
    if (!['domain', 'ip', 'hash'].includes(n.type)) return
    setSeedType(n.type)
    setSeedValue(n.value)
  }

  // ── Render ────────────────────────────────────────────────────────────────
  const existingTypeList = [...existingTypes].filter(t => t !== 'report')

  return (
    <div className="app">
      {/* ── LEFT SIDEBAR ── */}
      <div className="sidebar">
        <div className="logo">BOUNCE<span>CTI</span></div>

        <div className="section-label">New investigation</div>
        <select value={seedType} onChange={e => setSeedType(e.target.value)}>
          <option value="domain">Domain</option>
          <option value="ip">IP address</option>
          <option value="hash">File hash</option>
        </select>
        <input
          value={seedValue}
          onChange={e => setSeedValue(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && start()}
          placeholder={seedType === 'domain' ? 'example.com' : seedType === 'ip' ? '1.2.3.4' : 'sha256...'}
        />
        <button onClick={start}>Investigate →</button>

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

        {/* Graph toolbar */}
        <div className="graph-toolbar">
          <button className="toolbar-btn" onClick={() => cyRef.current?.fit(undefined, 80)} title="Fit graph">
            ⊡ Fit
          </button>
          <button className="toolbar-btn" onClick={relayout} title="Re-run layout">
            ⟳ Relayout
          </button>
          <button
            className={`toolbar-btn${showEdgeLabels ? ' active' : ''}`}
            onClick={() => setShowEdgeLabels(v => !v)}
            title="Toggle edge labels"
          >
            {showEdgeLabels ? '⌗ Labels on' : '⌗ Labels off'}
          </button>
          <button className="toolbar-btn" onClick={copyGraphJson} title="Export graph as JSON">
            {copied ? '✓ copied' : '↓ Export JSON'}
          </button>
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
                  <div>
                    <span className={`threat-badge threat-${(report.threat_assessment || 'unknown').replace(/\s+/g, '_')}`}>
                      {(report.threat_assessment || 'UNKNOWN').toUpperCase()}
                    </span>
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
                    {['domain', 'ip', 'hash'].includes(selected.type) && (
                      <button
                        className="btn-sm"
                        style={{ flex: 1 }}
                        onClick={() => pivot(selected)}
                      >
                        ↳ Pivot
                      </button>
                    )}
                    <button
                      className="btn-sm secondary"
                      style={{ flex: 1 }}
                      onClick={() => copyNodeJson(selected)}
                    >
                      {copied ? '✓ copied' : '↓ Copy JSON'}
                    </button>
                  </div>

                  <div>
                    <div className="section-label" style={{ margin: '8px 0 6px' }}>Metadata</div>
                    <pre className="meta-pre">{JSON.stringify(selected.metadata, null, 2)}</pre>
                  </div>
                </>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  )
}
