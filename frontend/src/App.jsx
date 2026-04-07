import React, { useEffect, useRef, useState, useCallback } from 'react'
import cytoscape from 'cytoscape'
import coseBilkent from 'cytoscape-cose-bilkent'

cytoscape.use(coseBilkent)

const NODE_COLORS = {
  domain: '#58a6ff', ip: '#f0883e', hash: '#bc8cff', url: '#79c0ff',
  cert: '#56d364', asn: '#d29922', email: '#ff7b72', registrar: '#a5a5a5',
  ns: '#39c5cf', favicon: '#e3b341', jarm: '#e3b341', report: '#f0f6fc'
}
const NODE_SHAPES = {
  domain: 'ellipse', ip: 'rectangle', ns: 'diamond', registrar: 'hexagon',
  cert: 'round-rectangle', asn: 'barrel', hash: 'triangle', report: 'star',
  jarm: 'pentagon', url: 'cut-rectangle'
}
const STATUS_COLOR = { running: '#d29922', done: '#56d364', cleared: '#8b949e' }

const wsMap = {}

export default function App() {
  const [seedType, setSeedType] = useState('domain')
  const [seedValue, setSeedValue] = useState('')
  const [invs, setInvs] = useState([])
  const [activeInv, setActiveInv] = useState(null)
  const [selected, setSelected] = useState(null)
  const [events, setEvents] = useState([])
  const [report, setReport] = useState(null)
  const [copied, setCopied] = useState(false)
  const cyRef = useRef(null)
  const containerRef = useRef(null)
  const activeInvRef = useRef(null)

  useEffect(() => { activeInvRef.current = activeInv }, [activeInv])

  useEffect(() => {
    cyRef.current = cytoscape({
      container: containerRef.current,
      style: [
        { selector: 'node', style: {
          'background-color': ele => NODE_COLORS[ele.data('type')] || '#8b949e',
          'shape': ele => NODE_SHAPES[ele.data('type')] || 'ellipse',
          'label': 'data(label)', 'color': '#e6edf3', 'font-size': 10,
          'text-valign': 'bottom', 'text-margin-y': 5,
          'width': ele => ele.data('type') === 'report' ? 36 : 22,
          'height': ele => ele.data('type') === 'report' ? 36 : 22,
          'border-width': 2, 'border-color': '#30363d'
        }},
        { selector: 'node[?seed]', style: { 'width': 32, 'height': 32, 'border-width': 3, 'border-color': '#f0f6fc', 'font-weight': 'bold' } },
        { selector: 'node[?cdn]', style: { 'border-color': '#1f6feb', 'border-width': 3, 'border-style': 'dashed' } },
        { selector: 'node[?suspicious]', style: { 'border-color': '#f85149', 'border-width': 3 } },
        { selector: 'node[?phishing]', style: { 'border-color': '#f85149', 'border-width': 3, 'background-color': '#f8514933' } },
        { selector: 'node[?parking]', style: { 'border-color': '#8b949e', 'border-style': 'dashed', 'opacity': 0.6 } },
        { selector: 'node[?sinkhole]', style: { 'border-color': '#ff7b72', 'border-style': 'dashed', 'opacity': 0.5 } },
        { selector: 'node[?shared_hosting]', style: { 'border-color': '#d29922', 'border-style': 'dashed', 'opacity': 0.7 } },
        { selector: 'node:selected', style: { 'border-color': '#ffffff', 'border-width': 4 } },
        { selector: 'edge', style: {
          'width': 1.5, 'line-color': '#30363d', 'target-arrow-color': '#30363d',
          'target-arrow-shape': 'triangle', 'curve-style': 'bezier',
          'label': 'data(relation)', 'font-size': 8, 'color': '#8b949e',
          'text-rotation': 'autorotate', 'text-background-color': '#0d1117',
          'text-background-opacity': 1, 'text-background-padding': 2
        }},
        { selector: 'edge[relation="resolves_to"]', style: { 'line-color': '#58a6ff44', 'target-arrow-color': '#58a6ff44' } },
        { selector: 'edge[relation="co_resolves"]', style: { 'line-color': '#f0883e44', 'target-arrow-color': '#f0883e44' } },
        { selector: 'edge[relation="has_subdomain"]', style: { 'line-color': '#58a6ff33', 'target-arrow-color': '#58a6ff33', 'line-style': 'dashed' } },
        { selector: 'edge[relation="known_ioc"]', style: { 'line-color': '#f8514966', 'target-arrow-color': '#f8514966', 'width': 2 } },
        { selector: 'edge[relation="same_ns_set"]', style: { 'line-color': '#56d36466', 'target-arrow-color': '#56d36466', 'width': 2 } },
      ],
      layout: { name: 'cose-bilkent', animate: false }
    })
    cyRef.current.on('tap', 'node', evt => {
      const d = evt.target.data()
      setSelected(d)
      if (d.type === 'report') setReport(d.metadata)
    })
    refreshInvs()
  }, [])

  const refreshInvs = async () => {
    const r = await fetch('/api/investigations')
    const data = await r.json()
    setInvs(data)
    return data
  }

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

  const openInv = useCallback((id) => {
    // Close previous WS
    Object.values(wsMap).forEach(ws => ws.close())
    Object.keys(wsMap).forEach(k => delete wsMap[k])
    setActiveInv(id)
    setSelected(null)
    setReport(null)
    setEvents([])
    cyRef.current.elements().remove()

    const ws = new WebSocket(`ws://${location.host}/ws/${id}`)
    wsMap[id] = ws
    ws.onmessage = (m) => {
      const evt = JSON.parse(m.data)
      handleEvent(evt)
      if (!evt.kind.startsWith('agent_')) {
        setEvents(e => [`${evt.kind}`, ...e].slice(0, 150))
      } else {
        const msg = evt.msg || evt.data || {}
        const label = (() => {
          if (evt.kind === 'agent_starting') return '▶ agent starting'
          if (evt.kind === 'agent_exit') return `■ agent exit rc=${msg.rc ?? msg?.msg?.rc ?? '?'}`
          if (evt.kind === 'agent_stderr') return `⚠ ${(msg.msg || msg || '').toString().slice(0, 80)}`
          if (evt.kind === 'agent_rate_limit_event') return '⏳ rate limit — waiting'
          if (evt.kind === 'agent_assistant') {
            const content = msg?.message?.content || []
            const tool = content.find(b => b.type === 'tool_use')
            if (tool) return `🔧 ${tool.name}(${JSON.stringify(tool.input || {}).slice(0, 60)})`
          }
          return null
        })()
        if (label) setEvents(e => [label, ...e].slice(0, 150))
      }
    }
    ws.onerror = () => setEvents(e => ['⚠ WS error', ...e])
  }, [])

  const handleEvent = (evt) => {
    const cy = cyRef.current
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
      const n = cy.$id(evt.node_id)
      if (n.length) n.data(evt.tag, true)
    }
  }

  const relayout = useCallback(() => {
    const cy = cyRef.current
    if (!cy || cy.nodes().length === 0) return
    cy.layout({ name: 'cose-bilkent', animate: true, animationDuration: 400, randomize: false }).run()
  }, [])

  const addCyNode = (n) => {
    const cy = cyRef.current
    const d = nodeData(n)
    if (cy.$id(n.id).length) { cy.$id(n.id).data(d); return }
    cy.add({ group: 'nodes', data: d })
  }
  const nodeData = (n) => {
    const label = n.value.length > 30 ? n.value.slice(0, 28) + '…' : n.value
    const d = { id: n.id, type: n.type, label, value: n.value,
      metadata: n.metadata, tags: n.tags, source: n.source, confidence: n.confidence }
    ;(n.tags || []).forEach(t => { d[t] = true })
    return d
  }
  const addCyEdge = (e) => {
    const cy = cyRef.current
    if (cy.$id(e.id).length) return
    if (!cy.$id(e.src).length || !cy.$id(e.dst).length) return
    cy.add({ group: 'edges', data: { id: e.id, source: e.src, target: e.dst, relation: e.relation, evidence: e.evidence } })
  }

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
    }
    await refreshInvs()
  }

  const rerunInv = async (id, ev) => {
    ev.stopPropagation()
    await fetch(`/api/investigations/${id}/rerun`, { method: 'POST' })
    await refreshInvs()
    openInv(id)
  }

  const pivot = (n) => {
    if (!['domain', 'ip', 'hash'].includes(n.type)) return
    setSeedType(n.type)
    setSeedValue(n.value)
  }

  const copyNodeJson = (n) => {
    const payload = {
      type: n.type,
      value: n.value,
      tags: n.tags,
      source: n.source,
      confidence: n.confidence,
      metadata: n.metadata,
    }
    navigator.clipboard.writeText(JSON.stringify(payload, null, 2))
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
            <div key={i.id} className={`inv-item ${activeInv === i.id ? 'active' : ''}`} onClick={() => openInv(i.id)}>
              <div className="inv-item-main">
                <span className="inv-seed">{i.seed_value}</span>
                <span className="inv-type">{i.seed_type}</span>
              </div>
              <div className="inv-item-meta">
                <span className="inv-status" style={{ color: STATUS_COLOR[i.status] || '#8b949e' }}>{i.status}</span>
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
          {events.length === 0 && <div className="event-empty">No events yet</div>}
          {events.map((e, i) => <div key={i} className="event-line">{e}</div>)}
        </div>
      </div>

      {/* ── GRAPH ── */}
      <div className="graph">
        <div id="cy" ref={containerRef} />
        {/* Toolbar */}
        {activeInv && (
          <div className="graph-toolbar">
            <button className="toolbar-btn" onClick={copyGraphJson} title="Copy full graph as JSON">
              {copied ? '✓ copied' : '⬇ export graph JSON'}
            </button>
            <button className="toolbar-btn" onClick={relayout} title="Re-run layout">⟳ relayout</button>
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
        {report && (
          <div className="report-box">
            <div className="report-title">Investigation Summary</div>
            <div className={`threat-badge threat-${report.threat_assessment}`}>
              {report.threat_assessment?.toUpperCase() || 'UNKNOWN'}
            </div>
            <p className="report-summary">{report.summary}</p>
            {report.key_findings?.length > 0 && (
              <>
                <div className="section-label">Key findings</div>
                <ul className="finding-list">
                  {report.key_findings.map((f, i) => <li key={i}>{f}</li>)}
                </ul>
              </>
            )}
            {report.pivot_suggestions?.length > 0 && (
              <>
                <div className="section-label">Pivot suggestions</div>
                <ul className="finding-list pivot">
                  {report.pivot_suggestions.map((f, i) => <li key={i}>{f}</li>)}
                </ul>
              </>
            )}
            {report.ioc_list?.length > 0 && (
              <>
                <div className="section-label">IOC list</div>
                <div className="ioc-list">
                  {report.ioc_list.map((ioc, i) => <span key={i} className="ioc">{ioc}</span>)}
                </div>
              </>
            )}
          </div>
        )}

        {!selected && !report && (
          <p className="hint">Click a node to inspect it.<br />Click the ★ report node for the full summary.</p>
        )}

        {selected && selected.type !== 'report' && (
          <>
            <div className="node-header">
              <span className="node-type-badge" style={{ background: NODE_COLORS[selected.type] + '33', borderColor: NODE_COLORS[selected.type] }}>
                {selected.type}
              </span>
              <span className="node-value">{selected.value}</span>
            </div>
            <div className="tag-row">
              {(selected.tags || []).map(t => <span key={t} className={`tag ${t}`}>{t}</span>)}
            </div>
            <div className="node-meta-row">
              <span>src: {selected.source}</span>
              <span>conf: {((selected.confidence || 0) * 100).toFixed(0)}%</span>
            </div>
            <div className="btn-row">
              {['domain', 'ip', 'hash'].includes(selected.type) && (
                <button onClick={() => pivot(selected)}>↳ Pivot</button>
              )}
              <button className="secondary" onClick={() => copyNodeJson(selected)}>
                {copied ? '✓ copied' : '⬇ copy JSON'}
              </button>
            </div>
            <div className="section-label" style={{ marginTop: 12 }}>Metadata</div>
            <pre>{JSON.stringify(selected.metadata, null, 2)}</pre>
          </>
        )}
      </div>
    </div>
  )
}
