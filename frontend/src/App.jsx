import React, { useEffect, useRef, useState } from 'react'
import cytoscape from 'cytoscape'
import coseBilkent from 'cytoscape-cose-bilkent'

cytoscape.use(coseBilkent)

const NODE_COLORS = {
  domain: '#58a6ff', ip: '#f0883e', hash: '#bc8cff', url: '#79c0ff',
  cert: '#56d364', asn: '#d29922', email: '#ff7b72', registrar: '#a5a5a5',
  ns: '#39c5cf', favicon: '#e3b341', jarm: '#e3b341', report: '#ffffff'
}

export default function App() {
  const [seedType, setSeedType] = useState('domain')
  const [seedValue, setSeedValue] = useState('')
  const [invs, setInvs] = useState([])
  const [activeInv, setActiveInv] = useState(null)
  const [selected, setSelected] = useState(null)
  const [events, setEvents] = useState([])
  const cyRef = useRef(null)
  const containerRef = useRef(null)

  // init cytoscape
  useEffect(() => {
    cyRef.current = cytoscape({
      container: containerRef.current,
      style: [
        { selector: 'node', style: {
          'background-color': ele => NODE_COLORS[ele.data('type')] || '#8b949e',
          'label': 'data(label)', 'color': '#e6edf3', 'font-size': 10,
          'text-valign': 'bottom', 'text-margin-y': 4, 'width': 24, 'height': 24,
          'border-width': 2, 'border-color': '#30363d'
        }},
        { selector: 'node[?cdn]', style: { 'border-color': '#1f6feb', 'border-width': 3 } },
        { selector: 'node[?suspicious]', style: { 'border-color': '#f85149', 'border-width': 3 } },
        { selector: 'node[?parking]', style: { 'border-color': '#f85149', 'border-style': 'dashed' } },
        { selector: 'node:selected', style: { 'border-color': '#ffffff', 'border-width': 4 } },
        { selector: 'edge', style: {
          'width': 1.5, 'line-color': '#30363d', 'target-arrow-color': '#30363d',
          'target-arrow-shape': 'triangle', 'curve-style': 'bezier',
          'label': 'data(relation)', 'font-size': 8, 'color': '#8b949e',
          'text-rotation': 'autorotate', 'text-background-color': '#0d1117',
          'text-background-opacity': 1, 'text-background-padding': 2
        }}
      ],
      layout: { name: 'cose-bilkent', animate: false }
    })
    cyRef.current.on('tap', 'node', evt => setSelected(evt.target.data()))
    refreshInvs()
  }, [])

  const refreshInvs = async () => {
    const r = await fetch('/api/investigations')
    setInvs(await r.json())
  }

  const start = async () => {
    if (!seedValue) return
    const r = await fetch('/api/investigations', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({seed_type: seedType, seed_value: seedValue})
    })
    const { id } = await r.json()
    await refreshInvs()
    openInv(id)
  }

  const openInv = (id) => {
    setActiveInv(id)
    setEvents([])
    cyRef.current.elements().remove()
    const ws = new WebSocket(`ws://${location.host}/ws/${id}`)
    ws.onmessage = (m) => {
      const evt = JSON.parse(m.data)
      handleEvent(evt)
      setEvents(e => [`${evt.kind}`, ...e].slice(0, 100))
    }
  }

  const handleEvent = (evt) => {
    const cy = cyRef.current
    if (evt.kind === 'snapshot') {
      evt.graph.nodes.forEach(n => addCyNode(n))
      evt.graph.edges.forEach(e => addCyEdge(e))
      cy.layout({ name: 'cose-bilkent', animate: false }).run()
    } else if (evt.kind === 'node_added' || evt.kind === 'node_updated') {
      addCyNode(evt.node)
      cy.layout({ name: 'cose-bilkent', animate: false }).run()
    } else if (evt.kind === 'edge_added') {
      addCyEdge(evt.edge)
      cy.layout({ name: 'cose-bilkent', animate: false }).run()
    } else if (evt.kind === 'node_tagged') {
      const n = cy.$id(evt.node_id)
      if (n.length) n.data(evt.tag, true)
    }
  }

  const addCyNode = (n) => {
    const cy = cyRef.current
    if (cy.$id(n.id).length) {
      cy.$id(n.id).data({ ...cy.$id(n.id).data(), ...nodeData(n) })
      return
    }
    cy.add({ group: 'nodes', data: nodeData(n) })
  }
  const nodeData = (n) => {
    const d = { id: n.id, type: n.type, label: n.value, value: n.value,
                metadata: n.metadata, tags: n.tags, source: n.source,
                confidence: n.confidence }
    ;(n.tags || []).forEach(t => d[t] = true)
    return d
  }
  const addCyEdge = (e) => {
    const cy = cyRef.current
    if (cy.$id(e.id).length) return
    if (!cy.$id(e.src).length || !cy.$id(e.dst).length) return
    cy.add({ group: 'edges', data: { id: e.id, source: e.src, target: e.dst, relation: e.relation, evidence: e.evidence }})
  }

  const pivot = (n) => {
    setSeedType(n.type)
    setSeedValue(n.value)
  }

  return (
    <div className="app">
      <div className="sidebar">
        <h1>BOUNCE-CTI</h1>
        <h2>New investigation</h2>
        <select value={seedType} onChange={e => setSeedType(e.target.value)}>
          <option value="domain">Domain</option>
          <option value="ip">IP</option>
          <option value="hash">File hash</option>
        </select>
        <input value={seedValue} onChange={e => setSeedValue(e.target.value)} placeholder="example.com" />
        <button onClick={start}>Investigate</button>
        <h2>Recent</h2>
        {invs.map(i => (
          <div key={i.id} className={`inv-item ${activeInv === i.id ? 'active' : ''}`} onClick={() => openInv(i.id)}>
            <b>{i.seed_value}</b><br/>
            <span style={{color: '#8b949e'}}>{i.seed_type} · {i.status}</span>
          </div>
        ))}
        <h2>Live events</h2>
        <div className="event-log">{events.map((e, i) => <div key={i}>{e}</div>)}</div>
      </div>
      <div className="graph"><div id="cy" ref={containerRef}></div></div>
      <div className="details">
        {!selected && <p style={{color: '#8b949e'}}>Click a node for details. Use "Pivot" to start a new investigation from it.</p>}
        {selected && (
          <>
            <h2>{selected.type}: {selected.value}</h2>
            <div>{(selected.tags || []).map(t => <span key={t} className={`tag ${t}`}>{t}</span>)}</div>
            <p><b>Source:</b> {selected.source} · <b>Confidence:</b> {selected.confidence}</p>
            <button className="secondary" onClick={() => pivot(selected)}>Pivot from this node</button>
            <h2>Metadata</h2>
            <pre>{JSON.stringify(selected.metadata, null, 2)}</pre>
          </>
        )}
      </div>
    </div>
  )
}
