import React, { useEffect, useRef, useState } from 'react'
import cytoscape from 'cytoscape'
import coseBilkent from 'cytoscape-cose-bilkent'

cytoscape.use(coseBilkent)

const NODE_COLORS = {
  domain: '#79c0ff', ip: '#ffa657', hash: '#d2a8ff', url: '#56d364',
  cert: '#3fb950', asn: '#e3b341', email: '#f78166', registrar: '#8b949e',
  ns: '#58a6ff', favicon: '#e3b341', jarm: '#bc8cff', report: '#f5a623',
  country: '#ff7b72',
}
const NODE_SHAPES = {
  domain: 'ellipse', ip: 'rectangle', ns: 'diamond', registrar: 'hexagon',
  cert: 'round-rectangle', asn: 'barrel', hash: 'triangle', report: 'concave-hexagon',
  jarm: 'pentagon', url: 'cut-rectangle', country: 'tag',
}

function iocString(v) {
  if (v == null) return ''
  if (typeof v === 'string') return v
  if (typeof v === 'object' && typeof v.value === 'string') return v.value
  return String(v)
}

// Read-only viewer for a shared investigation. Loads /api/share/<token>
// (no auth required), renders the graph with cytoscape, surfaces the report
// + timeline (only sections the share permits), and offers an Import button
// that clones the graph into the recipient's account when they're logged in.
export default function SharedView({ token }) {
  const [data, setData] = useState(null)
  const [err, setErr] = useState('')
  const [me, setMe] = useState(undefined) // undefined = unknown, null = anon, obj = user
  const [selected, setSelected] = useState(null)
  const [tab, setTab] = useState('report')
  const [importBusy, setImportBusy] = useState(false)
  const [panelOpen, setPanelOpen] = useState(true)
  // Target picker for the import action. '' = create a new investigation,
  // otherwise the analyst's existing investigation id we should merge into.
  const [importTarget, setImportTarget] = useState('')
  const [myInvs, setMyInvs] = useState([])
  const cyRef = useRef(null)
  const containerRef = useRef(null)

  // Fetch share + auth status in parallel. When authed, also pull the
  // recipient's investigations so we can offer 'merge into existing' as an
  // import target — fixes the duplicate-IOC-no-edges problem you get when
  // the receiver already has overlapping nodes in another graph.
  useEffect(() => {
    let cancel = false
    Promise.all([
      fetch(`/api/share/${encodeURIComponent(token)}`).then(r => r.ok ? r.json() : Promise.reject(r.status)),
      fetch('/api/auth/me', { credentials: 'same-origin' }).then(r => r.ok ? r.json() : null).catch(() => null),
    ]).then(([share, who]) => {
      if (cancel) return
      setData(share)
      setMe(who || null)
      if (who) {
        fetch('/api/investigations', { credentials: 'same-origin' })
          .then(r => r.ok ? r.json() : [])
          .then(list => { if (!cancel) setMyInvs(Array.isArray(list) ? list : []) })
          .catch(() => {})
      }
    }).catch((e) => {
      if (cancel) return
      setErr(typeof e === 'number' ? `Lien introuvable, révoqué ou expiré (HTTP ${e})` : 'Erreur réseau')
    })
    return () => { cancel = true }
  }, [token])

  // Mount cytoscape once we have data.
  useEffect(() => {
    if (!data || !containerRef.current || cyRef.current) return
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
          },
        },
        {
          selector: 'node[?seed]',
          style: { 'width': 32, 'height': 32, 'border-width': 3, 'border-color': '#f0f6fc', 'font-weight': 'bold' },
        },
        {
          selector: 'node[type="report"][value="investigation_summary"]',
          style: {
            'shape': 'star', 'width': 46, 'height': 46,
            'background-color': '#f0a500', 'border-color': '#c87800', 'border-width': 3,
            'font-size': 11, 'font-weight': 'bold',
          },
        },
        {
          selector: 'node:selected',
          style: { 'border-color': '#ffffff', 'border-width': 4 },
        },
        {
          selector: 'edge',
          style: {
            'width': 1.5,
            'line-color': '#30363d',
            'target-arrow-color': '#30363d',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'label': ele => ele.data('relation') || '',
            'font-size': 8,
            'color': '#8b949e',
            'text-rotation': 'autorotate',
            'text-background-color': '#0d1117',
            'text-background-opacity': 1,
            'text-background-padding': 2,
          },
        },
      ],
      layout: {
        name: 'cose-bilkent',
        animate: false,
        randomize: true,
        nodeRepulsion: 12000,
        idealEdgeLength: 140,
        edgeElasticity: 0.45,
        gravity: 0.15,
        gravityRangeCompound: 1.2,
        nestingFactor: 0.1,
        numIter: 2500,
        tile: true,
        nodeDimensionsIncludeLabels: true,
      },
    })

    // Hydrate elements from the payload.
    const nodes = data.graph.nodes.map(n => {
      const isSeed = (n.tags || []).includes('seed')
      const isReportSummary = n.type === 'report' && n.value === 'investigation_summary'
      const displayValue = iocString(n.value)
      const label = isReportSummary
        ? 'Investigation Summary'
        : (displayValue.length > 30 ? displayValue.slice(0, 28) + '…' : displayValue)
      const d = { id: n.id, type: n.type, label, value: n.value,
        metadata: n.metadata, tags: n.tags, source: n.source, confidence: n.confidence,
        created_at: n.created_at }
      if (isSeed) d.seed = true
      return { group: 'nodes', data: d }
    })
    const edges = data.graph.edges.map(e => ({
      group: 'edges',
      data: { id: e.id, source: e.src, target: e.dst, relation: e.relation, evidence: e.evidence },
    }))
    cyRef.current.add(nodes)
    cyRef.current.add(edges)
    cyRef.current.layout({
      name: 'cose-bilkent',
      animate: false,
      randomize: true,
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

    cyRef.current.on('tap', 'node', evt => {
      const d = evt.target.data()
      setSelected(d)
      if (d.type === 'report') setTab('report')
      else setTab('node')
    })
    cyRef.current.on('tap', evt => {
      if (evt.target === cyRef.current) setSelected(null)
    })

    return () => {
      try { cyRef.current?.destroy() } catch (_) {}
      cyRef.current = null
    }
  }, [data])

  // ── Import: clone (new inv) or merge (into one of mine), then jump there ──
  const importToMyAccount = async () => {
    if (!me) {
      // Send the analyst to login, then bring them back to this share URL.
      window.location.href = `/?next=${encodeURIComponent(window.location.search)}`
      return
    }
    setImportBusy(true)
    try {
      const r = await fetch(`/api/share/${encodeURIComponent(token)}/import`, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(importTarget ? { target_inv_id: importTarget } : {}),
      })
      if (!r.ok) {
        const t = await r.text()
        alert(`Import a échoué: ${t || r.status}`)
        return
      }
      const d = await r.json()
      if (d.mode === 'merge') {
        // Friendly counters so the analyst sees what landed in their graph.
        const summary = `Merge OK — +${d.nodes_added} nouveau(x), ${d.nodes_merged} dédupliqué(s), ${d.edges_added} edge(s).`
        try { console.log(summary) } catch (_) {}
      }
      window.location.href = `/?inv=${encodeURIComponent(d.id)}`
    } finally {
      setImportBusy(false)
    }
  }

  if (err) {
    return (
      <div className="auth-screen">
        <div className="auth-card">
          <img className="logo-mark logo-mark-auth" src="/logo-512.png" alt="Bounce-CTI" />
          <div className="logo">BOUNCE<span>CTI</span></div>
          <div className="auth-label">Lien partagé</div>
          <div className="auth-error">{err}</div>
          <a href="/" className="auth-btn secondary" style={{ textAlign: 'center', textDecoration: 'none' }}>
            ← Retour à Bounce-CTI
          </a>
        </div>
      </div>
    )
  }

  if (!data) {
    return (
      <div className="auth-screen">
        <div className="auth-card">
          <div className="logo">BOUNCE<span>CTI</span></div>
          <div className="auth-label">Chargement du graphe partagé…</div>
        </div>
      </div>
    )
  }

  const inv = data.investigation
  const sections = data.share.sections
  const reportNode = data.graph.nodes.find(n => n.type === 'report' && n.value === 'investigation_summary')
  const report = reportNode?.metadata || null
  const events = data.events || []

  return (
    <div className="shared-view">
      <header className="shared-topbar">
        <div className="shared-topbar-left">
          <img className="logo-mark logo-mark-sidebar" src="/logo-256.png" alt="" />
          <div>
            <div className="shared-title">
              <span className="shared-badge">PARTAGÉ</span>
              <span className="shared-seed">
                <span className="inv-type">{inv.seed_type}</span> {inv.seed_value}
              </span>
            </div>
            <div className="shared-subtitle">
              {sections.filter(s => s !== 'graph').join(' · ')} · lecture seule
            </div>
          </div>
        </div>
        <div className="shared-topbar-right">
          <button
            className="btn-sm secondary"
            onClick={() => setPanelOpen(v => !v)}
            title="Toggle the side panel"
          >
            {panelOpen ? '▶ panneau' : '◀ panneau'}
          </button>
          {me && myInvs.length > 0 && (
            <select
              className="shared-import-target"
              value={importTarget}
              onChange={e => setImportTarget(e.target.value)}
              title="Choisir où atterrir : nouveau graphe ou merge dans une investigation existante"
              disabled={importBusy}
            >
              <option value="">↪ Nouvelle investigation</option>
              <optgroup label="Merger dans une investigation existante">
                {myInvs.map(i => (
                  <option key={i.id} value={i.id}>
                    {i.seed_value.length > 36 ? i.seed_value.slice(0, 34) + '…' : i.seed_value}
                    {' '}({i.seed_type})
                  </option>
                ))}
              </optgroup>
            </select>
          )}
          <button
            className="auth-btn shared-import-btn"
            disabled={importBusy}
            onClick={importToMyAccount}
            title={!me
              ? 'Connectez-vous pour importer ce graphe'
              : importTarget
                ? 'Fusionner ce graphe dans l\'investigation choisie (dédupe par type+valeur)'
                : 'Cloner ce graphe dans une nouvelle investigation'}
          >
            {importBusy
              ? 'Import…'
              : !me
                ? 'Se connecter pour importer'
                : importTarget
                  ? '⤵ Merger ici'
                  : '↓ Importer dans mon compte'}
          </button>
        </div>
      </header>

      <div className="shared-body">
        <div className="shared-graph">
          <div ref={containerRef} style={{ position: 'absolute', inset: 0 }} />
          <div className="legend">
            {Object.entries(NODE_COLORS).filter(([k]) => k !== 'report').map(([type, color]) => (
              <span key={type} className="legend-item">
                <span className="legend-dot" style={{ background: color }} />
                {type}
              </span>
            ))}
          </div>
        </div>

        {panelOpen && (
          <aside className="shared-panel">
            <div className="panel-tabs">
              {sections.includes('report') && (
                <button className={`panel-tab${tab === 'report' ? ' active' : ''}`} onClick={() => setTab('report')}>
                  Rapport
                </button>
              )}
              <button className={`panel-tab${tab === 'node' ? ' active' : ''}`} onClick={() => setTab('node')}>
                Nœud
              </button>
              {sections.includes('timeline') && (
                <button className={`panel-tab${tab === 'timeline' ? ' active' : ''}`} onClick={() => setTab('timeline')}>
                  Timeline
                </button>
              )}
            </div>
            <div className="panel-content">
              {tab === 'report' && (
                report ? (
                  <>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                      <span className={`threat-badge threat-${(report.threat_assessment || 'unknown').replace(/\s+/g, '_')}`}>
                        {(report.threat_assessment || 'UNKNOWN').toUpperCase()}
                      </span>
                    </div>
                    {report.summary && (
                      <div style={{ fontSize: 13, lineHeight: 1.6, color: 'var(--on-surface)' }}>
                        {iocString(report.summary)}
                      </div>
                    )}
                    {report.key_findings?.length > 0 && (
                      <div>
                        <div className="section-label" style={{ margin: '8px 0 6px' }}>Key findings</div>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                          {report.key_findings.map((f, i) => (
                            <div key={i} className="finding-card">
                              <div className="finding-text">
                                {typeof f === 'string' ? f : iocString(f.text)}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                    {report.ioc_list?.length > 0 && (
                      <div>
                        <div className="section-label" style={{ margin: '8px 0 6px' }}>IOC list</div>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                          {report.ioc_list.map((ioc, i) => (
                            <span key={i} className="ioc-chip">{iocString(ioc)}</span>
                          ))}
                        </div>
                      </div>
                    )}
                  </>
                ) : (
                  <p className="hint">Le rapport n’a pas été inclus dans ce partage.</p>
                )
              )}
              {tab === 'node' && (
                selected ? (
                  <>
                    <div className="node-header">
                      <span className="type-badge"
                        style={{
                          background: (NODE_COLORS[selected.type] || '#8b949e') + '2a',
                          borderColor: NODE_COLORS[selected.type] || '#8b949e',
                          color: NODE_COLORS[selected.type] || '#8b949e',
                        }}>
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
                    <div>
                      <div className="section-label" style={{ margin: '8px 0 6px' }}>Metadata</div>
                      <pre className="meta-pre">{JSON.stringify(selected.metadata, null, 2)}</pre>
                    </div>
                  </>
                ) : (
                  <p className="hint">Tapez un nœud du graphe pour l’inspecter.</p>
                )
              )}
              {tab === 'timeline' && (() => {
                // Distill the raw event stream into something readable:
                // - agent_assistant events become either a "reasoning" note
                //   (when the agent emits a text block) or a grouped list of
                //   tool calls (when it emits tool_use blocks). The default
                //   `evt.kind` rendering was useless — every assistant turn
                //   just said "agent_assistant".
                // - lifecycle events (start / status / exit) get friendly labels.
                const items = []
                for (const evt of events) {
                  const ts = evt._ts || 0
                  const tsStr = ts ? new Date(ts * 1000).toLocaleTimeString() : ''
                  if (evt.kind === 'agent_assistant') {
                    const content = (evt.msg || evt.data || {})?.message?.content || []
                    const texts = content.filter(b => b.type === 'text').map(b => b.text).filter(Boolean)
                    const tools = content.filter(b => b.type === 'tool_use')
                    if (texts.length) {
                      const full = texts.join(' ').trim()
                      if (full.length > 5) {
                        items.push({ kind: 'reasoning', ts, tsStr, text: full.slice(0, 300) })
                      }
                    }
                    if (tools.length) {
                      // Collapse consecutive tool batches inside the same
                      // assistant message into one timeline group.
                      const prev = items[items.length - 1]
                      const chips = tools.map(t => {
                        const short = t.name.replace(/^mcp__cti__/, '').replace(/^mcp__graph__/, '')
                        const inputStr = JSON.stringify(t.input || {}).slice(0, 120)
                        return { name: short, detail: inputStr }
                      })
                      if (prev && prev.kind === 'tools' && ts - prev.ts < 2) {
                        prev.tools.push(...chips)
                      } else {
                        items.push({ kind: 'tools', ts, tsStr, tools: chips })
                      }
                    }
                  } else if (evt.kind === 'agent_starting') {
                    items.push({ kind: 'status', ts, tsStr, label: '▶ agent démarré' })
                  } else if (evt.kind === 'agent_exit') {
                    const m = evt.msg || {}
                    const phase = m.phase || ''
                    const rc = m.rc ?? '?'
                    items.push({
                      kind: 'status', ts, tsStr,
                      label: phase ? `■ fin (${phase}) rc=${rc}` : `■ fin rc=${rc}`,
                    })
                  } else if (evt.kind === 'status_change') {
                    const m = evt.msg || {}
                    const status = (typeof m === 'string' ? m : (m.status || '')) || '?'
                    items.push({ kind: 'status', ts, tsStr, label: `● statut : ${status}` })
                  } else if (evt.kind === 'node_tagged') {
                    items.push({ kind: 'tag', ts, tsStr, label: `+ tag ${evt.tag || ''}`.trim() })
                  }
                }
                if (items.length === 0) {
                  return <p className="hint">Pas d’événement dans la timeline.</p>
                }
                return (
                  <div className="timeline-list">
                    {items.slice(0, 300).map((it, i) => {
                      const isLast = i === items.length - 1
                      if (it.kind === 'reasoning') {
                        return (
                          <div key={i} className="timeline-entry timeline-note">
                            <div className="timeline-line">
                              <span className="timeline-dot timeline-dot-note" />
                              {!isLast && <span className="timeline-connector" />}
                            </div>
                            <div className="timeline-content">
                              <div className="timeline-header">
                                <span className="timeline-time">{it.tsStr}</span>
                              </div>
                              <div className="timeline-note-text">{it.text}</div>
                            </div>
                          </div>
                        )
                      }
                      if (it.kind === 'tools') {
                        return (
                          <div key={i} className="timeline-entry timeline-tool-group">
                            <div className="timeline-line">
                              <span className="timeline-dot timeline-dot-tool" />
                              {!isLast && <span className="timeline-connector" />}
                            </div>
                            <div className="timeline-content">
                              <div className="timeline-header">
                                <span className="timeline-time">{it.tsStr}</span>
                              </div>
                              <div className="timeline-tools">
                                {it.tools.map((t, j) => (
                                  <span key={j} className="timeline-tool-chip" title={t.detail}>
                                    {t.name}
                                  </span>
                                ))}
                              </div>
                            </div>
                          </div>
                        )
                      }
                      // status / tag rows
                      return (
                        <div key={i} className="timeline-entry timeline-mod">
                          <div className="timeline-line">
                            <span className="timeline-dot timeline-dot-mod" style={{ background: '#79c0ff' }} />
                            {!isLast && <span className="timeline-connector" />}
                          </div>
                          <div className="timeline-content">
                            <div className="timeline-header">
                              <span className="timeline-time">{it.tsStr}</span>
                              <span className="timeline-mod-label">{it.label}</span>
                            </div>
                          </div>
                        </div>
                      )
                    })}
                  </div>
                )
              })()}
            </div>
          </aside>
        )}
      </div>
    </div>
  )
}
