import React from 'react'
import { NODE_COLORS } from '../lib/constants.js'

// Unified timeline: graph nodes by creation time, interleaved with the
// agent's reasoning, tool calls and node modifications.
export default function TimelineTab({ cyRef, agentNotes, selected, focusNode, expandedReasoning, setExpandedReasoning }) {
  return (
    <>
      <div className="section-label" style={{ margin: '0 0 8px' }}>Investigation Timeline</div>
      {(() => {
        const cy = cyRef.current
        if (!cy) return <p className="hint">No graph loaded.</p>
        // Build unified timeline: nodes + agent notes
        const entries = []
        cy.nodes().forEach(n => {
          const d = n.data()
          if (d.type === 'report') return
          const md = d.metadata || {}
          entries.push({
            _kind: 'node', ts: d.created_at || 0,
            id: d.id, type: d.type, value: d.value,
            first_seen: md.first_seen || md.first_submission_date || md.creation_date || null,
            sources_seen: md.sources_seen || [],
            tags: d.tags || [],
          })
        })
        // Merge agent notes (reasoning + tool calls + modifications)
        for (const note of agentNotes) {
          entries.push({
            _kind: note.noteKind, ts: note.ts,
            text: note.text, detail: note.detail || null,
            nodeId: note.nodeId || null,
            nodeType: note.nodeType || null,
          })
        }
        entries.sort((a, b) => (a.ts || 0) - (b.ts || 0))
        // Collapse consecutive tool calls into groups
        const merged = []
        for (const e of entries) {
          if (e._kind === 'tool') {
            const prev = merged[merged.length - 1]
            if (prev && prev._kind === 'tools') {
              prev.tools.push(e)
            } else {
              merged.push({ _kind: 'tools', ts: e.ts, tools: [e] })
            }
          } else {
            merged.push(e)
          }
        }
        if (merged.length === 0) return <p className="hint">No nodes yet.</p>
        const selectedId = selected?.id
        return (
          <div className="timeline-list">
            {merged.map((tn, i) => {
              const tsStr = tn.ts ? new Date(tn.ts * 1000).toLocaleTimeString() : '?'
              if (tn._kind === 'node') {
                const color = NODE_COLORS[tn.type] || '#8b949e'
                const isSel = tn.id === selectedId
                return (
                  <div
                    key={tn.id}
                    ref={el => { if (el && isSel) el.scrollIntoView({ behavior: 'smooth', block: 'center' }) }}
                    className={`timeline-entry${isSel ? ' selected' : ''}`}
                    onClick={() => focusNode(tn.id)}
                    title="Click to focus this node on the graph"
                  >
                    <div className="timeline-line">
                      <span className="timeline-dot" style={{ background: color }} />
                      {i < merged.length - 1 && <span className="timeline-connector" />}
                    </div>
                    <div className="timeline-content">
                      <div className="timeline-header">
                        <span className="timeline-time">{tsStr}</span>
                        <span className="timeline-type" style={{ color }}>{tn.type}</span>
                        {tn.sources_seen.length >= 2 && (
                          <span className="timeline-src-count" title={`Seen by: ${tn.sources_seen.join(', ')}`}>
                            {tn.sources_seen.length} sources
                          </span>
                        )}
                      </div>
                      <div className="timeline-value">
                        {tn.value.length > 50 ? tn.value.slice(0, 48) + '...' : tn.value}
                      </div>
                      {tn.first_seen && (
                        <div className="timeline-first-seen">
                          ext. first seen: {String(tn.first_seen).slice(0, 19)}
                        </div>
                      )}
                      {tn.tags.length > 0 && (
                        <div style={{ display: 'flex', gap: 3, flexWrap: 'wrap', marginTop: 2 }}>
                          {tn.tags.slice(0, 4).map(t => (
                            <span key={t} className={`tag-chip tag-${t}`} style={{ fontSize: 9, padding: '0 4px' }}>{t}</span>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                )
              }
              if (tn._kind === 'reasoning') {
                const isExp = expandedReasoning.has(i)
                return (
                  <div key={`note-${i}`} className="timeline-entry timeline-note">
                    <div className="timeline-line">
                      <span className="timeline-dot timeline-dot-note" />
                      {i < merged.length - 1 && <span className="timeline-connector" />}
                    </div>
                    <div className="timeline-content">
                      <div
                        className={`timeline-note-text${isExp ? ' expanded' : ''}`}
                        title={isExp ? 'Click to collapse' : 'Click to expand full reasoning'}
                        onClick={() => setExpandedReasoning(prev => {
                          const next = new Set(prev)
                          if (next.has(i)) next.delete(i); else next.add(i)
                          return next
                        })}
                      >{tn.text}</div>
                    </div>
                  </div>
                )
              }
              if (tn._kind === 'tools') {
                return (
                  <div key={`tools-${i}`} className="timeline-entry timeline-tool-group">
                    <div className="timeline-line">
                      <span className="timeline-dot timeline-dot-tool" />
                      {i < merged.length - 1 && <span className="timeline-connector" />}
                    </div>
                    <div className="timeline-content">
                      <div className="timeline-header">
                        <span className="timeline-time">{tsStr}</span>
                      </div>
                      <div className="timeline-tools">
                        {tn.tools.map((t, j) => (
                          <span key={j} className="timeline-tool-chip" title={t.detail || ''}>
                            {t.text}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                )
              }
              // Modification entries: node updates, tag changes, report updates.
              if (tn._kind === 'node_updated' || tn._kind === 'node_tagged' || tn._kind === 'report_updated') {
                const isReport = tn._kind === 'report_updated'
                const color = isReport
                  ? '#f5a623'
                  : (NODE_COLORS[tn.nodeType] || '#79c0ff')
                const label = tn._kind === 'report_updated'
                  ? '✎ report updated'
                  : tn._kind === 'node_tagged'
                    ? '+ tag'
                    : '✎ updated'
                return (
                  <div
                    key={`mod-${i}`}
                    className={`timeline-entry timeline-mod${tn.nodeId ? ' clickable' : ''}`}
                    onClick={tn.nodeId ? () => focusNode(tn.nodeId) : undefined}
                    title={tn.nodeId ? 'Click to focus this node' : undefined}
                  >
                    <div className="timeline-line">
                      <span className="timeline-dot timeline-dot-mod" style={{ background: color }} />
                      {i < merged.length - 1 && <span className="timeline-connector" />}
                    </div>
                    <div className="timeline-content">
                      <div className="timeline-header">
                        <span className="timeline-time">{tsStr}</span>
                        <span className="timeline-mod-label" style={{ color }}>{label}</span>
                        {tn.nodeType && tn._kind !== 'report_updated' && (
                          <span className="timeline-type" style={{ color }}>{tn.nodeType}</span>
                        )}
                      </div>
                      <div className="timeline-value">
                        {tn.text && tn.text.length > 60 ? tn.text.slice(0, 58) + '…' : tn.text}
                      </div>
                    </div>
                  </div>
                )
              }
              return null
            })}
          </div>
        )
      })()}
    </>
  )
}
