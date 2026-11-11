import React from 'react'
import StaticAnalysis from './StaticAnalysis.jsx'
import NodeProvenance from './NodeProvenance.jsx'
import { NODE_COLORS, PIVOTABLE } from '../lib/constants.js'
import { evidenceSource } from '../lib/provenance.js'
import CopyLabel from './CopyLabel.jsx'

export default function NodeTab({ selected, activeInv, note, evidence, crossInv, ties, copied, actions }) {
  const { noteDraft, setNoteDraft, noteBusy, saveNote } = note
  const { evidenceData, setEvidenceData, evidenceLoading, setEvidenceLoading } = evidence
  const { crossInvHits, crossInvLoading } = crossInv
  const { togglePin, pivotHere, pivot, copyNodeJson, copyText, openInv, focusNode } = actions
  // Evidence is loaded on demand and belongs to one node: both the answers and
  // the "loading" flag carry the node id, so walking to a neighbour from the
  // provenance never shows the previous node's answers under the new one.
  const nodeEvidence = selected && evidenceData?.nodeId === selected.id ? evidenceData : null
  const loadEvidence = async () => {
    const nodeId = selected.id
    setEvidenceLoading(nodeId)
    setEvidenceData(null)
    let items = null
    try {
      const r = await fetch(`/api/investigations/${activeInv}/nodes/${nodeId}/evidence`)
      if (r.ok) items = (await r.json()).evidence || []
    } catch (_) { /* reported below as a failed load */ }
    setEvidenceData({ nodeId, items })
    setEvidenceLoading(cur => (cur === nodeId ? false : cur))
  }
  return (
    <>
      {!selected && (
        <p className="hint">Click a node in the graph to inspect it.</p>
      )}
      {selected && (
        <>
          <div className="node-header">
            <span
              className="type-badge type-ink"
              style={{
                '--type': NODE_COLORS[selected.type] || '#8b949e',
                background: (NODE_COLORS[selected.type] || '#8b949e') + '2a',
                borderColor: NODE_COLORS[selected.type] || '#8b949e',
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

          {/* Annotation row — Pin toggle + free-text note. Lives at the
              top of the Node tab so it's the first thing analysts see
              when triaging a node. Pin marks the node visually on the
              graph (gold halo); note becomes a small badge under it. */}
          {selected.type !== 'report' && (
            <div className="annot-row">
              <button
                className={`btn-sm annot-pin${(selected.tags || []).includes('pinned') ? ' on' : ''}`}
                onClick={() => togglePin(selected)}
                title={(selected.tags || []).includes('pinned')
                  ? 'Unpin this node'
                  : 'Pin this node — highlights it on the graph for quick triage'}
              >
                {(selected.tags || []).includes('pinned') ? '📌 Pinned' : '📌 Pin'}
              </button>
              <input
                className="annot-note-input"
                value={noteDraft}
                onChange={e => setNoteDraft(e.target.value)}
                onBlur={() => {
                  const current = (selected.metadata?.user_note) || ''
                  if (current !== noteDraft) saveNote()
                }}
                onKeyDown={e => {
                  if (e.key === 'Enter') { e.preventDefault(); saveNote(); e.target.blur() }
                  if (e.key === 'Escape') { setNoteDraft((selected.metadata?.user_note) || ''); e.target.blur() }
                }}
                placeholder="Note (ex. VPN, C2, sinkhole)…"
                maxLength={120}
                disabled={noteBusy}
              />
              {noteDraft && (
                <button
                  className="btn-sm secondary annot-clear"
                  onClick={() => { setNoteDraft(''); saveNote() }}
                  title="Clear note"
                >✕</button>
              )}
            </div>
          )}

          {/* Cross-investigation convergence — repeat infrastructure
              across the user's prior investigations. High signal:
              if the same JARM / registrant email / C2 IP shows up
              in several past campaigns, it's almost certainly the
              same actor cluster. */}
          {selected.type !== 'report' && (
            <div className="cross-inv-panel">
              {crossInvLoading && (
                <div className="cross-inv-loading">Checking prior investigations…</div>
              )}
              {!crossInvLoading && crossInvHits && crossInvHits.length === 0 && (
                <div className="cross-inv-empty">
                  <span style={{ color: 'var(--on-dim)', fontSize: 10 }}>
                    First time this IOC appears in your investigation history.
                  </span>
                </div>
              )}
              {!crossInvLoading && crossInvHits && crossInvHits.length > 0 && (
                <div className="cross-inv-block">
                  <div className="cross-inv-header">
                    <span className="cross-inv-icon">↺</span>
                    <span className="cross-inv-title">
                      Also seen in {crossInvHits.length} prior investigation{crossInvHits.length !== 1 ? 's' : ''}
                    </span>
                  </div>
                  <div className="cross-inv-list">
                    {crossInvHits.slice(0, 6).map(h => (
                      <button
                        key={h.investigation_id}
                        className="cross-inv-item"
                        onClick={() => openInv(h.investigation_id)}
                        title={`Open this prior investigation (started ${new Date((h.investigation_created_at || 0) * 1000).toLocaleString()})`}
                      >
                        <span className="cross-inv-seed-type">{h.seed_type}</span>
                        <span className="cross-inv-seed-value">
                          {h.title || h.seed_value}
                        </span>
                        {h.node_tags && h.node_tags.length > 0 && (
                          <span className="cross-inv-tags">
                            {h.node_tags.slice(0, 3).map(t => (
                              <span key={t} className={`tag-chip tag-${t}`} style={{ fontSize: 9, padding: '0 4px' }}>{t}</span>
                            ))}
                          </span>
                        )}
                      </button>
                    ))}
                    {crossInvHits.length > 6 && (
                      <div className="cross-inv-more">
                        + {crossInvHits.length - 6} more
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}

          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
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
              <CopyLabel done={copied === 'node-json'}>↓ Copy JSON</CopyLabel>
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


          {/* Provenance: where the node came from, the edges that tie it to
              the graph, then (on demand) what the sources answered. The
              sources named at the top used to be the "Seen by" chips. */}
          <NodeProvenance key={selected.id} node={selected} ties={ties} onOpenNode={focusNode} />

          {activeInv && selected.type !== 'report' && (
            <div className="prov">
              <p>
                <b>Evidence (raw data)</b> is what the sources answered about this exact
                value, as kept in the cache.
                <button
                  type="button"
                  className="btn-sm secondary prov-load"
                  onClick={loadEvidence}
                  disabled={evidenceLoading === selected.id}
                >
                  {evidenceLoading === selected.id ? 'Loading…' : 'Load'}
                </button>
              </p>
              {nodeEvidence && nodeEvidence.items === null && (
                <p>The cached answers could not be loaded.</p>
              )}
              {nodeEvidence && nodeEvidence.items && nodeEvidence.items.length === 0 && (
                <p>
                  No cached answer is about this exact value. An answer to a wider
                  question (a parent domain, a search) is filed under that question.
                </p>
              )}
              {nodeEvidence && nodeEvidence.items && nodeEvidence.items.length > 0 && (
                <>
                  <p>
                    {nodeEvidence.items.length} cached answer{nodeEvidence.items.length === 1 ? '' : 's'}, oldest first.
                  </p>
                  <div className="evidence-list">
                    {nodeEvidence.items.map((ev, i) => {
                      const sourceLabel = evidenceSource(ev.cache_key)
                      return (
                        <details key={i} className="evidence-entry">
                          <summary className="evidence-summary" title={ev.cache_key}>
                            <b>{sourceLabel.length > 40 ? sourceLabel.slice(0, 38) + '…' : sourceLabel}</b>
                            <span className="evidence-date">
                              {ev.cached_at ? `cached ${new Date(ev.cached_at * 1000).toLocaleString()}` : ''}
                            </span>
                          </summary>
                          <pre className="meta-pre" style={{ maxHeight: 300, overflow: 'auto' }}>
                            {JSON.stringify(ev.data, null, 2)}
                          </pre>
                        </details>
                      )
                    })}
                  </div>
                </>
              )}
            </div>
          )}

          {selected.type === 'hash' && selected.metadata?.static_analysis && (
            <StaticAnalysis sa={selected.metadata.static_analysis} />
          )}

          <div>
            <div className="section-label" style={{ margin: '8px 0 6px' }}>Metadata</div>
            <pre className="meta-pre">{JSON.stringify(selected.metadata, null, 2)}</pre>
          </div>

        </>
      )}
    </>
  )
}
