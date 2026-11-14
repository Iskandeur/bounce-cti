import React from 'react'
import Icon from './Icon.jsx'
import { pressable } from '../lib/pressable.js'
import HighlightedText from './HighlightedText.jsx'
import LeadsCard from './LeadsCard.jsx'
import HypothesisCard from './HypothesisCard.jsx'
import BudgetLog from './BudgetLog.jsx'
import { iocString } from '../lib/ioc.js'
import CopyLabel from './CopyLabel.jsx'

export default function ReportTab({
  report, hypothesis, hypothesisStamp, budgetLog, leadStats, nodeCount, invs, activeInv,
  activeVertical, nodeValues, focusNode, copied, copyReportMarkdown, setShareOpen, setRightTab,
}) {
  return (
    <>
      <LeadsCard leadStats={leadStats} />
      <HypothesisCard
        hypothesis={hypothesis}
        hypothesisStamp={hypothesisStamp}
        nodeCount={nodeCount}
        report={report}
      />
      <BudgetLog budgetLog={budgetLog} />
      {!report && (
        <p className="hint">Click the ★ report node for the full investigation summary.</p>
      )}
      {report && (
        <>
          <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: 8 }}>
            <span className={`threat-badge threat-${(report.threat_assessment || 'unknown').replace(/\s+/g, '_')}`}>
              {(report.threat_assessment || 'UNKNOWN').toUpperCase()}
            </span>
            {/* The report node is upserted as soon as the agent reaches
                STEP 8 in phase 1 — phases 1.5 / 2 / 3 may still be
                running and will refine the same node in place. Surface
                a "still being refined" hint while inv.status === 'running'
                so the analyst doesn't mistake the early draft for the
                final report. */}
            {(() => {
              const inv = invs.find(i => i.id === activeInv)
              return inv && inv.status === 'running' ? (
                <span
                  className="report-refining-badge"
                  title="The agent is still running follow-up phases. The summary will be updated in place."
                >
                  <span className="report-refining-dot" /> being refined…
                </span>
              ) : null
            })()}
            <button
              className="btn-sm export-btn"
              style={{ marginLeft: 'auto' }}
              onClick={copyReportMarkdown}
              title="Copy the full report as markdown (paste into ticket / chat)"
            >
              <CopyLabel done={copied === 'report-md'}><Icon name="copy" />Copy MD</CopyLabel>
            </button>
            {activeInv && (
              <button
                className="btn-sm export-btn"
                onClick={() => window.open(`/api/investigations/${activeInv}/pdf`, '_blank')}
                title="Download a structured PDF report for sharing"
              >
                <Icon name="download" />PDF
              </button>
            )}
            {activeInv && (
              <button
                className="btn-sm export-btn"
                onClick={() => window.open(`/api/investigations/${activeInv}/stix`, '_blank')}
                title="Download STIX 2.1 bundle (JSON) for threat intel sharing"
              >
                <Icon name="download" />STIX
              </button>
            )}
            {activeInv && (
              <button
                className="btn-sm export-btn"
                onClick={() => window.open(`/api/investigations/${activeInv}/csv`, '_blank')}
                title="Download observables as STIX-flavoured CSV (ready for an OpenCTI workbench)"
              >
                <Icon name="download" />CSV
              </button>
            )}
            {activeInv && (
              <button
                className="btn-sm export-btn"
                onClick={async () => {
                  try {
                    const r = await fetch(`/api/investigations/${activeInv}/osint_dossier`,
                                          { credentials: 'same-origin' })
                    if (!r.ok) throw new Error((await r.json()).detail || `HTTP ${r.status}`)
                    const j = await r.json()
                    const blob = new Blob([j.content || ''], { type: 'text/markdown' })
                    const a = document.createElement('a')
                    a.href = URL.createObjectURL(blob)
                    a.download = j.filename || `bounce-osint-${activeInv}.dossier.md`
                    a.click()
                    URL.revokeObjectURL(a.href)
                  } catch (e) { alert('Dossier export failed: ' + (e.message || e)) }
                }}
                title="Download an OSINT identity dossier (Markdown): accounts, identifiers, connections, provenance"
              >
                <Icon name="download" />Dossier
              </button>
            )}
            {activeInv && (
              <button
                className="btn-sm export-btn"
                onClick={async () => {
                  try {
                    const r = await fetch(`/api/investigations/${activeInv}/kyb_dossier`,
                                          { credentials: 'same-origin' })
                    if (!r.ok) throw new Error((await r.json()).detail || `HTTP ${r.status}`)
                    const j = await r.json()
                    const blob = new Blob([j.content || ''], { type: 'text/markdown' })
                    const a = document.createElement('a')
                    a.href = URL.createObjectURL(blob)
                    a.download = j.filename || `bounce-kyb-${activeInv}.dossier.md`
                    a.click()
                    URL.revokeObjectURL(a.href)
                  } catch (e) { alert('KYB dossier export failed: ' + (e.message || e)) }
                }}
                title="Download a KYB / Due-Diligence dossier (Markdown): sanctions exposure, identity, corporate hierarchy, officers/PSC, provenance"
              >
                <Icon name="download" />KYB
              </button>
            )}
            {activeInv && (
              <button
                className="btn-sm export-btn btn-lead"
                onClick={() => setShareOpen(true)}
                title="Generate a share link (graph-only, with optional report/timeline/evidence/chats)"
              >
                Share
              </button>
            )}
          </div>

          {report.summary && (
            <div style={{ fontSize: 13, lineHeight: 1.6, color: 'var(--on-surface)' }}>
              <HighlightedText text={report.summary} nodeValues={nodeValues} onNodeClick={focusNode} />
            </div>
          )}

          {/* Per-seed summaries (multi-seed investigations). Each seed
              gets its own collapsible block with its own threat badge
              and findings. Falls back gracefully: when the report is
              single-seed flat, the block below doesn't render. */}
          {report.per_seed_summaries && Object.keys(report.per_seed_summaries).length > 0 && (
            <div>
              <div className="section-label" style={{ margin: '8px 0 6px' }}>Per-seed</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {Object.entries(report.per_seed_summaries).map(([seedVal, s], i) => {
                  const nodeId = nodeValues.get(seedVal)
                  const ta = (s?.threat_assessment || 'unknown').toString()
                  return (
                    <details key={i} className="per-seed-card" open>
                      <summary className="per-seed-header">
                        <span className={`threat-badge threat-${ta.replace(/\s+/g, '_')}`}>
                          {ta.toUpperCase()}
                        </span>
                        <span
                          className={`per-seed-value${nodeId ? ' clickable' : ''}`}
                          onClick={nodeId ? (e) => { e.preventDefault(); focusNode(nodeId) } : undefined}
                          title={nodeId ? 'Focus this seed on the graph' : undefined}
                        >
                          {iocString(seedVal)}
                        </span>
                        {s?.type && <span className="per-seed-type">{s.type}</span>}
                      </summary>
                      {s?.summary && (
                        <div className="per-seed-summary">
                          <HighlightedText text={s.summary} nodeValues={nodeValues} onNodeClick={focusNode} />
                        </div>
                      )}
                      {Array.isArray(s?.key_findings) && s.key_findings.length > 0 && (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginTop: 6 }}>
                          {s.key_findings.map((f, j) => {
                            const text = typeof f === 'string' ? f : iocString(f.text)
                            const srcs = typeof f === 'object' && f !== null ? (f.sources || []) : []
                            return (
                              <div key={j} className="finding-card">
                                <div className="finding-text">
                                  <HighlightedText text={text} nodeValues={nodeValues} onNodeClick={focusNode} />
                                </div>
                                {srcs.length > 0 && (
                                  <div className="finding-sources">
                                    {srcs.map((src, k) => (
                                      <span key={k} className="source-chip">{iocString(src)}</span>
                                    ))}
                                  </div>
                                )}
                              </div>
                            )
                          })}
                        </div>
                      )}
                    </details>
                  )
                })}
              </div>
            </div>
          )}

          {/* Cross-seed findings: explicit attributes shared across seeds
              (IP, NS, cert, JARM, ASN, registrant, hash). Empty array
              also means "no shared infrastructure observed" — still
              useful, but we omit the section when missing/empty to
              keep single-seed reports clean. */}
          {Array.isArray(report.cross_seed_findings) && report.cross_seed_findings.length > 0 && (
            <div>
              <div className="section-label" style={{ margin: '8px 0 6px' }}>Cross-seed links</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {report.cross_seed_findings.map((c, i) => {
                  const text = typeof c === 'string' ? c : iocString(c.text)
                  const seeds = (typeof c === 'object' && Array.isArray(c.seeds)) ? c.seeds : []
                  const sources = (typeof c === 'object' && Array.isArray(c.sources)) ? c.sources : []
                  return (
                    <div key={i} className="finding-card cross-seed-card">
                      <div className="finding-text">
                        <HighlightedText text={text} nodeValues={nodeValues} onNodeClick={focusNode} />
                      </div>
                      {seeds.length > 0 && (
                        <div className="cross-seed-seeds">
                          {seeds.map((sv, j) => {
                            const nodeId = nodeValues.get(iocString(sv))
                            return (
                              <span
                                key={j}
                                className={`ioc-chip${nodeId ? ' clickable' : ''}`}
                                {...pressable(nodeId ? () => focusNode(nodeId) : undefined)}
                              >
                                {iocString(sv)}
                              </span>
                            )
                          })}
                        </div>
                      )}
                      {sources.length > 0 && (
                        <div className="finding-sources">
                          {sources.map((src, j) => (
                            <span key={j} className="source-chip">{iocString(src)}</span>
                          ))}
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            </div>
          )}

          {report.key_findings?.length > 0 && (
            <div>
              <div className="section-label" style={{ margin: '8px 0 6px' }}>Key findings</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {report.key_findings.map((f, i) => {
                  const text = typeof f === 'string' ? f : iocString(f.text)
                  const sources = typeof f === 'object' && f !== null ? (f.sources || []) : []
                  return (
                    <div key={i} className="finding-card">
                      <div className="finding-text">
                        <HighlightedText text={text} nodeValues={nodeValues} onNodeClick={focusNode} />
                      </div>
                      {sources.length > 0 && (
                        <div className="finding-sources">
                          {sources.map((s, j) => (
                            <span key={j} className="source-chip">{iocString(s)}</span>
                          ))}
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            </div>
          )}

          {/* MITRE ATT&CK mapping — agent-validated list of
              techniques the investigation observed. Each row links
              to the technique page on attack.mitre.org. */}
          {(() => {
            const m = report.mitre_attack_mapping
            let items = []
            if (Array.isArray(m)) items = m
            else if (m && Array.isArray(m.techniques)) items = m.techniques
            if (!items || items.length === 0) return null
            return (
              <div>
                <div className="section-label" style={{ margin: '8px 0 6px' }}>MITRE ATT&CK</div>
                <div className="mitre-list">
                  {items.map((t, i) => {
                    const tid = t.technique_id || t.id || '?'
                    const name = t.technique_name || t.name || ''
                    const tactics = Array.isArray(t.tactics) ? t.tactics : (t.tactic ? [t.tactic] : [])
                    const ev = t.evidence || t.rationale || ''
                    const conf = (t.confidence || '').toLowerCase()
                    const url = `https://attack.mitre.org/techniques/${tid.replace('.', '/')}/`
                    return (
                      <div key={i} className={`mitre-item${conf ? ` mitre-${conf}` : ''}`}>
                        <a href={url} target="_blank" rel="noopener noreferrer" className="mitre-id" title="Open on attack.mitre.org">
                          {tid}
                        </a>
                        <div className="mitre-body">
                          <div className="mitre-name">
                            {name}
                            {conf && <span className="mitre-conf">{conf}</span>}
                          </div>
                          {tactics.length > 0 && (
                            <div className="mitre-tactics">
                              {tactics.map(tac => (
                                <span key={tac} className="mitre-tactic">{String(tac).replace(/_/g, ' ').replace(/-/g, ' ')}</span>
                              ))}
                            </div>
                          )}
                          {ev && <div className="mitre-ev">{String(ev)}</div>}
                        </div>
                      </div>
                    )
                  })}
                </div>
              </div>
            )
          })()}

          {report.pivot_suggestions?.length > 0 && (
            <div>
              <div className="section-label" style={{ margin: '8px 0 6px' }}>Pivot suggestions</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                {report.pivot_suggestions.map((p, i) => (
                  <div key={i} className="pivot-item">
                    <span style={{ color: 'var(--primary)', flexShrink: 0 }}>›</span>
                    <span>{iocString(p)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {report.ioc_list?.length > 0 && (
            <div>
              <div className="section-label" style={{ margin: '8px 0 6px' }}>
                {activeVertical === 'dd' ? 'Entities & identifiers'
                  : activeVertical === 'osint' ? 'Identifiers'
                  : 'IOC list'}
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                {report.ioc_list.map((ioc, i) => {
                  const label = iocString(ioc)
                  const nodeId = nodeValues.get(label)
                  return (
                    <span
                      key={i}
                      className={`ioc-chip${nodeId ? ' clickable' : ''}`}
                      {...pressable(nodeId ? () => focusNode(nodeId) : undefined)}
                    >
                      {label}
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
                  <span key={i} className="source-chip">{iocString(s)}</span>
                ))}
              </div>
            </div>
          )}

          {/* Analyst prompts moved to Chat tab */}
          {Array.isArray(report.prompt_history) && report.prompt_history.length > 0 && (
            <div>
              <div className="section-label" style={{ margin: '12px 0 6px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <span>Analyst prompts ({report.prompt_history.length})</span>
                <button className="btn-sm btn-inline" onClick={() => setRightTab('chat')}>Open Chat</button>
              </div>
            </div>
          )}
        </>
      )}
    </>
  )
}
