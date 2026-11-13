import React from 'react'
import { STATUS_COLOR } from '../lib/constants.js'
import { formatCountdown } from '../lib/format.js'

export default function InvestigationHistory({ invs, activeInv, quotaState, actions, mergePickerSrc, setMergePickerSrc }) {
  const { openInv, stopInv, resumeInv, renameInv, rerunInv, mergeInv, deleteInv } = actions
  return (
    <>
      <div className="section-label">History</div>
      <div className="inv-list">
        {invs.map(i => {
          const seedCount = (i.seeds || []).length
          const extraSeeds = seedCount > 1 ? seedCount - 1 : 0
          return (
            <div
              key={i.id}
              className={`inv-item${activeInv === i.id ? ' active' : ''}`}
              onClick={() => openInv(i.id)}
              title={seedCount > 1
                ? `Multi-seed: ${(i.seeds || []).map(s => s.value).join(', ')}`
                : undefined}
            >
              <div className="inv-item-main">
                <span
                  className={`inv-seed${i.title ? ' has-title' : ''}`}
                  title={i.title ? `${i.title} — seed: ${i.seed_value}` : i.seed_value}
                >
                  {i.title || i.seed_value}
                </span>
                {extraSeeds > 0 && (
                  <span className="inv-seed-count" title={`${seedCount} seeds in this investigation`}>
                    +{extraSeeds}
                  </span>
                )}
                <span className="inv-type">{i.seed_type}</span>
                {i.vertical === 'osint' && (
                  <span className="inv-vertical-badge" title="OSINT vertical">OSINT</span>
                )}
              </div>
              <div className="inv-item-meta">
                <span className="inv-status-dot" style={{ background: STATUS_COLOR[i.status] || 'var(--on-dim)' }} />
                <span className="inv-status-text" style={{ color: STATUS_COLOR[i.status] || 'var(--on-dim)' }}>
                  {i.status === 'quota_exceeded'
                    ? (i.quota_reset_at
                        ? `quota — ${formatCountdown(i.quota_reset_at) || 'ready'}`
                        : 'quota reached')
                    : i.status}
                </span>
                {i.model && <span className="inv-model-badge">{i.model}</span>}
                <span className="inv-actions">
                  {i.status === 'running' && (
                    <button className="icon-btn warning" title="Stop" onClick={e => stopInv(i.id, e)}>■</button>
                  )}
                  {i.status === 'quota_exceeded' && (
                    <button
                      className="icon-btn primary"
                      title={quotaState.exhausted
                        ? `Claude quota cooldown — resumes in ${formatCountdown(quotaState.exhausted_until) || 'a moment'}`
                        : 'Resume this investigation from where it stopped'}
                      disabled={quotaState.exhausted}
                      onClick={e => resumeInv(i.id, e)}
                    >▶</button>
                  )}
                  <button
                    className="icon-btn"
                    title={i.title ? `Rename (current: ${i.title})` : 'Rename'}
                    onClick={e => renameInv(i.id, i.title, i.seed_value, e)}
                  >✎</button>
                  <button className="icon-btn" title="Rerun" onClick={e => rerunInv(i.id, e)}>↺</button>
                  {/* Merge into another of my investigations. Backend dedups
                      nodes (type, value) and edges (src, dst, relation),
                      unioning metadata + tags + sources_seen. Disabled while
                      the source is still running (its graph is half-built). */}
                  <button
                    className={`icon-btn${mergePickerSrc === i.id ? ' active' : ''}`}
                    title={i.status === 'running'
                      ? 'Stop the investigation before merging'
                      : 'Merge into another investigation'}
                    disabled={i.status === 'running'}
                    onClick={e => {
                      e.stopPropagation()
                      setMergePickerSrc(prev => prev === i.id ? null : i.id)
                    }}
                  >⇆</button>
                  <button className="icon-btn danger" title="Delete" onClick={e => deleteInv(i.id, e)}>✕</button>
                </span>
              </div>
              {/* Inline target picker. Listing only other invs owned by the
                  caller (the API is owner-checked too). */}
              {mergePickerSrc === i.id && (
                <div
                  className="inv-merge-picker"
                  onClick={e => e.stopPropagation()}
                >
                  <span className="inv-merge-label">Merge into:</span>
                  <select
                    className="inv-merge-select"
                    defaultValue=""
                    onChange={e => {
                      const dst = e.target.value
                      if (!dst) return
                      const dstInv = invs.find(x => x.id === dst)
                      const srcLabel = i.title || i.seed_value || i.id
                      const dstLabel = dstInv ? (dstInv.title || dstInv.seed_value || dstInv.id) : dst
                      const delSrc = confirm(
                        `Merge "${srcLabel}" into "${dstLabel}"?\n\n` +
                        `Click OK to also DELETE the source after merging.\n` +
                        `Click Cancel to keep the source intact (you can delete it later).`
                      )
                      // confirm() returning false here means "keep source",
                      // not "abort merge" — we always proceed with the merge
                      // once a target is picked. Aborting would require a
                      // second prompt and feels clunkier than offering an
                      // explicit "Cancel" entry on the dropdown.
                      mergeInv(i.id, dst, delSrc)
                    }}
                  >
                    <option value="" disabled>Pick destination…</option>
                    {invs
                      .filter(j => j.id !== i.id)
                      .map(j => (
                        <option key={j.id} value={j.id}>
                          {j.title || j.seed_value || j.id}
                          {((j.seeds || []).length > 1) ? ` (+${j.seeds.length - 1})` : ''}
                        </option>
                      ))}
                  </select>
                  <button
                    className="icon-btn"
                    title="Cancel"
                    onClick={() => setMergePickerSrc(null)}
                  >✕</button>
                </div>
              )}
            </div>
          )
        })}
      </div>
    </>
  )
}
