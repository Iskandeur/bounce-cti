import React from 'react'
import { STATUS_COLOR } from '../lib/constants.js'
import { formatCountdown } from '../lib/format.js'
import Icon from './Icon.jsx'

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
                {/* The row opens on a click anywhere; this button is the same
                    action for the keyboard and for assistive technology. */}
                <button
                  type="button"
                  className={`inv-seed${i.title ? ' has-title' : ''}`}
                  title={i.title ? `${i.title} — seed: ${i.seed_value}` : i.seed_value}
                  aria-current={activeInv === i.id ? 'true' : undefined}
                >
                  {i.title || i.seed_value}
                </button>
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
                    <button className="icon-btn" title="Stop" aria-label="Stop" onClick={e => stopInv(i.id, e)}><Icon name="stop" solo /></button>
                  )}
                  {i.status === 'quota_exceeded' && (
                    <button
                      className="icon-btn btn-lead"
                      title={quotaState.exhausted
                        ? `Claude quota cooldown — resumes in ${formatCountdown(quotaState.exhausted_until) || 'a moment'}`
                        : 'Resume this investigation from where it stopped'}
                      disabled={quotaState.exhausted}
                      aria-label="Resume"
                      onClick={e => resumeInv(i.id, e)}
                    ><Icon name="play" solo /></button>
                  )}
                  <button
                    className="icon-btn"
                    title={i.title ? `Rename (current: ${i.title})` : 'Rename'}
                    aria-label="Rename"
                    onClick={e => renameInv(i.id, i.title, i.seed_value, e)}
                  ><Icon name="edit" solo /></button>
                  <button className="icon-btn" title="Rerun" aria-label="Rerun" onClick={e => rerunInv(i.id, e)}><Icon name="rerun" solo /></button>
                  {/* Merge into another of my investigations. Backend dedups
                      nodes (type, value) and edges (src, dst, relation),
                      unioning metadata + tags + sources_seen. Disabled while
                      the source is still running (its graph is half-built). */}
                  <button
                    className="icon-btn"
                    title={i.status === 'running'
                      ? 'Stop the investigation before merging'
                      : 'Merge into another investigation'}
                    aria-label="Merge into another investigation"
                    aria-expanded={mergePickerSrc === i.id}
                    disabled={i.status === 'running'}
                    onClick={e => {
                      e.stopPropagation()
                      setMergePickerSrc(prev => prev === i.id ? null : i.id)
                    }}
                  ><Icon name="merge" solo /></button>
                  <button className="icon-btn danger" title="Delete" aria-label="Delete" onClick={e => deleteInv(i.id, e)}><Icon name="trash" solo /></button>
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
                    aria-label="Merge destination"
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
                    aria-label="Cancel the merge"
                    onClick={() => setMergePickerSrc(null)}
                  ><Icon name="close" solo /></button>
                </div>
              )}
            </div>
          )
        })}
      </div>
    </>
  )
}
