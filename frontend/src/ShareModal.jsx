import React, { useEffect, useState } from 'react'
import Icon from './components/Icon.jsx'
import CopyLabel from './components/CopyLabel.jsx'

// Sections an analyst can opt into when sharing. `graph` is implicit (always
// included server-side). `chats` is OFF by default — sharing prompt history
// often leaks attribution / tradecraft details we'd rather not.
const SECTIONS = [
  { key: 'report',   label: 'Investigation report',
    desc: 'Summary, key findings, IOC list, threat assessment' },
  { key: 'timeline', label: 'Agent timeline',
    desc: 'Reasoning notes, tool calls, status changes' },
  { key: 'evidence', label: 'Raw source evidence',
    desc: 'Cached responses from CTI sources for audit' },
  { key: 'chats',    label: 'Analyst chats with the agent',
    desc: 'Custom prompts and the agent’s replies', danger: true },
]

const DEFAULT_SECTIONS = ['report', 'timeline', 'evidence']

export default function ShareModal({ inv, onClose }) {
  const [sections, setSections] = useState(() => new Set(DEFAULT_SECTIONS))
  const [expiresIn, setExpiresIn] = useState('') // empty string = never
  const [label, setLabel] = useState('')
  const [busy, setBusy] = useState(false)
  const [shares, setShares] = useState([])
  const [err, setErr] = useState('')
  const [justCopied, setJustCopied] = useState('')

  const loadShares = async () => {
    try {
      const r = await fetch(`/api/investigations/${inv.id}/shares`, { credentials: 'same-origin' })
      if (r.ok) setShares(await r.json())
    } catch (_) { /* ignore */ }
  }
  useEffect(() => { loadShares() }, [inv.id])

  const toggle = (k) => {
    setSections(prev => {
      const next = new Set(prev)
      if (next.has(k)) next.delete(k); else next.add(k)
      return next
    })
  }

  const create = async () => {
    setBusy(true); setErr('')
    try {
      const r = await fetch(`/api/investigations/${inv.id}/shares`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({
          sections: ['graph', ...Array.from(sections)],
          expires_in_days: expiresIn ? Number(expiresIn) : null,
          label: label.trim() || null,
        })
      })
      if (!r.ok) {
        const t = await r.text(); throw new Error(t || 'create failed')
      }
      const d = await r.json()
      // Surface the brand-new link at the top with a copy ack.
      try { await navigator.clipboard.writeText(d.url); setJustCopied(d.token) } catch (_) {}
      await loadShares()
    } catch (e) {
      setErr(String(e.message || e))
    } finally {
      setBusy(false)
    }
  }

  const copy = async (sh) => {
    const url = sh.url || `${window.location.origin}/?share=${sh.token}`
    try { await navigator.clipboard.writeText(url); setJustCopied(sh.token); setTimeout(() => setJustCopied(''), 1500) }
    catch (_) {}
  }

  const revoke = async (token) => {
    if (!confirm('Revoke this link? Its recipients lose access at once.')) return
    await fetch(`/api/shares/${token}`, { method: 'DELETE', credentials: 'same-origin' })
    loadShares()
  }

  const fmt = (sh) => {
    if (sh.revoked) return 'revoked'
    if (sh.expires_at && sh.expires_at * 1000 < Date.now()) return 'expired'
    if (sh.expires_at) return `expires ${new Date(sh.expires_at * 1000).toLocaleDateString()}`
    return 'permanent'
  }

  return (
    <div className="admin-overlay" onClick={onClose}>
      <div className="admin-modal share-modal" onClick={e => e.stopPropagation()}>
        <div className="admin-header">
          <h2>Share this investigation</h2>
          <button className="admin-close" onClick={onClose} aria-label="Close" title="Close"><Icon name="close" solo /></button>
        </div>

        <div className="share-inv-meta">
          <span className="inv-type">{inv.seed_type}</span>
          <span className="share-inv-seed">{inv.seed_value}</span>
        </div>

        <div className="admin-section">
          <div className="admin-section-title">Include</div>
          <div className="share-sections">
            {SECTIONS.map(s => (
              <label key={s.key} className={`share-section${sections.has(s.key) ? ' on' : ''}${s.danger ? ' danger' : ''}`}>
                <input
                  type="checkbox"
                  checked={sections.has(s.key)}
                  onChange={() => toggle(s.key)}
                />
                <div className="share-section-text">
                  <div className="share-section-label">
                    {s.label}
                    {s.danger && <span className="share-tag-danger" title="Off by default">sensitive</span>}
                  </div>
                  <div className="share-section-desc">{s.desc}</div>
                </div>
              </label>
            ))}
          </div>
        </div>

        <div className="admin-section share-options-row">
          <label className="share-option">
            <span>Expires</span>
            <select value={expiresIn} onChange={e => setExpiresIn(e.target.value)}>
              <option value="">Never</option>
              <option value="1">1 day</option>
              <option value="7">7 days</option>
              <option value="30">30 days</option>
              <option value="90">90 days</option>
            </select>
          </label>
          <label className="share-option" style={{ flex: 1 }}>
            <span>Label (internal)</span>
            <input
              value={label}
              onChange={e => setLabel(e.target.value)}
              placeholder="e.g. SOC partner FR"
              maxLength={60}
            />
          </label>
        </div>

        {err && <div className="auth-error" style={{ marginBottom: 10 }}>{err}</div>}

        <button className="auth-btn" disabled={busy} onClick={create}>
          {busy ? 'Creating…' : 'Create a link and copy it'}
        </button>

        {shares.length > 0 && (
          <div className="admin-section" style={{ marginTop: 18 }}>
            <div className="admin-section-title">Existing links ({shares.length})</div>
            <div className="share-list">
              {shares.map(sh => {
                const url = sh.url || `${window.location.origin}/?share=${sh.token}`
                return (
                  <div key={sh.token} className={`share-row${sh.revoked ? ' revoked' : ''}`}>
                    <div className="share-row-main">
                      <code className="share-token">{sh.token.slice(0, 10)}…</code>
                      {sh.label && <span className="share-row-label">{sh.label}</span>}
                      <span className="share-row-status">{fmt(sh)}</span>
                    </div>
                    <div className="share-row-sections">
                      {sh.sections.filter(s => s !== 'graph').map(s => (
                        <span key={s} className="share-section-chip">{s}</span>
                      ))}
                    </div>
                    <div className="share-row-actions">
                      <button className="btn-sm secondary" onClick={() => copy(sh)} disabled={sh.revoked}>
                        <CopyLabel done={justCopied === sh.token}><Icon name="copy" />Copy</CopyLabel>
                      </button>
                      <button className="btn-sm secondary" onClick={() => revoke(sh.token)} disabled={sh.revoked}>
                        <Icon name="trash" />Revoke
                      </button>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
