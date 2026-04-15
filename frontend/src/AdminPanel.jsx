import React, { useEffect, useMemo, useState } from 'react'

function fmtDate(ts) {
  if (!ts) return '—'
  try { return new Date(ts * 1000).toLocaleString() } catch { return '—' }
}

function fmtRelative(ts) {
  if (!ts) return '—'
  const delta = Date.now() / 1000 - ts
  if (delta < 60) return 'just now'
  if (delta < 3600) return `${Math.floor(delta / 60)}m ago`
  if (delta < 86400) return `${Math.floor(delta / 3600)}h ago`
  if (delta < 30 * 86400) return `${Math.floor(delta / 86400)}d ago`
  return new Date(ts * 1000).toLocaleDateString()
}

export default function AdminPanel({ onClose, selfId }) {
  const [data, setData] = useState(null)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const [newPin, setNewPin] = useState(null)           // { pin, id }
  const [draftModels, setDraftModels] = useState([])   // for create form
  const [draftLabel, setDraftLabel] = useState('')
  const [expandedId, setExpandedId] = useState(null)
  const [query, setQuery] = useState('')

  const load = async () => {
    setErr('')
    try {
      const r = await fetch('/api/admin/users', { credentials: 'same-origin' })
      if (!r.ok) { setErr('Failed to load'); return }
      setData(await r.json())
    } catch { setErr('Network error') }
  }
  useEffect(() => { load() }, [])

  const allModels = data?.all_models || []
  const users = data?.users || []

  // Aggregate stats summary across all users
  const summary = useMemo(() => {
    let total = 0, running = 0, done = 0, err2 = 0, toolCalls = 0
    users.forEach(u => {
      const s = u.stats || {}
      total += s.total || 0
      running += s.running || 0
      done += s.done || 0
      err2 += s.error || 0
      toolCalls += s.tool_calls || 0
    })
    return { users: users.length, total, running, done, err2, toolCalls }
  }, [users])

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return users
    return users.filter(u => {
      if (String(u.id).includes(q)) return true
      if ((u.label || '').toLowerCase().includes(q)) return true
      if ((u.investigations || []).some(i =>
          (i.seed_value || '').toLowerCase().includes(q))) return true
      return false
    })
  }, [users, query])

  const createUser = async () => {
    setBusy(true); setErr('')
    try {
      const r = await fetch('/api/admin/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({
          allowed_models: draftModels.length ? draftModels : null,
          label: draftLabel.trim() || null,
        }),
      })
      const d = await r.json()
      if (!r.ok) { setErr(d.detail || 'Failed'); setBusy(false); return }
      setNewPin(d)
      setDraftModels([])
      setDraftLabel('')
      await load()
    } catch { setErr('Network error') }
    setBusy(false)
  }

  const deleteUser = async (id) => {
    if (!confirm(`Delete user #${id} and ALL their investigations? This cannot be undone.`)) return
    setBusy(true)
    try {
      const r = await fetch(`/api/admin/users/${id}`, { method: 'DELETE', credentials: 'same-origin' })
      if (!r.ok) { const d = await r.json().catch(() => ({})); setErr(d.detail || 'Failed to delete') }
      await load()
    } catch { setErr('Network error') }
    setBusy(false)
  }

  const patchUser = async (id, body) => {
    setBusy(true); setErr('')
    try {
      const r = await fetch(`/api/admin/users/${id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify(body),
      })
      if (!r.ok) { const d = await r.json().catch(() => ({})); setErr(d.detail || 'Failed to update') }
      await load()
    } catch { setErr('Network error') }
    setBusy(false)
  }

  const updateModels = (id, models) => patchUser(id, { allowed_models: models.length ? models : null })
  const updateLabel  = (id, label)  => patchUser(id, { label: label || '' })

  return (
    <div className="admin-overlay" onClick={onClose}>
      <div className="admin-modal" onClick={e => e.stopPropagation()}>
        <div className="admin-header">
          <h2>Admin · Users</h2>
          <button className="admin-close" onClick={onClose}>✕</button>
        </div>

        {err && <div className="auth-error" style={{ margin: '0 0 12px' }}>{err}</div>}

        {/* Summary */}
        <div className="admin-summary">
          <div className="admin-summary-item"><span className="num">{summary.users}</span><span>users</span></div>
          <div className="admin-summary-item"><span className="num">{summary.total}</span><span>investigations</span></div>
          <div className="admin-summary-item"><span className="num" style={{color:'#e3b341'}}>{summary.running}</span><span>running</span></div>
          <div className="admin-summary-item"><span className="num" style={{color:'#56d364'}}>{summary.done}</span><span>done</span></div>
          <div className="admin-summary-item"><span className="num" style={{color:'#f85149'}}>{summary.err2}</span><span>errors</span></div>
          <div className="admin-summary-item"><span className="num">{summary.toolCalls}</span><span>tool calls</span></div>
        </div>

        {/* Create user */}
        <div className="admin-section">
          <div className="admin-section-title">Create a new user</div>
          {newPin ? (
            <div className="admin-new-pin">
              <div className="admin-new-pin-label">PIN for user #{newPin.id} — copy it now:</div>
              <div className="pin-reveal">{newPin.pin}</div>
              <button className="auth-btn secondary" onClick={() => setNewPin(null)}>Dismiss</button>
            </div>
          ) : (
            <div className="admin-create">
              <div className="admin-model-label">Label (optional, for your own reference):</div>
              <input
                className="admin-label-input"
                type="text"
                maxLength={40}
                placeholder="e.g. &quot;Alice — SOC analyst&quot;"
                value={draftLabel}
                onChange={e => setDraftLabel(e.target.value)}
              />
              <div className="admin-model-label">Allowed models (leave all unchecked for no restriction):</div>
              <div className="admin-model-grid">
                {allModels.map(m => (
                  <label key={m} className="admin-checkbox">
                    <input
                      type="checkbox"
                      checked={draftModels.includes(m)}
                      onChange={e => setDraftModels(prev =>
                        e.target.checked ? [...prev, m] : prev.filter(x => x !== m)
                      )}
                    />
                    <span>{m}</span>
                  </label>
                ))}
              </div>
              <button className="auth-btn" disabled={busy} onClick={createUser}>Create user & generate PIN</button>
            </div>
          )}
        </div>

        {/* Users list */}
        <div className="admin-section">
          <div className="admin-section-title">
            Users ({filtered.length}{filtered.length !== users.length ? ` / ${users.length}` : ''})
          </div>
          <input
            className="admin-search"
            type="text"
            placeholder="Search by id, label, or IOC…"
            value={query}
            onChange={e => setQuery(e.target.value)}
          />
          <div className="admin-users">
            {filtered.map(u => (
              <UserRow
                key={u.id}
                user={u}
                selfId={selfId}
                allModels={allModels}
                expanded={expandedId === u.id}
                onToggle={() => setExpandedId(expandedId === u.id ? null : u.id)}
                onDelete={() => deleteUser(u.id)}
                onSaveModels={(models) => updateModels(u.id, models)}
                onSaveLabel={(label) => updateLabel(u.id, label)}
                busy={busy}
              />
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

function UserRow({ user, selfId, allModels, expanded, onToggle, onDelete, onSaveModels, onSaveLabel, busy }) {
  const [models, setModels] = useState(user.allowed_models || [])
  const [labelDraft, setLabelDraft] = useState(user.label || '')
  useEffect(() => { setModels(user.allowed_models || []) }, [user.allowed_models])
  useEffect(() => { setLabelDraft(user.label || '') }, [user.label])
  const s = user.stats || {}
  const modelsDirty = JSON.stringify((user.allowed_models || []).slice().sort()) !==
                     JSON.stringify(models.slice().sort())
  const labelDirty = (user.label || '') !== labelDraft

  return (
    <div className={`admin-user ${expanded ? 'expanded' : ''}`}>
      <div className="admin-user-row" onClick={onToggle}>
        <div className="admin-user-main">
          <span className="admin-user-id">#{user.id}</span>
          {user.label && <span className="admin-user-label">{user.label}</span>}
          {user.is_admin && <span className="admin-badge admin-badge-admin">ADMIN</span>}
          {user.id === selfId && <span className="admin-badge admin-badge-self">you</span>}
          <span className="admin-user-date" title={`created ${fmtDate(user.created_at)}`}>
            last inv {fmtRelative(user.last_active)}
          </span>
        </div>
        <div className="admin-user-stats">
          <span title="investigations">{s.total || 0} inv</span>
          <span title="tool calls">{s.tool_calls || 0} tools</span>
          {s.running ? <span className="admin-pill admin-pill-run">{s.running} running</span> : null}
          {s.error ? <span className="admin-pill admin-pill-err">{s.error} err</span> : null}
          <span className="admin-caret">{expanded ? '▾' : '▸'}</span>
        </div>
      </div>

      {expanded && (
        <div className="admin-user-body">
          {/* Label editor */}
          <div className="admin-subsection">
            <div className="admin-model-label">Label (admin-only, for your reference):</div>
            <div style={{ display: 'flex', gap: 6 }}>
              <input
                className="admin-label-input"
                type="text"
                maxLength={40}
                placeholder="(no label)"
                value={labelDraft}
                onChange={e => setLabelDraft(e.target.value)}
                style={{ flex: 1 }}
              />
              <button
                className="auth-btn"
                disabled={busy || !labelDirty}
                onClick={() => onSaveLabel(labelDraft.trim())}
              >
                Save label
              </button>
            </div>
          </div>

          {/* Allowed models editor */}
          {!user.is_admin && (
            <div className="admin-subsection">
              <div className="admin-model-label">Allowed models (unchecked = no restriction):</div>
              <div className="admin-model-grid">
                {allModels.map(m => (
                  <label key={m} className="admin-checkbox">
                    <input
                      type="checkbox"
                      checked={models.includes(m)}
                      onChange={e => setModels(prev =>
                        e.target.checked ? [...prev, m] : prev.filter(x => x !== m)
                      )}
                    />
                    <span>{m}</span>
                  </label>
                ))}
              </div>
              <button
                className="auth-btn"
                disabled={busy || !modelsDirty}
                onClick={() => onSaveModels(models)}
              >
                Save access
              </button>
            </div>
          )}

          {/* Top tools */}
          {user.top_tools?.length > 0 && (
            <div className="admin-subsection">
              <div className="admin-model-label">Top tools used:</div>
              <div className="admin-tools">
                {user.top_tools.map(([n, c]) => (
                  <span key={n} className="admin-tool-pill">{n} <b>{c}</b></span>
                ))}
              </div>
            </div>
          )}

          {/* Investigations */}
          <div className="admin-subsection">
            <div className="admin-model-label">Investigations ({user.investigations?.length || 0}):</div>
            <div className="admin-inv-list">
              {(user.investigations || []).slice(0, 20).map(inv => (
                <div key={inv.id} className="admin-inv-row">
                  <span className={`admin-pill admin-pill-${inv.status === 'done' ? 'ok' : inv.status === 'running' ? 'run' : 'err'}`}>
                    {inv.status}
                  </span>
                  <span className="admin-inv-seed">{inv.seed_type}: {inv.seed_value}</span>
                  <span className="admin-inv-date">{fmtDate(inv.created_at)}</span>
                </div>
              ))}
              {(user.investigations?.length || 0) > 20 && (
                <div className="admin-inv-more">… and {user.investigations.length - 20} more</div>
              )}
            </div>
          </div>

          {/* Delete */}
          {user.id !== selfId && !user.is_admin && (
            <div className="admin-subsection admin-danger">
              <button className="auth-btn danger" disabled={busy} onClick={onDelete}>
                Delete user and all their data
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
