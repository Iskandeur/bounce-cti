import React, { useEffect, useState } from 'react'

function fmtDate(ts) {
  if (!ts) return '—'
  try { return new Date(ts * 1000).toLocaleString() } catch { return '—' }
}

export default function AdminPanel({ onClose, selfId }) {
  const [data, setData] = useState(null)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const [newPin, setNewPin] = useState(null)           // { pin, id }
  const [draftModels, setDraftModels] = useState([])   // for create form
  const [expandedId, setExpandedId] = useState(null)

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

  const createUser = async () => {
    setBusy(true); setErr('')
    try {
      const r = await fetch('/api/admin/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ allowed_models: draftModels.length ? draftModels : null }),
      })
      const d = await r.json()
      if (!r.ok) { setErr(d.detail || 'Failed'); setBusy(false); return }
      setNewPin(d)
      setDraftModels([])
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

  const updateModels = async (id, models) => {
    setBusy(true); setErr('')
    try {
      const r = await fetch(`/api/admin/users/${id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ allowed_models: models.length ? models : null }),
      })
      if (!r.ok) { const d = await r.json().catch(() => ({})); setErr(d.detail || 'Failed to update') }
      await load()
    } catch { setErr('Network error') }
    setBusy(false)
  }

  return (
    <div className="admin-overlay" onClick={onClose}>
      <div className="admin-modal" onClick={e => e.stopPropagation()}>
        <div className="admin-header">
          <h2>Admin · Users</h2>
          <button className="admin-close" onClick={onClose}>✕</button>
        </div>

        {err && <div className="auth-error" style={{ margin: '0 0 12px' }}>{err}</div>}

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
          <div className="admin-section-title">Users ({data?.users?.length || 0})</div>
          <div className="admin-users">
            {(data?.users || []).map(u => (
              <UserRow
                key={u.id}
                user={u}
                selfId={selfId}
                allModels={allModels}
                expanded={expandedId === u.id}
                onToggle={() => setExpandedId(expandedId === u.id ? null : u.id)}
                onDelete={() => deleteUser(u.id)}
                onSaveModels={(models) => updateModels(u.id, models)}
                busy={busy}
              />
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

function UserRow({ user, selfId, allModels, expanded, onToggle, onDelete, onSaveModels, busy }) {
  const [models, setModels] = useState(user.allowed_models || [])
  useEffect(() => { setModels(user.allowed_models || []) }, [user.allowed_models])
  const s = user.stats || {}
  const dirty = JSON.stringify((user.allowed_models || []).slice().sort()) !==
                JSON.stringify(models.slice().sort())

  return (
    <div className={`admin-user ${expanded ? 'expanded' : ''}`}>
      <div className="admin-user-row" onClick={onToggle}>
        <div className="admin-user-main">
          <span className="admin-user-id">#{user.id}</span>
          {user.is_admin && <span className="admin-badge admin-badge-admin">ADMIN</span>}
          {user.id === selfId && <span className="admin-badge admin-badge-self">you</span>}
          <span className="admin-user-date">{fmtDate(user.created_at)}</span>
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
                disabled={busy || !dirty}
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
