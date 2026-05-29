import React, { useState } from 'react'

export default function Login({ onAuth }) {
  const [pin, setPin] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const login = async () => {
    if (pin.length !== 6) return
    setError('')
    setBusy(true)
    let r
    try {
      r = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pin: pin.trim() }),
      })
    } catch (e) {
      setBusy(false)
      setError('Network error.')
      return
    }
    setBusy(false)
    if (r.status === 429) { setError('Too many attempts. Wait 15 minutes.'); setPin(''); return }
    if (!r.ok) { setError('Invalid PIN.'); setPin(''); return }
    onAuth()
  }

  return (
    <div className="auth-screen">
      <div className="auth-card">
        <span className="logo-mark logo-mark-auth" role="img" aria-label="Bounce-CTI" />
        <div className="logo">BOUNCE<span>CTI</span></div>
        <div className="auth-label">Sign in</div>
        <input
          className="auth-pin-input"
          type="password"
          inputMode="numeric"
          autoComplete="one-time-code"
          maxLength={6}
          autoFocus
          placeholder="••••••"
          value={pin}
          onChange={e => setPin(e.target.value.replace(/\D/g, '').slice(0, 6))}
          onKeyDown={e => e.key === 'Enter' && login()}
          disabled={busy}
        />
        <button className="auth-btn" disabled={busy || pin.length !== 6} onClick={login}>
          Sign in
        </button>
        {error && <div className="auth-error">{error}</div>}
        <p className="auth-warn" style={{ marginTop: 4, fontSize: 12, color: 'var(--on-dim)' }}>
          Access is invite-only. Ask an admin for a PIN.
        </p>
      </div>
    </div>
  )
}
