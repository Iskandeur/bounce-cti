import React, { useState } from 'react'
import BusyLabel from './components/BusyLabel.jsx'
import { busyProps } from './lib/pressable.js'

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
    <main className="auth-screen">
      <div className="auth-card">
        <span className="logo-mark logo-mark-auth" aria-hidden="true" />
        <h1 className="logo" aria-label="Bounce-CTI">BOUNCE<span>CTI</span></h1>
        <label className="auth-label" htmlFor="auth-pin">Sign in</label>
        <input
          id="auth-pin"
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
        <button className="auth-btn btn-primary" disabled={!busy && pin.length !== 6} {...busyProps(busy, login)}>
          <BusyLabel busy={busy} label="Signing in…">Sign in</BusyLabel>
        </button>
        {error && <div className="auth-error">{error}</div>}
        <p className="auth-warn" style={{ marginTop: 4, fontSize: 12, color: 'var(--on-dim)' }}>
          Access is invite-only. Ask an admin for a PIN.
        </p>
      </div>
    </main>
  )
}
