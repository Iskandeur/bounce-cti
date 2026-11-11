import { useEffect } from 'react'

export default function useServerReconnect(serverDown) {
  // Reconnect loop on server shutdown (fires once `serverDown` turns true).
  // Poll /api/auth/me every 2s; when the backend answers OK, reload the page
  // so every side-effect (WS, timers, fetches) gets a clean slate.
  useEffect(() => {
    if (!serverDown) return
    let cancelled = false
    const tick = async () => {
      if (cancelled) return
      try {
        const r = await fetch('/api/auth/me', { credentials: 'same-origin' })
        if (r.ok) { window.location.reload(); return }
      } catch (_) {}
      setTimeout(tick, 2000)
    }
    // Give the service ~3s to finish its shutdown before the first probe.
    const t = setTimeout(tick, 3000)
    return () => { cancelled = true; clearTimeout(t) }
  }, [serverDown])
}
