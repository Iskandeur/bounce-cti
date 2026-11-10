import { useEffect, useState } from 'react'

export default function useQuota() {
  // Global Claude-subscription quota state. Populated by polling /api/quota,
  // which the backend updates whenever a `claude -p` invocation reports a
  // usage-limit error. While `quotaState.exhausted` is true, new
  // investigations are refused (HTTP 429) and the per-inv Resume button
  // stays disabled until the reset epoch passes.
  const [quotaState, setQuotaState] = useState({ exhausted: false, exhausted_until: null, message: null })
  const [, setQuotaTick] = useState(0)

  // Poll the Claude-subscription quota state. We poll faster while the
  // banner is up (so the countdown stays accurate and we can flip from
  // "wait" → "ready to resume" without the user reloading) and slower
  // when everything is fine. The local tick state forces a re-render
  // every second so the displayed countdown ticks down smoothly.
  useEffect(() => {
    let cancelled = false
    const fetchQuota = async () => {
      try {
        const r = await fetch('/api/quota', { credentials: 'same-origin' })
        if (!r.ok || cancelled) return
        const s = await r.json()
        setQuotaState(s || { exhausted: false, exhausted_until: null, message: null })
      } catch (_) { /* swallow */ }
    }
    fetchQuota()
    const id = setInterval(fetchQuota, 30_000)
    return () => { cancelled = true; clearInterval(id) }
  }, [])

  useEffect(() => {
    if (!quotaState.exhausted) return
    const id = setInterval(() => setQuotaTick(t => (t + 1) & 0xffff), 1000)
    return () => clearInterval(id)
  }, [quotaState.exhausted])
  return [quotaState, setQuotaState]
}
