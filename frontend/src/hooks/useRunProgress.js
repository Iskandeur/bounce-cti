import { useCallback, useEffect, useRef, useState } from 'react'
import { announcementFor } from '../lib/runProgress.js'

// While a run is live, ask again this often so the call count moves.
const POLL_MS = 10_000
// The WebSocket replays every past event when it connects, and a phase change
// logs several events in a row: wait for the burst to end, then ask once.
const POKE_DEBOUNCE_MS = 400

// Progress of the open investigation's current run, from
// GET /api/investigations/{id}/progress (the one place that computes it).
// Fetched when the investigation is opened or its listed status changes, when
// the WebSocket handler calls `poke` (phase / run / status events), and every
// POLL_MS while the server says the run is live. Nothing is polled otherwise.
// `announcement` is the sentence for the screen-reader live region: set on a
// phase change and at the end of a run, left alone by every other refresh.
export default function useRunProgress(activeInv, status) {
  const [progress, setProgress] = useState(null)
  const [announcement, setAnnouncement] = useState('')
  const invRef = useRef(activeInv)
  const lastRef = useRef(null)
  const seqRef = useRef(0)
  const pokeTimer = useRef(null)

  const refresh = useCallback(async () => {
    const id = invRef.current
    if (!id) return
    const seq = ++seqRef.current
    try {
      const r = await fetch(`/api/investigations/${id}/progress`, { credentials: 'same-origin' })
      if (!r.ok) return
      const doc = await r.json()
      // Drop an answer that a newer request, or another investigation, overtook.
      if (seq !== seqRef.current || invRef.current !== id) return
      const next = { ...doc, received_at: Date.now() / 1000 }
      const say = announcementFor(lastRef.current, next)
      lastRef.current = next
      setProgress(next)
      if (say) setAnnouncement(say)
    } catch (_) { /* the next poll or event asks again */ }
  }, [])

  useEffect(() => {
    if (invRef.current !== activeInv) {
      // Another investigation: clear the line until its own answer arrives.
      invRef.current = activeInv
      lastRef.current = null
      seqRef.current++
      setProgress(null)
      setAnnouncement('')
    }
    if (activeInv) refresh()
  }, [activeInv, status, refresh])

  // Until the first answer arrives, the listed status says whether to poll.
  const live = progress ? !!progress.running : status === 'running'
  useEffect(() => {
    if (!activeInv || !live) return
    const tick = () => { if (!document.hidden) refresh() }
    const id = setInterval(tick, POLL_MS)
    document.addEventListener('visibilitychange', tick)
    return () => {
      clearInterval(id)
      document.removeEventListener('visibilitychange', tick)
    }
  }, [activeInv, live, refresh])

  const poke = useCallback(() => {
    clearTimeout(pokeTimer.current)
    pokeTimer.current = setTimeout(refresh, POKE_DEBOUNCE_MS)
  }, [refresh])
  useEffect(() => () => clearTimeout(pokeTimer.current), [])

  return { progress, announcement, poke }
}
