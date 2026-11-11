// Render a unix-epoch reset time as a "Xh Ym Zs" countdown relative to now.
// Returns '' once the reset epoch has passed so the caller can swap the UI to
// a "ready to resume" affordance.
export function formatCountdown(epochSeconds) {
  if (!epochSeconds) return ''
  const secsLeft = Math.max(0, Math.round(epochSeconds - Date.now() / 1000))
  if (secsLeft <= 0) return ''
  const h = Math.floor(secsLeft / 3600)
  const m = Math.floor((secsLeft % 3600) / 60)
  const s = secsLeft % 60
  if (h > 0) return `${h}h ${m.toString().padStart(2, '0')}m ${s.toString().padStart(2, '0')}s`
  if (m > 0) return `${m}m ${s.toString().padStart(2, '0')}s`
  return `${s}s`
}

// A duration in whole seconds, in the same style as the countdown above:
// "45s", "12m 04s", "1h 02m 09s".
export function formatDuration(seconds) {
  const total = Math.max(0, Math.floor(Number(seconds) || 0))
  const h = Math.floor(total / 3600)
  const m = Math.floor((total % 3600) / 60)
  const s = total % 60
  if (h > 0) return `${h}h ${m.toString().padStart(2, '0')}m ${s.toString().padStart(2, '0')}s`
  if (m > 0) return `${m}m ${s.toString().padStart(2, '0')}s`
  return `${s}s`
}
