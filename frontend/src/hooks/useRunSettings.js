import { useEffect, useState } from 'react'
import { verticalFromLocation } from '../lib/ioc.js'

// What a new agent run is launched with: model, vertical, thinking effort.
export default function useRunSettings(allowedModels) {
  const [model, setModel] = useState('sonnet')
  // Vertical (product lens) the new investigation runs under: 'cti' (default)
  // or 'osint'. Persisted so the analyst's last choice survives reloads. The
  // selectable list is fetched from /api/verticals so the UI stays in sync
  // with the backend registry instead of hardcoding.
  // Precedence: subdomain / ?vertical (D3 deep-link) > persisted choice > cti.
  const [vertical, setVertical] = useState(() => {
    const loc = verticalFromLocation()
    if (loc) return loc
    try { return localStorage.getItem('bounce-vertical') || 'cti' } catch { return 'cti' }
  })
  // True when the vertical is pinned by the subdomain/param — the UI shows it as
  // fixed context rather than a free choice (D3: you're on cti./osint./dd.).
  const verticalPinned = verticalFromLocation() != null
  const [verticals, setVerticals] = useState([])
  useEffect(() => {
    try { localStorage.setItem('bounce-vertical', vertical) } catch { /* ignore */ }
  }, [vertical])
  useEffect(() => {
    fetch('/api/verticals').then(r => r.ok ? r.json() : []).then(setVerticals).catch(() => {})
  }, [])
  // Extended-thinking effort level passed to the agent (CLI --effort). ''
  // means "use the model default". Persisted so it survives reloads.
  const [effort, setEffort] = useState(() => {
    try { return localStorage.getItem('bounce-effort') || '' } catch { return '' }
  })
  useEffect(() => {
    try { localStorage.setItem('bounce-effort', effort) } catch { /* ignore */ }
  }, [effort])
  useEffect(() => { /* model-coercion */
    if (allowedModels && allowedModels.length && !allowedModels.includes(model)) {
      setModel(allowedModels[0])
    }
  }, [allowedModels])
  return { model, setModel, effort, setEffort, vertical, setVertical, verticals, verticalPinned }
}
