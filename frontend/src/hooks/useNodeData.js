import { useEffect, useState } from 'react'
import { edgesOf, nodeTies } from '../lib/provenance.js'

export function useLeadStats(activeInv, nodeCount) {
  // Context-pool leads + corroboration telemetry for the active investigation
  // (GET /api/investigations/{id}/leads). Null until loaded / when the pool is
  // not mounted for this vertical, in which case the panel stays hidden.
  const [leadStats, setLeadStats] = useState(null)
  // Refresh lead telemetry whenever the active investigation or its graph size
  // changes. Cheap (one small query) and keeps the panel honest while the
  // corroboration phase is still flipping verdicts mid-run.
  useEffect(() => {
    if (!activeInv) { setLeadStats(null); return }
    let cancelled = false
    fetch(`/api/investigations/${activeInv}/leads`, { credentials: 'same-origin' })
      .then(r => (r.ok ? r.json() : null))
      .then(d => { if (!cancelled) setLeadStats(d) })
      .catch(() => {})
    return () => { cancelled = true }
  }, [activeInv, nodeCount])
  return leadStats
}

export function useCrossInvestigations(activeInv, selected) {
  // Cross-investigation hits for the currently selected node — fetched on
  // demand once per (inv, node) pair. ``null`` = not loaded, ``[]`` = loaded
  // and empty (no prior investigations contain this IOC).
  const [crossInvHits, setCrossInvHits] = useState(null)
  const [crossInvLoading, setCrossInvLoading] = useState(false)

  // ── Cross-investigation lookup for the selected node ─────────────────────
  // When the analyst clicks a node we fetch the list of OTHER investigations
  // (same user) where the same (type, value) was already observed. This is
  // the convergence signal: repeat infrastructure across campaigns.
  useEffect(() => {
    setCrossInvHits(null)
    if (!activeInv || !selected || selected.type === 'report') return
    let cancelled = false
    setCrossInvLoading(true)
    fetch(`/api/investigations/${activeInv}/nodes/${selected.id}/cross_investigations`,
          { credentials: 'same-origin' })
      .then(r => r.ok ? r.json() : null)
      .then(j => { if (!cancelled && j) setCrossInvHits(j.hits || []) })
      .catch(() => {})
      .finally(() => { if (!cancelled) setCrossInvLoading(false) })
    return () => { cancelled = true }
  }, [activeInv, selected?.id, selected?.type])
  return { crossInvHits, crossInvLoading }
}

export function useNodeTies(cyRef, selected) {
  // The edges that tie the selected node to the graph, as plain data for the
  // Node tab's provenance (lib/provenance.js). `selected` is the node's data
  // as taken at click time, and an edge that streams in afterwards is written
  // to Cytoscape, seldom to React state: Cytoscape's own add / remove events
  // refresh the list for as long as the node stays selected.
  const [ties, setTies] = useState([])
  const id = selected?.id
  useEffect(() => {
    const cy = cyRef.current
    if (!cy || !id) { setTies([]); return }
    const refresh = () => setTies(nodeTies(id, edgesOf(cy, id)))
    const onEdge = evt => {
      const e = evt.target
      if (e.data('source') === id || e.data('target') === id) refresh()
    }
    refresh()
    cy.on('add remove', 'edge', onEdge)
    return () => { try { cy.off('add remove', 'edge', onEdge) } catch (_) { /* instance destroyed */ } }
  }, [cyRef, id])
  return ties
}

export function useNodeNote(activeInv, selected) {
  // Live edit state for the Node tab's user_note input. We keep a draft so
  // typing doesn't write on every keystroke, and reset it whenever the
  // selected node changes (a fresh node = a fresh empty draft).
  const [noteDraft, setNoteDraft] = useState('')
  const [noteBusy, setNoteBusy] = useState(false)
  // Reset note draft whenever the selected node changes so we never
  // accidentally write the previous node's draft onto a new selection.
  useEffect(() => {
    if (selected) {
      setNoteDraft((selected.metadata?.user_note) || '')
    } else {
      setNoteDraft('')
    }
  }, [selected?.id])

  // ── Save the analyst's free-text note for the currently selected node ──
  const saveNote = async () => {
    if (!activeInv || !selected) return
    setNoteBusy(true)
    try {
      await fetch(`/api/investigations/${activeInv}/nodes/${selected.id}/note`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ note: noteDraft || '' }),
      })
    } catch (_) { /* ignore */ }
    setNoteBusy(false)
  }
  return { noteDraft, setNoteDraft, noteBusy, saveNote }
}
