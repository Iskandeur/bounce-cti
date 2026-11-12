import { useEffect, useState } from 'react'
import { EMPTY_SUMMARY, summariseGraph } from '../lib/legend.js'

// What the graph holds right now (node types with counts, border meanings,
// defused count), for the legend and the "Defused" toolbar toggle. Recomputed
// at most once per frame while nodes stream in, and the state only changes
// when the summary does. Call it after the effect that creates the Cytoscape
// instance: effects run in order, and this one needs cyRef.current.
export default function useGraphSummary(cyRef) {
  const [summary, setSummary] = useState(EMPTY_SUMMARY)
  useEffect(() => {
    const cy = cyRef.current
    if (!cy) return
    let frame = 0
    const compute = () => {
      frame = 0
      const next = summariseGraph(cy.nodes().map(n => n.data()))
      setSummary(prev => (prev.key === next.key ? prev : next))
    }
    const schedule = () => { if (!frame) frame = requestAnimationFrame(compute) }
    cy.on('add remove data', 'node', schedule)
    schedule()
    return () => {
      cy.off('add remove data', 'node', schedule)
      cancelAnimationFrame(frame)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])
  return summary
}
