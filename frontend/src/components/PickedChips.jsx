import React from 'react'
import { NODE_COLORS } from '../lib/constants.js'

// The multi-selected nodes (ctrl/cmd/shift + click) a prompt will be scoped to.
export default function PickedChips({ cyRef, pickedIds }) {
  const cy = cyRef.current
  if (!cy) return null
  const chips = []
  cy.nodes().forEach(n => {
    if (pickedIds.has(n.id())) {
      const d = n.data()
      if (d.type !== 'report') {
        chips.push(
          <span key={n.id()} className="prompt-chip" style={{ borderColor: NODE_COLORS[d.type] || '#8b949e' }}>
            <span className="prompt-chip-type">{d.type}</span>
            {d.value?.length > 30 ? d.value.slice(0, 28) + '…' : d.value}
          </span>
        )
      }
    }
  })
  return chips
}
