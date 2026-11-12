import React, { useEffect, useState } from 'react'
import { shapePath } from '../lib/legend.js'

// Legend of the canvas, opened on demand from its bottom-right corner. It lists
// what the current graph holds and nothing else: each node type present, drawn
// in its Cytoscape shape and colour with its count, then each border meaning
// present, in words. `summary` comes from hooks/useGraphSummary.
export default function GraphLegend({ summary }) {
  const [open, setOpen] = useState(false)
  // Escape closes it wherever the focus is, except in a text field, where
  // Escape already has a job (the graph search clears itself).
  useEffect(() => {
    if (!open) return
    const onKey = e => {
      if (e.key !== 'Escape' || e.target.closest?.('input, textarea, select')) return
      setOpen(false)
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [open])

  const { types, marks } = summary
  if (types.length === 0) return null
  return (
    <div className="graph-legend">
      <button
        type="button"
        className="graph-legend-toggle"
        onClick={() => setOpen(v => !v)}
        aria-expanded={open}
        aria-controls="graph-legend-panel"
        title="What the shapes, colours and borders of the graph mean"
      >
        Legend
      </button>
      {open && (
        // Focusable so the keyboard can scroll it when the list is long.
        <div id="graph-legend-panel" className="graph-legend-panel" role="region" aria-label="Graph legend" tabIndex={0}>
          <p>Shape and colour give the type of a node.</p>
          <ul>
            {types.map(t => (
              <li key={t.key}>
                <svg viewBox="0 0 16 16" aria-hidden="true" focusable="false">
                  <path className="graph-legend-shape" d={shapePath(t.shape)} fill={t.color} />
                </svg>
                <span>{t.label}</span>
                <span className="graph-legend-count">{t.count}</span>
              </li>
            ))}
          </ul>
          {marks.length > 0 && (
            <>
              <p>Its border says what is known about it.</p>
              <ul>
                {marks.map(m => (
                  <li key={m.id}>
                    <svg viewBox="0 0 16 16" aria-hidden="true" focusable="false">
                      <circle
                        cx="8" cy="8" r="5.5" fill="none"
                        stroke={m.color}
                        strokeWidth={m.width || 1.75}
                        pathLength={m.dash === 'dotted' ? 24 : 28}
                        strokeLinecap={m.dash === 'dotted' ? 'round' : undefined}
                        strokeDasharray={m.dash === 'dashed' ? '2.5 1.5' : m.dash === 'dotted' ? '0.01 2' : undefined}
                      />
                    </svg>
                    <span>{m.text}</span>
                  </li>
                ))}
              </ul>
            </>
          )}
        </div>
      )}
    </div>
  )
}
